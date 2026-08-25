package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/viper"
)

// ambigCfg loads a config through the real YAML/Viper path — not a Go literal —
// because the defect these tests guard only exists once the loader has folded
// the condition key's case away. A config built in Go keeps its key case and
// never reaches the folded lookup at all.
func ambigCfg(t *testing.T, conditions string) (*Config, string) {
	t.Helper()
	const iss = "https://auth0.example.com"
	dir := t.TempDir()
	yaml := `
issuers:
  - issuer: "` + iss + `"
    provider: generic
    audiences: ["sts.amazonaws.com"]
    claim_mappings:
      subject: "sub"
role_mappings:
  - subject: "acme/platform"
    issuer: "` + iss + `"
    roles: ["arn:aws:iam::123456789012:role/prod-deploy"]
    conditions:
` + conditions
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CONFIG_PATH", dir)
	// LoadConfig reads through viper's package-level singleton, which keeps
	// state between calls in one test binary. Reset so each case loads only
	// its own YAML. Load into a fresh Config rather than NewConfig(): that one
	// is sync.Once-cached, and unmarshalling a second YAML over the cached
	// struct merges the two conditions instead of replacing them.
	viper.Reset()
	c := &Config{}
	if err := c.LoadConfig(); err != nil {
		t.Fatalf("load: %v", err)
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	return c, iss
}

const noneOfContractor = `      none_of:
        - claims:
            isContractor: "true"
`

// TestAmbiguousClaimCannotDisarmANoneOfVeto is the regression guard for the
// bypass: a `none_of` veto must not be silently disarmed by the presence of a
// second casing of the claim it vetoes.
//
// Denying only the leaf is polarity-dependent — under none_of, a leaf that
// cannot match is a veto that cannot fire — so the caller the config was
// written to refuse was authorized instead. The decoy case is the sharpest:
// the second casing carries a value that does not even match the pattern, so
// nothing about the caller's actual contractor status changed.
func TestAmbiguousClaimCannotDisarmANoneOfVeto(t *testing.T) {
	c, iss := ambigCfg(t, noneOfContractor)

	tests := []struct {
		name   string
		claims map[string]any
	}{
		{"single casing: veto fires as written", map[string]any{
			"sub": "acme/platform", "isContractor": "true"}},
		{"second casing of the same claim", map[string]any{
			"sub": "acme/platform", "isContractor": "true", "IsContractor": "true"}},
		{"decoy casing whose value does not match", map[string]any{
			"sub": "acme/platform", "isContractor": "true", "ISCONTRACTOR": "x"}},
		{"three casings", map[string]any{
			"sub": "acme/platform", "isContractor": "true",
			"IsContractor": "true", "ISCONTRACTOR": "true"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matched, roles := c.AuthorizeRoles(iss, "acme/platform", tt.claims)
			if matched {
				t.Fatalf("VETO DISARMED: contractor authorized for %v", roles)
			}
		})
	}
}

// An ambiguous claim must deny under a plain AND too. This direction already
// denied before the fix (the leaf could not match), so the test pins that the
// fix did not change it — the deny is now for the stronger reason. Note it is
// NOT evidence that the `ambiguous` flag works: deleting the flag entirely
// leaves this test passing, because a collision still resolves to nil and a
// leaf with no value fails an AND on its own. The flag is pinned by the none_of
// tests above, where a nil-resolving leaf would instead pass.
func TestAmbiguousClaimDeniesUnderPlainAnd(t *testing.T) {
	c, iss := ambigCfg(t, `      claims:
        isContractor: "false"
`)
	claims := map[string]any{
		"sub": "acme/platform", "isContractor": "false", "IsContractor": "false",
	}
	if matched, roles := c.AuthorizeRoles(iss, "acme/platform", claims); matched {
		t.Fatalf("ambiguous claim authorized under AND: %v", roles)
	}
}

// Ambiguity nested inside a none_of inside an any_of must still deny: the check
// is on the resolver, so it is independent of how many groups enclose the leaf.
func TestAmbiguousClaimDeniesWhenNestedUnderNegation(t *testing.T) {
	c, iss := ambigCfg(t, `      any_of:
        - none_of:
            - claims:
                isContractor: "true"
`)
	claims := map[string]any{
		"sub": "acme/platform", "isContractor": "true", "IsContractor": "true",
	}
	if matched, roles := c.AuthorizeRoles(iss, "acme/platform", claims); matched {
		t.Fatalf("VETO DISARMED through nesting: authorized for %v", roles)
	}
}

// The fix must not deny requests that were previously allowed for good reason.
// A non-contractor with a single claim casing still gets the role, and so does
// one whose token carries an unrelated mixed-case claim the config never names
// — ambiguity is only ever recorded for a claim a condition actually looks up.
func TestAmbiguousFixDoesNotDenyLegitimateCallers(t *testing.T) {
	c, iss := ambigCfg(t, noneOfContractor)

	tests := []struct {
		name   string
		claims map[string]any
	}{
		{"employee, single casing", map[string]any{
			"sub": "acme/platform", "isContractor": "false"}},
		{"employee, claim absent entirely", map[string]any{
			"sub": "acme/platform"}},
		{"unrelated claim collides but is never looked up", map[string]any{
			"sub": "acme/platform", "isContractor": "false",
			"costCenter": "a", "CostCenter": "b"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matched, roles := c.AuthorizeRoles(iss, "acme/platform", tt.claims)
			if !matched || len(roles) != 1 {
				t.Fatalf("legitimate caller denied: matched=%v roles=%v", matched, roles)
			}
		})
	}
}

// An exact-case hit does NOT settle a collision. This test previously asserted
// the opposite — that a lower-case claim matching the key exactly wins outright
// and a stray casing can never make it ambiguous. That premise was wrong, and it
// was the same bypass as TestAmbiguousClaimCannotDisarmANoneOfVeto reached
// through the other branch: viper has already lower-cased the key, so
// `iscontractor` is equally consistent with an operator who wrote
// `isContractor`, and preferring the exact claim decides on one the config may
// never have named. Under none_of it disarms the veto outright.
func TestExactHitDoesNotResolveACollision(t *testing.T) {
	c, iss := ambigCfg(t, `      claims:
        iscontractor: "false"
`)
	claims := map[string]any{
		"sub": "acme/platform", "iscontractor": "false",
		"IsContractor": "true", "ISCONTRACTOR": "true",
	}
	if matched, roles := c.AuthorizeRoles(iss, "acme/platform", claims); matched {
		t.Fatalf("collision resolved by exact hit instead of denying: %v", roles)
	}
}

// The veto must not be disarmed by a LOWER-CASE twin of the vetoed claim
// either. This is the direction the exact-first lookup used to authorize: the
// decoy is the claim whose name matches the folded key exactly, so it won the
// lookup and supplied a value that did not trip the veto.
func TestLowerCaseTwinCannotDisarmANoneOfVeto(t *testing.T) {
	c, iss := ambigCfg(t, noneOfContractor)

	tests := []struct {
		name   string
		claims map[string]any
	}{
		{"lower-case twin carrying a passing value", map[string]any{
			"sub": "acme/platform", "isContractor": "true", "iscontractor": "false"}},
		{"lower-case twin carrying nonsense", map[string]any{
			"sub": "acme/platform", "isContractor": "true", "iscontractor": "zzz"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if matched, roles := c.AuthorizeRoles(iss, "acme/platform", tt.claims); matched {
				t.Fatalf("VETO DISARMED by lower-case twin: authorized for %v", roles)
			}
		})
	}
}

// The all-lower-case path — every GitHub Actions deployment, since GitHub mints
// no upper-case claim name — must be untouched: no collision is possible, so the
// folded index is never even built and lookups answer from the raw claims.
func TestAllLowerCaseClaimsTakeTheUnfoldedPath(t *testing.T) {
	c, iss := ambigCfg(t, `      claims:
        iscontractor: "false"
`)
	claims := map[string]any{"sub": "acme/platform", "iscontractor": "false"}
	matched, roles := c.AuthorizeRoles(iss, "acme/platform", claims)
	if !matched || len(roles) != 1 {
		t.Fatalf("all-lower-case claims denied: matched=%v roles=%v", matched, roles)
	}

	res := newClaimResolver(claims)
	if v := res.lookup("iscontractor"); v != "false" {
		t.Fatalf("lookup returned %v", v)
	}
	if res.folded != nil {
		t.Fatal("folded index was built for all-lower-case claims; the fast path should skip it")
	}
	if res.ambiguous {
		t.Fatal("all-lower-case claims marked ambiguous")
	}
}
