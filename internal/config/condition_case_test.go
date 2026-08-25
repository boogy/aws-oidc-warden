package config

import (
	"os"
	"path/filepath"
	"testing"
)

// A condition key is written in the case the issuer actually mints. Viper
// lowercases every key it reads from a config file, so by the time the key
// reaches the compiler it is `iscontractor` while the token carries
// `isContractor`. If the leaf then resolves to "no value", the predicate is
// silently dead: harmless-looking under a plain AND (it denies), and an
// authorization BYPASS under none_of, where a veto that can never fire lets
// through exactly what the config was written to refuse.
//
// GitHub never surfaced this — every GitHub Actions claim is already
// lowercase. Any other issuer (Auth0, Entra, Keycloak, a custom IdP) routinely
// mints camelCase claims.
func TestConditionKeyResolvesClaimCaseInsensitively(t *testing.T) {
	tests := []struct {
		name   string
		cond   *Condition
		claims map[string]any
		want   bool
	}{
		{
			name:   "none_of veto fires against a camelCase claim",
			cond:   &Condition{NoneOf: []*Condition{{Claims: map[string]Patterns{"iscontractor": {"true"}}}}},
			claims: map[string]any{"isContractor": "true"},
			want:   false,
		},
		{
			name:   "none_of still passes when the camelCase claim does not match",
			cond:   &Condition{NoneOf: []*Condition{{Claims: map[string]Patterns{"iscontractor": {"true"}}}}},
			claims: map[string]any{"isContractor": "false"},
			want:   true,
		},
		{
			name:   "plain leaf matches a camelCase claim",
			cond:   &Condition{Claims: map[string]Patterns{"costcenter": {"cc-1234"}}},
			claims: map[string]any{"costCenter": "cc-1234"},
			want:   true,
		},
		{
			name:   "plain leaf still denies a camelCase claim that does not match",
			cond:   &Condition{Claims: map[string]Patterns{"costcenter": {"cc-1234"}}},
			claims: map[string]any{"costCenter": "cc-9999"},
			want:   false,
		},
		{
			// An exact hit does NOT settle it. The key reaching the matcher is
			// already lower-cased, so "role" may be what the operator wrote or
			// may be what "ROLE" was folded into — two claims are candidates
			// for one key and neither can be shown to be the intended one.
			// Preferring the exact one authorizes on a claim the config may
			// never have named; the same shape under none_of disarms the veto.
			name:   "an exact-case claim alongside a case variant is ambiguous and denies",
			cond:   &Condition{Claims: map[string]Patterns{"role": {"admin"}}},
			claims: map[string]any{"role": "admin", "ROLE": "nobody"},
			want:   false,
		},
		{
			name:   "a lone exact-case claim resolves normally",
			cond:   &Condition{Claims: map[string]Patterns{"role": {"admin"}}},
			claims: map[string]any{"role": "admin"},
			want:   true,
		},
		{
			name:   "two case variants and no exact match is ambiguous and denies",
			cond:   &Condition{Claims: map[string]Patterns{"role": {"admin"}}},
			claims: map[string]any{"Role": "admin", "ROLE": "admin"},
			want:   false,
		},
		{
			name:   "an array-valued camelCase claim matches on any element",
			cond:   &Condition{Claims: map[string]Patterns{"groupmembership": {"platform"}}},
			claims: map[string]any{"groupMembership": []any{"eng", "platform"}},
			want:   true,
		},
		{
			name:   "an absent claim is still absent",
			cond:   &Condition{Claims: map[string]Patterns{"iscontractor": {"true"}}},
			claims: map[string]any{"sub": "acme/app"},
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := compileCondition(tt.cond); err != nil {
				t.Fatalf("compile: %v", err)
			}
			if got := satisfiesConditions(tt.cond, tt.claims); got != tt.want {
				t.Errorf("satisfiesConditions = %v, want %v", got, tt.want)
			}
		})
	}
}

// The unit table above simulates the post-viper state directly. This one walks
// the whole chain — YAML file, viper's key lowercasing, Validate(), and
// AuthorizeRoles — so the regression is pinned where an operator would hit it:
// a `none_of` veto written against a camelCase claim, which before the
// claimResolver fix loaded and validated cleanly and then authorized the exact
// request it was written to refuse.
func TestNoneOfVetoOnCamelCaseClaimDeniesEndToEnd(t *testing.T) {
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
      none_of:
        - claims:
            isContractor: "true"
`
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CONFIG_PATH", dir)

	c, err := NewConfig()
	if err != nil {
		t.Fatal(err)
	}
	if err := c.LoadConfig(); err != nil {
		t.Fatalf("load: %v", err)
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}

	contractor := map[string]any{"sub": "acme/platform", "isContractor": "true"}
	if matched, roles := c.AuthorizeRoles(iss, "acme/platform", contractor); matched {
		t.Errorf("contractor authorized for %v despite the none_of veto", roles)
	}

	employee := map[string]any{"sub": "acme/platform", "isContractor": "false"}
	matched, roles := c.AuthorizeRoles(iss, "acme/platform", employee)
	if !matched || len(roles) != 1 {
		t.Errorf("employee should still be authorized; matched=%v roles=%v", matched, roles)
	}
}
