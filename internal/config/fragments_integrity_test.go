package config

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func a2Base(t *testing.T) *Config {
	t.Helper()
	c := &Config{
		Issuers:         singleIssuer("https://token.actions.githubusercontent.com", "sts.amazonaws.com"),
		RoleSessionName: "aws-oidc-warden",
		Cache:           &Cache{Type: "memory", TTL: time.Hour},
	}
	require.NoError(t, c.Validate())
	return c
}

func a2Write(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(p, []byte(body), 0o600))
	return p
}

// ---------------------------------------------------------------------------
// A. Can a disallowed key evade rejectDisallowedFragmentKeys?
// ---------------------------------------------------------------------------

func TestAudit_FragmentDisallowedKeyEvasionBattery(t *testing.T) {
	cases := []struct {
		name    string
		format  string
		body    string
		wantErr bool // true => must be rejected at parse
	}{
		{"upper_case_issuers", "yaml", "ISSUERS:\n  - issuer: https://evil\n    audiences: [x]\n", true},
		{"mixed_case_tag_auth", "yaml", "Tag_Auth:\n  enabled: true\n", true},
		{"null_issuers", "yaml", "issuers:\n", true},
		{"empty_list_issuers", "yaml", "issuers: []\n", true},
		{"empty_string_issuers", "yaml", "issuers: \"\"\n", true},
		{"empty_map_tag_auth", "yaml", "tag_auth: {}\n", false}, // no keys AND no data
		{"cross_account_allowed", "yaml", "cross_account:\n  enabled: true\n  allowed_accounts: [\"999999999999\"]\n", true},
		{"jwt_validation", "yaml", "jwt_validation:\n  mode: apigw\n", true},
		{"allow_insecure", "yaml", "allow_insecure_issuers: true\n", true},
		{"nested_only", "yaml", "cross_account:\n  allowed_accounts: [\"999999999999\"]\n", true},
		{"json_issuers", "json", `{"issuers":[{"issuer":"https://evil","audiences":["x"]}]}`, true},
		{"toml_tag_auth", "toml", "[tag_auth]\nenabled = true\n", true},
		{"role_session_name", "yaml", "role_session_name: pwn\n", true},
		{"config_fragments_self", "yaml", "config_fragments: [\"/etc/passwd\"]\n", true},
		{"trailing_space_key", "yaml", "\"issuers \": [1]\n", true}, // top segment "issuers " != allowed => rejected anyway
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			frag, err := parseFragment([]byte(tc.body), tc.format, "t")
			if tc.wantErr {
				require.Error(t, err, "expected rejection, got frag=%+v", frag)
				return
			}
			require.NoError(t, err)
			// If it parsed, prove it carries nothing beyond the 4 allowed fields.
			assert.Empty(t, frag.DefaultIssuer)
			assert.Empty(t, frag.RoleSets)
			assert.Empty(t, frag.RoleMappings)
			assert.Empty(t, frag.RoleGroups)
		})
	}
}

// Structural backstop: even if a key slipped past the allowlist, mergeFragment
// can only ever write the 4 FragmentConfig fields. Prove the base's
// security-critical fields are byte-identical before/after a merge.
func TestAudit_MergeFragmentTouchesOnlyFourFields(t *testing.T) {
	cfg := a2Base(t)
	cfg.TagAuth = &TagAuth{Enabled: true, TagPrefix: "aow/"}
	cfg.CrossAccount = &CrossAccount{Enabled: true, AllowedAccounts: []string{"111111111111"}}
	cfg.AllowInsecureIssuers = false
	require.NoError(t, cfg.Validate())

	before := cloneMustJSON(t, cfg)

	frag := &FragmentConfig{
		RoleMappings: []RoleMapping{{Subject: "o/r", Roles: []string{"arn:aws:iam::111111111111:role/x"}}},
	}
	require.NoError(t, mergeFragment(cfg, frag, "f", map[string]bool{cfg.Issuers[0].Issuer: true}))

	assert.Equal(t, before.Issuers, cfg.Issuers)
	assert.Equal(t, before.TagAuth, cfg.TagAuth)
	assert.Equal(t, before.CrossAccount, cfg.CrossAccount)
	assert.Equal(t, before.JWTValidation, cfg.JWTValidation)
	assert.Equal(t, before.AllowInsecureIssuers, cfg.AllowInsecureIssuers)
	assert.Equal(t, before.RoleSessionName, cfg.RoleSessionName)
}

func cloneMustJSON(t *testing.T, c *Config) *Config {
	t.Helper()
	cl, err := cloneConfig(c)
	require.NoError(t, err)
	return cl
}

// ---------------------------------------------------------------------------
// B. cloneConfig fidelity: does any security-relevant field vanish?
// ---------------------------------------------------------------------------

func TestAudit_CloneConfigPreservesSecurityFields(t *testing.T) {
	leeway := 45 * time.Second
	c := &Config{
		Issuers: []IssuerConfig{
			{
				Issuer: "https://a.example", Provider: "github",
				Audiences: []string{"sts.amazonaws.com"},
				JWKSURI:   "https://a.example/jwks",
				SessionTags: map[string]string{
					"repo": "repository",
				},
				RequiredClaims: []string{"repository"},
			},
			{
				Issuer: "https://b.example", Provider: "generic",
				Audiences:     []string{"aud-b"},
				ClaimMappings: map[string]string{"subject": "sub"},
			},
		},
		DefaultIssuer:   "https://a.example",
		RoleSessionName: "aws-oidc-warden",
		Cache:           &Cache{Type: "memory", TTL: time.Hour},
		RoleSets:        map[string][]string{"prod": {"arn:aws:iam::111111111111:role/prod"}},
		RoleMappings: []RoleMapping{
			{Subject: "o/r", Roles: []string{"@prod"}, SessionPolicyFile: "p.json",
				Conditions: &Condition{Branch: "main", Extra: map[string]string{"custom": "v"}}},
		},
		TagAuth:                 &TagAuth{Enabled: true, TagPrefix: "aow/", DefaultOrg: "acme", TransitiveSessionTags: true},
		CrossAccount:            &CrossAccount{Enabled: true, SpokeRoleName: "aow-spoke", ExternalID: "eid", AllowedAccounts: []string{"222222222222"}},
		JWTValidation:           JWTValidation{Mode: "alb", ALBExpectedSigner: "arn:aws:elasticloadbalancing:eu-west-1:111111111111:loadbalancer/app/x/y"},
		JWTLeeway:               &leeway,
		MaxTokenLifetime:        10 * time.Minute,
		MaxTokenAge:             5 * time.Minute,
		MaxTokenBytes:           4096,
		JWKSRefetchCooldown:     90 * time.Second,
		AllowInsecureIssuers:    true,
		LogLevel:                "warn",
		LogClaimValues:          true,
		AuditRequired:           true,
		LogToS3:                 true,
		LogBucket:               "b",
		ConfigFragments:         []string{"/tmp/f.yaml"},
		ConfigFragmentChecksums: map[string]string{"/tmp/f.yaml": "sha256:deadbeef"},
	}
	require.NoError(t, c.Validate())

	clone, err := cloneConfig(c)
	require.NoError(t, err)
	// Clone has NOT been validated yet: this is exactly the state applyFragments
	// would see if refreshLocked skipped validation. Validate it as refreshLocked does.
	require.NoError(t, clone.Validate())

	assert.Equal(t, c.Issuers, clone.Issuers)
	assert.Equal(t, c.DefaultIssuer, clone.DefaultIssuer)
	assert.Equal(t, c.RoleSets, clone.RoleSets)
	assert.Equal(t, c.AllowInsecureIssuers, clone.AllowInsecureIssuers)
	assert.Equal(t, *c.JWTLeeway, *clone.JWTLeeway)
	assert.Equal(t, c.MaxTokenLifetime, clone.MaxTokenLifetime)
	assert.Equal(t, c.MaxTokenAge, clone.MaxTokenAge)
	assert.Equal(t, c.MaxTokenBytes, clone.MaxTokenBytes)
	assert.Equal(t, c.JWKSRefetchCooldown, clone.JWKSRefetchCooldown)
	assert.Equal(t, c.AuditRequired, clone.AuditRequired)
	assert.Equal(t, c.LogClaimValues, clone.LogClaimValues)
	assert.Equal(t, c.JWTValidation, clone.JWTValidation)
	assert.Equal(t, c.CrossAccount, clone.CrossAccount)
	assert.Equal(t, c.ConfigFragmentChecksums, clone.ConfigFragmentChecksums)

	// TagAuth.multiIssuer is json:"-" -- prove Validate() rebuilds it.
	assert.True(t, c.TagAuth.multiIssuer, "source multiIssuer")
	assert.True(t, clone.TagAuth.multiIssuer, "clone multiIssuer LOST by cloneConfig and not rebuilt")

	// Compiled/derived state must be rebuilt.
	require.Len(t, clone.effective, 1)
	assert.NotNil(t, clone.effective[0].compiledPattern)
	assert.Equal(t, []string{"arn:aws:iam::111111111111:role/prod"}, clone.effective[0].Roles)
	assert.NotEmpty(t, clone.effective[0].Conditions.compiled)
}

// Same question, but through the real refresh path with a single issuer, where
// multiIssuer must be FALSE, and then with two issuers, where it must be TRUE.
func TestAudit_MultiIssuerGateSurvivesRefresh(t *testing.T) {
	base := a2Base(t)
	base.TagAuth = &TagAuth{Enabled: true, TagPrefix: "aow/"}
	base.Issuers = append(base.Issuers, IssuerConfig{
		Issuer: "https://second.example", Provider: "generic",
		Audiences: []string{"aud"}, ClaimMappings: map[string]string{"subject": "sub"},
	})
	base.DefaultIssuer = base.Issuers[0].Issuer
	require.NoError(t, base.Validate())
	require.True(t, base.TagAuth.multiIssuer)

	dir := t.TempDir()
	f := a2Write(t, dir, "f.yaml", "role_mappings:\n  - subject: \"o/r\"\n    roles: [\"arn:aws:iam::111111111111:role/x\"]\n")
	base.ConfigFragments = []string{f}
	require.NoError(t, base.Validate())

	p := NewProvider(base, time.Minute, "yaml", nil)
	require.NoError(t, p.Refresh(context.Background()))

	got := p.Get()
	require.NotNil(t, got.TagAuth)
	assert.True(t, got.TagAuth.multiIssuer,
		"cross-issuer tag-auth gate silently disabled after hot reload")
}

// ---------------------------------------------------------------------------
// C. Checksum pinning: is a pin enforced when the fragment is "unchanged"?
// ---------------------------------------------------------------------------

func TestAudit_ChecksumPinNotReappliedToCachedFragment(t *testing.T) {
	dir := t.TempDir()
	f := a2Write(t, dir, "f.yaml", "role_mappings:\n  - subject: \"o/r\"\n    roles: [\"arn:aws:iam::111111111111:role/x\"]\n")

	base := a2Base(t)
	base.ConfigFragments = []string{f}
	require.NoError(t, base.Validate())

	// Cycle 1: no pin -> fragment applied, cached.
	p := NewProvider(base, time.Minute, "yaml", nil)
	require.NoError(t, p.Refresh(context.Background()))
	require.Len(t, p.Get().RoleMappings, 1)

	// Cycle 2: operator now pins a DIFFERENT (wrong) checksum on the base.
	// The file is unchanged, so the etag matches the cache — this is exactly
	// the incident-response case: quarantine content that is ALREADY applied.
	base.ConfigFragmentChecksums = map[string]string{f: "sha256:0000000000000000000000000000000000000000000000000000000000000000"}
	err := p.Refresh(context.Background())
	t.Logf("refresh with mismatched pin on unchanged fragment: err=%v", err)

	// Regression: the pin used to be compared only inside applyFragments'
	// "changed" branch, so a cache hit (etag == prevETag) skipped it entirely
	// and a newly-added or rotated pin was silently inert. It is now checked
	// on every cycle, before the cache-hit branch.
	require.Error(t, err, "a mismatched pin must be enforced on the cache-hit path too")
	assert.Contains(t, err.Error(), "failed integrity check")

	// Refresh failed, so the last-good config is retained unchanged.
	assert.Len(t, p.Get().RoleMappings, 1, "last-good config must be retained on a failed refresh")
}

// The pin is compared against the fetcher-supplied etag, not a hash of the
// returned bytes. Prove whether a fetcher returning a matching etag with
// different content is accepted.
func TestAudit_ChecksumPinTrustsFetcherETagNotContent(t *testing.T) {
	base := a2Base(t)
	base.ConfigFragments = []string{"s3://bucket/frag.yaml"}
	base.ConfigFragmentChecksums = map[string]string{"s3://bucket/frag.yaml": "pinned-etag"}
	require.NoError(t, base.Validate())

	evil := []byte("role_mappings:\n  - subject: \"victim/.+\"\n    roles: [\"arn:aws:iam::999999999999:role/attacker\"]\n")
	fetch := func(_ context.Context, _, _ string) ([]byte, string, error) {
		return evil, "pinned-etag", nil
	}

	p := NewProvider(base, time.Minute, "yaml", nil, WithFragmentFetcher(fetch))
	err := p.Refresh(context.Background())
	t.Logf("refresh err=%v", err)

	// Documented design (config.go:271-273: the pin is "whatever a fragment's
	// fetch reports as its etag"), NOT reported as a finding: for the intended
	// S3 fetcher the ETag is server-computed and not attacker-forgeable. This
	// pins the trust boundary so whoever wires WithFragmentFetcher sees it: the
	// pin authenticates the fetcher's token, never the bytes.
	require.NoError(t, err, "a fetcher-supplied etag matching the pin is accepted regardless of content")
	require.Len(t, p.Get().RoleMappings, 1)
	assert.Equal(t, "victim/.+", p.Get().RoleMappings[0].Subject)
}

// ---------------------------------------------------------------------------
// D. Ordering: can a fragment preempt a BASE mapping's session policy?
// ---------------------------------------------------------------------------

func TestAudit_FragmentMappingOutranksBaseRoleGroup(t *testing.T) {
	dir := t.TempDir()
	// Fragment grants the SAME role to the SAME subject, with no session policy.
	f := a2Write(t, dir, "f.yaml", `
role_mappings:
  - subject: "acme/app"
    roles: ["arn:aws:iam::111111111111:role/prod"]
`)

	base := a2Base(t)
	// Base restricts the role via a role_group session policy.
	base.RoleGroups = []RoleGroup{{
		Subjects: []string{"acme/app"},
		Defaults: RoleGroupDefaults{
			Roles:             []string{"arn:aws:iam::111111111111:role/prod"},
			SessionPolicyFile: "restrict-prod.json",
		},
	}}
	base.ConfigFragments = []string{f}
	require.NoError(t, base.Validate())

	// Before any fragment merge, the base policy applies.
	pol, polFile := base.FindSessionPolicy(base.Issuers[0].Issuer, "acme/app",
		"arn:aws:iam::111111111111:role/prod", map[string]any{})
	t.Logf("base-only: policy=%v file=%v", pol, polFile)
	require.NotNil(t, polFile)

	p := NewProvider(base, time.Minute, "yaml", nil)
	require.NoError(t, p.Refresh(context.Background()))
	cfg := p.Get()

	pol2, polFile2 := cfg.FindSessionPolicy(cfg.Issuers[0].Issuer, "acme/app",
		"arn:aws:iam::111111111111:role/prod", map[string]any{})
	t.Logf("after fragment merge: policy=%v file=%v", pol2, polFile2)

	// FINDING F1 (current, insecure behavior asserted): Validate() appends every
	// role_mappings entry (base AND fragment) to c.effective before any
	// role_groups entry, so a fragment's role_mapping always gets a lower
	// `order` than a base role_group. FindSessionPolicy takes the lowest order,
	// so the base's scoping policy is dropped and credentials are issued
	// unscoped. Flip these to NotNil/Equal("restrict-prod.json") to make this a
	// regression test once fixed.
	assert.Nil(t, pol2, "base role_group session policy should have survived")
	assert.Nil(t, polFile2, "base role_group session_policy_file should have survived")
}

// Same question but base uses role_mappings (declared before fragments append).
func TestAudit_FragmentCannotPreemptBaseRoleMapping(t *testing.T) {
	dir := t.TempDir()
	f := a2Write(t, dir, "f.yaml", `
role_mappings:
  - subject: "acme/app"
    roles: ["arn:aws:iam::111111111111:role/prod"]
`)
	base := a2Base(t)
	base.RoleMappings = []RoleMapping{{
		Subject:           "acme/app",
		Roles:             []string{"arn:aws:iam::111111111111:role/prod"},
		SessionPolicyFile: "restrict-prod.json",
	}}
	base.ConfigFragments = []string{f}
	require.NoError(t, base.Validate())

	p := NewProvider(base, time.Minute, "yaml", nil)
	require.NoError(t, p.Refresh(context.Background()))
	cfg := p.Get()

	_, polFile := cfg.FindSessionPolicy(cfg.Issuers[0].Issuer, "acme/app",
		"arn:aws:iam::111111111111:role/prod", map[string]any{})
	require.NotNil(t, polFile, "base role_mapping policy must survive")
	assert.Equal(t, "restrict-prod.json", *polFile)
}

// ---------------------------------------------------------------------------
// E. default_issuer re-binding across issuers
// ---------------------------------------------------------------------------

func TestAudit_FragmentDefaultIssuerCannotRebindBaseMappings(t *testing.T) {
	dir := t.TempDir()
	f := a2Write(t, dir, "f.yaml", "default_issuer: \"https://second.example\"\n")

	base := a2Base(t)
	base.Issuers = append(base.Issuers, IssuerConfig{
		Issuer: "https://second.example", Provider: "generic",
		Audiences: []string{"aud"}, ClaimMappings: map[string]string{"subject": "sub"},
	})
	// Base mapping with NO explicit issuer + 2 issuers + no default_issuer.
	base.RoleMappings = []RoleMapping{{
		Subject: "acme/app", Roles: []string{"arn:aws:iam::111111111111:role/prod"},
	}}
	base.ConfigFragments = []string{f}
	err := base.Validate()
	t.Logf("base Validate() with 2 issuers, no default, issuer-less mapping: %v", err)

	// A fragment can only ever set default_issuer when the base left it empty
	// (fragments.go:111 rejects a conflicting override). For a fragment's
	// default_issuer to REBIND an existing base mapping, that mapping would
	// have to be issuer-less while >1 issuer is configured — and refreshLocked
	// validates base+overlay BEFORE applyFragments runs (provider.go:171-184),
	// so that config never survives to the merge. This is the guard that makes
	// the whole rebinding class unreachable via fragments; assert it hard.
	require.Error(t, err, "base with 2 issuers + no default + issuer-less mapping must not validate")
	assert.Contains(t, err.Error(), "issuer must be set explicitly")
	assert.Contains(t, err.Error(), "acme/app")
}

// Reverse: base has 1 issuer + issuer-less mappings, the PRIMARY overlay adds a
// second issuer + default_issuer, fragment supplies mappings. Does anything
// silently move namespace?
func TestAudit_OverlayAddsIssuerThenFragmentDefaultIssuer(t *testing.T) {
	dir := t.TempDir()
	f := a2Write(t, dir, "f.yaml", "role_mappings:\n  - subject: \"frag/repo\"\n    roles: [\"arn:aws:iam::111111111111:role/f\"]\n")

	base := a2Base(t)
	base.RoleMappings = []RoleMapping{{
		Subject: "acme/app", Roles: []string{"arn:aws:iam::111111111111:role/prod"},
	}}
	base.ConfigFragments = []string{f}
	require.NoError(t, base.Validate())
	require.Equal(t, "https://token.actions.githubusercontent.com", base.effective[0].Issuer)

	overlay := []byte(`
issuers:
  - issuer: "https://token.actions.githubusercontent.com"
    provider: github
    audiences: ["sts.amazonaws.com"]
  - issuer: "https://evil.example"
    provider: generic
    audiences: ["aud"]
    claim_mappings: {subject: "sub"}
default_issuer: "https://evil.example"
`)
	p := NewProvider(base, time.Minute, "yaml", func(context.Context) ([]byte, error) { return overlay, nil })
	err := p.Refresh(context.Background())
	t.Logf("refresh with overlay-supplied default_issuer: %v", err)
	cfg := p.Get()
	for _, m := range cfg.effective {
		t.Logf("effective subject=%q issuer=%q roles=%v", m.Subject, m.Issuer, m.Roles)
	}

	// FINDING F3 (current, insecure behavior asserted). mergeFragment guards
	// this for fragments; MergeBytes has no equivalent guard, so the overlay
	// can add an issuer AND set default_issuer in one atomic merge and
	// resolveIssuer (config.go:796) then rebinds every issuer-less base mapping
	// to it. Flip these to assert the GitHub issuer once fixed.
	require.NoError(t, err)
	prod := "arn:aws:iam::111111111111:role/prod"
	ok, roles := cfg.AuthorizeRoles("https://evil.example", "acme/app", map[string]any{})
	assert.True(t, ok, "base grant moved into the newly-added issuer's namespace")
	assert.Contains(t, roles, prod)

	okGH, _ := cfg.AuthorizeRoles("https://token.actions.githubusercontent.com", "acme/app", map[string]any{})
	assert.False(t, okGH, "base grant no longer resolves under the issuer it was written for")
}

// ---------------------------------------------------------------------------
// F. Fragment cache aliasing across reloads (shared backing arrays / pointers)
// ---------------------------------------------------------------------------

func TestAudit_CachedFragmentNotMutatedAcrossReloads(t *testing.T) {
	dir := t.TempDir()
	f := a2Write(t, dir, "f.yaml", `
role_sets:
  fragset: ["arn:aws:iam::111111111111:role/a", "arn:aws:iam::111111111111:role/b"]
role_mappings:
  - subject: "o/r"
    roles: ["@fragset"]
    conditions:
      branch: "main"
role_groups:
  - subjects: ["g/one", "g/two"]
    defaults:
      roles: ["arn:aws:iam::111111111111:role/g"]
      conditions:
        event_name: "push"
`)
	base := a2Base(t)
	base.ConfigFragments = []string{f}
	require.NoError(t, base.Validate())

	p := NewProvider(base, time.Minute, "yaml", nil)
	require.NoError(t, p.Refresh(context.Background()))

	cached := p.fragments[f]
	require.NotNil(t, cached)
	snap := []string{}
	snap = append(snap, cached.parsed.RoleMappings[0].Roles...)
	condBranch := cached.parsed.RoleMappings[0].Conditions.Branch
	setLen := len(cached.parsed.RoleSets["fragset"])

	for i := 0; i < 5; i++ {
		require.NoError(t, p.Refresh(context.Background()))
		cfg := p.Get()
		// Grants must be stable across reloads.
		ok, roles := cfg.AuthorizeRoles(cfg.Issuers[0].Issuer, "o/r", map[string]any{"ref": "main"})
		require.True(t, ok, "iteration %d: mapping lost", i)
		require.Equal(t, []string{
			"arn:aws:iam::111111111111:role/a",
			"arn:aws:iam::111111111111:role/b",
		}, roles, "iteration %d: roles drifted", i)

		// The condition must still DENY a non-main branch.
		ok2, _ := cfg.AuthorizeRoles(cfg.Issuers[0].Issuer, "o/r", map[string]any{"ref": "attacker"})
		require.False(t, ok2, "iteration %d: condition stopped denying (cached-fragment corruption)", i)
	}

	c2 := p.fragments[f]
	assert.Equal(t, snap, c2.parsed.RoleMappings[0].Roles, "cached fragment Roles mutated (@role_set expanded in place)")
	assert.Equal(t, condBranch, c2.parsed.RoleMappings[0].Conditions.Branch)
	assert.Equal(t, setLen, len(c2.parsed.RoleSets["fragset"]))
	// Unexported per-mapping state must not have leaked into the cached parse.
	assert.Nil(t, c2.parsed.RoleMappings[0].compiledPattern, "compiledPattern leaked into cached fragment")
	assert.Empty(t, c2.parsed.RoleMappings[0].Conditions.compiled, "compiled conditions leaked into cached fragment")
}

// ---------------------------------------------------------------------------
// G. Duplicate URI in config_fragments
// ---------------------------------------------------------------------------

func TestAudit_DuplicateFragmentURI(t *testing.T) {
	dir := t.TempDir()
	f := a2Write(t, dir, "f.yaml", "role_mappings:\n  - subject: \"o/r\"\n    roles: [\"arn:aws:iam::111111111111:role/x\"]\n")

	base := a2Base(t)
	base.ConfigFragments = []string{f, f}
	require.NoError(t, base.Validate())

	p := NewProvider(base, time.Minute, "yaml", nil)
	err := p.Refresh(context.Background())
	t.Logf("duplicate URI refresh: err=%v", err)

	// Merged twice (the p.fragments cache is only swapped in after the loop, so
	// the second pass sees the same prev). Additive only: 2 identical mappings,
	// no widening. A duplicate that defines role_sets errors on collision.
	require.NoError(t, err)
	cfg := p.Get()
	require.Len(t, cfg.RoleMappings, 2, "duplicate URI merges twice")
	assert.Equal(t, cfg.RoleMappings[0], cfg.RoleMappings[1])
	_, roles := cfg.AuthorizeRoles(cfg.Issuers[0].Issuer, "o/r", map[string]any{})
	assert.Equal(t, []string{
		"arn:aws:iam::111111111111:role/x",
		"arn:aws:iam::111111111111:role/x",
	}, roles, "duplicate grant must not widen beyond the same role")
}

// ---------------------------------------------------------------------------
// H. Fragment removal from the list: are its grants actually revoked?
// ---------------------------------------------------------------------------

func TestAudit_RemovedFragmentRevokesGrants(t *testing.T) {
	dir := t.TempDir()
	f1 := a2Write(t, dir, "f1.yaml", "role_mappings:\n  - subject: \"o/one\"\n    roles: [\"arn:aws:iam::111111111111:role/one\"]\n")
	f2 := a2Write(t, dir, "f2.yaml", "role_mappings:\n  - subject: \"o/two\"\n    roles: [\"arn:aws:iam::111111111111:role/two\"]\n")

	base := a2Base(t)
	base.ConfigFragments = []string{f1, f2}
	require.NoError(t, base.Validate())

	p := NewProvider(base, time.Minute, "yaml", nil)
	require.NoError(t, p.Refresh(context.Background()))
	ok, _ := p.Get().AuthorizeRoles(base.Issuers[0].Issuer, "o/two", map[string]any{})
	require.True(t, ok)

	base.ConfigFragments = []string{f1}
	require.NoError(t, p.Refresh(context.Background()))
	ok2, roles := p.Get().AuthorizeRoles(base.Issuers[0].Issuer, "o/two", map[string]any{})
	assert.False(t, ok2, "removed fragment's grant survived: %v", roles)
	_, stillCached := p.fragments[f2]
	assert.False(t, stillCached, "removed fragment left in cache")
}

// ---------------------------------------------------------------------------
// I. Root-cause control for D: is the preemption fragment-specific, or is it
//    the global "all role_mappings get a lower order than any role_group" rule?
//    No fragments involved here.
// ---------------------------------------------------------------------------

func TestAudit_RoleMappingOutranksRoleGroupWithoutFragments(t *testing.T) {
	c := a2Base(t)
	// Declared FIRST in the YAML/struct: the restricted role_group.
	c.RoleGroups = []RoleGroup{{
		Subjects: []string{"acme/app"},
		Defaults: RoleGroupDefaults{
			Roles:             []string{"arn:aws:iam::111111111111:role/prod"},
			SessionPolicyFile: "restrict-prod.json",
		},
	}}
	// Declared SECOND: an unrestricted role_mapping for the same subject+role.
	c.RoleMappings = []RoleMapping{{
		Subject: "acme/app",
		Roles:   []string{"arn:aws:iam::111111111111:role/prod"},
	}}
	require.NoError(t, c.Validate())

	for _, m := range c.effective {
		t.Logf("order=%d subject=%q policyFile=%q", m.order, m.Subject, m.SessionPolicyFile)
	}

	pol, polFile := c.FindSessionPolicy(c.Issuers[0].Issuer, "acme/app",
		"arn:aws:iam::111111111111:role/prod", map[string]any{})
	t.Logf("FindSessionPolicy => policy=%v file=%v", pol, polFile)

	// Root cause of F1, with no fragments involved: appendEffective numbers
	// every role_mappings entry before every role_groups entry, so a role_group
	// can NEVER outrank a role_mapping no matter how the file is written --
	// contradicting docs/CONFIGURATION.md:133 ("the first-declared (config
	// order) wins"). Assert the order assignment AND the dropped policy.
	require.Len(t, c.effective, 2)
	assert.Equal(t, 0, c.effective[0].order)
	assert.Empty(t, c.effective[0].SessionPolicyFile, "role_mapping took order 0")
	assert.Equal(t, "restrict-prod.json", c.effective[1].SessionPolicyFile, "role_group pushed to order 1")
	assert.Nil(t, pol, "scoped role_group policy should have won on config order")
	assert.Nil(t, polFile, "scoped role_group policy should have won on config order")
}

// Confirm the reverse ordering is honoured: a role_group declared first wins
// against a role_group declared second.
func TestAudit_RoleGroupOrderingAmongstThemselves(t *testing.T) {
	c := a2Base(t)
	c.RoleGroups = []RoleGroup{
		{Subjects: []string{"acme/app"}, Defaults: RoleGroupDefaults{
			Roles: []string{"arn:aws:iam::111111111111:role/prod"}, SessionPolicyFile: "first.json"}},
		{Subjects: []string{"acme/app"}, Defaults: RoleGroupDefaults{
			Roles: []string{"arn:aws:iam::111111111111:role/prod"}}},
	}
	require.NoError(t, c.Validate())
	_, polFile := c.FindSessionPolicy(c.Issuers[0].Issuer, "acme/app",
		"arn:aws:iam::111111111111:role/prod", map[string]any{})
	require.NotNil(t, polFile)
	assert.Equal(t, "first.json", *polFile)
}
