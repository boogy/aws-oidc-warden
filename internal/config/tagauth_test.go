package config

import (
	"bytes"
	"log/slog"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------- Authorize ----------

func TestTagAuth_Authorize(t *testing.T) {
	ta := &TagAuth{Enabled: true, TagPrefix: "aow/"}
	claims := map[string]any{
		"repository":         "acme/api",
		"repository_owner":   "acme",
		"ref":                "refs/heads/main",
		"ref_type":           "branch",
		"event_name":         "push",
		"actor":              "deploy-bot",
		"runner_environment": "github-hosted",
		"environment":        "production",
		"workflow_ref":       "acme/api/.github/workflows/deploy.yml@refs/heads/main",
	}
	cases := []struct {
		name string
		tags map[string]string
		want bool
	}{
		{"exact repo", map[string]string{"aow/repo": "acme/api"}, true},
		{"repo space-list", map[string]string{"aow/repo": "acme/web acme/api"}, true},
		{"owner match", map[string]string{"aow/repo-owner": "acme"}, true},
		{"no identity tag -> deny", map[string]string{"aow/branch": "refs/heads/main"}, false},
		{"wrong repo -> deny", map[string]string{"aow/repo": "acme/web"}, false},
		{"repo + branch short name", map[string]string{"aow/repo": "acme/api", "aow/branch": "main"}, true},
		{"repo + branch full ref", map[string]string{"aow/repo": "acme/api", "aow/branch": "refs/heads/main"}, true},
		{"repo + wrong branch -> deny", map[string]string{"aow/repo": "acme/api", "aow/branch": "dev"}, false},
		{"all dims pass", map[string]string{"aow/repo": "acme/api", "aow/ref-type": "branch", "aow/event-name": "push", "aow/actor": "deploy-bot"}, true},
		{"one dim fails -> deny", map[string]string{"aow/repo": "acme/api", "aow/event-name": "pull_request"}, false},
		{"repo AND exact ref", map[string]string{"aow/repo": "acme/api", "aow/ref": "refs/heads/main"}, true},
		{"repo AND wrong ref -> deny", map[string]string{"aow/repo": "acme/api", "aow/ref": "refs/heads/dev"}, false},
		{"workflow-ref match", map[string]string{"aow/repo": "acme/api", "aow/workflow-ref": "acme/api/.github/workflows/deploy.yml@refs/heads/main"}, true},
		{"workflow-ref mismatch -> deny", map[string]string{"aow/repo": "acme/api", "aow/workflow-ref": "acme/api/.github/workflows/other.yml@refs/heads/main"}, false},
		{"non-aow tags ignored", map[string]string{"aow/repo": "acme/api", "Team": "platform"}, true},
		{"empty tags -> deny", map[string]string{}, false},
		// 3.0.0: aow/environment checks the deployment-environment claim, the
		// same claim conditions.environment checks; the runner type moved to
		// its own tag. Before 3.0.0 aow/environment checked runner_environment,
		// so "github-hosted" here used to pass.
		{"environment is the deployment environment", map[string]string{"aow/repo": "acme/api", "aow/environment": "production"}, true},
		{"environment is not the runner type -> deny", map[string]string{"aow/repo": "acme/api", "aow/environment": "github-hosted"}, false},
		{"runner-environment tag", map[string]string{"aow/repo": "acme/api", "aow/runner-environment": "github-hosted"}, true},
		{"wrong runner-environment -> deny", map[string]string{"aow/repo": "acme/api", "aow/runner-environment": "self-hosted"}, false},
	}
	const iss = "https://issuer.example"
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.want, ta.Authorize(c.tags, claims, iss, "acme/api"))
		})
	}
}

func TestTagAuth_Authorize_Disabled(t *testing.T) {
	ta := &TagAuth{Enabled: false, TagPrefix: "aow/"}
	assert.False(t, ta.Authorize(map[string]string{"aow/repo": "acme/api"}, map[string]any{"repository": "acme/api"}, "https://issuer.example", "acme/api"))
}

func TestTagAuth_Authorize_DefaultOrg(t *testing.T) {
	const iss = "https://issuer.example"
	ta := &TagAuth{Enabled: true, TagPrefix: "aow/", DefaultOrg: "acme"}
	claims := map[string]any{"repository": "acme/api", "repository_owner": "acme"}
	cases := []struct {
		name string
		tags map[string]string
		want bool
	}{
		{"bare expands to default org", map[string]string{"aow/repo": "api"}, true},
		{"bare wrong repo", map[string]string{"aow/repo": "web"}, false},
		{"bare list one matches", map[string]string{"aow/repo": "web api"}, true},
		{"full form still works", map[string]string{"aow/repo": "acme/api"}, true},
		{"full form other org allowed", map[string]string{"aow/repo": "beta/web acme/api"}, true},
		{"bare 'org/' token never matches", map[string]string{"aow/repo": "acme/"}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.want, ta.Authorize(c.tags, claims, iss, "acme/api"))
		})
	}

	// Security property: a bare token is org-scoped and must NOT match a repo of
	// the same name in a different org. claim org (beta) != default_org (acme).
	otherOrgClaims := map[string]any{"repository": "beta/api", "repository_owner": "beta"}
	assert.False(t, ta.Authorize(map[string]string{"aow/repo": "api"}, otherOrgClaims, iss, "beta/api"))
	// ...but the explicit full form for that other org still authorizes (lenient).
	assert.True(t, ta.Authorize(map[string]string{"aow/repo": "beta/api"}, otherOrgClaims, iss, "beta/api"))

	// Empty repository claim never matches, even with default_org set.
	assert.False(t, ta.Authorize(map[string]string{"aow/repo": "api"}, map[string]any{}, iss, ""))

	// No default_org: bare tokens must not match (current behavior preserved).
	taNoOrg := &TagAuth{Enabled: true, TagPrefix: "aow/"}
	assert.False(t, taNoOrg.Authorize(map[string]string{"aow/repo": "api"}, claims, iss, "acme/api"))
	assert.True(t, taNoOrg.Authorize(map[string]string{"aow/repo": "acme/api"}, claims, iss, "acme/api"))
}

func TestTagAuthGates(t *testing.T) {
	base := func(multi bool) *TagAuth {
		return &TagAuth{Enabled: true, TagPrefix: "aow/", multiIssuer: multi}
	}
	claims := map[string]any{"repository": "myorg/repo", "repository_owner": "myorg", "ref": "refs/heads/main", "actor": "alice"}

	// No identity tag at all -> deny even if every other dimension matches.
	if base(false).Authorize(map[string]string{"aow/ref": "refs/heads/main"}, claims, vIss, "myorg/repo") {
		t.Error("FAIL-OPEN: tag-auth authorized with no identity tag")
	}
	// Identity tag present but non-matching.
	if base(false).Authorize(map[string]string{"aow/subject": "other/repo"}, claims, vIss, "myorg/repo") {
		t.Error("non-matching subject tag authorized")
	}
	// Empty identity tag value.
	if base(false).Authorize(map[string]string{"aow/subject": ""}, claims, vIss, "myorg/repo") {
		t.Error("empty subject tag authorized")
	}
	// Happy path.
	if !base(false).Authorize(map[string]string{"aow/subject": "myorg/repo"}, claims, vIss, "myorg/repo") {
		t.Error("matching subject tag should authorize")
	}
	// Multi-issuer: missing issuer tag fails closed.
	if base(true).Authorize(map[string]string{"aow/subject": "myorg/repo"}, claims, vIss, "myorg/repo") {
		t.Error("MULTI-ISSUER LEAK: authorized without an issuer tag")
	}
	// Multi-issuer: wrong issuer tag fails closed.
	if base(true).Authorize(map[string]string{"aow/subject": "myorg/repo", "aow/issuer": vIss2}, claims, vIss, "myorg/repo") {
		t.Error("wrong issuer tag authorized")
	}
	if !base(true).Authorize(map[string]string{"aow/subject": "myorg/repo", "aow/issuer": vIss}, claims, vIss, "myorg/repo") {
		t.Error("correct issuer tag should authorize")
	}
	// Extra dimension is AND'd.
	if base(false).Authorize(map[string]string{"aow/subject": "myorg/repo", "aow/ref": "refs/heads/prod"}, claims, vIss, "myorg/repo") {
		t.Error("AND VIOLATION: mismatched ref tag authorized")
	}
	// Tag matching is exact, never regex.
	for _, v := range []string{"myorg/.*", ".*", "myorg/rep*", "myorg/repo*"} {
		if base(false).Authorize(map[string]string{"aow/subject": v}, claims, vIss, "myorg/repo") {
			t.Errorf("REGEX IN TAG: value %q matched", v)
		}
	}
	// Disabled tag-auth never authorizes.
	if (&TagAuth{Enabled: false, TagPrefix: "aow/"}).Authorize(map[string]string{"aow/subject": "myorg/repo"}, claims, vIss, "myorg/repo") {
		t.Error("disabled tag-auth authorized")
	}
	// nil receiver.
	var nilTA *TagAuth
	if nilTA.Authorize(map[string]string{"aow/subject": "myorg/repo"}, claims, vIss, "myorg/repo") {
		t.Error("nil tag-auth authorized")
	}
	// Bare repo token without default_org must not match.
	if base(false).Authorize(map[string]string{"aow/repo": "repo"}, claims, vIss, "myorg/repo") {
		t.Error("bare repo token matched without default_org")
	}
	withOrg := &TagAuth{Enabled: true, TagPrefix: "aow/", DefaultOrg: "myorg"}
	if !withOrg.Authorize(map[string]string{"aow/repo": "repo"}, claims, vIss, "myorg/repo") {
		t.Error("bare repo token should match with default_org")
	}
	// default_org must not let a foreign org through.
	foreign := map[string]any{"repository": "evil/repo", "repository_owner": "evil"}
	if withOrg.Authorize(map[string]string{"aow/repo": "repo"}, foreign, vIss, "evil/repo") {
		t.Error("DEFAULT_ORG BYPASS: foreign org matched a bare repo token")
	}
}

// TestTagAuthPrefixConfusion checks that tags outside the prefix are
// ignored and cannot be used to forge an identity.

// TestTagAuthPrefixConfusion checks that tags outside the prefix are
// ignored and cannot be used to forge an identity.
func TestTagAuthPrefixConfusion(t *testing.T) {
	ta := &TagAuth{Enabled: true, TagPrefix: "aow/"}
	claims := map[string]any{"repository": "myorg/repo"}
	for _, k := range []string{"subject", "AOW/subject", "aow-subject", "xaow/subject", "aow//subject"} {
		if ta.Authorize(map[string]string{k: "myorg/repo"}, claims, vIss, "myorg/repo") {
			t.Errorf("PREFIX CONFUSION: tag key %q was honored", k)
		}
	}
}

// ---------- cross-account / transitive knobs ----------

func TestTagAuthTransitive_CrossAccountAllowedAccounts_Env(t *testing.T) {
	viper.Reset()
	once = sync.Once{}
	for _, k := range []string{"AOW_TAG_AUTH_ENABLED", "AOW_TAG_AUTH_TRANSITIVE_SESSION_TAGS", "AOW_CROSS_ACCOUNT_ENABLED", "AOW_CROSS_ACCOUNT_ALLOWED_ACCOUNTS", "CONFIG_NAME"} {
		orig := os.Getenv(k)
		t.Cleanup(func() { _ = os.Setenv(k, orig) })
	}
	_ = os.Setenv("AOW_TAG_AUTH_ENABLED", "true")
	_ = os.Setenv("AOW_TAG_AUTH_TRANSITIVE_SESSION_TAGS", "true")
	_ = os.Setenv("AOW_CROSS_ACCOUNT_ENABLED", "true")
	_ = os.Setenv("AOW_CROSS_ACCOUNT_ALLOWED_ACCOUNTS", "111111111111, 222222222222")
	_ = os.Setenv("CONFIG_NAME", "nonexistent-config-file")

	c := &Config{}
	require.NoError(t, c.LoadConfig())
	require.NotNil(t, c.TagAuth)
	assert.True(t, c.TagAuth.TransitiveSessionTags)
	require.NotNil(t, c.CrossAccount)
	assert.True(t, c.CrossAccount.Enabled)
	assert.Equal(t, []string{"111111111111", "222222222222"}, c.CrossAccount.AllowedAccounts)
}

func TestMergeBytes_EnvTagAuthTransitiveAndCrossAccountAllowedAccounts(t *testing.T) {
	t.Setenv("AOW_TAG_AUTH_TRANSITIVE_SESSION_TAGS", "true")
	t.Setenv("AOW_CROSS_ACCOUNT_ALLOWED_ACCOUNTS", "111111111111, 222222222222")

	c := &Config{
		Issuers:         singleIssuer("https://token.actions.githubusercontent.com", "sts.amazonaws.com"),
		RoleSessionName: "base-session",
		Cache:           &Cache{Type: "memory", TTL: 3600000000000},
	}
	require.NoError(t, c.Validate())

	// S3 payload enables tag_auth and cross_account but does not set the other
	// keys; the env vars must survive the hot-reload via reapplyEnvOverrides.
	yaml := []byte("tag_auth:\n  enabled: true\ncross_account:\n  enabled: true\n")
	require.NoError(t, c.MergeBytes(yaml, "yaml"))

	require.NotNil(t, c.TagAuth)
	assert.True(t, c.TagAuth.TransitiveSessionTags, "AOW_TAG_AUTH_TRANSITIVE_SESSION_TAGS must survive S3 hot-reload")
	require.NotNil(t, c.CrossAccount)
	assert.Equal(t, []string{"111111111111", "222222222222"}, c.CrossAccount.AllowedAccounts, "AOW_CROSS_ACCOUNT_ALLOWED_ACCOUNTS must survive S3 hot-reload, whitespace-trimmed")
}

func TestCrossAccount_AllowedAccounts_RejectsMalformed(t *testing.T) {
	c := &Config{
		Issuers: singleIssuer("https://x", "a"), RoleSessionName: "test",
		CrossAccount: &CrossAccount{Enabled: true, AllowedAccounts: []string{"123"}},
	}
	err := c.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "allowed_accounts")
}

func TestCrossAccount_DefaultsNormalizedOnValidate(t *testing.T) {
	c := &Config{
		Issuers: singleIssuer("https://x", "a"), RoleSessionName: "test",
		CrossAccount: &CrossAccount{Enabled: true},
	}
	require.NoError(t, c.Validate())
	assert.Equal(t, "aow-spoke", c.CrossAccount.SpokeRoleName)
	assert.Equal(t, "15m0s", c.CrossAccount.SpokeSessionDuration.String())
}

// TestSessionTagsTransitive_DefaultsOff pins that an unconfigured deploy
// boots with transitivity off, so upgrading to the top-level key cannot
// silently break a target role that re-tags with the same keys while
// chaining.

// TestSessionTagsTransitive_DefaultsOff pins that an unconfigured deploy
// boots with transitivity off, so upgrading to the top-level key cannot
// silently break a target role that re-tags with the same keys while
// chaining.
func TestSessionTagsTransitive_DefaultsOff(t *testing.T) {
	viper.Reset()
	once = sync.Once{}

	origName := os.Getenv("CONFIG_NAME")
	defer func() {
		if origName == "" {
			_ = os.Unsetenv("CONFIG_NAME")
		} else {
			_ = os.Setenv("CONFIG_NAME", origName)
		}
	}()
	t.Setenv("CONFIG_NAME", "nonexistent-config-file")

	c := &Config{}
	require.NoError(t, c.LoadConfig())
	assert.False(t, c.TransitiveSessionTags(),
		"default stays off so upgrades cannot break a role-chaining target")
}

// TestSessionTagsTransitive_ExplicitTrueSurvivesClone pins that an operator's
// explicit opt-in survives the JSON round-trip cloneConfig performs on every
// remote/hot-reload refresh (omitempty is safe here only because the zero
// value and the default agree).

// TestSessionTagsTransitive_ExplicitTrueSurvivesClone pins that an operator's
// explicit opt-in survives the JSON round-trip cloneConfig performs on every
// remote/hot-reload refresh (omitempty is safe here only because the zero
// value and the default agree).
func TestSessionTagsTransitive_ExplicitTrueSurvivesClone(t *testing.T) {
	cfg := &Config{
		Issuers:               singleIssuer("https://issuer.com", "aud"),
		RoleSessionName:       "test",
		SessionTagsTransitive: true,
	}
	require.NoError(t, cfg.Validate())

	clone, err := cloneConfig(cfg)
	require.NoError(t, err)
	assert.True(t, clone.TransitiveSessionTags(),
		"an operator who opted in must not silently lose it on a config refresh")
}

// ---------- Validate() scoping warnings ----------

// captureWarnings runs fn with the default logger pointed at a buffer and
// returns everything it wrote.
func captureWarnings(t *testing.T, fn func()) string {
	t.Helper()
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
	defer slog.SetDefault(prev)
	fn()
	return buf.String()
}

func tagAuthScopingCfg(tagAuthEnabled bool, m RoleMapping) *Config {
	cfg := &Config{
		Issuers: []IssuerConfig{{
			Issuer:    "https://token.actions.githubusercontent.com",
			Provider:  "github",
			Audiences: []string{"sts.amazonaws.com"},
		}},
		RoleSessionName: "warden",
		Cache:           &Cache{TTL: 0},
		RoleMappings:    []RoleMapping{m},
	}
	if tagAuthEnabled {
		cfg.TagAuth = &TagAuth{Enabled: true, TagPrefix: "aow/"}
	}
	return cfg
}

// TestValidate_WarnsWhenTagAuthCanBypassSessionPolicy pins the load-time
// warning for a scoping asymmetry that is invisible in the config file.
//
// When AuthorizeRoles matches no mapping, the tag-auth fallback can still
// grant the role from the role's own IAM tags — and findAuthorizingMapping
// then returns nil, so FindSessionPolicy and FindRoleSessionName both come
// back empty. An operator who carefully scoped a role with a session policy in
// role_mappings and separately tagged it for tag-auth has a second, unscoped
// way into that role and nothing in the config says so.

// TestValidate_WarnsWhenTagAuthCanBypassSessionPolicy pins the load-time
// warning for a scoping asymmetry that is invisible in the config file.
//
// When AuthorizeRoles matches no mapping, the tag-auth fallback can still
// grant the role from the role's own IAM tags — and findAuthorizingMapping
// then returns nil, so FindSessionPolicy and FindRoleSessionName both come
// back empty. An operator who carefully scoped a role with a session policy in
// role_mappings and separately tagged it for tag-auth has a second, unscoped
// way into that role and nothing in the config says so.
func TestValidate_WarnsWhenTagAuthCanBypassSessionPolicy(t *testing.T) {
	cfg := tagAuthScopingCfg(true, RoleMapping{
		Subject:       Patterns{"org/repo"},
		Roles:         []string{"arn:aws:iam::111111111111:role/deploy"},
		SessionPolicy: `{"Version":"2012-10-17","Statement":[]}`,
	})

	out := captureWarnings(t, func() {
		if err := cfg.Validate(); err != nil {
			t.Fatalf("Validate: %v", err)
		}
	})

	if !strings.Contains(out, "tag_auth is enabled and this role is scoped") {
		t.Errorf("no warning that tag-auth bypasses the mapping's session policy; got: %s", out)
	}
	if !strings.Contains(out, "arn:aws:iam::111111111111:role/deploy") {
		t.Errorf("warning does not name the affected role; got: %s", out)
	}
	if !strings.Contains(out, `"scopedBy":"session_policy"`) {
		t.Errorf("warning does not say what the scoping was; got: %s", out)
	}
}

// A multi-subject entry fans out to N mappings, but the warning is deduped by
// role, so consolidating entries into a list must not multiply or silence it.
func TestValidate_WarnsOncePerRoleForMultiSubjectEntry(t *testing.T) {
	cfg := tagAuthScopingCfg(true, RoleMapping{
		Subject:       Patterns{"org/repo", "org/other", "org/third"},
		Roles:         []string{"arn:aws:iam::111111111111:role/deploy"},
		SessionPolicy: `{"Version":"2012-10-17","Statement":[]}`,
	})

	out := captureWarnings(t, func() {
		if err := cfg.Validate(); err != nil {
			t.Fatalf("Validate: %v", err)
		}
	})

	if n := strings.Count(out, "tag_auth is enabled and this role is scoped"); n != 1 {
		t.Errorf("want exactly 1 bypass warning for the role, got %d; out: %s", n, out)
	}
}

// A per-mapping role_session_name is bypassed the same way: the tag-auth path
// falls back to the global name, so CloudTrail attribution silently changes.
func TestValidate_WarnsWhenTagAuthCanBypassRoleSessionName(t *testing.T) {
	cfg := tagAuthScopingCfg(true, RoleMapping{
		Subject:         Patterns{"org/repo"},
		Roles:           []string{"arn:aws:iam::111111111111:role/deploy"},
		RoleSessionName: "gha-org-repo",
	})

	out := captureWarnings(t, func() {
		if err := cfg.Validate(); err != nil {
			t.Fatalf("Validate: %v", err)
		}
	})

	if !strings.Contains(out, `"scopedBy":"role_session_name"`) {
		t.Errorf("no warning for the bypassed role_session_name; got: %s", out)
	}
}

// With tag_auth off there is no second path, so the warning must not fire —
// a warning every config emits is a warning operators learn to ignore.

// With tag_auth off there is no second path, so the warning must not fire —
// a warning every config emits is a warning operators learn to ignore.
func TestValidate_NoTagAuthWarningWhenTagAuthDisabled(t *testing.T) {
	cfg := tagAuthScopingCfg(false, RoleMapping{
		Subject:       Patterns{"org/repo"},
		Roles:         []string{"arn:aws:iam::111111111111:role/deploy"},
		SessionPolicy: `{"Version":"2012-10-17","Statement":[]}`,
	})

	out := captureWarnings(t, func() {
		if err := cfg.Validate(); err != nil {
			t.Fatalf("Validate: %v", err)
		}
	})

	if strings.Contains(out, "tag_auth is enabled") {
		t.Errorf("warned about tag-auth scoping with tag_auth disabled; got: %s", out)
	}
}

// An unscoped mapping has nothing for tag-auth to bypass.

// An unscoped mapping has nothing for tag-auth to bypass.
func TestValidate_NoTagAuthWarningForUnscopedMapping(t *testing.T) {
	cfg := tagAuthScopingCfg(true, RoleMapping{
		Subject: Patterns{"org/repo"},
		Roles:   []string{"arn:aws:iam::111111111111:role/deploy"},
	})

	out := captureWarnings(t, func() {
		if err := cfg.Validate(); err != nil {
			t.Fatalf("Validate: %v", err)
		}
	})

	if strings.Contains(out, "tag_auth is enabled and this role is scoped") {
		t.Errorf("warned about a mapping that declares no scoping; got: %s", out)
	}
}

// The issuer-agnostic `<prefix>claim.<name>` tag-auth dimension.
//
// Every other suffix Authorize understands (repo, ref, actor, workflow-ref, …)
// names a GitHub Actions claim, so before this dimension existed a non-GitHub
// issuer could constrain a tag-authorized role on `subject` and nothing else.
// These tests pin that a claim.* tag reaches an arbitrary verified claim, that
// it can only narrow access, and that every non-matching shape denies.

func TestTagAuth_GenericClaimDimension(t *testing.T) {
	ta := &TagAuth{Enabled: true, TagPrefix: "aow/"}
	const iss = "https://gitlab.example.com"
	const sub = "project_path:acme/api:ref_type:branch:ref:main"

	claims := map[string]any{
		"project_path":   "acme/api",
		"namespace_path": "acme",
		"ref":            "main",
		"isContractor":   "true",
		"groups":         []any{"platform", "sre"},
		"groups_typed":   []string{"platform", "sre"},
		"seats":          42, // non-string scalar
		// What encoding/json actually hands back for a JSON number and a JSON
		// bool. GitHub mints every claim as a string, so these shapes only
		// appear on other issuers — which is exactly who the `claim.` form
		// exists for.
		"seats_decoded":  float64(42),
		"email_verified": true,
		"mfa":            false,
		"scores":         []any{float64(1), float64(2)},
		"profile":        map[string]any{"tier": "gold"},
		"nulled":         nil,
	}

	cases := []struct {
		name string
		tags map[string]string
		want bool
	}{
		{
			name: "claim tag matches a mapped-subject issuer's own claim",
			tags: map[string]string{"aow/subject": sub, "aow/claim.project_path": "acme/api"},
			want: true,
		},
		{
			name: "claim tag that does not match denies even though subject matches",
			tags: map[string]string{"aow/subject": sub, "aow/claim.project_path": "acme/other"},
			want: false,
		},
		{
			name: "space-separated claim tag value means OR",
			tags: map[string]string{"aow/subject": sub, "aow/claim.namespace_path": "widgets acme"},
			want: true,
		},
		{
			name: "every claim tag must match (AND)",
			tags: map[string]string{
				"aow/subject":              sub,
				"aow/claim.project_path":   "acme/api",
				"aow/claim.namespace_path": "widgets",
			},
			want: false,
		},
		{
			name: "claim name is matched case-sensitively, as written on the tag",
			tags: map[string]string{"aow/subject": sub, "aow/claim.isContractor": "true"},
			want: true,
		},
		{
			name: "a differently-cased claim name names no claim and denies",
			tags: map[string]string{"aow/subject": sub, "aow/claim.iscontractor": "true"},
			want: false,
		},
		{
			name: "list claim matches when any element does",
			tags: map[string]string{"aow/subject": sub, "aow/claim.groups": "sre"},
			want: true,
		},
		{
			name: "[]string list claim matches when any element does",
			tags: map[string]string{"aow/subject": sub, "aow/claim.groups_typed": "platform"},
			want: true,
		},
		{
			name: "list claim with no matching element denies",
			tags: map[string]string{"aow/subject": sub, "aow/claim.groups": "admins"},
			want: false,
		},
		// A tag compares against the claim VALUE, not its JSON type. Before
		// this, `claim.` read strings only, so an operator narrowing access
		// with `aow/claim.email_verified = "true"` on an issuer minting a JSON
		// bool got a tag that denied every caller — the rule silently could not
		// hold rather than holding when it should.
		{
			name: "non-string scalar claim matches on its value",
			tags: map[string]string{"aow/subject": sub, "aow/claim.seats": "42"},
			want: true,
		},
		{
			name: "a decoded JSON number matches its integer rendering",
			tags: map[string]string{"aow/subject": sub, "aow/claim.seats_decoded": "42"},
			want: true,
		},
		{
			name: "a decoded number is not rendered in scientific notation",
			tags: map[string]string{"aow/subject": sub, "aow/claim.seats_decoded": "4.2e+01"},
			want: false,
		},
		{
			name: "bool true matches \"true\"",
			tags: map[string]string{"aow/subject": sub, "aow/claim.email_verified": "true"},
			want: true,
		},
		{
			name: "bool false does not match \"true\"",
			tags: map[string]string{"aow/subject": sub, "aow/claim.mfa": "true"},
			want: false,
		},
		{
			name: "bool false matches \"false\"",
			tags: map[string]string{"aow/subject": sub, "aow/claim.mfa": "false"},
			want: true,
		},
		{
			name: "a numeric list element matches on its own value",
			tags: map[string]string{"aow/subject": sub, "aow/claim.scores": "2"},
			want: true,
		},
		// A shape with no scalar reading still never matches. claim.* tags only
		// ever narrow, so this is fail-closed by construction.
		{
			name: "an object claim has no reading and denies",
			tags: map[string]string{"aow/subject": sub, "aow/claim.profile": "gold"},
			want: false,
		},
		{
			name: "a null claim has no reading and denies",
			tags: map[string]string{"aow/subject": sub, "aow/claim.nulled": "anything"},
			want: false,
		},
		{
			name: "absent claim denies",
			tags: map[string]string{"aow/subject": sub, "aow/claim.nope": "anything"},
			want: false,
		},
		{
			name: "bare claim. tag names no claim and denies",
			tags: map[string]string{"aow/subject": sub, "aow/claim.": "acme/api"},
			want: false,
		},
		{
			name: "claim tag alone is not an identity tag: it cannot grant access",
			tags: map[string]string{"aow/claim.project_path": "acme/api"},
			want: false,
		},
		{
			name: "a claim tag under a different prefix is not read",
			tags: map[string]string{"aow/subject": sub, "other/claim.project_path": "acme/other"},
			want: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, ta.Authorize(tc.tags, claims, iss, sub))
		})
	}
}

// The dimension must not weaken the gates that run before it: a claim.* tag
// that matches cannot rescue a role whose issuer or identity tag is wrong.
func TestTagAuth_GenericClaimDimensionCannotBypassEarlierGates(t *testing.T) {
	claims := map[string]any{"project_path": "acme/api"}
	const sub = "project_path:acme/api"

	t.Run("wrong issuer still denies", func(t *testing.T) {
		ta := &TagAuth{Enabled: true, TagPrefix: "aow/", multiIssuer: true}
		tags := map[string]string{
			"aow/issuer":             "https://other.example.com",
			"aow/subject":            sub,
			"aow/claim.project_path": "acme/api",
		}
		assert.False(t, ta.Authorize(tags, claims, "https://gitlab.example.com", sub))
	})

	t.Run("wrong subject still denies", func(t *testing.T) {
		ta := &TagAuth{Enabled: true, TagPrefix: "aow/"}
		tags := map[string]string{
			"aow/subject":            "project_path:acme/other",
			"aow/claim.project_path": "acme/api",
		}
		assert.False(t, ta.Authorize(tags, claims, "https://gitlab.example.com", sub))
	})

	t.Run("missing identity tag still denies", func(t *testing.T) {
		ta := &TagAuth{Enabled: true, TagPrefix: "aow/", multiIssuer: true}
		tags := map[string]string{
			"aow/issuer":             "https://gitlab.example.com",
			"aow/claim.project_path": "acme/api",
		}
		assert.False(t, ta.Authorize(tags, claims, "https://gitlab.example.com", sub))
	})
}

// TestTagAuth_PerIssuerTagPrefix pins that the tag keys inspected for a
// request are namespaced by the issuer that verified the token: an issuer
// declaring tag_prefix is read only under that prefix, and one declaring none
// falls back to tag_auth.tag_prefix. Without this, a role tagged for one
// issuer's namespace could authorize a token from another.
func TestTagAuth_PerIssuerTagPrefix(t *testing.T) {
	const (
		gh = "https://token.actions.githubusercontent.com"
		gl = "https://gitlab.com"
		bk = "https://token.example.buildkite.com"
	)
	c := &Config{
		RoleSessionName: "test",
		Issuers: []IssuerConfig{
			{Issuer: gh, Provider: "github", Audiences: []string{"sts.amazonaws.com"}, TagPrefix: "gh/"},
			{Issuer: gl, Provider: "generic", Audiences: []string{"aud"}, ClaimMappings: map[string]string{"subject": "project_path"}, TagPrefix: "gl/"},
			{Issuer: bk, Provider: "generic", Audiences: []string{"aud"}, ClaimMappings: map[string]string{"subject": "pipeline_slug"}},
		},
		TagAuth: &TagAuth{Enabled: true},
	}
	require.NoError(t, c.Validate())
	ta := c.TagAuth
	assert.Equal(t, "aow/", ta.TagPrefix, "global prefix must still default for issuers with no override")

	ghClaims := map[string]any{"repository": "acme/api", "repository_owner": "acme"}
	ghTags := map[string]string{"gh/issuer": gh, "gh/subject": "acme/api"}
	assert.True(t, ta.Authorize(ghTags, ghClaims, gh, "acme/api"))
	assert.False(t, ta.Authorize(ghTags, ghClaims, gl, "acme/api"), "gh/ tags must be invisible to the gitlab namespace")
	assert.False(t, ta.Authorize(ghTags, ghClaims, bk, "acme/api"), "gh/ tags must be invisible to an issuer on the global prefix")
	assert.False(t, ta.Authorize(map[string]string{"aow/issuer": gh, "aow/subject": "acme/api"}, ghClaims, gh, "acme/api"),
		"an issuer that overrides the prefix must stop reading the global one")

	// Named GitHub dimensions and default_org expansion follow the prefix too.
	assert.True(t, ta.Authorize(map[string]string{"gh/issuer": gh, "gh/repo-owner": "acme", "gh/repo": "acme/api"}, ghClaims, gh, "acme/api"))
	assert.False(t, ta.Authorize(map[string]string{"gh/issuer": gh, "gh/repo": "acme/api", "gh/actor": "someone-else"}, ghClaims, gh, "acme/api"))

	// claim.<name> is namespaced as well.
	glClaims := map[string]any{"project_path": "grp/proj"}
	glTags := func(claimVal string) map[string]string {
		return map[string]string{"gl/issuer": gl, "gl/subject": "grp/proj", "gl/claim.project_path": claimVal}
	}
	assert.True(t, ta.Authorize(glTags("grp/proj"), glClaims, gl, "grp/proj"))
	assert.False(t, ta.Authorize(glTags("other/proj"), glClaims, gl, "grp/proj"))

	// An issuer with no override keeps reading the global prefix.
	bkClaims := map[string]any{"pipeline_slug": "deploy"}
	assert.True(t, ta.Authorize(map[string]string{"aow/issuer": bk, "aow/subject": "deploy"}, bkClaims, bk, "deploy"))
	assert.False(t, ta.Authorize(map[string]string{"gh/issuer": bk, "gh/subject": "deploy"}, bkClaims, bk, "deploy"))
}

// TestTagAuth_NestedTagPrefixesDoNotLeak covers the one prefix pair where
// namespaces could bleed: one issuer's prefix is a textual prefix of another's
// ("aow/" and "aow/gh/"). Tag lookups are exact-key, and claim.<name> is
// matched against the full "<prefix>claim." string, so the nested issuer's
// tags must be invisible to the outer one — including as a claim dimension,
// which is the form that scans keys rather than looking one up.
func TestTagAuth_NestedTagPrefixesDoNotLeak(t *testing.T) {
	c := &Config{
		RoleSessionName: "test",
		Issuers: []IssuerConfig{
			{Issuer: vIss, Provider: "github", Audiences: []string{"aud"}},
			{Issuer: vIss2, Provider: "github", Audiences: []string{"aud"}, TagPrefix: "aow/gh/"},
		},
		TagAuth: &TagAuth{Enabled: true, TagPrefix: "aow/"},
	}
	require.NoError(t, c.Validate())
	claims := map[string]any{"repository": "acme/api"}

	nested := map[string]string{"aow/gh/issuer": vIss2, "aow/gh/subject": "acme/api", "aow/gh/claim.repository": "acme/api"}
	assert.True(t, c.TagAuth.Authorize(nested, claims, vIss2, "acme/api"), "the nested issuer reads its own prefix")
	assert.False(t, c.TagAuth.Authorize(nested, claims, vIss, "acme/api"),
		"PREFIX LEAK: aow/gh/* tags must not authorize the issuer on aow/")

	// The reverse direction: the outer issuer's tags are not the nested one's.
	outer := map[string]string{"aow/issuer": vIss, "aow/subject": "acme/api"}
	assert.True(t, c.TagAuth.Authorize(outer, claims, vIss, "acme/api"))
	assert.False(t, c.TagAuth.Authorize(outer, claims, vIss2, "acme/api"))

	// The case only exact-key lookup can refuse: the nested role names the
	// OUTER issuer and a subject that caller really has, so the issuer and
	// identity gates would both pass on the tag VALUES. Nothing but reading
	// "aow/issuer"/"aow/subject" as literal keys — never "aow/" + something
	// that ends in "issuer" — keeps this from granting.
	trap := map[string]string{"aow/gh/issuer": vIss, "aow/gh/subject": "acme/api"}
	assert.False(t, c.TagAuth.Authorize(trap, claims, vIss, "acme/api"),
		"PREFIX LEAK: a nested-namespace tag whose value names the outer issuer must not authorize it")
}

// TestTagAuth_PerIssuerTagPrefixOverGlobalOverride pins the resolution order:
// the issuer's prefix wins over an operator-set global prefix, which in turn
// serves every issuer that declares none.
func TestTagAuth_PerIssuerTagPrefixOverGlobalOverride(t *testing.T) {
	c := &Config{
		RoleSessionName: "test",
		Issuers: []IssuerConfig{
			{Issuer: vIss, Provider: "github", Audiences: []string{"aud"}, TagPrefix: "gh/"},
			{Issuer: vIss2, Provider: "github", Audiences: []string{"aud"}},
		},
		TagAuth: &TagAuth{Enabled: true, TagPrefix: "corp:"},
	}
	require.NoError(t, c.Validate())
	claims := map[string]any{"repository": "acme/api"}

	assert.True(t, c.TagAuth.Authorize(map[string]string{"gh/issuer": vIss, "gh/subject": "acme/api"}, claims, vIss, "acme/api"))
	assert.False(t, c.TagAuth.Authorize(map[string]string{"corp:issuer": vIss, "corp:subject": "acme/api"}, claims, vIss, "acme/api"))
	assert.True(t, c.TagAuth.Authorize(map[string]string{"corp:issuer": vIss2, "corp:subject": "acme/api"}, claims, vIss2, "acme/api"))
}

// TestTagAuth_TagPrefixValidation pins boot-time rejection of a prefix that
// cannot appear in an IAM tag key: a config that can never match any role is
// an operator error, not a silent no-op at request time.
func TestTagAuth_TagPrefixValidation(t *testing.T) {
	cases := []struct {
		name         string
		issuerPrefix string
		globalPrefix string
		wantErr      string
	}{
		{name: "both unset"},
		{name: "valid issuer prefix", issuerPrefix: "gh/"},
		{name: "valid global prefix", globalPrefix: "corp:aow/"},
		{name: "issuer prefix with space", issuerPrefix: "gh /", wantErr: "issuers[0]"},
		{name: "issuer prefix with tab", issuerPrefix: "gh\t/", wantErr: "tag_prefix"},
		{name: "issuer prefix too long", issuerPrefix: strings.Repeat("a", 65), wantErr: "tag_prefix"},
		{name: "global prefix with space", globalPrefix: "aow /", wantErr: "tag_auth.tag_prefix"},
		{name: "global prefix with invalid char", globalPrefix: "aow!/", wantErr: "tag_auth.tag_prefix"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := &Config{
				RoleSessionName: "test",
				Issuers:         []IssuerConfig{{Issuer: vIss, Provider: "github", Audiences: []string{"aud"}, TagPrefix: tc.issuerPrefix}},
				TagAuth:         &TagAuth{Enabled: true, TagPrefix: tc.globalPrefix},
			}
			err := c.Validate()
			if tc.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErr)
		})
	}
}

// TestTagAuth_PerIssuerTagPrefixSurvivesRemoteReload pins that an issuer's
// tag_prefix survives a remote-config reload. Provider.refresh and MergeBytes
// both rebuild the config by JSON round-tripping it (cloneConfig), so a field
// without a json tag is silently dropped and the issuer falls back to the
// global prefix — every tag-authorized role for that issuer would stop
// matching on the first S3 refresh, with nothing but a deny to show for it.
func TestTagAuth_PerIssuerTagPrefixSurvivesRemoteReload(t *testing.T) {
	c := &Config{
		RoleSessionName: "test",
		Cache:           &Cache{Type: "memory", TTL: time.Hour},
		Issuers: []IssuerConfig{
			{Issuer: vIss, Provider: "github", Audiences: []string{"aud"}, TagPrefix: "gh/"},
			{Issuer: vIss2, Provider: "github", Audiences: []string{"aud"}},
		},
		TagAuth: &TagAuth{Enabled: true},
	}
	require.NoError(t, c.Validate())
	claims := map[string]any{"repository": "acme/api"}
	ghTags := map[string]string{"gh/issuer": vIss, "gh/subject": "acme/api"}
	require.True(t, c.TagAuth.Authorize(ghTags, claims, vIss, "acme/api"), "precondition")

	clone, err := cloneConfig(c)
	require.NoError(t, err)
	require.NoError(t, clone.Validate())
	assert.Equal(t, "gh/", clone.Issuers[0].TagPrefix, "tag_prefix must survive the JSON clone")
	assert.True(t, clone.TagAuth.Authorize(ghTags, claims, vIss, "acme/api"),
		"the cloned config must still read the issuer's own prefix")

	// The same through the overlay path, where the payload leaves issuers alone.
	require.NoError(t, c.MergeBytes([]byte("tag_auth:\n  enabled: true\n"), "yaml"))
	assert.Equal(t, "gh/", c.Issuers[0].TagPrefix)
	assert.True(t, c.TagAuth.Authorize(ghTags, claims, vIss, "acme/api"))

	// A cloned TagAuth is a fresh allocation, so rebuilding prefixByIssuer on
	// one config cannot race a request reading it through another.
	assert.NotSame(t, c.TagAuth, clone.TagAuth)
}
