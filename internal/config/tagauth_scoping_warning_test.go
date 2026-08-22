package config

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

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
func TestValidate_WarnsWhenTagAuthCanBypassSessionPolicy(t *testing.T) {
	cfg := tagAuthScopingCfg(true, RoleMapping{
		Subject:       "org/repo",
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

// A per-mapping role_session_name is bypassed the same way: the tag-auth path
// falls back to the global name, so CloudTrail attribution silently changes.
func TestValidate_WarnsWhenTagAuthCanBypassRoleSessionName(t *testing.T) {
	cfg := tagAuthScopingCfg(true, RoleMapping{
		Subject:         "org/repo",
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
func TestValidate_NoTagAuthWarningWhenTagAuthDisabled(t *testing.T) {
	cfg := tagAuthScopingCfg(false, RoleMapping{
		Subject:       "org/repo",
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
func TestValidate_NoTagAuthWarningForUnscopedMapping(t *testing.T) {
	cfg := tagAuthScopingCfg(true, RoleMapping{
		Subject: "org/repo",
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
