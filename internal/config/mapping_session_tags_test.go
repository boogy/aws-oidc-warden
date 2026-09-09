package config

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// tagCfg builds a one-issuer config whose issuer declares repo/actor, plus
// whatever mappings the test needs.
func tagCfg(mappings ...RoleMapping) *Config {
	return &Config{
		Issuers: []IssuerConfig{{
			Issuer:      "https://token.actions.githubusercontent.com",
			Provider:    "github",
			Audiences:   []string{"sts.amazonaws.com"},
			SessionTags: map[string]string{"repo": "repository", "actor": "actor"},
		}},
		RoleSessionName: "aow",
		Cache:           &Cache{TTL: 0},
		RoleMappings:    mappings,
	}
}

const tagIssuer = "https://token.actions.githubusercontent.com"

func TestEffectiveSessionTags_MappingExtendsIssuerSpec(t *testing.T) {
	cfg := tagCfg(RoleMapping{
		Subject:     Patterns{"acme/api"},
		Roles:       []string{"arn:aws:iam::123456789012:role/app"},
		SessionTags: map[string]string{"tier": "environment"},
	})
	require.NoError(t, cfg.Validate())

	d := cfg.Authorize(tagIssuer, "acme/api", "arn:aws:iam::123456789012:role/app", map[string]any{})
	require.True(t, d.Matched)

	got := cfg.EffectiveSessionTags(tagIssuer, d)
	require.Equal(t, map[string]string{
		"repo":  "repository",
		"actor": "actor",
		"tier":  "environment",
	}, got)
}

// The issuer spec is the contract: a mapping's extras must not be able to
// mutate it for the next request, so the merge cannot write into the live map.
func TestEffectiveSessionTags_DoesNotMutateIssuerSpec(t *testing.T) {
	cfg := tagCfg(RoleMapping{
		Subject:     Patterns{"acme/api"},
		Roles:       []string{"arn:aws:iam::123456789012:role/app"},
		SessionTags: map[string]string{"tier": "environment"},
	})
	require.NoError(t, cfg.Validate())

	d := cfg.Authorize(tagIssuer, "acme/api", "arn:aws:iam::123456789012:role/app", map[string]any{})
	cfg.EffectiveSessionTags(tagIssuer, d)

	require.Equal(t, map[string]string{"repo": "repository", "actor": "actor"},
		cfg.IssuerSessionTags(tagIssuer), "issuer spec was mutated by the merge")
}

// A role granted without an authorizing mapping (tag-auth) gets the issuer
// spec and nothing else — there is no mapping layer to apply.
func TestEffectiveSessionTags_NoAuthorizingMappingGetsIssuerSpecOnly(t *testing.T) {
	cfg := tagCfg(RoleMapping{
		Subject:     Patterns{"acme/api"},
		Roles:       []string{"arn:aws:iam::123456789012:role/app"},
		SessionTags: map[string]string{"tier": "environment"},
	})
	require.NoError(t, cfg.Validate())

	// Requesting a role this mapping does not grant leaves authorizing nil.
	d := cfg.Authorize(tagIssuer, "acme/api", "arn:aws:iam::123456789012:role/other", map[string]any{})
	require.Equal(t, map[string]string{"repo": "repository", "actor": "actor"},
		cfg.EffectiveSessionTags(tagIssuer, d))
}

// Only the mapping that actually granted the role contributes: a sibling
// mapping's extras must not leak onto another subject's session.
func TestEffectiveSessionTags_ExtrasDoNotLeakAcrossMappings(t *testing.T) {
	cfg := tagCfg(
		RoleMapping{
			Subject:     Patterns{"acme/api"},
			Roles:       []string{"arn:aws:iam::123456789012:role/app"},
			SessionTags: map[string]string{"tier": "environment"},
		},
		RoleMapping{
			Subject: Patterns{"acme/web"},
			Roles:   []string{"arn:aws:iam::123456789012:role/web"},
		},
	)
	require.NoError(t, cfg.Validate())

	d := cfg.Authorize(tagIssuer, "acme/web", "arn:aws:iam::123456789012:role/web", map[string]any{})
	require.True(t, d.Matched)
	got := cfg.EffectiveSessionTags(tagIssuer, d)
	require.NotContains(t, got, "tier")
	require.Len(t, got, 2)
}

func TestValidate_MappingSessionTagsAreAdditiveOnly(t *testing.T) {
	tests := []struct {
		name    string
		tags    map[string]string
		wantErr string
	}{
		{"adds a new key", map[string]string{"tier": "environment"}, ""},
		{"redefines an issuer key", map[string]string{"repo": "repository_owner"}, "a mapping may only add tags"},
		{"redefines with the same claim", map[string]string{"repo": "repository"}, "a mapping may only add tags"},
		{"invalid STS tag key", map[string]string{"bad*key": "environment"}, "not a valid STS tag key"},
		{"oversized STS tag key", map[string]string{strings.Repeat("k", 129): "environment"}, "not a valid STS tag key"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := tagCfg(RoleMapping{
				Subject:     Patterns{"acme/api"},
				Roles:       []string{"arn:aws:iam::123456789012:role/app"},
				SessionTags: tc.tags,
			})
			err := cfg.Validate()
			if tc.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			require.Contains(t, err.Error(), tc.wantErr)
		})
	}
}

// A role_group must carry its defaults' session_tags into every expanded
// mapping, or the feature silently does nothing inside a group.
func TestValidate_RoleGroupDefaultsCarrySessionTags(t *testing.T) {
	cfg := tagCfg()
	cfg.RoleGroups = []RoleGroup{{
		Subjects: Patterns{"acme/api", "acme/web"},
		Defaults: RoleGroupDefaults{
			Roles:       []string{"arn:aws:iam::123456789012:role/app"},
			SessionTags: map[string]string{"tier": "environment"},
		},
	}}
	require.NoError(t, cfg.Validate())

	for _, subject := range []string{"acme/api", "acme/web"} {
		d := cfg.Authorize(tagIssuer, subject, "arn:aws:iam::123456789012:role/app", map[string]any{})
		require.True(t, d.Matched, subject)
		require.Equal(t, "environment", cfg.EffectiveSessionTags(tagIssuer, d)["tier"], subject)
	}
}

// The additive-only invariant must also hold for keys inherited from a group's
// defaults, not just ones written on a mapping directly.
func TestValidate_RoleGroupDefaultsRejectIssuerKeyCollision(t *testing.T) {
	cfg := tagCfg()
	cfg.RoleGroups = []RoleGroup{{
		Subjects: Patterns{"acme/api"},
		Defaults: RoleGroupDefaults{
			Roles:       []string{"arn:aws:iam::123456789012:role/app"},
			SessionTags: map[string]string{"actor": "repository_owner"},
		},
	}}
	err := cfg.Validate()
	require.Error(t, err)
	require.Contains(t, err.Error(), "a mapping may only add tags")
}

// An issuer the config does not know gets nothing, mirroring
// IssuerSessionTags' fail-closed contract.
func TestEffectiveSessionTags_UnknownIssuerGetsNothing(t *testing.T) {
	cfg := tagCfg()
	require.NoError(t, cfg.Validate())

	require.Nil(t, cfg.EffectiveSessionTags("https://evil.example", Decision{}))
}

// An issuer declaring no session_tags of its own still gets the mapping's
// extras — the empty-base regression.
func TestEffectiveSessionTags_IssuerWithoutOwnTags(t *testing.T) {
	cfg := &Config{
		Issuers: []IssuerConfig{{
			Issuer:    tagIssuer,
			Provider:  "github",
			Audiences: []string{"sts.amazonaws.com"},
		}},
		RoleSessionName: "aow",
		Cache:           &Cache{TTL: 0},
		RoleMappings: []RoleMapping{{
			Subject:     Patterns{"acme/api"},
			Roles:       []string{"arn:aws:iam::123456789012:role/app"},
			SessionTags: map[string]string{"tier": "environment"},
		}},
	}
	require.NoError(t, cfg.Validate())

	d := cfg.Authorize(tagIssuer, "acme/api", "arn:aws:iam::123456789012:role/app", map[string]any{})
	require.Equal(t, map[string]string{"tier": "environment"},
		cfg.EffectiveSessionTags(tagIssuer, d))
}

// Regression: a claim referenced only by a mapping-level session tag must
// still be auditable, or the record and the STS session disagree about which
// claims the caller asserted.
func TestAuditableClaims_CoversMappingSessionTags(t *testing.T) {
	cfg := tagCfg(RoleMapping{
		Subject:     Patterns{"acme/api"},
		Roles:       []string{"arn:aws:iam::123456789012:role/app"},
		SessionTags: map[string]string{"tier": "environment"},
	})
	require.NoError(t, cfg.Validate())

	for _, claim := range []string{"repository", "actor", "environment"} {
		require.True(t, cfg.AuditableClaims(tagIssuer, claim), "claim %q attached as a session tag but not auditable", claim)
	}
}
