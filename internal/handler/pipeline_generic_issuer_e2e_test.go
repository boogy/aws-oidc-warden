package handler_test

// End-to-end verification that the pipeline is issuer-agnostic: a non-GitHub
// OIDC issuer, with none of GitHub's claim names, must flow through claims
// extraction, condition evaluation, session-policy selection, and session
// tagging exactly as a GitHub issuer does.
//
// The GitHub e2e suite next door cannot catch an accidental dependency on
// GitHub's vocabulary, because every claim it feeds happens to be one of the
// names types.Claims models natively. Everything asserted here is driven from
// claim names GitHub never issues (`project_path`, `pipeline_source`,
// `groups`), a `provider: generic` issuer, and a subject that is not
// `repo:owner/name:...`.

import (
	"testing"

	"github.com/boogy/aws-oidc-warden/internal/config"
	"github.com/boogy/aws-oidc-warden/internal/types"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const gE2EIssuer = "https://gitlab.example.com"

// gE2ECfg builds a config whose ONLY issuer is a generic one, so nothing can
// fall back to a GitHub default.
func gE2ECfg(t *testing.T, mappings []config.RoleMapping) *config.Config {
	t.Helper()
	cfg := &config.Config{
		Issuers: []config.IssuerConfig{{
			Issuer:    gE2EIssuer,
			Provider:  "generic",
			Audiences: []string{"sts.amazonaws.com"},
			ClaimMappings: map[string]string{
				"subject": "project_path",
			},
			SessionTags: map[string]string{"project": "project_path"},
		}},
		RoleSessionName: "aow",
		RoleMappings:    mappings,
	}
	require.NoError(t, cfg.Validate())
	return cfg
}

// gE2EClaims mimics what the generic adapter produces: the canonical Subject
// comes from claim_mappings.subject, every GitHub-native struct field stays
// zero, and Raw carries the issuer's own vocabulary.
//
// Those three properties are not assumed here — they are pinned against a real
// signed token in validator.TestValidate_GenericProvider_SubjectMappingIgnoresRogueClaim,
// which is what makes this fixture faithful rather than a fiction. This suite
// starts from claims on purpose: it covers the half of the pipeline AFTER
// extraction, and the validator suite covers the half before it.
func gE2EClaims(projectPath, pipelineSource string, groups []any) *types.Claims {
	return &types.Claims{
		RegisteredClaims: jwt.RegisteredClaims{Issuer: gE2EIssuer, Subject: projectPath},
		Sub:              "project_path:" + projectPath + ":ref_type:branch",
		Raw: map[string]any{
			"iss":             gE2EIssuer,
			"sub":             "project_path:" + projectPath + ":ref_type:branch",
			"project_path":    projectPath,
			"pipeline_source": pipelineSource,
			"groups":          groups,
		},
	}
}

// A generic issuer's claims must drive the whole allow path: the subject match,
// the condition gate (on a claim GitHub does not issue), the session policy
// attached to the authorizing mapping, and the session tag spec handed to STS.
func TestGenericIssuer_AllowPathReachesSTSWithPolicyAndTags(t *testing.T) {
	const role = "arn:aws:iam::123456789012:role/gitlab-deploy"
	cfg := gE2ECfg(t, []config.RoleMapping{{
		Subject: "acme/platform/api",
		Issuer:  gE2EIssuer,
		Roles:   []string{role},
		Conditions: &config.Condition{
			Claims: map[string]config.Patterns{"pipeline_source": {"push", "web"}},
		},
		SessionPolicy: `{"Version":"2012-10-17","Statement":[]}`,
	}})

	rec := &vRecorder{allowAccount: true}
	creds, err := vRun(t, cfg, rec, gE2EClaims("acme/platform/api", "push", nil), role)

	require.NoError(t, err)
	require.NotNil(t, creds)
	assert.Equal(t, 1, rec.assumeCalls, "STS must be reached exactly once")
	assert.Equal(t, role, rec.assumedRole)
	require.NotNil(t, rec.gotPolicy, "the mapping's session policy must reach STS")
	assert.JSONEq(t, `{"Version":"2012-10-17","Statement":[]}`, *rec.gotPolicy)
	assert.Equal(t, map[string]string{"project": "project_path"}, rec.gotTagSpec,
		"the generic issuer's session_tags spec must reach AssumeRole")
	assert.Zero(t, rec.tagAuthCalled, "tag-auth must not be consulted once a mapping authorizes")
}

// The condition gate must DENY on a generic issuer's own claim, not merely
// fail open because the claim has no types.Claims field.
func TestGenericIssuer_ConditionOnIssuerClaimDenies(t *testing.T) {
	const role = "arn:aws:iam::123456789012:role/gitlab-deploy"
	cfg := gE2ECfg(t, []config.RoleMapping{{
		Subject: "acme/platform/api",
		Issuer:  gE2EIssuer,
		Roles:   []string{role},
		Conditions: &config.Condition{
			Claims: map[string]config.Patterns{"pipeline_source": {"push"}},
		},
	}})

	rec := &vRecorder{allowAccount: true}
	// Same subject, same role — only the gated claim differs.
	_, err := vRun(t, cfg, rec, gE2EClaims("acme/platform/api", "schedule", nil), role)

	require.Error(t, err)
	assert.Zero(t, rec.assumeCalls, "a denied request must never reach STS")
}

// An array-valued claim — the shape GitLab/Okta/Entra use for groups and
// scopes, and one GitHub never issues — must gate correctly end to end.
func TestGenericIssuer_ArrayClaimConditionGatesEndToEnd(t *testing.T) {
	const role = "arn:aws:iam::123456789012:role/gitlab-deploy"
	cfg := gE2ECfg(t, []config.RoleMapping{{
		Subject:    "acme/platform/api",
		Issuer:     gE2EIssuer,
		Roles:      []string{role},
		Conditions: &config.Condition{Claims: map[string]config.Patterns{"groups": {"platform-admins"}}},
	}})

	t.Run("member of the required group is allowed", func(t *testing.T) {
		rec := &vRecorder{allowAccount: true}
		_, err := vRun(t, cfg, rec,
			gE2EClaims("acme/platform/api", "push", []any{"everyone", "platform-admins"}), role)
		require.NoError(t, err)
		assert.Equal(t, 1, rec.assumeCalls)
	})

	t.Run("non-member is denied", func(t *testing.T) {
		rec := &vRecorder{allowAccount: true}
		_, err := vRun(t, cfg, rec,
			gE2EClaims("acme/platform/api", "push", []any{"everyone", "contractors"}), role)
		require.Error(t, err)
		assert.Zero(t, rec.assumeCalls)
	})
}

// A subject verified against one issuer must never authorize against another
// issuer's mappings, even when the subject strings are identical. This is the
// property that keeps a second issuer from being a privilege-escalation path
// into the first issuer's grants.
func TestGenericIssuer_SubjectDoesNotCrossIssuerBoundary(t *testing.T) {
	const role = "arn:aws:iam::123456789012:role/github-only"
	cfg := &config.Config{
		Issuers: []config.IssuerConfig{
			{
				Issuer: vE2EIssuer, Provider: "github", Audiences: []string{"sts.amazonaws.com"},
			},
			{
				Issuer: gE2EIssuer, Provider: "generic", Audiences: []string{"sts.amazonaws.com"},
				ClaimMappings: map[string]string{"subject": "project_path"},
			},
		},
		RoleSessionName: "aow",
		// Granted to the GitHub issuer ONLY.
		RoleMappings: []config.RoleMapping{{
			Subject: "acme/platform", Issuer: vE2EIssuer, Roles: []string{role},
		}},
	}
	require.NoError(t, cfg.Validate())

	rec := &vRecorder{allowAccount: true}
	// A GitLab token whose project_path is byte-identical to the GitHub repo.
	_, err := vRun(t, cfg, rec, gE2EClaims("acme/platform", "push", nil), role)

	require.Error(t, err, "a gitlab subject must not inherit a github mapping")
	assert.Zero(t, rec.assumeCalls)
}
