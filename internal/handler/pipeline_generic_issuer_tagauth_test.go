package handler_test

// Tag-based authorization for a non-GitHub issuer, end to end.
//
// Every named tag dimension (`repo`, `repo-owner`, `branch`, `actor`, …) spells
// a GitHub Actions claim, so an issuer that emits none of them can only be
// authorized through `<prefix>subject` plus the issuer-agnostic
// `<prefix>claim.<name>` form. That is the documented escape hatch; these tests
// exercise it through the real pipeline rather than through TagAuth.Authorize
// alone, so a regression anywhere between claim extraction and the IAM tag read
// is caught.

import (
	"testing"

	"github.com/boogy/aws-oidc-warden/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const gTagRole = "arn:aws:iam::123456789012:role/gitlab-tagged"

// gTagCfg is gE2ECfg plus tag-auth, and deliberately declares NO role mappings:
// tag-auth is the only thing that can authorize, so a pass proves the tag path
// carried the decision on its own.
func gTagCfg(t *testing.T) *config.Config {
	t.Helper()
	cfg := gE2ECfg(t, nil)
	cfg.TagAuth = &config.TagAuth{Enabled: true, TagPrefix: "aow/"}
	require.NoError(t, cfg.Validate())
	return cfg
}

// The canonical subject tag plus an issuer-agnostic claim tag must authorize a
// GitLab-shaped token that carries none of GitHub's claims.
func TestGenericIssuer_TagAuthAuthorizesViaClaimDimension(t *testing.T) {
	cfg := gTagCfg(t)
	rec := &vRecorder{allowAccount: true, tags: map[string]string{
		"aow/subject":               "acme/platform/api",
		"aow/claim.pipeline_source": "push web",
	}}

	creds, err := vRun(t, cfg, rec, gE2EClaims("acme/platform/api", "push", nil), gTagRole)

	require.NoError(t, err)
	require.NotNil(t, creds)
	assert.Equal(t, 1, rec.tagAuthCalled, "tag-auth is the only authorizer available")
	assert.Equal(t, 1, rec.assumeCalls)
	assert.Equal(t, gTagRole, rec.assumedRole)
	assert.Nil(t, rec.gotPolicy, "a tag-authorized role carries no config-declared session policy")
	assert.Equal(t, map[string]string{"project": "project_path"}, rec.gotTagSpec,
		"the issuer's session_tags spec still applies on the tag-auth path")
}

// A claim tag that does not match must deny, even though the identity tag does.
// Claim dimensions AND with the identity gate; they can narrow, never widen.
func TestGenericIssuer_TagAuthClaimDimensionNarrows(t *testing.T) {
	cfg := gTagCfg(t)
	rec := &vRecorder{allowAccount: true, tags: map[string]string{
		"aow/subject":               "acme/platform/api",
		"aow/claim.pipeline_source": "schedule",
	}}

	_, err := vRun(t, cfg, rec, gE2EClaims("acme/platform/api", "push", nil), gTagRole)

	require.Error(t, err, "pipeline_source=push must not satisfy claim.pipeline_source=schedule")
	assert.Zero(t, rec.assumeCalls, "STS must not be reached on a denied request")
}

// A role tagged only with claim dimensions and no identity tag must be denied:
// claim tags narrow an existing grant, they never establish identity.
func TestGenericIssuer_TagAuthClaimDimensionAloneCannotGrant(t *testing.T) {
	cfg := gTagCfg(t)
	rec := &vRecorder{allowAccount: true, tags: map[string]string{
		"aow/claim.pipeline_source": "push",
		"aow/claim.project_path":    "acme/platform/api",
	}}

	_, err := vRun(t, cfg, rec, gE2EClaims("acme/platform/api", "push", nil), gTagRole)

	require.Error(t, err, "claim tags alone must not pass the identity gate")
	assert.Zero(t, rec.assumeCalls)
}

// GitHub's named dimensions must not accidentally authorize a generic issuer.
// `aow/repo` reads the `repository` claim, which a GitLab token never carries,
// so the identity gate has nothing to match and must fail closed rather than
// treating the absent claim as a wildcard.
func TestGenericIssuer_GitHubNamedTagDimensionsDoNotMatch(t *testing.T) {
	cfg := gTagCfg(t)
	for name, tags := range map[string]map[string]string{
		"repo tag alone":       {"aow/repo": "acme/platform/api"},
		"repo-owner tag alone": {"aow/repo-owner": "acme"},
	} {
		t.Run(name, func(t *testing.T) {
			rec := &vRecorder{allowAccount: true, tags: tags}
			_, err := vRun(t, cfg, rec, gE2EClaims("acme/platform/api", "push", nil), gTagRole)
			require.Error(t, err, "an absent GitHub claim must not satisfy the identity gate")
			assert.Zero(t, rec.assumeCalls)
		})
	}
}

// A claim tag naming a list claim matches when any element matches, mirroring
// how conditions treat list claims. `groups` is a claim GitHub never issues.
func TestGenericIssuer_TagAuthClaimDimensionMatchesListClaim(t *testing.T) {
	cfg := gTagCfg(t)

	rec := &vRecorder{allowAccount: true, tags: map[string]string{
		"aow/subject":      "acme/platform/api",
		"aow/claim.groups": "platform-admins",
	}}
	claims := gE2EClaims("acme/platform/api", "push", []any{"developers", "platform-admins"})
	_, err := vRun(t, cfg, rec, claims, gTagRole)
	require.NoError(t, err, "membership in the required group must authorize")
	assert.Equal(t, 1, rec.assumeCalls)

	rec2 := &vRecorder{allowAccount: true, tags: map[string]string{
		"aow/subject":      "acme/platform/api",
		"aow/claim.groups": "platform-admins",
	}}
	claims2 := gE2EClaims("acme/platform/api", "push", []any{"developers"})
	_, err = vRun(t, cfg, rec2, claims2, gTagRole)
	require.Error(t, err, "non-membership must deny")
	assert.Zero(t, rec2.assumeCalls)
}
