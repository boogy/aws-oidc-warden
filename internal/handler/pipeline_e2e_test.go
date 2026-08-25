package handler_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsiam "github.com/aws/aws-sdk-go-v2/service/iam"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
	"github.com/boogy/aws-oidc-warden/internal/config"
	"github.com/boogy/aws-oidc-warden/internal/handler"
	"github.com/boogy/aws-oidc-warden/internal/types"
	"github.com/boogy/aws-oidc-warden/internal/validator"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const vE2EIssuer = "https://token.actions.githubusercontent.com"

type vExtractor struct {
	claims *types.Claims
	err    error
}

func (e *vExtractor) Extract(context.Context, validator.ExtractionInput) (*types.Claims, error) {
	return e.claims, e.err
}

// vRecorder records exactly what the pipeline hands to STS.
type vRecorder struct {
	assumeCalls   int
	assumedRole   string
	gotPolicy     *string
	gotTagSpec    map[string]string
	tags          map[string]string
	tagsErr       error
	allowAccount  bool
	getS3Called   int
	s3Body        string
	s3Err         error
	tagAuthCalled int
}

func (f *vRecorder) ReadS3Configuration() error { return nil }
func (f *vRecorder) GetS3Object(string, string) (io.ReadCloser, error) {
	f.getS3Called++
	if f.s3Err != nil {
		return nil, f.s3Err
	}
	return io.NopCloser(stringReader(f.s3Body)), nil
}
func (f *vRecorder) GetRole(string) (*awsiam.GetRoleOutput, error) { return nil, nil }
func (f *vRecorder) GetRoleTags(string) (map[string]string, error) {
	f.tagAuthCalled++
	return f.tags, f.tagsErr
}
func (f *vRecorder) IsTargetAccountAllowed(string) (bool, error) { return f.allowAccount, nil }
func (f *vRecorder) AssumeRole(roleARN, _ string, policy *string, _ *int32, _ *types.Claims, spec map[string]string) (*ststypes.Credentials, error) {
	f.assumeCalls++
	f.assumedRole = roleARN
	f.gotPolicy = policy
	f.gotTagSpec = spec
	return &ststypes.Credentials{
		AccessKeyId: aws.String("AKIA"), SecretAccessKey: aws.String("s"),
		SessionToken: aws.String("t"), Expiration: aws.Time(time.Now().Add(time.Hour)),
	}, nil
}

type stringReader string

func (s stringReader) Read(p []byte) (int, error) {
	if len(s) == 0 {
		return 0, io.EOF
	}
	n := copy(p, s)
	return n, io.EOF
}

func vE2ECfg(t *testing.T, mappings []config.RoleMapping) *config.Config {
	t.Helper()
	cfg := &config.Config{
		Issuers: []config.IssuerConfig{{
			Issuer: vE2EIssuer, Provider: "github", Audiences: []string{"sts.amazonaws.com"},
			SessionTags: map[string]string{"repo": "repository"},
		}},
		RoleSessionName:       "aow",
		S3SessionPolicyBucket: "policies",
		RoleMappings:          mappings,
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	return cfg
}

func vE2EClaims(subject, ref string) *types.Claims {
	return &types.Claims{
		RegisteredClaims: jwt.RegisteredClaims{Issuer: vE2EIssuer, Subject: subject},
		Sub:              "repo:" + subject,
		Repository:       subject, Ref: ref,
		Raw: map[string]any{
			"iss": vE2EIssuer, "repository": subject, "ref": ref,
			"repository_owner": "myorg", "actor": "alice", "event_name": "push",
		},
	}
}

func vRun(t *testing.T, cfg *config.Config, rec *vRecorder, claims *types.Claims, role string) (*ststypes.Credentials, error) {
	t.Helper()
	p := handler.NewRequestProcessor(
		config.NewStaticProvider(cfg), rec, &vExtractor{claims: claims}, nil, "test")
	ctx := context.WithValue(context.Background(), handler.StartTimeContextKey, time.Now())
	return p.ProcessRequest(ctx, &handler.RequestData{Role: role},
		validator.ExtractionInput{Token: "t"}, "req-1",
		slog.New(slog.NewTextHandler(io.Discard, nil)))
}

// ---------- E1: the scoping policy actually reaches STS ----------

func TestPipeline_ScopedPolicyReachesSTS(t *testing.T) {
	priv := "arn:aws:iam::111111111111:role/privileged"
	broad := "arn:aws:iam::111111111111:role/broad"
	cfg := vE2ECfg(t, []config.RoleMapping{
		{Subject: "myorg/.*", Roles: []string{broad}},
		{Subject: "myorg/repo", Roles: []string{priv}, SessionPolicy: `{"scoped":true}`},
	})
	rec := &vRecorder{allowAccount: true}
	if _, err := vRun(t, cfg, rec, vE2EClaims("myorg/repo", "refs/heads/main"), priv); err != nil {
		t.Fatalf("expected allow, got %v", err)
	}
	if rec.gotPolicy == nil || *rec.gotPolicy != `{"scoped":true}` {
		t.Fatalf("UNSCOPED ASSUMPTION: STS received policy %v for the privileged role", rec.gotPolicy)
	}
	if rec.gotTagSpec["repo"] != "repository" {
		t.Errorf("issuer session_tags spec not forwarded: %v", rec.gotTagSpec)
	}
}

// ---------- E2: every deny path stops before STS ----------

func TestPipeline_DenyPathsNeverReachSTS(t *testing.T) {
	role := "arn:aws:iam::111111111111:role/deploy"
	cfg := vE2ECfg(t, []config.RoleMapping{{
		Subject: "myorg/repo", Roles: []string{role},
		Conditions: &config.Condition{Ref: config.Patterns{"refs/heads/main"}},
	}})

	cases := []struct {
		name   string
		claims *types.Claims
		role   string
		allow  bool
		want   error
	}{
		{"subject not mapped", vE2EClaims("evil/repo", "refs/heads/main"), role, true, handler.ErrRoleNotPermitted},
		{"role not granted", vE2EClaims("myorg/repo", "refs/heads/main"), "arn:aws:iam::111111111111:role/other", true, handler.ErrRoleNotPermitted},
		{"condition unmet", vE2EClaims("myorg/repo", "refs/heads/feature"), role, true, handler.ErrRoleNotPermitted},
		{"account blocked", vE2EClaims("myorg/repo", "refs/heads/main"), role, false, handler.ErrAccountNotAllowed},
	}
	for _, tc := range cases {
		rec := &vRecorder{allowAccount: tc.allow}
		_, err := vRun(t, cfg, rec, tc.claims, tc.role)
		if err == nil {
			t.Errorf("%s: FAIL-OPEN — request allowed", tc.name)
		} else if !errors.Is(err, tc.want) {
			t.Errorf("%s: wrong sentinel: got %v want %v", tc.name, err, tc.want)
		}
		if rec.assumeCalls != 0 {
			t.Errorf("%s: CRITICAL — STS AssumeRole called on a denied request", tc.name)
		}
	}

	// Extraction failure (invalid token) must also stop before everything.
	rec := &vRecorder{allowAccount: true}
	p := handler.NewRequestProcessor(config.NewStaticProvider(cfg), rec,
		&vExtractor{err: errors.New("bad signature")}, nil, "test")
	ctx := context.WithValue(context.Background(), handler.StartTimeContextKey, time.Now())
	_, err := p.ProcessRequest(ctx, &handler.RequestData{Role: role},
		validator.ExtractionInput{Token: "t"}, "r", slog.New(slog.NewTextHandler(io.Discard, nil)))
	if !errors.Is(err, handler.ErrTokenValidationFailed) {
		t.Errorf("extraction failure sentinel wrong: %v", err)
	}
	if rec.assumeCalls != 0 {
		t.Error("CRITICAL: STS called after token validation failure")
	}
}

// ---------- E3: an unreadable/invalid policy file denies, never falls through ----------

func TestPipeline_PolicyFileFailureDenies(t *testing.T) {
	role := "arn:aws:iam::111111111111:role/deploy"
	cfg := vE2ECfg(t, []config.RoleMapping{
		{Subject: "myorg/repo", Roles: []string{role}, SessionPolicyFile: "scoped.json"},
	})

	// S3 read fails -> deny, no assumption.
	rec := &vRecorder{allowAccount: true, s3Err: errors.New("access denied")}
	if _, err := vRun(t, cfg, rec, vE2EClaims("myorg/repo", "refs/heads/main"), role); err == nil {
		t.Error("FAIL-OPEN: policy file unreadable but request allowed")
	}
	if rec.assumeCalls != 0 {
		t.Error("CRITICAL: role assumed unscoped after policy-file read failure")
	}

	// Invalid JSON -> deny, no assumption.
	rec2 := &vRecorder{allowAccount: true, s3Body: "not json{"}
	if _, err := vRun(t, cfg, rec2, vE2EClaims("myorg/repo", "refs/heads/main"), role); err == nil {
		t.Error("FAIL-OPEN: invalid policy JSON but request allowed")
	}
	if rec2.assumeCalls != 0 {
		t.Error("CRITICAL: role assumed unscoped after invalid policy JSON")
	}

	// Valid policy -> allowed and forwarded.
	rec3 := &vRecorder{allowAccount: true, s3Body: `{"Version":"2012-10-17"}`}
	if _, err := vRun(t, cfg, rec3, vE2EClaims("myorg/repo", "refs/heads/main"), role); err != nil {
		t.Fatalf("valid policy file should allow: %v", err)
	}
	if rec3.gotPolicy == nil || *rec3.gotPolicy != `{"Version":"2012-10-17"}` {
		t.Errorf("policy file content not forwarded: %v", rec3.gotPolicy)
	}
}

// ---------- E4: tag-auth is only a fallback, and only when enabled ----------

func TestPipeline_TagAuthIsFallbackOnly(t *testing.T) {
	role := "arn:aws:iam::111111111111:role/deploy"
	cfg := vE2ECfg(t, []config.RoleMapping{{Subject: "myorg/repo", Roles: []string{role}}})

	// tag_auth disabled (default): role tags must never be consulted.
	rec := &vRecorder{allowAccount: true, tags: map[string]string{"aow/subject": "evil/repo"}}
	if _, err := vRun(t, cfg, rec, vE2EClaims("evil/repo", "refs/heads/main"), role); err == nil {
		t.Error("FAIL-OPEN: unmapped subject allowed with tag_auth disabled")
	}
	if rec.tagAuthCalled != 0 {
		t.Error("role tags read despite tag_auth being disabled")
	}

	// Explicit match short-circuits: no IAM tag read on the happy path.
	rec2 := &vRecorder{allowAccount: true}
	if _, err := vRun(t, cfg, rec2, vE2EClaims("myorg/repo", "refs/heads/main"), role); err != nil {
		t.Fatal(err)
	}
	if rec2.tagAuthCalled != 0 {
		t.Error("role tags read even though the explicit mapping matched")
	}

	// tag_auth enabled: a matching tag authorizes, but with NO session policy.
	cfg2 := vE2ECfg(t, []config.RoleMapping{{Subject: "myorg/other", Roles: []string{role}, SessionPolicy: "unrelated"}})
	cfg2.TagAuth = &config.TagAuth{Enabled: true, TagPrefix: "aow/"}
	if err := cfg2.Validate(); err != nil {
		t.Fatal(err)
	}
	rec3 := &vRecorder{allowAccount: true, tags: map[string]string{"aow/subject": "myorg/repo"}}
	if _, err := vRun(t, cfg2, rec3, vE2EClaims("myorg/repo", "refs/heads/main"), role); err != nil {
		t.Fatalf("tag-auth should allow: %v", err)
	}
	if rec3.gotPolicy != nil {
		t.Errorf("POLICY LEAK: tag-authorized role inherited an unrelated mapping's policy %q", *rec3.gotPolicy)
	}
}

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

// Tag-based authorization for a non-GitHub issuer, end to end.
//
// Every named tag dimension (`repo`, `repo-owner`, `branch`, `actor`, …) spells
// a GitHub Actions claim, so an issuer that emits none of them can only be
// authorized through `<prefix>subject` plus the issuer-agnostic
// `<prefix>claim.<name>` form. That is the documented escape hatch; these tests
// exercise it through the real pipeline rather than through TagAuth.Authorize
// alone, so a regression anywhere between claim extraction and the IAM tag read
// is caught.

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
