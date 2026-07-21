package handler_test

// End-to-end verification of the request pipeline: what actually reaches STS
// on an allow, and that every deny path stops before it.

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
		Conditions: &config.Condition{Ref: "refs/heads/main"},
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
