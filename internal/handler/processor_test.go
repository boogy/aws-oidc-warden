package handler_test

// ProcessRequest end to end short of a frontend: authorization, tag-based
// authorization, the resolved role_session_name, and serving a request across
// a config hot-reload.
import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync/atomic"
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

const testIssuer = "https://token.actions.githubusercontent.com"

// fixedExtractor returns a fixed set of claims without touching any token.
type fixedExtractor struct{ claims *types.Claims }

func (f *fixedExtractor) Extract(_ context.Context, _ validator.ExtractionInput) (*types.Claims, error) {
	return f.claims, nil
}

// staticProvider builds a config.Provider that maps "org/repo" → "arn:aws:iam::123456789012:role/MyRole".
func staticProvider(t *testing.T) *config.Provider {
	t.Helper()
	cfg := &config.Config{
		Issuers: []config.IssuerConfig{{
			Issuer:    testIssuer,
			Provider:  "github",
			Audiences: []string{"sts.amazonaws.com"},
		}},
		RoleSessionName: "test",
		Cache:           &config.Cache{TTL: 0},
		RoleMappings: []config.RoleMapping{{
			Subject: "org/repo",
			Roles:   []string{"arn:aws:iam::123456789012:role/MyRole"},
		}},
	}
	require.NoError(t, cfg.Validate())
	return config.NewStaticProvider(cfg)
}

// mockConsumer returns a fakeConsumer that successfully assumes any role.
func mockConsumer(t *testing.T) *fakeConsumer {
	t.Helper()
	exp := time.Now().Add(time.Hour)
	return &fakeConsumer{
		assumeOut: &ststypes.Credentials{
			AccessKeyId:     aws.String("AKID"),
			SecretAccessKey: aws.String("SECRET"),
			SessionToken:    aws.String("TOKEN"),
			Expiration:      &exp,
		},
		allowAccount: true,
	}
}

func TestProcessRequest_DelegatedMode(t *testing.T) {
	// extractor returns fixed claims without touching a token (delegated/apigw mode)
	ex := &fixedExtractor{claims: &types.Claims{
		RegisteredClaims: jwt.RegisteredClaims{Issuer: testIssuer, Subject: "org/repo"},
		Repository:       "org/repo",
		Ref:              "refs/heads/main",
		Actor:            "octocat",
	}}
	proc := handler.NewRequestProcessor(staticProvider(t), mockConsumer(t), ex, nil, "test")
	creds, err := proc.ProcessRequest(
		context.Background(),
		&handler.RequestData{Role: "arn:aws:iam::123456789012:role/MyRole"},
		validator.ExtractionInput{AuthorizerClaims: map[string]string{"repository": "org/repo"}},
		"req-123",
		slog.Default(),
	)
	require.NoError(t, err)
	assert.NotNil(t, creds)
}

// ---------- authorization ----------

// stubExtractor always returns an error to simulate extraction failure.
type stubExtractor struct{ err error }

func (s *stubExtractor) Extract(_ context.Context, _ validator.ExtractionInput) (*types.Claims, error) {
	return nil, s.err
}

func TestProcessRequest_TokenValidationErrorIsSentinel(t *testing.T) {
	cfg := &config.Config{
		Issuers: []config.IssuerConfig{{
			Issuer:    testIssuer,
			Provider:  "github",
			Audiences: []string{"sts.amazonaws.com"},
		}},
		RoleSessionName: "test",
		Cache:           &config.Cache{TTL: 0},
	}
	require.NoError(t, cfg.Validate())

	provider := config.NewStaticProvider(cfg)
	ex := &stubExtractor{err: errors.New("token is expired")}
	proc := handler.NewRequestProcessor(provider, nil, ex, nil, "test")

	_, err := proc.ProcessRequest(
		context.Background(),
		&handler.RequestData{Token: "t", Role: "r"},
		validator.ExtractionInput{Token: "t"},
		"req-id",
		slog.Default(),
	)
	require.Error(t, err)
	assert.True(t, errors.Is(err, handler.ErrTokenValidationFailed),
		"expected ErrTokenValidationFailed in error chain, got: %v", err)
}

// ---------- tag-based authorization ----------

type tagModeExtractor struct{ claims *types.Claims }

func (e *tagModeExtractor) Extract(_ context.Context, _ validator.ExtractionInput) (*types.Claims, error) {
	return e.claims, nil
}

type fakeConsumer struct {
	tags            map[string]string
	tagsErr         error
	assumed         string
	gotClaims       *types.Claims     // claims passed to AssumeRole → drive session tags (ABAC)
	gotSessionTags  map[string]string // session_tags spec passed to AssumeRole
	gotSessionName  string            // STS session name passed to AssumeRole
	assumeOut       *ststypes.Credentials
	allowAccount    bool
	allowAccountErr error
}

func (f *fakeConsumer) ReadS3Configuration() error { return nil }
func (f *fakeConsumer) GetS3Object(string, string) (io.ReadCloser, error) {
	return nil, errors.New("not used")
}
func (f *fakeConsumer) GetRole(string) (*awsiam.GetRoleOutput, error) { return nil, nil }
func (f *fakeConsumer) GetRoleTags(string) (map[string]string, error) { return f.tags, f.tagsErr }
func (f *fakeConsumer) IsTargetAccountAllowed(string) (bool, error) {
	return f.allowAccount, f.allowAccountErr
}
func (f *fakeConsumer) AssumeRole(roleARN, sessionName string, _ *string, _ *int32, claims *types.Claims, sessionTags map[string]string) (*ststypes.Credentials, error) {
	f.assumed = roleARN
	f.gotSessionName = sessionName
	f.gotClaims = claims
	f.gotSessionTags = sessionTags
	return f.assumeOut, nil
}

func baseTagCfg(t *testing.T) *config.Config {
	cfg := &config.Config{
		Issuers: []config.IssuerConfig{{
			Issuer:    testIssuer,
			Provider:  "github",
			Audiences: []string{"sts.amazonaws.com"},
		}},
		RoleSessionName: "test",
		Cache:           &config.Cache{TTL: 0},
		TagAuth:         &config.TagAuth{Enabled: true, TagPrefix: "aow/"},
		CrossAccount:    &config.CrossAccount{Enabled: true},
	}
	require.NoError(t, cfg.Validate())
	return cfg
}

func TestProcessRequest_TagAuthAllows(t *testing.T) {
	cfg := baseTagCfg(t)
	claims := &types.Claims{
		RegisteredClaims: jwt.RegisteredClaims{Issuer: testIssuer, Subject: "acme/api"},
		Repository:       "acme/api", RepositoryOwner: "acme", Ref: "refs/heads/main",
		// Raw mirrors what normalizeClaims populates in production (the verified
		// raw claim set); tag-auth/condition matching reads from it, not from the
		// typed struct fields.
		Raw: map[string]any{"repository": "acme/api", "repository_owner": "acme", "ref": "refs/heads/main"},
	}
	exp := time.Now()
	fc := &fakeConsumer{
		tags:         map[string]string{"aow/repo": "acme/api"},
		assumeOut:    &ststypes.Credentials{AccessKeyId: aws.String("AK"), SecretAccessKey: aws.String("SK"), SessionToken: aws.String("ST"), Expiration: &exp},
		allowAccount: true,
	}
	proc := handler.NewRequestProcessor(config.NewStaticProvider(cfg), fc, &tagModeExtractor{claims}, nil, "test")
	creds, err := proc.ProcessRequest(context.Background(),
		&handler.RequestData{Token: "t", Role: "arn:aws:iam::111111111111:role/app"},
		validator.ExtractionInput{Token: "t"},
		"rid", slog.Default())
	require.NoError(t, err)
	assert.Equal(t, "AK", *creds.AccessKeyId)
	assert.Equal(t, "arn:aws:iam::111111111111:role/app", fc.assumed)
	// Claims must reach AssumeRole so session tags (repo/ref/...) are attached for ABAC.
	require.NotNil(t, fc.gotClaims)
	assert.Equal(t, "acme/api", fc.gotClaims.Repository)
}

func TestProcessRequest_TagAuthDenies(t *testing.T) {
	cfg := baseTagCfg(t)
	claims := &types.Claims{
		RegisteredClaims: jwt.RegisteredClaims{Issuer: testIssuer, Subject: "acme/api"},
		Repository:       "acme/api", RepositoryOwner: "acme", Ref: "refs/heads/main",
		Raw: map[string]any{"repository": "acme/api", "repository_owner": "acme", "ref": "refs/heads/main"},
	}
	fc := &fakeConsumer{tags: map[string]string{"aow/repo": "acme/other"}, allowAccount: true}
	proc := handler.NewRequestProcessor(config.NewStaticProvider(cfg), fc, &tagModeExtractor{claims}, nil, "test")
	_, err := proc.ProcessRequest(context.Background(),
		&handler.RequestData{Token: "t", Role: "arn:aws:iam::111111111111:role/app"},
		validator.ExtractionInput{Token: "t"},
		"rid", slog.Default())
	require.Error(t, err)
	assert.True(t, errors.Is(err, handler.ErrRoleNotPermitted))
}

// TestProcessRequest_TagAuthOverridesFailedMapping documents (and locks in) the
// additive precedence foot-gun: tag-auth is an OR-ed fallback, so a role that an
// explicit mapping deliberately constrains (here branch=main) is still assumable
// from a different branch when its aow/* tags match and carry no aow/branch tag.
// Operators must not rely on a mapping constraint alone to *deny* such a role.
func TestProcessRequest_TagAuthOverridesFailedMapping(t *testing.T) {
	cfg := &config.Config{
		Issuers: []config.IssuerConfig{{
			Issuer:    testIssuer,
			Provider:  "github",
			Audiences: []string{"sts.amazonaws.com"},
		}},
		RoleSessionName: "test",
		Cache:           &config.Cache{TTL: 0},
		TagAuth:         &config.TagAuth{Enabled: true, TagPrefix: "aow/"},
		RoleMappings: []config.RoleMapping{{
			Subject:    "acme/api",
			Roles:      []string{"arn:aws:iam::111111111111:role/app"},
			Conditions: &config.Condition{Ref: config.Patterns{"main"}}, // requires ref == main
		}},
	}
	require.NoError(t, cfg.Validate())

	// Claims are for a feature branch → the explicit mapping's branch condition
	// fails, so the explicit path denies.
	claims := &types.Claims{
		RegisteredClaims: jwt.RegisteredClaims{Issuer: testIssuer, Subject: "acme/api"},
		Repository:       "acme/api", RepositoryOwner: "acme", Ref: "refs/heads/feature",
		Raw: map[string]any{"repository": "acme/api", "repository_owner": "acme", "ref": "refs/heads/feature"},
	}
	exp := time.Now()
	fc := &fakeConsumer{
		tags:         map[string]string{"aow/repo": "acme/api"}, // no aow/branch → branch unchecked
		assumeOut:    &ststypes.Credentials{AccessKeyId: aws.String("AK"), SecretAccessKey: aws.String("SK"), SessionToken: aws.String("ST"), Expiration: &exp},
		allowAccount: true,
	}
	proc := handler.NewRequestProcessor(config.NewStaticProvider(cfg), fc, &tagModeExtractor{claims}, nil, "test")
	creds, err := proc.ProcessRequest(context.Background(),
		&handler.RequestData{Token: "t", Role: "arn:aws:iam::111111111111:role/app"},
		validator.ExtractionInput{Token: "t"},
		"rid", slog.Default())
	require.NoError(t, err, "tag-auth should authorize despite the failed mapping constraint")
	assert.Equal(t, "AK", *creds.AccessKeyId)
}

func TestProcessRequest_AccountNotAllowed(t *testing.T) {
	cfg := baseTagCfg(t)
	claims := &types.Claims{
		RegisteredClaims: jwt.RegisteredClaims{Issuer: testIssuer, Subject: "acme/api"},
		Repository:       "acme/api", RepositoryOwner: "acme", Ref: "refs/heads/main",
	}
	// allowAccount defaults to false → target account is denied.
	fc := &fakeConsumer{tags: map[string]string{"aow/repo": "acme/api"}}
	proc := handler.NewRequestProcessor(config.NewStaticProvider(cfg), fc, &tagModeExtractor{claims}, nil, "test")
	_, err := proc.ProcessRequest(context.Background(),
		&handler.RequestData{Token: "t", Role: "arn:aws:iam::999999999999:role/app"},
		validator.ExtractionInput{Token: "t"},
		"rid", slog.Default())
	require.Error(t, err)
	assert.True(t, errors.Is(err, handler.ErrAccountNotAllowed))
}

func TestProcessRequest_AccountCheckError(t *testing.T) {
	cfg := baseTagCfg(t)
	claims := &types.Claims{
		RegisteredClaims: jwt.RegisteredClaims{Issuer: testIssuer, Subject: "acme/api"},
		Repository:       "acme/api", RepositoryOwner: "acme", Ref: "refs/heads/main",
	}
	// Infra error must take precedence over the allow/deny bool and map to a 5xx
	// (ErrAssumeRoleFailed), never a 403 (ErrAccountNotAllowed).
	fc := &fakeConsumer{tags: map[string]string{"aow/repo": "acme/api"}, allowAccount: true, allowAccountErr: errors.New("infra fail")}
	proc := handler.NewRequestProcessor(config.NewStaticProvider(cfg), fc, &tagModeExtractor{claims}, nil, "test")
	_, err := proc.ProcessRequest(context.Background(),
		&handler.RequestData{Token: "t", Role: "arn:aws:iam::999999999999:role/app"},
		validator.ExtractionInput{Token: "t"},
		"rid", slog.Default())
	require.Error(t, err)
	assert.True(t, errors.Is(err, handler.ErrAssumeRoleFailed))
	assert.False(t, errors.Is(err, handler.ErrAccountNotAllowed))
}

// TestProcessRequest_AccountNotAllowed_CrossAccountNil locks in that the account
// guardrail runs even when cross-account transport is not configured at all:
// IsTargetAccountAllowed itself encodes disabled-means-hub-only, so a false
// result must still deny before role tags are read or AssumeRole is attempted.
func TestProcessRequest_AccountNotAllowed_CrossAccountNil(t *testing.T) {
	cfg := &config.Config{
		Issuers: []config.IssuerConfig{{
			Issuer:    testIssuer,
			Provider:  "github",
			Audiences: []string{"sts.amazonaws.com"},
		}},
		RoleSessionName: "test",
		Cache:           &config.Cache{TTL: 0},
		TagAuth:         &config.TagAuth{Enabled: true, TagPrefix: "aow/"},
		// CrossAccount intentionally left nil.
	}
	require.NoError(t, cfg.Validate())
	claims := &types.Claims{
		RegisteredClaims: jwt.RegisteredClaims{Issuer: testIssuer, Subject: "acme/api"},
		Repository:       "acme/api", RepositoryOwner: "acme", Ref: "refs/heads/main",
	}
	// allowAccount defaults to false → target account is denied even though tags would match.
	fc := &fakeConsumer{tags: map[string]string{"aow/repo": "acme/api"}}
	proc := handler.NewRequestProcessor(config.NewStaticProvider(cfg), fc, &tagModeExtractor{claims}, nil, "test")
	_, err := proc.ProcessRequest(context.Background(),
		&handler.RequestData{Token: "t", Role: "arn:aws:iam::999999999999:role/app"},
		validator.ExtractionInput{Token: "t"},
		"rid", slog.Default())
	require.Error(t, err)
	assert.True(t, errors.Is(err, handler.ErrAccountNotAllowed))
	assert.Empty(t, fc.assumed, "AssumeRole must not be called when the account guard denies")
}

// TestProcessRequest_AccountCheckError_CrossAccountNil mirrors
// TestProcessRequest_AccountCheckError but with cross-account unconfigured,
// confirming the infra-error mapping to ErrAssumeRoleFailed also applies
// unconditionally.
func TestProcessRequest_AccountCheckError_CrossAccountNil(t *testing.T) {
	cfg := &config.Config{
		Issuers: []config.IssuerConfig{{
			Issuer:    testIssuer,
			Provider:  "github",
			Audiences: []string{"sts.amazonaws.com"},
		}},
		RoleSessionName: "test",
		Cache:           &config.Cache{TTL: 0},
		TagAuth:         &config.TagAuth{Enabled: true, TagPrefix: "aow/"},
	}
	require.NoError(t, cfg.Validate())
	claims := &types.Claims{
		RegisteredClaims: jwt.RegisteredClaims{Issuer: testIssuer, Subject: "acme/api"},
		Repository:       "acme/api", RepositoryOwner: "acme", Ref: "refs/heads/main",
	}
	fc := &fakeConsumer{tags: map[string]string{"aow/repo": "acme/api"}, allowAccountErr: errors.New("infra fail")}
	proc := handler.NewRequestProcessor(config.NewStaticProvider(cfg), fc, &tagModeExtractor{claims}, nil, "test")
	_, err := proc.ProcessRequest(context.Background(),
		&handler.RequestData{Token: "t", Role: "arn:aws:iam::999999999999:role/app"},
		validator.ExtractionInput{Token: "t"},
		"rid", slog.Default())
	require.Error(t, err)
	assert.True(t, errors.Is(err, handler.ErrAssumeRoleFailed))
	assert.False(t, errors.Is(err, handler.ErrAccountNotAllowed))
	assert.Empty(t, fc.assumed)
}

// ---------- role_session_name ----------

// sessionNameCfg builds a config whose two mappings differ only in their
// role_session_name override, so a test can prove the name follows the mapping
// that authorized the role rather than the first one that matched the subject.
func sessionNameCfg(t *testing.T, override string) *config.Config {
	t.Helper()
	cfg := &config.Config{
		Issuers: []config.IssuerConfig{{
			Issuer:    testIssuer,
			Provider:  "github",
			Audiences: []string{"sts.amazonaws.com"},
		}},
		RoleSessionName: "global-default",
		Cache:           &config.Cache{TTL: 0},
		RoleMappings: []config.RoleMapping{{
			Subject:         "org/repo",
			Roles:           []string{"arn:aws:iam::123456789012:role/MyRole"},
			RoleSessionName: override,
		}},
	}
	require.NoError(t, cfg.Validate())
	return cfg
}

func assumeWith(t *testing.T, cfg *config.Config, subject, role string) *fakeConsumer {
	t.Helper()
	consumer := mockConsumer(t)
	proc := handler.NewRequestProcessor(config.NewStaticProvider(cfg), consumer,
		&fixedExtractor{claims: allowClaims(subject)}, nil, "test")

	_, err := proc.ProcessRequest(context.Background(),
		&handler.RequestData{Role: role},
		validator.ExtractionInput{Token: "t"}, "req-session-name", slog.Default())
	require.NoError(t, err)
	return consumer
}

// TestAssumeRole_UsesPerMappingSessionName proves the per-mapping
// role_session_name reaches STS.
//
// Every handler-level mock bound AssumeRole's sessionName argument to `_`, so
// nothing in this package could tell the override apart from the global
// default — the whole point of the feature is CloudTrail attribution, and a
// wiring regression between FindRoleSessionName and the AssumeRole call would
// have been invisible.
func TestAssumeRole_UsesPerMappingSessionName(t *testing.T) {
	consumer := assumeWith(t, sessionNameCfg(t, "gha-org-repo"), "org/repo",
		"arn:aws:iam::123456789012:role/MyRole")

	assert.Equal(t, "gha-org-repo", consumer.gotSessionName,
		"the per-mapping role_session_name never reached AssumeRole")
}

// With no override the global role_session_name is used — the fallback must
// not regress into an empty session name, which STS rejects.
func TestAssumeRole_FallsBackToGlobalSessionName(t *testing.T) {
	consumer := assumeWith(t, sessionNameCfg(t, ""), "org/repo",
		"arn:aws:iam::123456789012:role/MyRole")

	assert.Equal(t, "global-default", consumer.gotSessionName)
}

// The name must come from the mapping that authorized THIS role, not from an
// earlier mapping that merely matched the subject. Same resolution rule as the
// session policy, and the same failure if it regresses: CloudTrail attributes
// a privileged assumption to the wrong session name.
func TestAssumeRole_SessionNameComesFromAuthorizingMapping(t *testing.T) {
	cfg := &config.Config{
		Issuers: []config.IssuerConfig{{
			Issuer:    testIssuer,
			Provider:  "github",
			Audiences: []string{"sts.amazonaws.com"},
		}},
		RoleSessionName: "global-default",
		Cache:           &config.Cache{TTL: 0},
		RoleMappings: []config.RoleMapping{
			{
				// Declared first and matches the subject, but does not grant
				// the requested role.
				Subject:         "org/repo",
				Roles:           []string{"arn:aws:iam::123456789012:role/OtherRole"},
				RoleSessionName: "wrong-name",
			},
			{
				Subject:         "org/repo",
				Roles:           []string{"arn:aws:iam::123456789012:role/MyRole"},
				RoleSessionName: "right-name",
			},
		},
	}
	require.NoError(t, cfg.Validate())

	consumer := assumeWith(t, cfg, "org/repo", "arn:aws:iam::123456789012:role/MyRole")
	assert.Equal(t, "right-name", consumer.gotSessionName,
		"session name came from a mapping that did not authorize the requested role")
}

// The audit record must report the name actually used, or CloudTrail and the
// audit trail disagree about who assumed the role.
func TestAuditRecord_ReportsSessionNameUsed(t *testing.T) {
	cfg := sessionNameCfg(t, "gha-org-repo")
	sink := &fakeAuditSink{}
	proc := handler.NewRequestProcessor(config.NewStaticProvider(cfg), mockConsumer(t),
		&fixedExtractor{claims: allowClaims("org/repo")}, sink, "test")

	_, err := proc.ProcessRequest(context.Background(),
		&handler.RequestData{Role: "arn:aws:iam::123456789012:role/MyRole"},
		validator.ExtractionInput{Token: "t"}, "req-session-name-audit", slog.Default())
	require.NoError(t, err)

	assert.Equal(t, "gha-org-repo", sink.last(t)["sessionName"])
}

// ---------- hot reload ----------

const (
	hotReloadRoleA = "arn:aws:iam::123456789012:role/RoleA"
	hotReloadRoleB = "arn:aws:iam::123456789012:role/RoleB"
)

// TestHotReload_AuthorizationDecisionFollowsRemoteConfig proves the operator
// promise that role_mappings can be changed by rewriting the remote (S3)
// config object alone — no Lambda redeploy, no cold start — and that both
// directions take effect: a newly granted role becomes assumable and a
// withdrawn role stops being assumable on the very next request.
//
// The pipeline seam under test is ProcessRequest's leading
// provider.MaybeRefresh(ctx) + single-snapshot Get(): config-level reload is
// covered by config.TestProvider_RemovedKeyDisappearsOnReload, but nothing
// asserted that a reload actually changes the authorization OUTCOME through
// the handler. Without the MaybeRefresh call site, a running Lambda would
// serve the cold-start config forever while the operator believes a
// revocation has landed.
func TestHotReload_AuthorizationDecisionFollowsRemoteConfig(t *testing.T) {
	mappings := func(role string) string {
		return fmt.Sprintf(
			`{"role_mappings":[{"subject":"org/repo","issuer":%q,"roles":[%q]}]}`,
			testIssuer, role)
	}

	// payload stands in for the S3 config object's bytes; rewriting it models an
	// operator uploading a new object version.
	var payload atomic.Pointer[string]
	v1 := mappings(hotReloadRoleA)
	payload.Store(&v1)

	base := auditTestCfg(t, false, false)
	// A 1ns interval makes every request due for a refresh, so the test does not
	// depend on wall-clock timing to observe the reload.
	provider := config.NewProvider(base, time.Nanosecond, "json", func(context.Context) ([]byte, error) {
		return []byte(*payload.Load()), nil
	})
	require.NoError(t, provider.Refresh(context.Background()))

	proc := handler.NewRequestProcessor(provider, mockConsumer(t),
		&fixedExtractor{claims: allowClaims("org/repo")}, &fakeAuditSink{}, "test")

	assume := func(role string) error {
		_, err := proc.ProcessRequest(context.Background(),
			&handler.RequestData{Role: role},
			validator.ExtractionInput{Token: "t"}, "req-hot-reload", slog.Default())
		return err
	}

	// v1: RoleA granted, RoleB unknown.
	require.NoError(t, assume(hotReloadRoleA), "RoleA is granted by the initially fetched config")
	require.Error(t, assume(hotReloadRoleB), "RoleB is not granted by the initially fetched config")

	// Operator rewrites the object: RoleA withdrawn, RoleB granted.
	v2 := mappings(hotReloadRoleB)
	payload.Store(&v2)

	err := assume(hotReloadRoleA)
	require.Error(t, err, "withdrawing RoleA in the remote config must revoke it without a redeploy")
	assert.True(t, errors.Is(err, handler.ErrRoleNotPermitted), "want ErrRoleNotPermitted, got %v", err)
	assert.NoError(t, assume(hotReloadRoleB), "granting RoleB in the remote config must take effect without a redeploy")

	// A broken object must not open anything up or take the service down: the
	// last-good config keeps being served (reload fails safe).
	broken := `{"role_mappings":[{"subject":".*","issuer":"` + testIssuer + `","roles":["` + hotReloadRoleA + `"]}]}`
	payload.Store(&broken) // bare-wildcard subject: rejected by Validate()

	assert.Error(t, assume(hotReloadRoleA),
		"a config Validate() rejects must not be applied, so RoleA stays withdrawn")
	assert.NoError(t, assume(hotReloadRoleB),
		"the last-good config keeps being served after a rejected reload")
}
