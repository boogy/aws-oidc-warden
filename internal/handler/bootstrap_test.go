package handler

// NewBootstrap wiring: the claim extractor it selects, config_fragments, and
// the JWKS warm-up.
import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/boogy/aws-oidc-warden/internal/aws"
	"github.com/boogy/aws-oidc-warden/internal/config"
	"github.com/boogy/aws-oidc-warden/internal/idp"
	"github.com/boogy/aws-oidc-warden/internal/logevent"
	s3logger "github.com/boogy/aws-oidc-warden/internal/s3logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func multiIssuerConfig(mode string) *config.Config {
	return &config.Config{
		RoleSessionName: "test",
		JWTValidation:   config.JWTValidation{Mode: mode},
		Issuers: []config.IssuerConfig{
			{
				Issuer:    "https://token.actions.githubusercontent.com",
				Provider:  "github",
				Audiences: []string{"sts.amazonaws.com"},
			},
			{
				Issuer:        "https://gitlab.com",
				Provider:      "generic",
				Audiences:     []string{"aws-oidc-warden"},
				ClaimMappings: map[string]string{"subject": "project_path"},
			},
		},
	}
}

// apigw mode gives each route its own JWT authorizer, so several configured
// issuers is a valid deployment and must not fail closed at cold start.
func TestNewClaimsExtractor_APIGWAllowsMultipleIssuers(t *testing.T) {
	ex, err := newClaimsExtractor(config.NewStaticProvider(multiIssuerConfig("apigw")), nil)
	require.NoError(t, err)
	assert.NotNil(t, ex)
}

// alb mode still trusts a single OIDC IdP, so a multi-issuer config stays
// ambiguous and must be rejected.
func TestNewClaimsExtractor_ALBStillRequiresSingleIssuer(t *testing.T) {
	cfg := multiIssuerConfig("alb")
	cfg.JWTValidation.ALBExpectedSigner = "arn:aws:elasticloadbalancing:eu-west-1:111122223333:loadbalancer/app/x/y"

	ex, err := newClaimsExtractor(config.NewStaticProvider(cfg), nil)
	require.Error(t, err)
	assert.Nil(t, ex)
	assert.Contains(t, err.Error(), "exactly one configured issuer")
}

// A single-issuer apigw config keeps working unchanged.
func TestNewClaimsExtractor_APIGWSingleIssuerStillWorks(t *testing.T) {
	cfg := multiIssuerConfig("apigw")
	cfg.Issuers = cfg.Issuers[:1]

	ex, err := newClaimsExtractor(config.NewStaticProvider(cfg), nil)
	require.NoError(t, err)
	assert.NotNil(t, ex)
}

// ---------- config fragments ----------

// fragmentTestBaseConfig returns a minimal valid config with one issuer and
// one base role mapping, listing fragmentPath under config_fragments.
func fragmentTestBaseConfig(t *testing.T, fragmentPath string) *config.Config {
	t.Helper()
	cfg := &config.Config{
		Issuers: []config.IssuerConfig{{
			Issuer:    "https://token.actions.githubusercontent.com",
			Provider:  "github",
			Audiences: []string{"sts.amazonaws.com"},
		}},
		RoleSessionName: "test-session",
		RoleMappings: []config.RoleMapping{{
			Subject: config.Patterns{"org/base-repo"},
			Roles:   []string{"arn:aws:iam::123456789012:role/BaseRole"},
		}},
	}
	if fragmentPath != "" {
		cfg.ConfigFragments = []string{fragmentPath}
	}
	require.NoError(t, cfg.Validate())
	return cfg
}

// TestBuildConfigProvider_LocalFragmentsWithoutS3Source is the regression test
// for fragments being silently dropped when no S3 config source is set: the
// provider BuildConfigProvider returns must serve a config with the fragment's
// role_mappings merged in, not the bare base config.
func TestBuildConfigProvider_LocalFragmentsWithoutS3Source(t *testing.T) {
	fragPath := filepath.Join(t.TempDir(), "team-fragment.yaml")
	require.NoError(t, os.WriteFile(fragPath, []byte(`
role_mappings:
  - subject: org/frag-repo
    roles:
      - arn:aws:iam::123456789012:role/FragmentRole
`), 0o600))

	cfg := fragmentTestBaseConfig(t, fragPath)
	require.Empty(t, cfg.S3ConfigBucket, "test premise: no S3 config source")

	provider, err := BuildConfigProvider(cfg, nil)
	require.NoError(t, err)

	served := provider.Get()

	matched, roles := served.AuthorizeRoles(
		"https://token.actions.githubusercontent.com", "org/frag-repo", nil)
	assert.True(t, matched, "fragment role_mapping must be merged and authorizable")
	assert.Contains(t, roles, "arn:aws:iam::123456789012:role/FragmentRole")

	matched, roles = served.AuthorizeRoles(
		"https://token.actions.githubusercontent.com", "org/base-repo", nil)
	assert.True(t, matched, "base role_mapping must survive the fragment merge")
	assert.Contains(t, roles, "arn:aws:iam::123456789012:role/BaseRole")
}

// TestBuildConfigProvider_NoFragmentsNoS3IsStatic pins the fast path: with
// neither an S3 source nor fragments, the provider serves the base config
// as-is.
func TestBuildConfigProvider_NoFragmentsNoS3IsStatic(t *testing.T) {
	cfg := fragmentTestBaseConfig(t, "")

	provider, err := BuildConfigProvider(cfg, nil)
	require.NoError(t, err)
	assert.Same(t, cfg, provider.Get(), "no-fragment path must serve the base config unchanged")
}

// TestBuildConfigProvider_InvalidFragmentFailsFast: a broken fragment must
// fail bootstrap (fail closed), not silently serve the base config.
func TestBuildConfigProvider_InvalidFragmentFailsFast(t *testing.T) {
	fragPath := filepath.Join(t.TempDir(), "bad-fragment.yaml")
	require.NoError(t, os.WriteFile(fragPath, []byte(`
tag_auth:
  enabled: true
`), 0o600))

	cfg := fragmentTestBaseConfig(t, fragPath)
	_, err := BuildConfigProvider(cfg, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not allowed in a config fragment")
}

// ---------- JWKS warm-up ----------

// fakeWarmer records WarmPrefetch calls and the deadline it was handed.
type fakeWarmer struct {
	calls       int
	hadDeadline bool
	deadline    time.Time
	block       time.Duration // if set, simulate a slow/hung issuer
	ctxErr      error         // context error observed when blocking ended
}

func (f *fakeWarmer) WarmPrefetch(ctx context.Context) {
	f.calls++
	f.deadline, f.hadDeadline = ctx.Deadline()
	if f.block > 0 {
		select {
		case <-ctx.Done():
			f.ctxErr = ctx.Err()
		case <-time.After(f.block):
		}
	}
}

// TestWarmJWKSCache_SelfModePrefetches is the regression test for WarmPrefetch
// being dead code: in self mode, bootstrap must actually invoke it so the first
// request doesn't pay a cold JWKS fetch.
func TestWarmJWKSCache_SelfModePrefetches(t *testing.T) {
	w := &fakeWarmer{}

	attempted := warmJWKSCache("self", w)

	assert.True(t, attempted, "self mode must attempt a warm prefetch")
	assert.Equal(t, 1, w.calls, "WarmPrefetch must be called exactly once")
}

// TestWarmJWKSCache_DelegatedModesSkip guards the gating: apigw/alb verify
// upstream and never consult JWKS, so prefetching there is wasted INIT latency.
func TestWarmJWKSCache_DelegatedModesSkip(t *testing.T) {
	for _, mode := range []string{"apigw", "alb"} {
		t.Run(mode, func(t *testing.T) {
			w := &fakeWarmer{}

			attempted := warmJWKSCache(mode, w)

			assert.False(t, attempted, "delegated mode must not prefetch")
			assert.Zero(t, w.calls, "WarmPrefetch must not be called in %s mode", mode)
		})
	}
}

// TestWarmJWKSCache_PassesBoundedContext proves the prefetch is given a
// deadline, so a slow issuer cannot consume the whole Lambda INIT budget.
func TestWarmJWKSCache_PassesBoundedContext(t *testing.T) {
	w := &fakeWarmer{}

	require.True(t, warmJWKSCache("self", w))

	require.True(t, w.hadDeadline, "prefetch context must carry a deadline")
	assert.WithinDuration(t, time.Now().Add(jwksWarmPrefetchTimeout), w.deadline, time.Second)
}

// TestWarmJWKSCache_HungIssuerDoesNotStallInit is the safety property that makes
// this change safe to run during INIT: an unreachable issuer must be abandoned
// at the timeout rather than blocking bootstrap indefinitely.
func TestWarmJWKSCache_HungIssuerDoesNotStallInit(t *testing.T) {
	w := &fakeWarmer{block: time.Minute} // issuer that never responds

	start := time.Now()
	warmJWKSCache("self", w)
	elapsed := time.Since(start)

	assert.Less(t, elapsed, jwksWarmPrefetchTimeout+2*time.Second,
		"a hung issuer must not block INIT past the timeout")
	assert.ErrorIs(t, w.ctxErr, context.DeadlineExceeded,
		"prefetch must be cancelled by the deadline, not run to completion")
}

// TestWarmJWKSCache_NilValidatorIsSafe ensures the helper cannot panic during
// bootstrap if no validator was constructed.
func TestWarmJWKSCache_NilValidatorIsSafe(t *testing.T) {
	assert.NotPanics(t, func() {
		assert.False(t, warmJWKSCache("self", nil))
	})
}

type countingS3 struct{ puts atomic.Int32 }

func (c *countingS3) PutObject(_ context.Context, _ *s3.PutObjectInput, _ ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	c.puts.Add(1)
	return &s3.PutObjectOutput{}, nil
}

func TestCleanup_FlushesBufferedAuditRecords(t *testing.T) {
	l := s3logger.NewS3Logger(&config.Config{LogToS3: true, LogBucket: "audit-bucket"})
	spy := &countingS3{}
	l.SetS3Client(spy)
	require.NoError(t, l.BufferRecord([]byte(`{"decision":"allow"}`)))
	require.Zero(t, spy.puts.Load(), "record must still be buffered before Cleanup")

	b := &Bootstrap{S3Logger: l, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	b.Cleanup()

	assert.Equal(t, int32(1), spy.puts.Load())
}

const bootstrapKMSARN = "arn:aws:kms:eu-west-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab"

func bootstrapIdPConfig(issuer string, enabled bool) *config.IdPConfig {
	return &config.IdPConfig{
		Enabled:  enabled,
		Issuer:   issuer,
		Audience: "sts.amazonaws.com",
		SigningKeys: []config.IdPSigningKey{
			{KMSKeyID: bootstrapKMSARN, Algorithm: "RS256", Status: config.IdPKeyActive},
		},
	}
}

func bootstrapBaseConfig(t *testing.T, idpCfg *config.IdPConfig) *config.Config {
	t.Helper()
	cfg := fragmentTestBaseConfig(t, "")
	cfg.IdP = idpCfg
	require.NoError(t, cfg.Validate())
	return cfg
}

func TestBootstrapIdPAbsent(t *testing.T) {
	provider := config.NewStaticProvider(bootstrapBaseConfig(t, nil))
	svc := NewIdPService(provider, func() idp.KMSAPI { t.Fatal("kms must not be used"); return nil }, nil)
	require.Nil(t, svc)
}

func TestBootstrapIdPDisabledNoKeyLoad(t *testing.T) {
	provider := config.NewStaticProvider(bootstrapBaseConfig(t, bootstrapIdPConfig("https://idp.example.com", false)))
	calls := 0
	svc := NewIdPService(provider, func() idp.KMSAPI { calls++; return nil }, nil)
	require.NotNil(t, svc)
	require.Equal(t, 0, calls)
}

type overlayConsumer struct {
	aws.AwsConsumerInterface
	overlay   []byte
	warmCalls int
	warmErr   error
}

func (c *overlayConsumer) IsTargetAccountAllowed(context.Context, string) (bool, error) {
	c.warmCalls++
	return false, c.warmErr
}

func (c *overlayConsumer) SetConfigSource(func() *config.Config) {}

func (c *overlayConsumer) GetS3Object(context.Context, string, string) (io.ReadCloser, error) {
	return io.NopCloser(bytes.NewReader(c.overlay)), nil
}

func (c *overlayConsumer) GetS3ObjectIfChanged(context.Context, string, string, string, string) ([]byte, string, error) {
	return nil, "", errors.New("not implemented")
}

func TestBootstrapIdPUsesOverlay(t *testing.T) {
	base := bootstrapBaseConfig(t, bootstrapIdPConfig("https://a.example.com", false))
	base.JWTValidation.Mode = "apigw"
	base.Cache = &config.Cache{Type: "memory", TTL: time.Hour}
	base.S3ConfigBucket, base.S3ConfigPath = "bucket", "config.yaml"
	consumer := &overlayConsumer{overlay: []byte("idp:\n  issuer: https://b.example.com\n")}

	var buf bytes.Buffer
	logger := slog.New(logevent.NewHandler(slog.NewJSONHandler(&buf, nil)))
	b, err := newBootstrap("test", logger, base, consumer, func() idp.KMSAPI { return nil })
	require.NoError(t, err)
	require.NotNil(t, b.IdP)
	require.Equal(t, "https://b.example.com", b.IdP.Config().Issuer)
	require.Equal(t, "https://b.example.com/.well-known/jwks.json", b.IdP.Config().JWKSURI)

	r := NewRequestProcessor(b.Provider, nil, nil, nil, "test").WithIdP(b.IdP)
	r.warnFrozenDrift(context.Background(), logger, b.Provider.Get())
	require.Equal(t, 0, strings.Count(buf.String(), "config.idp.reload_ignored"))
	require.Equal(t, 1, consumer.warmCalls, "STS caller identity is warmed once at cold start")
}

func TestBootstrapWarmCallerIdentityNeverFailsBootstrap(t *testing.T) {
	tests := []struct {
		name     string
		warmErr  error
		wantWarn int
	}{
		{"warm succeeds", nil, 0},
		{"warm fails", errors.New("sts unreachable"), 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			base := bootstrapBaseConfig(t, bootstrapIdPConfig("https://a.example.com", false))
			base.JWTValidation.Mode = "apigw"
			base.Cache = &config.Cache{Type: "memory", TTL: time.Hour}
			base.S3ConfigBucket, base.S3ConfigPath = "bucket", "config.yaml"
			consumer := &overlayConsumer{overlay: []byte("{}"), warmErr: tt.warmErr}

			var buf bytes.Buffer
			logger := slog.New(logevent.NewHandler(slog.NewJSONHandler(&buf, nil)))
			b, err := newBootstrap("test", logger, base, consumer, func() idp.KMSAPI { return nil })
			require.NoError(t, err)
			require.NotNil(t, b)
			assert.Equal(t, 1, consumer.warmCalls)
			assert.Equal(t, tt.wantWarn, strings.Count(buf.String(), `"eventType":"app.warm.failure"`))
		})
	}
}

func TestBootstrapAdaptersAttachIdP(t *testing.T) {
	svc := idp.NewService(*bootstrapIdPConfig("https://idp.example.com", false), nil)
	tests := []struct {
		name  string
		mode  string
		build func(*Bootstrap) *RequestProcessor
	}{
		{"apigateway", "self", func(b *Bootstrap) *RequestProcessor { return NewAwsApiGatewayFromBootstrap(b).processor }},
		{"lambdaurl", "self", func(b *Bootstrap) *RequestProcessor { return NewAwsLambdaUrlFromBootstrap(b).processor }},
		{"alb", "self", func(b *Bootstrap) *RequestProcessor { return NewAwsApplicationLoadBalancerFromBootstrap(b).processor }},
		{"apigatewayv2", "apigw", func(b *Bootstrap) *RequestProcessor { return NewAwsApiGatewayV2FromBootstrap(b).processor }},
	}
	for _, tt := range tests {
		for _, withIdP := range []bool{true, false} {
			t.Run(fmt.Sprintf("%s/idp=%t", tt.name, withIdP), func(t *testing.T) {
				cfg := &config.Config{JWTValidation: config.JWTValidation{Mode: tt.mode}}
				b := &Bootstrap{Config: cfg, Provider: config.NewStaticProvider(cfg), Adapter: tt.name}
				if withIdP {
					b.IdP = svc
				}
				got := tt.build(b).idp
				if withIdP {
					require.Same(t, svc, got)
				} else {
					require.Nil(t, got)
				}
			})
		}
	}
}

func TestWarnFrozenDriftOnRemovedIdPBlock(t *testing.T) {
	svc := idp.NewService(*bootstrapIdPConfig("https://idp.example.com", false), nil)
	var buf bytes.Buffer
	logger := slog.New(logevent.NewHandler(slog.NewJSONHandler(&buf, nil)))

	r := NewRequestProcessor(nil, nil, nil, nil, "test").WithIdP(svc)
	r.warnFrozenDrift(context.Background(), logger, bootstrapBaseConfig(t, nil))
	assert.Equal(t, 1, strings.Count(buf.String(), "config.idp.reload_ignored"))

	buf.Reset()
	NewRequestProcessor(nil, nil, nil, nil, "test").warnFrozenDrift(context.Background(), logger, bootstrapBaseConfig(t, nil))
	assert.Zero(t, strings.Count(buf.String(), "config.idp.reload_ignored"))
}

type etagOverlayConsumer struct {
	aws.AwsConsumerInterface
	prevETags []string
}

func (c *etagOverlayConsumer) GetS3ObjectIfChanged(_ context.Context, _, _, prevETag, _ string) ([]byte, string, error) {
	c.prevETags = append(c.prevETags, prevETag)
	if prevETag == `"e1"` {
		return nil, prevETag, nil
	}
	return []byte("log_claim_values: true\n"), `"e1"`, nil
}

func TestOverlayFetchUsesConditionalGet(t *testing.T) {
	base := bootstrapBaseConfig(t, nil)
	base.S3ConfigBucket, base.S3ConfigPath, base.S3ConfigBucketOwner = "bucket", "config.yaml", "123456789012"
	consumer := &etagOverlayConsumer{}

	p, err := BuildConfigProvider(base, consumer)
	require.NoError(t, err)
	require.NoError(t, p.Refresh(context.Background()))

	assert.Equal(t, []string{"", `"e1"`}, consumer.prevETags)
	assert.True(t, p.Get().LogClaimValues, "an unchanged overlay must still be applied")
}
