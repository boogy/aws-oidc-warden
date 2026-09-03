package handler

// NewBootstrap wiring: the claim extractor it selects, config_fragments, and
// the JWKS warm-up.
import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/boogy/aws-oidc-warden/internal/config"
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
// provider buildConfigProvider returns must serve a config with the fragment's
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

	provider, err := buildConfigProvider(cfg, nil)
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

	provider, err := buildConfigProvider(cfg, nil)
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
	_, err := buildConfigProvider(cfg, nil)
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
