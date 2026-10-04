package handler_test

import (
	"bytes"
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/boogy/aws-oidc-warden/internal/config"
	"github.com/boogy/aws-oidc-warden/internal/handler"
	"github.com/boogy/aws-oidc-warden/internal/idp/idptest"
	"github.com/boogy/aws-oidc-warden/internal/types"
	"github.com/boogy/aws-oidc-warden/internal/validator"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const staleMappingsBody = "role_mappings:\n  - subject: org/repo\n    idp_token: true\n    roles: [\"" + testRoleARN + "\"]\n"

type countingExtractor struct {
	inner validator.ClaimsExtractorInterface
	calls atomic.Int32
}

func (c *countingExtractor) Extract(ctx context.Context, in validator.ExtractionInput) (*types.Claims, error) {
	c.calls.Add(1)
	return c.inner.Extract(ctx, in)
}

// staleProvider returns a provider whose mappings came from a fetcher that can be switched to failing.
func staleProvider(t *testing.T, maxStale *time.Duration) (*config.Provider, *atomic.Bool) {
	t.Helper()
	cfg := idpConfig(t, true, "", func(c *config.Config) {
		c.RoleMappings = nil
		c.MappingsFile = "s3://b/m.yaml"
		c.S3ConfigBucketOwner = "123456789012"
		c.ConfigReloadInterval = 10 * time.Millisecond
		c.MappingsMaxStale = maxStale
	})
	var fail atomic.Bool
	fn := func(context.Context, string, string, string) ([]byte, string, error) {
		if fail.Load() {
			return nil, "", errors.New("s3 unavailable")
		}
		return []byte(staleMappingsBody), "sha256:fixed", nil
	}
	p := config.NewProvider(cfg, cfg.ConfigReloadInterval, "", nil, config.WithFragmentFetcher(fn))
	require.NoError(t, p.Refresh(context.Background()))
	return p, &fail
}

func staleProcessor(t *testing.T, p *config.Provider, cons *fakeConsumer, ext *countingExtractor) (*handler.RequestProcessor, *fakeAuditSink) {
	t.Helper()
	sink := &fakeAuditSink{}
	signer := &countingSigner{Signer: idptest.NewSigner(t)}
	proc := handler.NewRequestProcessor(p, cons, ext, sink, "apigatewayv2").
		WithIdP(idpService(t, p.Get(), signer, nil))
	return proc, sink
}

func TestConfigStaleDeniesRequest(t *testing.T) {
	p, fail := staleProvider(t, new(20*time.Millisecond))
	cons := mockConsumer(t)
	ext := &countingExtractor{inner: idpClaims(nil)}
	proc, sink := staleProcessor(t, p, cons, ext)

	fail.Store(true)
	time.Sleep(50 * time.Millisecond)

	_, err := proc.ProcessRequest(context.Background(), &handler.RequestData{Token: "t", Role: testRoleARN},
		validator.ExtractionInput{Token: "t"}, "req-1", idpLogger(&bytes.Buffer{}))

	require.ErrorIs(t, err, handler.ErrConfigStale)
	assert.Zero(t, ext.calls.Load())
	assert.Zero(t, cons.assumeCalls)
	rec := sink.last(t)
	assert.Equal(t, "deny", rec["decision"])
	assert.Equal(t, "config", rec["stage"])
}

func TestConfigStaleDeniesMint(t *testing.T) {
	p, fail := staleProvider(t, new(20*time.Millisecond))
	cons := mockConsumer(t)
	ext := &countingExtractor{inner: idpClaims(nil)}
	proc, sink := staleProcessor(t, p, cons, ext)

	fail.Store(true)
	time.Sleep(50 * time.Millisecond)

	_, err := mint(t, proc, handler.RequestData{}, &bytes.Buffer{})

	require.ErrorIs(t, err, handler.ErrConfigStale)
	assert.Zero(t, ext.calls.Load())
	assert.Zero(t, cons.wiCalls)
	rec := sink.last(t)
	assert.Equal(t, "deny", rec["decision"])
	assert.Equal(t, "config", rec["stage"])
}

func TestConfigStaleNotAppliedToFreshOrDisabled(t *testing.T) {
	tests := []struct {
		name     string
		maxStale time.Duration
		failed   bool
	}{
		{"fresh", time.Hour, false},
		{"max_stale_disabled", 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, fail := staleProvider(t, &tt.maxStale)
			cons := mockConsumer(t)
			ext := &countingExtractor{inner: idpClaims(nil)}
			proc, _ := staleProcessor(t, p, cons, ext)

			fail.Store(tt.failed)
			time.Sleep(50 * time.Millisecond)

			_, err := proc.ProcessRequest(context.Background(), &handler.RequestData{Token: "t", Role: testRoleARN},
				validator.ExtractionInput{Token: "t"}, "req-1", idpLogger(&bytes.Buffer{}))

			assert.NotErrorIs(t, err, handler.ErrConfigStale)
			assert.Equal(t, int32(1), ext.calls.Load())
		})
	}
}
