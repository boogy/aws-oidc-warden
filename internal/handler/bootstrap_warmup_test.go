package handler

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
