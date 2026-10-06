package config

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type backoffFixture struct {
	p     *Provider
	calls atomic.Int32
	fail  atomic.Bool
	now   time.Time
}

func newBackoffFixture(t *testing.T, failing bool) *backoffFixture {
	t.Helper()
	f := &backoffFixture{now: time.Unix(1_700_000_000, 0)}
	f.fail.Store(failing)
	f.p = NewProvider(baseConfig(t), time.Minute, "yaml", func(context.Context) ([]byte, error) {
		f.calls.Add(1)
		if f.fail.Load() {
			return nil, errors.New("boom")
		}
		return []byte(`{}`), nil
	})
	f.p.now = func() time.Time { return f.now }
	return f
}

func (f *backoffFixture) step(d time.Duration) int32 {
	f.now = f.now.Add(d)
	f.p.MaybeRefresh(context.Background())
	return f.calls.Load()
}

func TestProviderBackoffFailedFetchNotRetriedPerRequest(t *testing.T) {
	f := newBackoffFixture(t, true)
	for i := 0; i < 50; i++ {
		f.p.MaybeRefresh(context.Background())
	}
	assert.Equal(t, int32(1), f.calls.Load())
}

func TestProviderBackoffGrowsExponentially(t *testing.T) {
	f := newBackoffFixture(t, true)
	f.p.MaybeRefresh(context.Background())
	steps := []struct {
		name string
		by   time.Duration
		want int32
	}{
		{"1m: inside 2m window", time.Minute, 1},
		{"2m: attempt 2", time.Minute, 2},
		{"3m after attempt 2: inside 4m window", 3 * time.Minute, 2},
		{"4m: attempt 3", time.Minute, 3},
		{"7m after attempt 3: inside 8m window", 7 * time.Minute, 3},
		{"8m: attempt 4", time.Minute, 4},
		{"7m after attempt 4: inside 8m cap", 7 * time.Minute, 4},
		{"8m: attempt 5 (never 16m)", time.Minute, 5},
	}
	for _, s := range steps {
		assert.Equal(t, s.want, f.step(s.by), s.name)
	}
}

func TestProviderBackoffResetsOnSuccess(t *testing.T) {
	f := newBackoffFixture(t, true)
	f.p.MaybeRefresh(context.Background())
	assert.Equal(t, int32(2), f.step(2*time.Minute))
	f.fail.Store(false)
	assert.Equal(t, int32(2), f.step(3*time.Minute), "inside 4m window")
	assert.Equal(t, int32(3), f.step(time.Minute), "success")
	assert.Zero(t, f.p.failures.Load())
	assert.Equal(t, int32(3), f.step(30*time.Second))
	assert.Equal(t, int32(4), f.step(30*time.Second), "back to 1m window")
}

func TestProviderBackoffNeverBlocksRequests(t *testing.T) {
	var calls atomic.Int32
	p := NewProvider(baseConfig(t), time.Minute, "yaml", func(context.Context) ([]byte, error) {
		calls.Add(1)
		return []byte(`{}`), nil
	})
	p.lock()
	done := make(chan struct{})
	go func() { p.MaybeRefresh(context.Background()); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("MaybeRefresh blocked")
	}
	p.unlock()
	assert.Zero(t, calls.Load())
}

func TestProviderBackoffKeepsLastGoodConfig(t *testing.T) {
	f := newBackoffFixture(t, false)
	f.p.MaybeRefresh(context.Background())
	good := f.p.Get()
	f.fail.Store(true)
	f.step(time.Minute)
	f.step(2 * time.Minute)
	assert.Equal(t, int32(3), f.calls.Load())
	assert.Same(t, good, f.p.Get())
}

func TestProviderBackoffDoesNotAffectStale(t *testing.T) {
	c, st := s3MappingsCfg(t, time.Minute)
	d := 10 * time.Minute
	c.MappingsMaxStale = &d
	p := NewProvider(c, time.Minute, "yaml", nil, WithFragmentFetcher(st.fetch))
	now := time.Unix(1_700_000_000, 0)
	p.now = func() time.Time { return now }
	ctx := context.Background()

	p.MaybeRefresh(ctx)
	require.NotZero(t, p.lastRefresh.Load())
	st.delete(c.MappingsFile)
	now = now.Add(5 * time.Minute)
	p.MaybeRefresh(ctx)
	require.Equal(t, int32(1), p.failures.Load())

	age, _, stale := p.Stale()
	assert.Equal(t, 5*time.Minute, age)
	assert.False(t, stale)
}

func TestProviderBackoffExplicitRefreshIgnoresBackoff(t *testing.T) {
	f := newBackoffFixture(t, true)
	f.p.MaybeRefresh(context.Background())
	require.Error(t, f.p.Refresh(context.Background()))
	assert.Equal(t, int32(2), f.calls.Load())
}

func TestProviderBackoffColdStartRefreshCountsAsAttempt(t *testing.T) {
	f := newBackoffFixture(t, false)
	require.NoError(t, f.p.Refresh(context.Background()))
	f.p.MaybeRefresh(context.Background())
	assert.Equal(t, int32(1), f.calls.Load())
}

func TestProviderBackoffDisabledWhenStale(t *testing.T) {
	c, st := s3MappingsCfg(t, time.Minute)
	d := 10 * time.Minute
	c.MappingsMaxStale = &d
	st.delete(c.MappingsFile)
	p := NewProvider(c, time.Minute, "yaml", nil, WithFragmentFetcher(st.fetch))
	now := time.Unix(1_700_000_000, 0)
	p.now = func() time.Time { return now }
	ctx := context.Background()

	_, _, stale := p.Stale()
	require.True(t, stale)
	for i, by := range []time.Duration{0, time.Minute, time.Minute, time.Minute} {
		now = now.Add(by)
		p.MaybeRefresh(ctx)
		assert.Equal(t, i+1, st.checks[c.MappingsFile], "attempt %d", i+1)
	}
}

func TestProviderStaleRetriesBeforeFullInterval(t *testing.T) {
	c, st := s3MappingsCfg(t, time.Minute)
	d := 10 * time.Minute
	c.MappingsMaxStale = &d
	st.delete(c.MappingsFile)
	p := NewProvider(c, time.Minute, "yaml", nil, WithFragmentFetcher(st.fetch))
	now := time.Unix(1_700_000_000, 0)
	p.now = func() time.Time { return now }
	ctx := context.Background()

	p.MaybeRefresh(ctx)
	require.Equal(t, 1, st.checks[c.MappingsFile])

	now = now.Add(staleRetryInterval - time.Second)
	p.MaybeRefresh(ctx)
	assert.Equal(t, 1, st.checks[c.MappingsFile], "retried before staleRetryInterval")

	now = now.Add(time.Second)
	p.MaybeRefresh(ctx)
	assert.Equal(t, 2, st.checks[c.MappingsFile], "not retried after staleRetryInterval")
}

func staleMappingsProvider(t *testing.T, calls *atomic.Int32) *Provider {
	t.Helper()
	c, st := s3MappingsCfg(t, time.Minute)
	fetch := func(ctx context.Context, uri, prevETag, owner string) ([]byte, string, error) {
		calls.Add(1)
		if err := ctx.Err(); err != nil {
			return nil, "", err
		}
		return st.fetch(ctx, uri, prevETag, owner)
	}
	p := NewProvider(c, time.Minute, "yaml", nil, WithFragmentFetcher(fetch))
	_, _, stale := p.Stale()
	require.True(t, stale)
	return p
}

func TestProviderStaleWaitsForHeldRefreshLock(t *testing.T) {
	var calls atomic.Int32
	p := staleMappingsProvider(t, &calls)
	p.lock()
	done := make(chan struct{})
	go func() { p.MaybeRefresh(context.Background()); close(done) }()
	select {
	case <-done:
		t.Fatal("stale MaybeRefresh returned without waiting for the refresh lock")
	case <-time.After(50 * time.Millisecond):
	}
	require.NoError(t, p.attemptLocked(context.Background(), false))
	p.unlock()
	<-done
	assert.Equal(t, int32(1), calls.Load(), "waiter reuses the holder's refresh")
}

func TestProviderStaleWaitEndsWithCallerContext(t *testing.T) {
	p := staleMappingsProvider(t, new(atomic.Int32))
	p.lock()
	defer p.unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	p.MaybeRefresh(ctx)
	assert.ErrorIs(t, ctx.Err(), context.DeadlineExceeded)
}

func TestProviderRefreshOutlivesCallerCancellation(t *testing.T) {
	var calls atomic.Int32
	p := staleMappingsProvider(t, &calls)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	p.MaybeRefresh(ctx)
	require.Zero(t, p.failures.Load())
	_, _, stale := p.Stale()
	require.False(t, stale)

	p.MaybeRefresh(ctx)
	assert.Equal(t, int32(1), calls.Load(), "a disconnecting caller cannot bypass the reload interval")
}

func TestProviderCancelledRefreshIsNotAFailure(t *testing.T) {
	p := NewProvider(baseConfig(t), time.Minute, "yaml", func(ctx context.Context) ([]byte, error) { return nil, ctx.Err() })
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	require.ErrorIs(t, p.Refresh(ctx), context.Canceled)
	assert.Zero(t, p.failures.Load())
	assert.NotZero(t, p.lastAttempt.Load())
}

func TestProviderRefreshIfDueDoesNotWaitWhileStale(t *testing.T) {
	var calls atomic.Int32
	p := staleMappingsProvider(t, &calls)
	p.lock()
	defer p.unlock()
	p.RefreshIfDue(context.Background())
	assert.Zero(t, calls.Load())
}

func TestProviderCallerDeadlineRefreshIsNotAFailure(t *testing.T) {
	var calls atomic.Int32
	p := NewProvider(baseConfig(t), time.Minute, "yaml", func(ctx context.Context) ([]byte, error) {
		calls.Add(1)
		<-ctx.Done()
		return nil, ctx.Err()
	})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	p.MaybeRefresh(ctx)
	require.Zero(t, p.failures.Load())

	p.MaybeRefresh(context.Background())
	assert.Equal(t, int32(1), calls.Load(), "a hung source is retried per interval, not per request")
}

func TestProviderStaleWaitIsCapped(t *testing.T) {
	prev := staleWaitTimeout
	staleWaitTimeout = 20 * time.Millisecond
	t.Cleanup(func() { staleWaitTimeout = prev })

	p := staleMappingsProvider(t, new(atomic.Int32))
	p.lock()
	defer p.unlock()
	done := make(chan struct{})
	go func() { p.MaybeRefresh(context.Background()); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("stale MaybeRefresh waited past staleWaitTimeout")
	}
}
