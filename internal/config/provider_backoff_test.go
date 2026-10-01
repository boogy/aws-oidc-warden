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
	p.mu.Lock()
	done := make(chan struct{})
	go func() { p.MaybeRefresh(context.Background()); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("MaybeRefresh blocked")
	}
	p.mu.Unlock()
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
