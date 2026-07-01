package config

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// baseConfig returns a minimal valid base config (as produced by env/file/defaults).
func baseConfig(t *testing.T) *Config {
	t.Helper()
	c := &Config{
		Issuers:         singleIssuer("https://token.actions.githubusercontent.com", "sts.amazonaws.com"),
		RoleSessionName: "aws-oidc-warden",
		Cache:           &Cache{Type: "memory", TTL: time.Hour},
	}
	require.NoError(t, c.Validate())
	return c
}

func TestStaticProvider_NeverRefreshes(t *testing.T) {
	base := baseConfig(t)
	p := NewStaticProvider(base)

	assert.Same(t, base, p.Get())
	// MaybeRefresh must be a no-op (no fetch, interval 0).
	p.MaybeRefresh(context.Background())
	assert.Same(t, base, p.Get())
}

func TestProvider_RefreshOverlaysAndCompiles(t *testing.T) {
	base := baseConfig(t)

	yamlCfg := []byte(`
repo_role_mappings:
  - repo: "owner/.*"
    roles:
      - "arn:aws:iam::123456789012:role/ci"
    constraints:
      branch: "main"
`)
	p := NewProvider(base, time.Minute, "yaml", func(context.Context) ([]byte, error) {
		return yamlCfg, nil
	})

	require.NoError(t, p.Refresh(context.Background()))

	cfg := p.Get()
	require.Len(t, cfg.RepoRoleMappings, 1)

	// The overlaid mapping's regex pattern must be compiled (the bug fix:
	// otherwise MatchRolesToRepo skips nil-pattern mappings).
	matched, roles := cfg.MatchRolesToRepo("owner/repo")
	assert.True(t, matched)
	assert.Equal(t, []string{"arn:aws:iam::123456789012:role/ci"}, roles)

	// Base scalars not present in the overlay are preserved.
	assert.Equal(t, base.Issuers, cfg.Issuers)
	assert.Equal(t, "aws-oidc-warden", cfg.RoleSessionName)
}

func TestProvider_RemovedKeyDisappearsOnReload(t *testing.T) {
	base := baseConfig(t)

	withMapping := []byte(`
repo_role_mappings:
  - repo: "owner/.*"
    roles: ["arn:aws:iam::123456789012:role/ci"]
`)
	empty := []byte(`{}`)

	var payload atomic.Value
	payload.Store(withMapping)

	p := NewProvider(base, time.Minute, "yaml", func(context.Context) ([]byte, error) {
		return payload.Load().([]byte), nil
	})

	require.NoError(t, p.Refresh(context.Background()))
	require.Len(t, p.Get().RepoRoleMappings, 1)

	// A newer payload omits the mapping; cloning from the pristine base means
	// the stale mapping must not persist.
	payload.Store(empty)
	require.NoError(t, p.Refresh(context.Background()))
	assert.Empty(t, p.Get().RepoRoleMappings)
}

func TestProvider_MaybeRefreshRespectsInterval(t *testing.T) {
	base := baseConfig(t)

	var calls int32
	now := time.Unix(1_000_000, 0)
	p := NewProvider(base, time.Minute, "yaml", func(context.Context) ([]byte, error) {
		atomic.AddInt32(&calls, 1)
		return []byte(`{}`), nil
	})
	p.now = func() time.Time { return now }

	// First call refreshes (lastRefresh == 0).
	p.MaybeRefresh(context.Background())
	assert.Equal(t, int32(1), atomic.LoadInt32(&calls))

	// Within the interval: no refetch.
	now = now.Add(30 * time.Second)
	p.MaybeRefresh(context.Background())
	assert.Equal(t, int32(1), atomic.LoadInt32(&calls))

	// After the interval elapses: refetch.
	now = now.Add(40 * time.Second)
	p.MaybeRefresh(context.Background())
	assert.Equal(t, int32(2), atomic.LoadInt32(&calls))
}

func TestProvider_RefreshErrorKeepsPreviousConfig(t *testing.T) {
	base := baseConfig(t)

	good := []byte(`
repo_role_mappings:
  - repo: "owner/.*"
    roles: ["arn:aws:iam::123456789012:role/ci"]
`)

	var fail atomic.Bool
	p := NewProvider(base, time.Minute, "yaml", func(context.Context) ([]byte, error) {
		if fail.Load() {
			return nil, errors.New("s3 unavailable")
		}
		return good, nil
	})

	require.NoError(t, p.Refresh(context.Background()))
	prev := p.Get()
	require.Len(t, prev.RepoRoleMappings, 1)

	// Fetch failure: MaybeRefresh logs and keeps the previous config.
	fail.Store(true)
	p.now = func() time.Time { return time.Unix(2_000_000, 0) } // force interval elapsed
	p.MaybeRefresh(context.Background())
	assert.Same(t, prev, p.Get())

	// Invalid config (missing required fields would fail Validate) also keeps previous.
	require.Error(t, p.Refresh(context.Background()))
	assert.Same(t, prev, p.Get())
}

func TestProvider_RefreshRejectsInvalidConfig(t *testing.T) {
	base := baseConfig(t)

	// A mapping missing roles fails Validate().
	bad := []byte(`
repo_role_mappings:
  - repo: "owner/.*"
`)
	p := NewProvider(base, time.Minute, "yaml", func(context.Context) ([]byte, error) {
		return bad, nil
	})

	err := p.Refresh(context.Background())
	require.Error(t, err)
	// Active config remains the base.
	assert.Same(t, base, p.Get())
}

func TestProvider_MaybeRefreshNoConcurrentBurst(t *testing.T) {
	base := baseConfig(t)
	var calls atomic.Int32
	now := time.Unix(2_000_000, 0)

	p := NewProvider(base, time.Minute, "yaml", func(context.Context) ([]byte, error) {
		calls.Add(1)
		return []byte(`{}`), nil
	})
	p.now = func() time.Time { return now }

	// Prime lastRefresh so the interval guard is active.
	p.MaybeRefresh(context.Background())
	require.Equal(t, int32(1), calls.Load())

	// Advance past the interval so all goroutines would pass the fast-path check.
	now = now.Add(2 * time.Minute)

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p.MaybeRefresh(context.Background())
		}()
	}
	wg.Wait()

	// Only one additional fetch should have occurred despite 50 concurrent calls.
	assert.Equal(t, int32(2), calls.Load())
}

func TestProvider_ReloadIntervalUpdatedFromS3Config(t *testing.T) {
	base := baseConfig(t)

	// S3 config changes config_reload_interval to 5 minutes.
	payload := []byte("config_reload_interval: 5m")
	p := NewProvider(base, time.Minute, "yaml", func(context.Context) ([]byte, error) {
		return payload, nil
	})

	require.NoError(t, p.Refresh(context.Background()))

	// After reload the effective interval should be 5 minutes.
	assert.Equal(t, 5*time.Minute, time.Duration(p.IntervalForTest()))
}
