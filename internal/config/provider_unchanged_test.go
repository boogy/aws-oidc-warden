package config

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const unchangedFragURI = "s3://bucket/frag.yaml"

const unchangedFragV1 = `
role_mappings:
  - subject: "owner/v1"
    roles: ["arn:aws:iam::111111111111:role/v1"]
`

// unchangedProvider wires a Provider with a mutable overlay and one remote fragment.
type unchangedProvider struct {
	*Provider
	store   *fakeFragmentStore
	overlay atomic.Value // []byte
	fetches atomic.Int32
	clock   atomic.Int64
}

func newUnchangedProvider(t *testing.T) *unchangedProvider {
	t.Helper()
	u := &unchangedProvider{store: newFakeFragmentStore()}
	u.store.set(unchangedFragURI, []byte(unchangedFragV1))
	u.overlay.Store([]byte("log_level: info\n"))

	base := baseConfig(t)
	base.ConfigFragments = []string{unchangedFragURI}
	require.NoError(t, base.Validate())

	u.Provider = NewProvider(base, time.Minute, "yaml", func(context.Context) ([]byte, error) {
		u.fetches.Add(1)
		return u.overlay.Load().([]byte), nil
	}, WithFragmentFetcher(u.store.fetch))
	u.clock.Store(time.Unix(1000, 0).UnixNano())
	u.now = func() time.Time { return time.Unix(0, u.clock.Load()) }
	require.NoError(t, u.Refresh(context.Background()))
	return u
}

func TestProviderRefresh_UnchangedKeepsConfig(t *testing.T) {
	u := newUnchangedProvider(t)
	first := u.Get()
	require.Len(t, first.RoleMappings, 1)
	before := u.lastRefresh.Load()

	u.clock.Add(int64(time.Minute))
	require.NoError(t, u.Refresh(context.Background()))

	assert.Same(t, first, u.Get(), "nothing changed: the Config must not be rebuilt")
	assert.Greater(t, u.lastRefresh.Load(), before, "an unchanged refresh still counts as fresh")
	assert.Equal(t, int32(0), u.failures.Load())
	assert.Equal(t, 1, u.store.fetches[unchangedFragURI], "unchanged fragment body is not re-downloaded")
	assert.Equal(t, 2, u.store.checks[unchangedFragURI], "the fragment etag is still probed")
}

func TestProviderRefresh_ChangedInputsRebuild(t *testing.T) {
	tests := []struct {
		name   string
		change func(u *unchangedProvider)
		verify func(t *testing.T, cfg *Config)
	}{
		{
			"overlay",
			func(u *unchangedProvider) { u.overlay.Store([]byte("log_level: debug\n")) },
			func(t *testing.T, cfg *Config) { assert.Equal(t, "debug", cfg.LogLevel) },
		},
		{
			"fragment",
			func(u *unchangedProvider) {
				u.store.set(unchangedFragURI, []byte(`
role_mappings:
  - subject: "owner/v2"
    roles: ["arn:aws:iam::111111111111:role/v2"]
`))
			},
			func(t *testing.T, cfg *Config) {
				require.Len(t, cfg.RoleMappings, 1)
				assert.Equal(t, Patterns{"owner/v2"}, cfg.RoleMappings[0].Subject)
			},
		},
		{
			"base",
			func(u *unchangedProvider) { u.base.RoleSessionName = "another-name" },
			func(t *testing.T, cfg *Config) { assert.Equal(t, "another-name", cfg.RoleSessionName) },
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			u := newUnchangedProvider(t)
			first := u.Get()
			tc.change(u)
			u.clock.Add(int64(time.Minute))
			require.NoError(t, u.Refresh(context.Background()))
			assert.NotSame(t, first, u.Get())
			tc.verify(t, u.Get())
		})
	}
}

// A pin rotated away from an unchanged fragment must fail even on the skip path.
func TestProviderRefresh_UnchangedStillEnforcesPins(t *testing.T) {
	u := newUnchangedProvider(t)
	first := u.Get()

	u.base.ConfigFragmentChecksums = []FragmentChecksum{{URI: unchangedFragURI, Checksum: "sha256:deadbeef"}}
	u.clock.Add(int64(time.Minute))
	err := u.Refresh(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "integrity")
	assert.Same(t, first, u.Get())
}

func TestProviderRefresh_FailedFetchAfterUnchangedStillFails(t *testing.T) {
	u := newUnchangedProvider(t)
	u.store.delete(unchangedFragURI)
	u.clock.Add(int64(time.Minute))
	require.Error(t, u.Refresh(context.Background()))
}

func TestProviderRefresh_UnchangedRaceSafe(t *testing.T) {
	u := newUnchangedProvider(t)
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 50 {
				u.clock.Add(int64(time.Minute))
				u.MaybeRefresh(context.Background())
				_ = u.Get().RoleMappings
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := range 20 {
			if i%2 == 0 {
				u.overlay.Store([]byte("log_level: debug\n"))
			} else {
				u.overlay.Store([]byte("log_level: info\n"))
			}
			_ = u.Refresh(context.Background())
		}
	}()
	wg.Wait()
}
