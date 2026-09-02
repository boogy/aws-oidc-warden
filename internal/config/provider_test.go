package config

// The remote config Provider: lazy refresh, the atomic swap from a pristine
// base, what a failed or invalid fetch must leave in place, and the same
// again with config_fragments layered on top.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
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
role_mappings:
  - subject: "owner/.*"
    roles:
      - "arn:aws:iam::123456789012:role/ci"
    conditions:
      ref: "refs/heads/main"
`)
	p := NewProvider(base, time.Minute, "yaml", func(context.Context) ([]byte, error) {
		return yamlCfg, nil
	})

	require.NoError(t, p.Refresh(context.Background()))

	cfg := p.Get()
	require.Len(t, cfg.RoleMappings, 1)

	// The overlaid mapping's regex pattern must be compiled (the bug fix:
	// otherwise AuthorizeRoles skips nil-pattern mappings).
	matched, roles := cfg.AuthorizeRoles(base.Issuers[0].Issuer, "owner/repo", map[string]any{"ref": "refs/heads/main"})
	assert.True(t, matched)
	assert.Equal(t, []string{"arn:aws:iam::123456789012:role/ci"}, roles)

	// Base scalars not present in the overlay are preserved.
	assert.Equal(t, base.Issuers, cfg.Issuers)
	assert.Equal(t, "aws-oidc-warden", cfg.RoleSessionName)
}

func TestProvider_RemovedKeyDisappearsOnReload(t *testing.T) {
	base := baseConfig(t)

	withMapping := []byte(`
role_mappings:
  - subject: "owner/.*"
    roles: ["arn:aws:iam::123456789012:role/ci"]
`)
	empty := []byte(`{}`)

	var payload atomic.Value
	payload.Store(withMapping)

	p := NewProvider(base, time.Minute, "yaml", func(context.Context) ([]byte, error) {
		return payload.Load().([]byte), nil
	})

	require.NoError(t, p.Refresh(context.Background()))
	require.Len(t, p.Get().RoleMappings, 1)

	// A newer payload omits the mapping; cloning from the pristine base means
	// the stale mapping must not persist.
	payload.Store(empty)
	require.NoError(t, p.Refresh(context.Background()))
	assert.Empty(t, p.Get().RoleMappings)
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
role_mappings:
  - subject: "owner/.*"
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
	require.Len(t, prev.RoleMappings, 1)

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
role_mappings:
  - subject: "owner/.*"
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

// ---------- fragments ----------

// fakeFragmentStore is a minimal in-memory FragmentFetchFunc backend for
// tests, mimicking an S3-HeadObject-then-conditional-GetObject fetcher: it
// signals "unchanged" (nil data) when the caller's prevETag already matches.
type fakeFragmentStore struct {
	mu      sync.Mutex
	data    map[string][]byte
	fetches map[string]int // count of full-body fetches (i.e. content actually returned)
	checks  map[string]int // count of fetch() invocations, changed or not
}

func newFakeFragmentStore() *fakeFragmentStore {
	return &fakeFragmentStore{
		data:    make(map[string][]byte),
		fetches: make(map[string]int),
		checks:  make(map[string]int),
	}
}

func (s *fakeFragmentStore) set(uri string, content []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[uri] = content
}

func (s *fakeFragmentStore) delete(uri string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.data, uri)
}

func etagOf(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func (s *fakeFragmentStore) fetch(_ context.Context, uri, prevETag string) ([]byte, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.checks[uri]++

	content, ok := s.data[uri]
	if !ok {
		return nil, "", fmt.Errorf("fake fragment store: %q not found", uri)
	}
	etag := etagOf(content)
	if etag == prevETag {
		return nil, etag, nil // cheap "unchanged" path, like an S3 HeadObject match
	}
	s.fetches[uri]++
	return content, etag, nil
}

func noopBaseFetch(context.Context) ([]byte, error) { return []byte(`{}`), nil }

func TestProvider_FragmentsMergeDeterministically(t *testing.T) {
	dir := t.TempDir()
	frag1 := filepath.Join(dir, "frag1.yaml")
	frag2 := filepath.Join(dir, "frag2.yaml")
	require.NoError(t, os.WriteFile(frag1, []byte(`
role_mappings:
  - subject: "owner/frag1-repo"
    roles: ["arn:aws:iam::111111111111:role/frag1"]
`), 0o600))
	require.NoError(t, os.WriteFile(frag2, []byte(`
role_sets:
  frag2set: ["arn:aws:iam::111111111111:role/frag2"]
role_mappings:
  - subject: "owner/frag2-repo"
    roles: ["@frag2set"]
`), 0o600))

	base := baseConfig(t)
	base.ConfigFragments = []string{frag1, frag2}
	require.NoError(t, base.Validate())

	p := NewProvider(base, time.Minute, "yaml", noopBaseFetch)
	require.NoError(t, p.Refresh(context.Background()))

	cfg := p.Get()
	require.Len(t, cfg.RoleMappings, 2)
	assert.Equal(t, Patterns{"owner/frag1-repo"}, cfg.RoleMappings[0].Subject)
	assert.Equal(t, Patterns{"owner/frag2-repo"}, cfg.RoleMappings[1].Subject)

	matched, roles := cfg.AuthorizeRoles(base.Issuers[0].Issuer, "owner/frag2-repo", map[string]any{})
	assert.True(t, matched)
	assert.Equal(t, []string{"arn:aws:iam::111111111111:role/frag2"}, roles)
}

func TestProvider_FragmentRejectsDisallowedKey(t *testing.T) {
	dir := t.TempDir()
	frag := filepath.Join(dir, "frag.yaml")
	require.NoError(t, os.WriteFile(frag, []byte(`
issuers:
  - issuer: "https://evil.example.com"
    audiences: ["sts.amazonaws.com"]
`), 0o600))

	base := baseConfig(t)
	base.ConfigFragments = []string{frag}
	require.NoError(t, base.Validate())

	p := NewProvider(base, time.Minute, "yaml", noopBaseFetch)
	err := p.Refresh(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), `"issuers"`)
	assert.Same(t, base, p.Get(), "a rejected fragment must retain last-good, never a partial merge")
}

func TestProvider_FragmentRejectsTagAuth(t *testing.T) {
	dir := t.TempDir()
	frag := filepath.Join(dir, "frag.yaml")
	require.NoError(t, os.WriteFile(frag, []byte("tag_auth:\n  enabled: true\n"), 0o600))

	base := baseConfig(t)
	base.ConfigFragments = []string{frag}
	require.NoError(t, base.Validate())

	p := NewProvider(base, time.Minute, "yaml", noopBaseFetch)
	err := p.Refresh(context.Background())
	require.Error(t, err)
	assert.Same(t, base, p.Get())
}

func TestProvider_FragmentDefaultIssuerUnknownRejected(t *testing.T) {
	dir := t.TempDir()
	frag := filepath.Join(dir, "frag.yaml")
	require.NoError(t, os.WriteFile(frag, []byte(`default_issuer: "https://not-configured.example.com"`), 0o600))

	base := baseConfig(t)
	base.ConfigFragments = []string{frag}
	require.NoError(t, base.Validate())

	p := NewProvider(base, time.Minute, "yaml", noopBaseFetch)
	err := p.Refresh(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not a base-defined issuer")
	assert.Same(t, base, p.Get())
}

func TestProvider_FragmentRoleSetCollisionRejected(t *testing.T) {
	dir := t.TempDir()
	frag := filepath.Join(dir, "frag.yaml")
	require.NoError(t, os.WriteFile(frag, []byte(`
role_sets:
  prod: ["arn:aws:iam::222222222222:role/evil"]
`), 0o600))

	base := baseConfig(t)
	base.RoleSets = map[string][]string{"prod": {"arn:aws:iam::111111111111:role/prod"}}
	base.ConfigFragments = []string{frag}
	require.NoError(t, base.Validate())

	p := NewProvider(base, time.Minute, "yaml", noopBaseFetch)
	err := p.Refresh(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "collides")
	assert.Same(t, base, p.Get())
}

func TestProvider_UnchangedFragmentSkipsRefetch(t *testing.T) {
	const uri = "s3://bucket/frag.yaml"
	store := newFakeFragmentStore()
	store.set(uri, []byte(`role_mappings: []`))

	base := baseConfig(t)
	base.ConfigFragments = []string{uri}
	require.NoError(t, base.Validate())

	p := NewProvider(base, time.Minute, "yaml", noopBaseFetch, WithFragmentFetcher(store.fetch))

	require.NoError(t, p.Refresh(context.Background()))
	assert.Equal(t, 1, store.fetches[uri])
	assert.Equal(t, 1, store.checks[uri])

	// Unchanged content: fetch() is still called (per E2, the caller always
	// checks) but must not be counted as a full re-fetch/re-parse.
	require.NoError(t, p.Refresh(context.Background()))
	assert.Equal(t, 1, store.fetches[uri], "unchanged fragment must not be re-fetched/re-parsed")
	assert.Equal(t, 2, store.checks[uri])
}

func TestProvider_ChangedFragmentTriggersReload(t *testing.T) {
	const uri = "s3://bucket/frag.yaml"
	store := newFakeFragmentStore()
	store.set(uri, []byte(`
role_mappings:
  - subject: "owner/v1"
    roles: ["arn:aws:iam::111111111111:role/v1"]
`))

	base := baseConfig(t)
	base.ConfigFragments = []string{uri}
	require.NoError(t, base.Validate())

	p := NewProvider(base, time.Minute, "yaml", noopBaseFetch, WithFragmentFetcher(store.fetch))
	require.NoError(t, p.Refresh(context.Background()))
	require.Len(t, p.Get().RoleMappings, 1)
	assert.Equal(t, Patterns{"owner/v1"}, p.Get().RoleMappings[0].Subject)

	store.set(uri, []byte(`
role_mappings:
  - subject: "owner/v2"
    roles: ["arn:aws:iam::111111111111:role/v2"]
`))
	require.NoError(t, p.Refresh(context.Background()))
	require.Len(t, p.Get().RoleMappings, 1)
	assert.Equal(t, Patterns{"owner/v2"}, p.Get().RoleMappings[0].Subject)
	assert.Equal(t, 2, store.fetches[uri])
}

func TestProvider_FailedFragmentFetchRetainsLastGood(t *testing.T) {
	const uri = "s3://bucket/frag.yaml"
	store := newFakeFragmentStore()
	store.set(uri, []byte(`
role_mappings:
  - subject: "owner/v1"
    roles: ["arn:aws:iam::111111111111:role/v1"]
`))

	base := baseConfig(t)
	base.ConfigFragments = []string{uri}
	require.NoError(t, base.Validate())

	p := NewProvider(base, time.Minute, "yaml", noopBaseFetch, WithFragmentFetcher(store.fetch))
	require.NoError(t, p.Refresh(context.Background()))
	good := p.Get()

	store.delete(uri)

	err := p.Refresh(context.Background())
	require.Error(t, err)
	assert.Same(t, good, p.Get())
}

func TestProvider_RemoteFragmentWithoutFetcherFails(t *testing.T) {
	base := baseConfig(t)
	base.ConfigFragments = []string{"s3://bucket/frag.yaml"}
	require.NoError(t, base.Validate())

	p := NewProvider(base, time.Minute, "yaml", noopBaseFetch) // no WithFragmentFetcher
	err := p.Refresh(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "requires a fragment fetcher")
	assert.Same(t, base, p.Get())
}

func TestProvider_FragmentChecksumMismatchRejected(t *testing.T) {
	const uri = "s3://bucket/frag.yaml"
	store := newFakeFragmentStore()
	store.set(uri, []byte(`role_mappings: []`))

	base := baseConfig(t)
	base.ConfigFragments = []string{uri}
	base.ConfigFragmentChecksums = []FragmentChecksum{{URI: uri, Checksum: "sha256:deadbeef"}}
	require.NoError(t, base.Validate())

	p := NewProvider(base, time.Minute, "yaml", noopBaseFetch, WithFragmentFetcher(store.fetch))
	err := p.Refresh(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "integrity check")
	assert.Same(t, base, p.Get())
}

func TestProvider_FragmentChecksumMatchAccepted(t *testing.T) {
	const uri = "s3://bucket/frag.yaml"
	content := []byte(`
role_mappings:
  - subject: "owner/repo"
    roles: ["arn:aws:iam::111111111111:role/ci"]
`)
	store := newFakeFragmentStore()
	store.set(uri, content)

	base := baseConfig(t)
	base.ConfigFragments = []string{uri}
	base.ConfigFragmentChecksums = []FragmentChecksum{{URI: uri, Checksum: etagOf(content)}}
	require.NoError(t, base.Validate())

	p := NewProvider(base, time.Minute, "yaml", noopBaseFetch, WithFragmentFetcher(store.fetch))
	require.NoError(t, p.Refresh(context.Background()))
	require.Len(t, p.Get().RoleMappings, 1)
}

func TestProvider_FragmentOnlyNoPrimaryFetch(t *testing.T) {
	dir := t.TempDir()
	frag := filepath.Join(dir, "frag.yaml")
	require.NoError(t, os.WriteFile(frag, []byte(`
role_mappings:
  - subject: "owner/repo"
    roles: ["arn:aws:iam::111111111111:role/ci"]
`), 0o600))

	base := baseConfig(t)
	base.ConfigFragments = []string{frag}
	require.NoError(t, base.Validate())

	// No primary S3/remote overlay at all (fetch == nil) — fragments must
	// still be fetched/merged, both via an explicit Refresh...
	p := NewProvider(base, time.Minute, "yaml", nil)
	require.NoError(t, p.Refresh(context.Background()))
	require.Len(t, p.Get().RoleMappings, 1)

	// ...and via MaybeRefresh, which must not treat fetch==nil as "nothing
	// to do" when config_fragments is non-empty.
	require.NoError(t, os.WriteFile(frag, []byte(`
role_mappings:
  - subject: "owner/repo2"
    roles: ["arn:aws:iam::111111111111:role/ci2"]
`), 0o600))
	p.now = func() time.Time { return time.Now().Add(2 * time.Minute) }
	p.MaybeRefresh(context.Background())
	require.Len(t, p.Get().RoleMappings, 1)
	assert.Equal(t, Patterns{"owner/repo2"}, p.Get().RoleMappings[0].Subject)
}

// TestProvider_FragmentReload_Race exercises concurrent MaybeRefresh (with
// fragment content changing underneath) and concurrent Get()/AuthorizeRoles
// reads, to be run under `go test -race`. It asserts no torn reads/writes;
// exact reload counts are not checked (only race-freedom and no panics).
func TestProvider_FragmentReload_Race(t *testing.T) {
	const uri = "s3://bucket/frag.yaml"
	store := newFakeFragmentStore()
	store.set(uri, []byte(`role_mappings: []`))

	base := baseConfig(t)
	base.ConfigFragments = []string{uri}
	require.NoError(t, base.Validate())

	p := NewProvider(base, time.Millisecond, "yaml", noopBaseFetch, WithFragmentFetcher(store.fetch))

	var wg sync.WaitGroup
	stop := make(chan struct{})

	wg.Add(1)
	go func() {
		defer wg.Done()
		i := 0
		for {
			select {
			case <-stop:
				return
			default:
			}
			i++
			store.set(uri, []byte(fmt.Sprintf(`
role_mappings:
  - subject: "owner/repo-%d"
    roles: ["arn:aws:iam::111111111111:role/r%d"]
`, i, i)))
		}
	}()

	for r := 0; r < 8; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				p.MaybeRefresh(context.Background())
			}
		}()
	}

	for r := 0; r < 8; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				cfg := p.Get()
				_, _ = cfg.AuthorizeRoles(base.Issuers[0].Issuer, "owner/repo-1", map[string]any{})
			}
		}()
	}

	time.Sleep(50 * time.Millisecond)
	close(stop)
	wg.Wait()
}
