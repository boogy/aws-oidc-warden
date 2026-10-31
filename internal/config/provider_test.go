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
	"strings"
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

		S3ConfigBucketOwner: "123456789012",
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
	assert.Equal(t, 5*time.Minute, time.Duration(p.interval.Load()))
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

func (s *fakeFragmentStore) fetch(_ context.Context, uri, prevETag, _ string) ([]byte, string, error) {
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

func TestProvider_FragmentFetchUsesBaseBucketOwner(t *testing.T) {
	const uri = "s3://bucket/frag.yaml"
	base := baseConfig(t)
	base.ConfigFragments = []string{uri}
	base.S3ConfigBucketOwner = "111122223333"
	require.NoError(t, base.Validate())

	var got string
	fetch := func(_ context.Context, _, _, owner string) ([]byte, string, error) {
		got = owner
		return []byte(`role_mappings: []`), "sha256:x", nil
	}
	overlay := func(context.Context) ([]byte, error) { return []byte(`{}`), nil }
	p := NewProvider(base, time.Minute, "yaml", overlay, WithFragmentFetcher(fetch))

	require.NoError(t, p.Refresh(context.Background()))
	assert.Equal(t, "111122223333", got)
}

func TestProvider_OverlayBucketOwner(t *testing.T) {
	tests := []struct {
		name      string
		baseOwner string
		overlay   string
		wantOwner string
	}{
		{"base owner wins over overlay", "111122223333", "s3_config_bucket_owner: \"444455556666\"\nconfig_fragments: [\"s3://bucket/frag.yaml\"]", "111122223333"},
		{"overlay cannot fill unset base owner", "", "s3_config_bucket_owner: \"444455556666\"\nconfig_fragments: [\"s3://bucket/frag.yaml\"]", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			base := baseConfig(t)
			base.S3ConfigBucketOwner = tt.baseOwner
			require.NoError(t, base.Validate())
			var got string
			fetch := func(_ context.Context, _, _, owner string) ([]byte, string, error) {
				got = owner
				return []byte(`role_mappings: []`), "sha256:x", nil
			}
			overlay := func(context.Context) ([]byte, error) { return []byte(tt.overlay), nil }
			p := NewProvider(base, time.Minute, "yaml", overlay, WithFragmentFetcher(fetch))

			err := p.Refresh(context.Background())
			if tt.wantOwner == "" {
				require.ErrorContains(t, err, "s3_config_bucket_owner is required")
				assert.Empty(t, got, "no fragment read may happen with an overlay-chosen owner")
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantOwner, got)
			assert.Equal(t, tt.wantOwner, p.Get().S3ConfigBucketOwner)
		})
	}
}

func TestProvider_OverlaySessionPolicyBucketOwner(t *testing.T) {
	const overlayOwner = "session_policy_bucket: \"swapped\"\nsession_policy_bucket_owner: \"444455556666\"\n"
	tests := []struct {
		name      string
		baseOwner string
		overlay   string
		wantOwner string
	}{
		{"overlay cannot change base owner", "111122223333", overlayOwner, "111122223333"},
		{"overlay cannot fill unset owner", "", overlayOwner, ""},
		{"overlay without the key keeps base owner", "111122223333", "session_policy_bucket: \"swapped\"\n", "111122223333"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			base := baseConfig(t)
			base.S3SessionPolicyBucket, base.SessionPolicyBucketOwner = "policies", tt.baseOwner
			require.NoError(t, base.Validate())
			overlay := func(context.Context) ([]byte, error) { return []byte(tt.overlay), nil }
			p := NewProvider(base, time.Minute, "yaml", overlay)

			require.NoError(t, p.Refresh(context.Background()))
			assert.Equal(t, "swapped", p.Get().S3SessionPolicyBucket)
			assert.Equal(t, tt.wantOwner, p.Get().SessionPolicyBucketOwner)
		})
	}
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

func TestProvider_EmptyFragmentRetainsLastGood(t *testing.T) {
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

	store.set(uri, []byte{})

	require.ErrorContains(t, p.Refresh(context.Background()), "is empty")
	assert.Same(t, good, p.Get())
}

func TestProvider_EmptyLocalFragmentFailsColdStart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mappings.yaml")
	require.NoError(t, os.WriteFile(path, nil, 0o600))

	base := baseConfig(t)
	base.ConfigFragments = []string{path}
	require.NoError(t, base.Validate())

	p := NewProvider(base, time.Minute, "yaml", noopBaseFetch)
	require.ErrorContains(t, p.Refresh(context.Background()), "is empty")
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
			store.set(uri, fmt.Appendf(nil, `
role_mappings:
  - subject: "owner/repo-%d"
    roles: ["arn:aws:iam::111111111111:role/r%d"]
`, i, i))
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

func TestProviderRefreshRejectsIdPIssuerCollision(t *testing.T) {
	const idpIssuer = "https://idp.example.com"
	overlay := func(issuers ...string) []byte {
		out := "issuers:\n"
		for _, i := range issuers {
			out += "  - issuer: \"" + i + "\"\n    provider: github\n    audiences: [\"sts.amazonaws.com\"]\n"
		}
		return []byte(out)
	}
	tests := []struct {
		name      string
		freeze    bool
		sourceID  string
		overlay   []byte
		wantErr   bool
		errHas    string
		omitSrcID bool
	}{
		{"inbound equals idp issuer", true, IdPDefaultSourceIdentity, overlay(idpIssuer), true, "must differ", false},
		{"inbound contains hash", true, IdPDefaultSourceIdentity, overlay("https://other.example.com/a#b"), true, "must not contain #", false},
		{"unrelated inbound issuer", true, IdPDefaultSourceIdentity, overlay("https://other.example.com"), false, "", false},
		{"collision with frozen only", true, IdPDefaultSourceIdentity, overlay("https://token.actions.githubusercontent.com", idpIssuer), true, "must differ", false},
		{"second issuer with issuer-less frozen source identity", true, "{subject}", overlay("https://a.example.com", "https://b.example.com"), true, "must contain {issuer}", false},
		{"second issuer with issuer-bound frozen source identity", true, IdPDefaultSourceIdentity, overlay("https://a.example.com", "https://b.example.com"), false, "", false},
		{"second issuer with unrendered issuer-less source identity", true, "{subject}", overlay("https://a.example.com", "https://b.example.com"), false, "", true},
		{"hostless inbound issuer with issuer-bound source identity", true, IdPDefaultSourceIdentity, overlay("a.example.com"), false, "", false},
		{"inbound issuers rendering the same issuer", true, IdPDefaultSourceIdentity, overlay("https://a.example.com", "https://a.example.com/"), true, "render the same {issuer}", false},
		{"inbound issuers rendering the same unrendered issuer", true, IdPDefaultSourceIdentity, overlay("https://a.example.com", "https://a.example.com/"), false, "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			base := baseConfig(t)
			p := NewProvider(base, time.Minute, "yaml", func(context.Context) ([]byte, error) { return tt.overlay, nil })
			if tt.freeze {
				include := !tt.omitSrcID
				p.FreezeIdP(&IdPConfig{Issuer: idpIssuer, SourceIdentity: tt.sourceID, IncludeSourceIdentity: &include})
			}
			before := p.lastRefresh.Load()

			err := p.Refresh(context.Background())
			if !tt.wantErr {
				require.NoError(t, err)
				assert.NotSame(t, base, p.Get())
				return
			}
			require.ErrorContains(t, err, tt.errHas)
			assert.Same(t, base, p.Get())
			assert.Equal(t, before, p.lastRefresh.Load())
		})
	}
}

func TestProvider_OverlayCannotRaiseMaxConfigBytes(t *testing.T) {
	const uri = "s3://bucket/frag.yaml"
	base := baseConfig(t)
	base.ConfigFragments = []string{uri}
	base.S3ConfigBucketOwner = "111122223333"
	base.MaxConfigBytes = 64
	require.NoError(t, base.Validate())

	fetch := func(context.Context, string, string, string) ([]byte, string, error) {
		return []byte("role_mappings: []\n" + strings.Repeat("#", 100)), "sha256:x", nil
	}
	overlay := func(context.Context) ([]byte, error) { return []byte("max_config_bytes: 1048576\n"), nil }
	p := NewProvider(base, time.Minute, "yaml", overlay, WithFragmentFetcher(fetch))

	require.ErrorContains(t, p.Refresh(context.Background()), "exceeds 64 byte cap")
}

func TestProvider_OverlayBaseOnlyKeysWarn(t *testing.T) {
	tests := []struct {
		name, overlay string
		base          int
		warn          bool
	}{
		{
			name: "differing values warn", base: 64, warn: true,
			overlay: "max_config_bytes: 1048576\ns3_config_bucket_owner: \"999999999999\"\nsession_policy_bucket_owner: \"999999999999\"\n",
		},
		{name: "invalid negative value warns", base: 64, overlay: "max_config_bytes: -5\n", warn: true},
		{name: "zero overlay meaning the default differs from a custom base", base: 64, overlay: "max_config_bytes: 0\n", warn: true},
		{name: "restated values are silent", base: 64, overlay: "max_config_bytes: 64\n"},
		{name: "zero overlay meaning the default is silent", base: 0, overlay: "max_config_bytes: 0\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := captureUnknownKeyWarnings(t)
			base := baseConfig(t)
			base.MaxConfigBytes = tt.base
			base.S3ConfigBucketOwner = "111122223333"
			base.SessionPolicyBucketOwner = "111122223333"
			require.NoError(t, base.Validate())
			overlay := func(context.Context) ([]byte, error) { return []byte(tt.overlay), nil }
			p := NewProvider(base, time.Minute, "yaml", overlay)
			require.NoError(t, p.Refresh(context.Background()))
			assert.Equal(t, base.MaxConfigBytes, p.Get().MaxConfigBytes)
			assert.Equal(t, "111122223333", p.Get().S3ConfigBucketOwner)
			assert.Equal(t, "111122223333", p.Get().SessionPolicyBucketOwner)
			if !tt.warn {
				assert.NotContains(t, buf.String(), "overlay_base_only_keys_ignored")
				return
			}
			assert.Contains(t, buf.String(), "overlay_base_only_keys_ignored")
			assert.Contains(t, buf.String(), "max_config_bytes")
			if strings.Contains(tt.overlay, "owner") {
				assert.Contains(t, buf.String(), "s3_config_bucket_owner")
				assert.Contains(t, buf.String(), "session_policy_bucket_owner")
			} else {
				assert.NotContains(t, buf.String(), "s3_config_bucket_owner")
				assert.NotContains(t, buf.String(), "session_policy_bucket_owner")
			}
		})
	}
}

func TestProvider_ReloadKeepsFrozenJWTMode(t *testing.T) {
	const signerA, signerB = "arn:aws:elasticloadbalancing:us-east-1:111122223333:loadbalancer/app/a/1", "arn:aws:elasticloadbalancing:us-east-1:111122223333:loadbalancer/app/b/2"
	tests := []struct {
		name       string
		overlay    string
		wantErr    bool
		wantSigner string
	}{
		{name: "mode switch dropping the signer is rejected", overlay: "jwt_validation:\n  mode: self\n  alb_expected_signer: \"\"\n", wantErr: true, wantSigner: signerA},
		{name: "mode switch keeping the signer is ignored", overlay: "jwt_validation:\n  mode: apigw\n", wantSigner: signerA},
		{name: "second issuer under alb is rejected", overlay: "issuers:\n  - issuer: https://token.actions.githubusercontent.com\n    provider: github\n    audiences: [sts.amazonaws.com]\n  - issuer: https://gitlab.com\n    provider: generic\n    audiences: [sts.amazonaws.com]\n    claim_mappings: {subject: sub}\n", wantErr: true, wantSigner: signerA},
		{name: "signer rotation still applies", overlay: "jwt_validation:\n  alb_expected_signer: " + signerB + "\n", wantSigner: signerB},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			base := baseConfig(t)
			base.JWTValidation = JWTValidation{Mode: "alb", ALBExpectedSigner: signerA}
			require.NoError(t, base.Validate())
			overlay := "log_level: info\n"
			p := NewProvider(base, time.Minute, "yaml", func(context.Context) ([]byte, error) { return []byte(overlay), nil })
			require.NoError(t, p.Refresh(context.Background()))
			p.FreezeJWTMode(p.Get().JWTValidation.Mode)

			overlay = tt.overlay
			err := p.Refresh(context.Background())
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			assert.Equal(t, "alb", p.Get().JWTValidation.Mode)
			assert.Equal(t, tt.wantSigner, p.Get().JWTValidation.ALBExpectedSigner)
		})
	}
}

func TestProvider_OverlayCannotMoveItself(t *testing.T) {
	buf := captureUnknownKeyWarnings(t)
	base := baseConfig(t)
	base.S3ConfigBucket, base.S3ConfigPath = "cfg-bucket", "overlay.yaml"
	require.NoError(t, base.Validate())
	overlay := func(context.Context) ([]byte, error) {
		return []byte("s3_config_bucket: other-bucket\ns3_config_path: moved.yaml\n"), nil
	}
	p := NewProvider(base, time.Minute, "yaml", overlay)
	require.NoError(t, p.Refresh(context.Background()))

	assert.Equal(t, "cfg-bucket", p.Get().S3ConfigBucket)
	assert.Equal(t, "overlay.yaml", p.Get().S3ConfigPath)
	assert.Contains(t, buf.String(), "overlay_base_only_keys_ignored")
	assert.Contains(t, buf.String(), "s3_config_path")
}

func TestProvider_EmptyOverlayKeepsPreviousConfig(t *testing.T) {
	overlay := []byte("role_mappings:\n  - subject: \"owner/.*\"\n    roles: [\"arn:aws:iam::123456789012:role/ci\"]\n")
	p := NewProvider(baseConfig(t), time.Minute, "yaml", func(context.Context) ([]byte, error) { return overlay, nil })
	require.NoError(t, p.Refresh(context.Background()))
	prev := p.Get()
	require.Len(t, prev.RoleMappings, 1)

	for _, empty := range [][]byte{nil, {}} {
		overlay = empty
		require.ErrorContains(t, p.Refresh(context.Background()), "overlay is empty")
		assert.Same(t, prev, p.Get())
	}
}

func TestProvider_EmptyOverlayFailsColdStart(t *testing.T) {
	p := NewProvider(baseConfig(t), time.Minute, "yaml", func(context.Context) ([]byte, error) { return []byte{}, nil })
	require.ErrorContains(t, p.Refresh(context.Background()), "overlay is empty")
}

func TestProvider_CommentOnlyOverlayResetsToBase(t *testing.T) {
	overlay := []byte("role_mappings:\n  - subject: \"owner/.*\"\n    roles: [\"arn:aws:iam::123456789012:role/ci\"]\n")
	p := NewProvider(baseConfig(t), time.Minute, "yaml", func(context.Context) ([]byte, error) { return overlay, nil })
	require.NoError(t, p.Refresh(context.Background()))
	require.Len(t, p.Get().RoleMappings, 1)

	overlay = []byte("# intentionally empty\n")
	require.NoError(t, p.Refresh(context.Background()))
	assert.Empty(t, p.Get().RoleMappings)
}

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

func TestProviderStaleDoesNotWaitAfterFailures(t *testing.T) {
	p := staleMappingsProvider(t, new(atomic.Int32))
	p.failures.Store(1)
	p.lock()
	defer p.unlock()
	done := make(chan struct{})
	go func() { p.MaybeRefresh(context.Background()); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("stale MaybeRefresh queued behind an in-flight refresh although the source is failing")
	}
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

func TestProviderRefreshWarnsOnFrozenIdPDrift(t *testing.T) {
	drifted := strings.Replace(idpTestBlockYAML, `audience: "sts.amazonaws.com"`, `audience: "drifted.example.com"`, 1)
	tests := []struct {
		name       string
		boot, next string
		freeze     bool
		want       int
	}{
		{"unchanged", idpTestBlockYAML, idpTestBlockYAML + "log_level: debug\n", true, 0},
		{"frozen field changed", idpTestBlockYAML, drifted, true, 1},
		{"block removed", idpTestBlockYAML, "log_level: info\n", true, 0},
		{"block added to a warden built without one", "log_level: info\n", idpTestBlockYAML, true, 1},
		{"cold start before freeze", "log_level: info\n", idpTestBlockYAML, false, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := []byte(tt.boot)
			p := NewProvider(baseConfig(t), time.Minute, "yaml", func(context.Context) ([]byte, error) { return body, nil })
			require.NoError(t, p.Refresh(context.Background()))
			if tt.freeze {
				p.FreezeIdP(p.Get().IdP)
			}
			body = []byte(tt.next)
			out := captureWarnings(t, func() { require.NoError(t, p.Refresh(context.Background())) })
			assert.Equal(t, tt.want, strings.Count(out, `config.idp.reload_ignored`))
		})
	}
}

func TestProviderRefreshLogsIdPBlockRemovedAndRestored(t *testing.T) {
	body := []byte(idpTestBlockYAML)
	p := NewProvider(baseConfig(t), time.Minute, "yaml", func(context.Context) ([]byte, error) { return body, nil })
	require.NoError(t, p.Refresh(context.Background()))
	p.FreezeIdP(p.Get().IdP)

	drifted := strings.Replace(idpTestBlockYAML, `audience: "sts.amazonaws.com"`, `audience: "drifted.example.com"`, 1)
	for _, step := range []struct {
		body    string
		enabled bool
		ignored int
	}{{"log_level: info\n", false, 0}, {idpTestBlockYAML, true, 0}, {"log_level: info\n", false, 0}, {drifted, true, 1}} {
		body = []byte(step.body)
		out := captureWarnings(t, func() { require.NoError(t, p.Refresh(context.Background())) })
		assert.Equal(t, step.enabled, p.Get().IdP != nil && p.Get().IdP.Enabled)
		assert.Contains(t, out, fmt.Sprintf(`"enabled":%t`, step.enabled))
		assert.Equal(t, 1, strings.Count(out, `config.idp.enabled_changed`))
		assert.Contains(t, out, fmt.Sprintf(`"blockPresent":%t`, step.enabled))
		assert.Equal(t, step.ignored, strings.Count(out, `config.idp.reload_ignored`))
	}
}

func TestProviderRefreshLogsIdPEnabledFlip(t *testing.T) {
	tests := []struct {
		name          string
		base, overlay bool
		coldStart     bool
		env           string
		want, wantLog bool
	}{
		{"disable", true, false, false, "", false, true},
		{"enable", false, true, false, "", true, true},
		{"unchanged", true, true, false, "", true, false},
		{"env beats overlay", true, false, false, "true", true, false},
		{"cold start", false, true, true, "", true, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.env != "" {
				t.Setenv("AOW_IDP_ENABLED", tt.env)
			}
			base := baseConfig(t)
			base.IdP = validIdP()
			base.IdP.Enabled = tt.base
			require.NoError(t, base.Validate())
			body := fmt.Appendf(nil, "idp:\n  enabled: %t\n", tt.overlay)
			p := NewProvider(base, time.Minute, "yaml", func(context.Context) ([]byte, error) { return body, nil })
			if !tt.coldStart {
				p.FreezeIdP(base.IdP)
			}

			out := captureWarnings(t, func() { require.NoError(t, p.Refresh(context.Background())) })
			got := p.Get().IdP
			require.Equal(t, tt.want, got != nil && got.Enabled)
			if !tt.wantLog {
				assert.NotContains(t, out, "config.idp.enabled_changed")
				return
			}
			assert.Contains(t, out, "config.idp.enabled_changed")
			assert.Contains(t, out, fmt.Sprintf(`"enabled":%t`, tt.want))
			assert.Contains(t, out, `"blockPresent":true`)
		})
	}
}
