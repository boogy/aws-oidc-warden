package config

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
	assert.Equal(t, "owner/frag1-repo", cfg.RoleMappings[0].Subject)
	assert.Equal(t, "owner/frag2-repo", cfg.RoleMappings[1].Subject)

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
	assert.Equal(t, "owner/v1", p.Get().RoleMappings[0].Subject)

	store.set(uri, []byte(`
role_mappings:
  - subject: "owner/v2"
    roles: ["arn:aws:iam::111111111111:role/v2"]
`))
	require.NoError(t, p.Refresh(context.Background()))
	require.Len(t, p.Get().RoleMappings, 1)
	assert.Equal(t, "owner/v2", p.Get().RoleMappings[0].Subject)
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
	base.ConfigFragmentChecksums = map[string]string{uri: "sha256:deadbeef"}
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
	base.ConfigFragmentChecksums = map[string]string{uri: etagOf(content)}
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
	assert.Equal(t, "owner/repo2", p.Get().RoleMappings[0].Subject)
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
