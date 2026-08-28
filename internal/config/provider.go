package config

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

// FetchFunc retrieves the raw configuration bytes from a remote source.
type FetchFunc func(context.Context) ([]byte, error)

// FragmentFetchFunc retrieves one config_fragments entry's current content.
// prevETag is the etag last successfully applied (empty on first fetch); may
// return (nil, prevETag, nil) to signal "unchanged" and skip the body fetch.
// Required for "scheme://" entries; local paths are read directly.
//
// etag must be stable and content-derived: Provider treats etag == prevETag
// as unchanged regardless of data, so a constant/empty etag would silently
// hide real content changes.
type FragmentFetchFunc func(ctx context.Context, uri, prevETag string) (data []byte, etag string, err error)

// cachedFragment is the last-successfully-applied parse of one fragment
// source, keyed by its config_fragments URI/path.
type cachedFragment struct {
	etag   string
	parsed *FragmentConfig
}

// fragmentMappingSoftCap: exceeding it only logs a warning, never blocks a reload.
const fragmentMappingSoftCap = 5000

// ProviderOption configures optional Provider behavior at construction.
type ProviderOption func(*Provider)

// WithFragmentFetcher installs the fetch function for "scheme://" fragment
// entries. Without one, a refresh hitting a remote entry fails (and retains
// the last-good config) rather than silently skipping it.
func WithFragmentFetcher(fetch FragmentFetchFunc) ProviderOption {
	return func(p *Provider) { p.fragmentFetch = fetch }
}

// Provider holds the active configuration behind an atomic pointer and can
// lazily refresh it from a remote source without redeploying. Each refresh
// clones the pristine base, overlays fetched bytes, merges config_fragments,
// re-validates, then atomically swaps in the result.
type Provider struct {
	current       atomic.Pointer[Config]
	base          *Config      // pristine env/file/defaults config, cloned on each refresh
	interval      atomic.Int64 // nanoseconds; <= 0 means disabled
	format        string       // viper config type ("json"/"yaml"/"toml")
	lastRefresh   atomic.Int64 // unix nanos of last successful refresh; 0 = never
	now           func() time.Time
	mu            sync.Mutex                 // serializes refreshes
	fetch         FetchFunc                  // nil if there's no primary remote/S3 config overlay
	fragmentFetch FragmentFetchFunc          // nil if no remote ("scheme://") fragments are configured
	fragments     map[string]*cachedFragment // last-applied fragment cache; only touched under mu (in refreshLocked)
}

// NewStaticProvider returns a Provider that always serves cfg and never reloads.
func NewStaticProvider(cfg *Config, opts ...ProviderOption) *Provider {
	p := &Provider{base: cfg, now: time.Now, fragments: make(map[string]*cachedFragment)}
	for _, opt := range opts {
		opt(p)
	}
	p.current.Store(cfg)
	return p
}

// NewProvider returns a reloadable Provider. fetch may be nil if base only
// carries config_fragments; interval <= 0 disables reloading; format is the
// viper config type of fetched bytes (empty defaults to "json"). The served
// config is base until the first successful Refresh.
func NewProvider(base *Config, interval time.Duration, format string, fetch FetchFunc, opts ...ProviderOption) *Provider {
	p := &Provider{base: base, format: format, fetch: fetch, now: time.Now, fragments: make(map[string]*cachedFragment)}
	for _, opt := range opts {
		opt(p)
	}
	p.interval.Store(int64(interval))
	p.current.Store(base)
	return p
}

// Get returns the currently active configuration.
func (p *Provider) Get() *Config {
	return p.current.Load()
}

// IntervalForTest exposes the current effective interval for testing only.
func (p *Provider) IntervalForTest() int64 { return p.interval.Load() }

// MaybeRefresh reloads if reloading is enabled and the interval has elapsed.
// Double-checked locking ensures at most one fetch per interval boundary
// under concurrent load. Errors are logged; the previous config is retained.
func (p *Provider) MaybeRefresh(ctx context.Context) {
	if p.fetch == nil && len(p.base.ConfigFragments) == 0 {
		return
	}
	interval := time.Duration(p.interval.Load())
	if interval <= 0 {
		return
	}

	// Fast path: clearly not due (no lock).
	last := p.lastRefresh.Load()
	if last != 0 && p.now().UnixNano()-last < int64(interval) {
		return
	}

	// Slow path: re-check under lock so only the first goroutine through fetches.
	p.mu.Lock()
	defer p.mu.Unlock()

	last = p.lastRefresh.Load()
	if last != 0 && p.now().UnixNano()-last < int64(interval) {
		return
	}

	if err := p.refreshLocked(ctx); err != nil {
		slog.Error("Configuration refresh failed; keeping previous configuration", slog.String("error", err.Error()))
	}
}

// Refresh fetches, overlays, validates, and atomically swaps in a new config.
// On any error the active configuration is left unchanged.
func (p *Provider) Refresh(ctx context.Context) error {
	if p.fetch == nil && len(p.base.ConfigFragments) == 0 {
		return errors.New("no configuration fetch source configured")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.refreshLocked(ctx)
}

// refreshLocked performs the actual fetch+merge+swap. Must be called with
// p.mu held. On any error cfg and p.fragments are discarded — reload fails safe.
func (p *Provider) refreshLocked(ctx context.Context) error {
	cfg, err := cloneConfig(p.base)
	if err != nil {
		return fmt.Errorf("failed to clone base configuration: %w", err)
	}

	if p.fetch != nil {
		data, err := p.fetch(ctx)
		if err != nil {
			return fmt.Errorf("failed to fetch configuration: %w", err)
		}
		if err := cfg.MergeBytes(data, p.format); err != nil {
			return fmt.Errorf("invalid configuration after reload: %w", err)
		}
	} else if err := cfg.Validate(); err != nil {
		// No primary overlay: still rebuild transient state cloneConfig
		// doesn't copy, before fragments merge on top.
		return fmt.Errorf("invalid base configuration: %w", err)
	}

	nextFragments, err := p.applyFragments(ctx, cfg)
	if err != nil {
		return fmt.Errorf("failed to apply config fragments: %w", err)
	}
	if len(cfg.ConfigFragments) > 0 {
		if err := cfg.Validate(); err != nil {
			return fmt.Errorf("invalid configuration after fragment merge: %w", err)
		}
	}

	p.current.Store(cfg)
	p.fragments = nextFragments
	p.lastRefresh.Store(p.now().UnixNano())

	// Propagate a changed interval so operators can adjust polling without a cold start.
	if cfg.ConfigReloadInterval > 0 {
		p.interval.Store(int64(cfg.ConfigReloadInterval))
	}

	slog.Info("Configuration reloaded",
		slog.Int("roleMappings", len(cfg.effective)),
		slog.Int("fragments", len(cfg.ConfigFragments)))
	return nil
}

// applyFragments fetches, verifies, and merges every cfg.ConfigFragments
// entry (list order) onto cfg. Mutates cfg in place but returns the fragment
// cache separately; caller only commits it after a nil error, so a
// failed/invalid fragment can't partially apply into the served config.
func (p *Provider) applyFragments(ctx context.Context, cfg *Config) (map[string]*cachedFragment, error) {
	if len(cfg.ConfigFragments) == 0 {
		return nil, nil
	}

	baseIssuers := make(map[string]bool, len(cfg.Issuers))
	for _, iss := range cfg.Issuers {
		baseIssuers[iss.Issuer] = true
	}

	next := make(map[string]*cachedFragment, len(cfg.ConfigFragments))
	totalMappings := len(cfg.RoleMappings)
	for _, g := range cfg.RoleGroups {
		totalMappings += len(g.Subjects)
	}

	for _, uri := range cfg.ConfigFragments {
		prev := p.fragments[uri]
		prevETag := ""
		if prev != nil {
			prevETag = prev.etag
		}

		data, etag, err := p.fetchFragment(ctx, uri, prevETag)
		if err != nil {
			return nil, fmt.Errorf("config_fragments: %w", err)
		}
		if len(data) > maxFragmentBytes {
			return nil, fmt.Errorf("config_fragments: %q exceeds %d byte cap", uri, maxFragmentBytes)
		}

		// Checked on EVERY cycle, before the cache-hit branch: a pin added/rotated
		// to quarantine already-applied content must take effect immediately.
		if expected, pinned := cfg.fragmentChecksum(uri); pinned && expected != etag {
			return nil, fmt.Errorf("config_fragments: %q failed integrity check (expected %q, got %q)", uri, expected, etag)
		}

		var frag *FragmentConfig
		if prev != nil && etag == prevETag {
			// Unchanged since the last successful apply — reuse the cached
			// parse, whether the fetcher skipped the body fetch (data == nil,
			// the cheap S3-HeadObject-style path) or returned it anyway
			// (e.g. a local file, re-read every cycle but unchanged).
			frag = prev.parsed
		} else {
			if data == nil {
				return nil, fmt.Errorf("config_fragments: %q: fetch returned no data for a changed fragment", uri)
			}
			frag, err = parseFragment(data, FormatFromPath(uri), uri)
			if err != nil {
				return nil, err
			}
		}

		if err := mergeFragment(cfg, frag, uri, baseIssuers); err != nil {
			return nil, err
		}

		next[uri] = &cachedFragment{etag: etag, parsed: frag}
		totalMappings += len(frag.RoleMappings)
		for _, g := range frag.RoleGroups {
			totalMappings += len(g.Subjects)
		}
	}

	if totalMappings > fragmentMappingSoftCap {
		slog.Warn("config_fragments: merged mapping count exceeds soft cap",
			slog.Int("total_mappings", totalMappings),
			slog.Int("soft_cap", fragmentMappingSoftCap),
			slog.Int("fragment_count", len(cfg.ConfigFragments)))
	}
	slog.Info("config_fragments merged",
		slog.Int("fragment_count", len(cfg.ConfigFragments)),
		slog.Int("total_mappings", totalMappings))

	return next, nil
}

// fetchFragment reads local paths directly; remote URIs go through the
// injected FragmentFetchFunc (nil is a hard error, never silently skipped).
func (p *Provider) fetchFragment(ctx context.Context, uri, prevETag string) ([]byte, string, error) {
	if !isRemoteFragment(uri) {
		return readLocalFragment(uri)
	}
	if p.fragmentFetch == nil {
		return nil, "", fmt.Errorf("%q requires a fragment fetcher (none configured)", uri)
	}
	return p.fragmentFetch(ctx, uri, prevETag)
}

// cloneConfig deep-copies a Config via a JSON round-trip. Unexported caches
// (compiled regex, estimatedRolesPerRepo) aren't copied; Validate() rebuilds them.
func cloneConfig(c *Config) (*Config, error) {
	data, err := json.Marshal(c)
	if err != nil {
		return nil, err
	}
	var clone Config
	if err := json.Unmarshal(data, &clone); err != nil {
		return nil, err
	}
	return &clone, nil
}
