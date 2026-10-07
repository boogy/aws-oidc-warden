package config

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/boogy/aws-oidc-warden/internal/logevent"
)

// FetchFunc retrieves the raw configuration bytes from a remote source.
type FetchFunc func(context.Context) ([]byte, error)

// FragmentFetchFunc fetches a fragment; (nil, prevETag, nil) means unchanged, and etag must be content-derived.
type FragmentFetchFunc func(ctx context.Context, uri, prevETag, owner string) (data []byte, etag string, err error)

// cachedFragment is the last applied parse of one config_fragments entry.
type cachedFragment struct {
	etag   string
	parsed *FragmentConfig
}

// fragmentMappingSoftCap: exceeding it only logs a warning, never blocks a reload.
const fragmentMappingSoftCap = 5000

// refreshTimeout caps a request-triggered refresh, which outlives its caller's cancellation.
const refreshTimeout = 30 * time.Second

// staleRetryInterval is the attempt spacing while stale, when shorter than the reload interval.
const staleRetryInterval = 10 * time.Second

// staleWaitTimeout caps how long a stale request waits on an in-flight refresh before failing fast.
var staleWaitTimeout = 5 * time.Second

// ProviderOption configures optional Provider behavior at construction.
type ProviderOption func(*Provider)

// WithFragmentFetcher installs the fetcher for "scheme://" fragments; without one, remote fragments fail the refresh.
func WithFragmentFetcher(fetch FragmentFetchFunc) ProviderOption {
	return func(p *Provider) { p.fragmentFetch = fetch }
}

// Provider serves the active configuration and lazily refreshes it, swapping atomically from a pristine base.
type Provider struct {
	current       atomic.Pointer[Config]
	base          *Config      // pristine env/file/defaults config, cloned on each refresh
	interval      atomic.Int64 // nanoseconds; <= 0 means disabled
	format        string       // viper config type ("json"/"yaml"/"toml")
	lastRefresh   atomic.Int64 // unix nanos of last successful refresh; 0 = never
	lastAttempt   atomic.Int64 // unix nanos of last refresh attempt, success or failure; 0 = never
	failures      atomic.Int32 // consecutive failed attempts
	now           func() time.Time
	sem           chan struct{}              // 1-slot lock serializing refreshes; a channel so stale callers can wait with ctx
	fetch         FetchFunc                  // nil if there's no primary remote/S3 config overlay
	fragmentFetch FragmentFetchFunc          // nil if no remote ("scheme://") fragments are configured
	fragments     map[string]*cachedFragment // last-applied fragment cache; only touched under sem (in refreshLocked)
	frozenIdP     *IdPConfig                 // idp config the running service was built from; guarded by sem
	built         bool                       // a refresh has fully applied overlaySum and fragments; guarded by sem
	overlaySum    [sha256.Size]byte          // digest of base + overlay bytes behind current; guarded by sem
}

// NewStaticProvider returns a Provider that always serves cfg and never reloads.
func NewStaticProvider(cfg *Config, opts ...ProviderOption) *Provider {
	p := &Provider{base: cfg, now: time.Now, sem: make(chan struct{}, 1), fragments: make(map[string]*cachedFragment)}
	for _, opt := range opts {
		opt(p)
	}
	p.current.Store(cfg)
	return p
}

// NewProvider returns a reloadable Provider; interval <= 0 disables reloading and format defaults to "json".
func NewProvider(base *Config, interval time.Duration, format string, fetch FetchFunc, opts ...ProviderOption) *Provider {
	p := &Provider{base: base, format: format, fetch: fetch, now: time.Now, sem: make(chan struct{}, 1), fragments: make(map[string]*cachedFragment)}
	for _, opt := range opts {
		opt(p)
	}
	p.interval.Store(int64(interval))
	p.current.Store(base)
	return p
}

// FreezeIdP records the IdP config the running service was built from.
func (p *Provider) FreezeIdP(c *IdPConfig) {
	p.lock()
	defer p.unlock()
	p.frozenIdP = c
	p.built = false
}

// Get returns the currently active configuration.
func (p *Provider) Get() *Config {
	return p.current.Load()
}

// MaybeRefresh reloads once the interval or failure backoff has elapsed; while stale it waits for an in-flight refresh.
func (p *Provider) MaybeRefresh(ctx context.Context) { p.maybeRefresh(ctx, true) }

// RefreshIfDue is MaybeRefresh that never waits for an in-flight refresh.
func (p *Provider) RefreshIfDue(ctx context.Context) { p.maybeRefresh(ctx, false) }

func (p *Provider) maybeRefresh(ctx context.Context, waitIfStale bool) {
	if !p.refreshable() {
		return
	}
	interval := time.Duration(p.interval.Load())
	if interval <= 0 {
		return
	}
	_, _, stale := p.Stale()
	if !stale && !p.due(interval, false) {
		return
	}
	// After a failure the refresh is likely to fail again; do not queue requests behind it.
	if stale && waitIfStale && p.failures.Load() == 0 {
		wctx, cancel := context.WithTimeout(ctx, staleWaitTimeout)
		locked := p.lockCtx(wctx)
		cancel()
		if !locked {
			return
		}
	} else if !p.tryLock() {
		return
	}
	defer p.unlock()
	_, _, stale = p.Stale()
	if !p.due(interval, stale) {
		return
	}
	rctx, cancel, callerBound := detach(ctx)
	defer cancel()
	if err := p.attemptLocked(rctx, callerBound); err != nil {
		logevent.Error(ctx, nil, logevent.ConfigReloadFailure, "configuration refresh failed; keeping previous configuration", slog.String("error", err.Error()))
	}
}

// due reports whether the interval, stretched 2x/4x/8x by consecutive failures, has elapsed since the last attempt; while stale it is at most staleRetryInterval.
func (p *Provider) due(interval time.Duration, stale bool) bool {
	last := p.lastAttempt.Load()
	if last == 0 {
		return true
	}
	wait := interval << min(p.failures.Load(), 3)
	if stale {
		wait = min(interval, staleRetryInterval)
	}
	return p.now().UnixNano()-last >= int64(wait)
}

func (p *Provider) lock()   { p.sem <- struct{}{} }
func (p *Provider) unlock() { <-p.sem }

func (p *Provider) tryLock() bool {
	select {
	case p.sem <- struct{}{}:
		return true
	default:
		return false
	}
}

func (p *Provider) lockCtx(ctx context.Context) bool {
	if p.tryLock() {
		return true
	}
	select {
	case p.sem <- struct{}{}:
		return true
	case <-ctx.Done():
		return false
	}
}

// detach keeps a refresh running when its caller goes away, bounded by the caller's deadline and refreshTimeout; callerBound reports the caller's deadline won.
func detach(ctx context.Context) (context.Context, context.CancelFunc, bool) {
	deadline := time.Now().Add(refreshTimeout)
	d, ok := ctx.Deadline()
	callerBound := ok && d.Before(deadline)
	if callerBound {
		deadline = d
	}
	rctx, cancel := context.WithDeadline(context.WithoutCancel(ctx), deadline)
	return rctx, cancel, callerBound
}

// attemptLocked runs one refresh and records it for backoff; a caller-imposed ctx end is not a failure. Must be called with p.sem held.
func (p *Provider) attemptLocked(ctx context.Context, callerBound bool) error {
	p.lastAttempt.Store(p.now().UnixNano())
	err := p.refreshLocked(ctx)
	switch {
	case err == nil:
		p.failures.Store(0)
	case callerBound && ctx.Err() != nil:
	default:
		p.failures.Add(1)
	}
	return err
}

// Refresh fetches, validates and swaps in a new config; on error the active config is unchanged.
func (p *Provider) Refresh(ctx context.Context) error {
	if !p.refreshable() {
		return errors.New("no configuration fetch source configured")
	}
	p.lock()
	defer p.unlock()
	return p.attemptLocked(ctx, true)
}

// refreshLocked performs the fetch, merge and swap. Must be called with p.sem held.
func (p *Provider) refreshLocked(ctx context.Context) error {
	baseJSON, err := json.Marshal(p.base)
	if err != nil {
		return fmt.Errorf("failed to clone base configuration: %w", err)
	}
	var data []byte
	if p.fetch != nil {
		if data, err = p.fetch(ctx); err != nil {
			return fmt.Errorf("failed to fetch configuration: %w", err)
		}
	}
	// The digest covers the base too, so a changed base is never skipped.
	h := sha256.New()
	h.Write(baseJSON)
	h.Write([]byte{0})
	h.Write(data)
	var sum [sha256.Size]byte
	h.Sum(sum[:0])

	// Same overlay bytes and fragment etags: a rebuild would reproduce current.
	var probed map[string]fetchedFragment
	if p.built && sum == p.overlaySum {
		var unchanged bool
		unchanged, probed, err = p.fragmentsUnchanged(ctx, p.current.Load())
		if err != nil {
			return fmt.Errorf("failed to apply config fragments: %w", err)
		}
		if unchanged {
			p.lastRefresh.Store(p.now().UnixNano())
			return nil
		}
	}

	cfg := new(Config)
	if err := json.Unmarshal(baseJSON, cfg); err != nil {
		return fmt.Errorf("failed to clone base configuration: %w", err)
	}

	if p.fetch != nil {
		if err := cfg.MergeBytes(data, p.format); err != nil {
			return fmt.Errorf("invalid configuration after reload: %w", err)
		}
		cfg.S3ConfigBucketOwner = p.base.S3ConfigBucketOwner
		cfg.SessionPolicyBucketOwner = p.base.SessionPolicyBucketOwner
		cfg.MaxConfigBytes = p.base.MaxConfigBytes
		if err := cfg.validateS3ConfigOwner(); err != nil {
			return fmt.Errorf("invalid configuration after reload: %w", err)
		}
	} else if err := cfg.Validate(); err != nil {
		// No primary overlay: still rebuild transient state cloneConfig doesn't copy.
		return fmt.Errorf("invalid base configuration: %w", err)
	}

	if err := cfg.validateMappingsSplit(); err != nil {
		return fmt.Errorf("invalid base configuration: %w", err)
	}

	nextFragments, err := p.applyFragments(ctx, cfg, probed)
	if err != nil {
		return fmt.Errorf("failed to apply config fragments: %w", err)
	}
	if len(cfg.fragmentSources()) > 0 {
		if err := cfg.Validate(); err != nil {
			return fmt.Errorf("invalid configuration after fragment merge: %w", err)
		}
	}

	if p.frozenIdP != nil {
		if err := p.frozenIdP.checkInbound(cfg.Issuers); err != nil {
			logevent.Error(ctx, nil, logevent.ConfigIdPIssuerCollision, "reload rejected: inbound issuers conflict with the frozen idp config",
				slog.String("issuer", p.frozenIdP.Issuer), slog.String("error", err.Error()))
			return err
		}
	}

	if cfg.ConfigReloadInterval <= 0 {
		cfg.ConfigReloadInterval = time.Duration(p.interval.Load())
	}

	p.current.Store(cfg)
	p.fragments = nextFragments
	p.overlaySum, p.built = sum, true
	p.lastRefresh.Store(p.now().UnixNano())

	// Propagate a changed interval so operators can adjust polling without a cold start.
	if cfg.ConfigReloadInterval > 0 {
		p.interval.Store(int64(cfg.ConfigReloadInterval))
	}

	logevent.Info(ctx, nil, logevent.ConfigReloadSuccess, "configuration reloaded",
		slog.Int("roleMappings", len(cfg.effective)),
		slog.Int("fragments", len(cfg.fragmentSources())))
	return nil
}

// fragmentsUnchanged reports whether every fragment still has its applied etag, returning the fetches for reuse.
func (p *Provider) fragmentsUnchanged(ctx context.Context, cur *Config) (bool, map[string]fetchedFragment, error) {
	sources := cur.fragmentSources()
	if len(sources) != len(p.fragments) {
		return false, nil, nil
	}
	unchanged := true
	fetched := make(map[string]fetchedFragment, len(sources))
	for _, uri := range sources {
		prev := p.fragments[uri]
		if prev == nil {
			return false, fetched, nil
		}
		data, etag, err := p.fetchFragment(ctx, uri, prev.etag, cur.S3ConfigBucketOwner)
		if err != nil {
			return false, nil, fmt.Errorf("config_fragments: %w", err)
		}
		if err := cur.checkFragment(uri, data, etag); err != nil {
			return false, nil, err
		}
		fetched[uri] = fetchedFragment{data: data, etag: etag}
		if etag != prev.etag {
			unchanged = false
		}
	}
	return unchanged, fetched, nil
}

// checkFragment enforces the size cap and checksum pin on one fetched fragment.
func (c *Config) checkFragment(uri string, data []byte, etag string) error {
	if limit := c.EffectiveMaxConfigBytes(); len(data) > limit {
		return fmt.Errorf("config_fragments: %q exceeds %d byte cap", uri, limit)
	}
	if expected, pinned := c.fragmentChecksum(uri); pinned && expected != etag {
		return fmt.Errorf("config_fragments: %q failed integrity check (expected %q, got %q)", uri, expected, etag)
	}
	return nil
}

// fetchedFragment is one fragment read already made during this refresh.
type fetchedFragment struct {
	data []byte
	etag string
}

// applyFragments merges every fragment onto cfg in list order; the caller commits the returned cache only on success.
func (p *Provider) applyFragments(ctx context.Context, cfg *Config, probed map[string]fetchedFragment) (map[string]*cachedFragment, error) {
	sources := cfg.fragmentSources()
	if len(sources) == 0 {
		return nil, nil
	}

	baseIssuers := make(map[string]bool, len(cfg.Issuers))
	for _, iss := range cfg.Issuers {
		baseIssuers[iss.Issuer] = true
	}

	next := make(map[string]*cachedFragment, len(sources))
	totalMappings := len(cfg.RoleMappings)
	for _, g := range cfg.RoleGroups {
		totalMappings += len(g.Subjects)
	}

	for _, uri := range sources {
		prev := p.fragments[uri]
		prevETag := ""
		if prev != nil {
			prevETag = prev.etag
		}

		var data []byte
		var etag string
		var err error
		if f, ok := probed[uri]; ok {
			data, etag = f.data, f.etag
		} else if data, etag, err = p.fetchFragment(ctx, uri, prevETag, cfg.S3ConfigBucketOwner); err != nil {
			return nil, fmt.Errorf("config_fragments: %w", err)
		}
		// Checked every cycle before the cache hit so a rotated pin takes effect immediately.
		if err := cfg.checkFragment(uri, data, etag); err != nil {
			return nil, err
		}

		var frag *FragmentConfig
		if prev != nil && etag == prevETag {
			// Unchanged since the last apply: reuse the cached parse.
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
		logevent.Warn(ctx, nil, logevent.ConfigFragmentsSoftCap, "config_fragments merged mapping count exceeds soft cap",
			slog.Int("totalMappings", totalMappings),
			slog.Int("softCap", fragmentMappingSoftCap),
			slog.Int("fragmentCount", len(sources)))
	}
	logevent.Info(ctx, nil, logevent.ConfigFragmentsMerged, "config_fragments merged",
		slog.Int("fragmentCount", len(sources)),
		slog.Int("totalMappings", totalMappings))

	return next, nil
}

// refreshable reports whether any reload source (remote config or fragments) is configured.
func (p *Provider) refreshable() bool {
	return p.fetch != nil || len(p.base.fragmentSources()) > 0
}

// Stale reports the last successful refresh's age against mappings_max_stale from one config snapshot.
func (p *Provider) Stale() (age, limit time.Duration, stale bool) {
	if !p.refreshable() {
		return 0, 0, false
	}
	limit = p.Get().effectiveMappingsMaxStale()
	if limit <= 0 {
		return 0, 0, false
	}
	last := p.lastRefresh.Load()
	if last == 0 {
		return 0, limit, true
	}
	age = p.now().Sub(time.Unix(0, last))
	return age, limit, age > limit
}

// fetchFragment reads local paths directly and remote URIs through the fragment fetcher.
func (p *Provider) fetchFragment(ctx context.Context, uri, prevETag, owner string) ([]byte, string, error) {
	if !isRemoteFragment(uri) {
		return readLocalFragment(uri, p.base.EffectiveMaxConfigBytes())
	}
	if p.fragmentFetch == nil {
		return nil, "", fmt.Errorf("%q requires a fragment fetcher (none configured)", uri)
	}
	return p.fragmentFetch(ctx, uri, prevETag, owner)
}

// cloneConfig deep-copies a Config via JSON; Validate() rebuilds the unexported caches.
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
