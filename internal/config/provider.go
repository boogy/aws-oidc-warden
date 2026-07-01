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

// Provider holds the active configuration behind an atomic pointer and can
// lazily refresh it from a remote source without redeploying.
//
// Refresh semantics: each refresh starts from a clone of the pristine base
// config (env/file/defaults), overlays the freshly fetched bytes, re-validates
// (recompiling regex patterns), then atomically swaps the result in.
type Provider struct {
	current     atomic.Pointer[Config]
	base        *Config      // pristine env/file/defaults config, cloned on each refresh
	interval    atomic.Int64 // nanoseconds; <= 0 means disabled
	format      string       // viper config type ("json"/"yaml"/"toml")
	lastRefresh atomic.Int64 // unix nanos of last successful refresh; 0 = never
	now         func() time.Time
	mu          sync.Mutex // serializes refreshes
	fetch       FetchFunc  // nil for a static provider
}

// NewStaticProvider returns a Provider that always serves cfg and never reloads.
func NewStaticProvider(cfg *Config) *Provider {
	p := &Provider{base: cfg, now: time.Now}
	p.current.Store(cfg)
	return p
}

// NewProvider returns a reloadable Provider. base is the pristine config;
// fetch supplies remote bytes; interval is the minimum time between reloads
// (<= 0 disables reloading); format is the viper config type of the fetched
// bytes ("json"/"yaml"/"toml", empty defaults to "json"). The initial served
// config is base until the first successful Refresh.
func NewProvider(base *Config, interval time.Duration, format string, fetch FetchFunc) *Provider {
	p := &Provider{base: base, format: format, fetch: fetch, now: time.Now}
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

// MaybeRefresh reloads the configuration if reloading is enabled and the
// interval has elapsed since the last successful refresh. Uses double-checked
// locking to ensure at most one S3 fetch occurs per interval boundary under
// concurrent load. Errors are logged and the previous configuration is retained.
func (p *Provider) MaybeRefresh(ctx context.Context) {
	if p.fetch == nil {
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

	// Slow path: acquire lock and re-check before fetching.
	// This prevents N concurrent goroutines at an interval boundary from each
	// triggering a full S3 fetch; only the first one through does the work.
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
	if p.fetch == nil {
		return errors.New("no configuration fetch source configured")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.refreshLocked(ctx)
}

// refreshLocked performs the actual fetch+merge+swap. Must be called with p.mu held.
func (p *Provider) refreshLocked(ctx context.Context) error {
	data, err := p.fetch(ctx)
	if err != nil {
		return fmt.Errorf("failed to fetch configuration: %w", err)
	}

	cfg, err := cloneConfig(p.base)
	if err != nil {
		return fmt.Errorf("failed to clone base configuration: %w", err)
	}

	if err := cfg.MergeBytes(data, p.format); err != nil {
		return fmt.Errorf("invalid configuration after reload: %w", err)
	}

	p.current.Store(cfg)
	p.lastRefresh.Store(p.now().UnixNano())

	// Propagate a changed reload interval so operators can adjust polling
	// frequency via S3 config without a cold start.
	if cfg.ConfigReloadInterval > 0 {
		p.interval.Store(int64(cfg.ConfigReloadInterval))
	}

	slog.Info("Configuration reloaded", slog.Int("roleMappings", len(cfg.effective)))
	return nil
}

// cloneConfig deep-copies a Config via a JSON round-trip. Unexported caches
// (compiled regex patterns, estimatedRolesPerRepo) are not copied; they are
// rebuilt by the subsequent Validate().
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
