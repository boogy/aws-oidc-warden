package cache

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/boogy/aws-oidc-warden/internal/logevent"
	"github.com/boogy/aws-oidc-warden/internal/types"
)

// localEntry is one item in a localCache.
type localEntry struct {
	value      *types.JWKS
	expiration time.Time
	lastAccess time.Time
}

// localLookup is the outcome of a localCache.get, distinguishing an absent key
// from one dropped for being past its expiration.
type localLookup int

const (
	localMiss localLookup = iota
	localExpired
	localHit
)

// localCache is the in-process LRU tier in front of every backend; methods take mu themselves.
type localCache struct {
	mu         sync.Mutex
	entries    map[string]*localEntry
	maxSize    int
	defaultTTL time.Duration
	backend    string
}

func newLocalCache(maxSize int, defaultTTL time.Duration, backend string) *localCache {
	return &localCache{
		entries:    make(map[string]*localEntry),
		maxSize:    maxSize,
		defaultTTL: defaultTTL,
		backend:    backend,
	}
}

// get returns the live value for key, dropping it first if it has expired.
func (c *localCache) get(key string) (*types.JWKS, localLookup) {
	c.mu.Lock()
	defer c.mu.Unlock()

	entry, found := c.entries[key]
	if !found {
		return nil, localMiss
	}

	if time.Now().After(entry.expiration) {
		delete(c.entries, key)
		return nil, localExpired
	}

	entry.lastAccess = time.Now()
	return entry.value, localHit
}

// put stores value under key until expiration, evicting the least recently
// used entry first if a new key would exceed maxSize. A zero expiration means
// defaultTTL from now.
func (c *localCache) put(ctx context.Context, key string, value *types.JWKS, expiration time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if expiration.IsZero() {
		expiration = time.Now().Add(c.defaultTTL)
	}

	// Evict only when adding a new key at capacity; overwrites don't grow the map
	if _, exists := c.entries[key]; !exists && len(c.entries) >= c.maxSize {
		c.evictLRU(ctx)
	}

	c.entries[key] = &localEntry{
		value:      value,
		expiration: expiration,
		lastAccess: time.Now(),
	}
}

// evictLRU removes the least recently used entry. Caller must hold c.mu.
func (c *localCache) evictLRU(ctx context.Context) {
	var oldestKey string
	var oldestTime time.Time

	for k, entry := range c.entries {
		if oldestTime.IsZero() || entry.lastAccess.Before(oldestTime) {
			oldestKey = k
			oldestTime = entry.lastAccess
		}
	}

	if oldestKey != "" {
		logevent.Debug(ctx, nil, logevent.CacheEvict, "evicting LRU cache entry",
			cacheAttrs(c.backend, oldestKey, slog.Time("lastAccess", oldestTime))...)
		delete(c.entries, oldestKey)
	}
}

// resolveAWSConfig returns the caller-supplied AWS config, or loads the
// default one. backend labels the cache backend in the error log.
func resolveAWSConfig(ctx context.Context, supplied aws.Config, backend string) (aws.Config, error) {
	if supplied.Credentials != nil {
		return supplied, nil
	}
	cfg, err := config.LoadDefaultConfig(ctx,
		config.WithRetryMaxAttempts(Defaults.MaxRetries),
	)
	if err != nil {
		logevent.Error(ctx, nil, logevent.AppInitFailure, "failed to load AWS config",
			slog.String("component", "aws_config"), backendAttr(backend), slog.String("error", err.Error()))
		return aws.Config{}, fmt.Errorf("failed to load AWS config: %w", err)
	}
	return cfg, nil
}
