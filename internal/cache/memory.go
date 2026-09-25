package cache

import (
	"context"
	"log/slog"
	"time"

	"github.com/boogy/aws-oidc-warden/internal/logevent"
	"github.com/boogy/aws-oidc-warden/internal/types"
)

// memoryCache is the local LRU tier used on its own, with no remote store.
type memoryCache struct {
	local *localCache
}

// MemoryCacheOption is a function that configures the memory cache
type MemoryCacheOption func(*memoryCache)

// WithMemoryMaxSize sets the maximum number of items in the cache
func WithMemoryMaxSize(size int) MemoryCacheOption {
	return func(c *memoryCache) {
		if size > 0 {
			c.local.maxSize = size
		}
	}
}

// WithMemoryDefaultTTL sets the default TTL for cache entries
func WithMemoryDefaultTTL(ttl time.Duration) MemoryCacheOption {
	return func(c *memoryCache) {
		if ttl > 0 {
			c.local.defaultTTL = ttl
		}
	}
}

func NewMemoryCache(opts ...MemoryCacheOption) Cache {
	c := &memoryCache{local: newLocalCache(Defaults.MaxLocalSize, Defaults.TTL, backendMemory)}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

func (c *memoryCache) Get(ctx context.Context, key string) (*types.JWKS, bool) {
	value, lookup := c.local.get(key)
	switch lookup {
	case localMiss:
		logevent.Debug(ctx, nil, logevent.CacheMiss, "cache miss", cacheAttrs(backendMemory, key)...)
		return nil, false
	case localExpired:
		logevent.Debug(ctx, nil, logevent.CacheExpired, "cache entry expired", cacheAttrs(backendMemory, key)...)
		return nil, false
	}

	logevent.Debug(ctx, nil, logevent.CacheHit, "cache hit", cacheAttrs(backendMemory, key)...)
	return value, true
}

func (c *memoryCache) Set(ctx context.Context, key string, value *types.JWKS, ttl time.Duration) {
	if ttl <= 0 {
		ttl = c.local.defaultTTL
	}
	c.local.put(ctx, key, value, time.Now().Add(ttl))

	logevent.Debug(ctx, nil, logevent.CacheSet, "cache entry set",
		cacheAttrs(backendMemory, key, slog.Int64("ttlMs", ttl.Milliseconds()))...)
}
