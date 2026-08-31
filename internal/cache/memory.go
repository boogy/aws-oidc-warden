package cache

import (
	"log/slog"
	"time"

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
	c := &memoryCache{local: newLocalCache(Defaults.MaxLocalSize, Defaults.TTL)}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

func (c *memoryCache) Get(key string) (*types.JWKS, bool) {
	value, lookup := c.local.get(key)
	switch lookup {
	case localMiss:
		slog.Debug("Cache miss", "key", key)
		return nil, false
	case localExpired:
		slog.Debug("Cache entry expired", "key", key)
		return nil, false
	}

	slog.Debug("Cache hit", "key", key)
	return value, true
}

func (c *memoryCache) Set(key string, value *types.JWKS, ttl time.Duration) {
	if ttl <= 0 {
		ttl = c.local.defaultTTL
	}
	c.local.put(key, value, time.Now().Add(ttl))

	slog.Debug("Cached value", "key", key, "ttl", ttl)
}
