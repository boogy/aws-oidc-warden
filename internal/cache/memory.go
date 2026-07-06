package cache

import (
	"log/slog"
	"sync"
	"time"

	"github.com/boogy/aws-oidc-warden/internal/types"
)

type memoryCache struct {
	data       map[string]cacheItem
	mu         sync.Mutex
	maxSize    int           // Maximum number of items to store
	defaultTTL time.Duration // Default TTL for cache entries
}

type cacheItem struct {
	value      *types.JWKS
	expiration time.Time
	lastAccess time.Time // For LRU eviction
}

// MemoryCacheOption is a function that configures the memory cache
type MemoryCacheOption func(*memoryCache)

// WithMemoryMaxSize sets the maximum number of items in the cache
func WithMemoryMaxSize(size int) MemoryCacheOption {
	return func(c *memoryCache) {
		if size > 0 {
			c.maxSize = size
		}
	}
}

// WithMemoryDefaultTTL sets the default TTL for cache entries
func WithMemoryDefaultTTL(ttl time.Duration) MemoryCacheOption {
	return func(c *memoryCache) {
		if ttl > 0 {
			c.defaultTTL = ttl
		}
	}
}

func NewMemoryCache(opts ...MemoryCacheOption) Cache {
	c := &memoryCache{
		data:       make(map[string]cacheItem),
		maxSize:    Defaults.MaxLocalSize,
		defaultTTL: Defaults.TTL,
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

func (c *memoryCache) Get(key string) (*types.JWKS, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	item, found := c.data[key]
	if !found {
		slog.Debug("Cache miss", "key", key)
		return nil, false
	}

	if time.Now().After(item.expiration) {
		slog.Debug("Cache entry expired", "key", key)
		delete(c.data, key)
		return nil, false
	}

	// Update last access time for LRU tracking
	item.lastAccess = time.Now()
	c.data[key] = item

	slog.Debug("Cache hit", "key", key)
	return item.value, true
}

func (c *memoryCache) Set(key string, value *types.JWKS, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Use default TTL if not specified
	if ttl <= 0 {
		ttl = c.defaultTTL
	}

	// Evict only when adding a new key at capacity; overwrites don't grow the map
	if _, exists := c.data[key]; !exists && len(c.data) >= c.maxSize {
		c.evictLRU()
	}

	c.data[key] = cacheItem{
		value:      value,
		expiration: time.Now().Add(ttl),
		lastAccess: time.Now(),
	}

	slog.Debug("Cached value", "key", key, "ttl", ttl)
}

// evictLRU removes the least recently used item from the cache.
// Caller must hold c.mu.
func (c *memoryCache) evictLRU() {
	var oldestKey string
	var oldestTime time.Time

	// Find the oldest accessed item
	for k, entry := range c.data {
		if oldestTime.IsZero() || entry.lastAccess.Before(oldestTime) {
			oldestKey = k
			oldestTime = entry.lastAccess
		}
	}

	// Remove it
	if oldestKey != "" {
		slog.Debug("Evicting LRU cache item", "key", oldestKey, "lastAccess", oldestTime)
		delete(c.data, oldestKey)
	}
}
