package cache

import (
	"log/slog"
	"sync"
	"time"

	"github.com/boogy/aws-oidc-warden/pkg/types"
)

type memoryCache struct {
	data       map[string]cacheItem
	mu         sync.RWMutex
	maxSize    int           // Maximum number of items to store
	defaultTTL time.Duration // Default TTL for cache entries
}

type cacheItem struct {
	value      *types.JWKS
	expiration time.Time
	lastAccess time.Time // For LRU eviction
	createdAt  time.Time // For monitoring/debugging
}

func NewMemoryCache() Cache {
	return &memoryCache{
		data:       make(map[string]cacheItem),
		maxSize:    Defaults.MaxLocalSize,
		defaultTTL: Defaults.TTL,
	}
}

func (c *memoryCache) Get(key string) (*types.JWKS, bool) {
	c.mu.RLock()
	item, found := c.data[key]
	c.mu.RUnlock()

	if !found {
		slog.Debug("Cache miss", "key", key)
		return nil, false
	}

	// Check if expired
	if time.Now().After(item.expiration) {
		slog.Debug("Cache entry expired", "key", key)

		// Remove expired item
		c.mu.Lock()
		delete(c.data, key)
		c.mu.Unlock()

		return nil, false
	}

	// Update last access time for LRU tracking
	c.mu.Lock()
	item.lastAccess = time.Now()
	c.data[key] = item
	c.mu.Unlock()

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

	// Check if we need to evict items
	if len(c.data) >= c.maxSize {
		c.evictLRU()
	}

	// Store item with metadata
	c.data[key] = cacheItem{
		value:      value,
		expiration: time.Now().Add(ttl),
		lastAccess: time.Now(),
		createdAt:  time.Now(),
	}

	slog.Debug("Cached value", "key", key, "ttl", ttl)
}

// evictLRU removes the least recently used item from the cache
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

// Cleanup removes all expired items from the cache
func (c *memoryCache) Cleanup() {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	expiredCount := 0

	// Find and remove expired items
	for key, item := range c.data {
		if now.After(item.expiration) {
			delete(c.data, key)
			expiredCount++
		}
	}

	if expiredCount > 0 {
		slog.Debug("Cleaned up expired cache entries", "count", expiredCount)
	}
}

// GetStats returns statistics about the cache
func (c *memoryCache) GetStats() map[string]interface{} {
	c.mu.RLock()
	defer c.mu.RUnlock()

	stats := map[string]interface{}{
		"size":    len(c.data),
		"maxSize": c.maxSize,
	}

	// Count expired items
	now := time.Now()
	expired := 0

	for _, item := range c.data {
		if now.After(item.expiration) {
			expired++
		}
	}

	stats["expired"] = expired

	return stats
}
