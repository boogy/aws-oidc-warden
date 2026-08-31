package cache

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
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

// localCache is the in-process LRU tier every backend keeps in front of its
// remote store (and the whole of the memory backend). Every method takes mu
// itself; callers hold no lock.
type localCache struct {
	mu         sync.Mutex
	entries    map[string]*localEntry
	maxSize    int
	defaultTTL time.Duration
}

func newLocalCache(maxSize int, defaultTTL time.Duration) *localCache {
	return &localCache{
		entries:    make(map[string]*localEntry),
		maxSize:    maxSize,
		defaultTTL: defaultTTL,
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
func (c *localCache) put(key string, value *types.JWKS, expiration time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if expiration.IsZero() {
		expiration = time.Now().Add(c.defaultTTL)
	}

	// Evict only when adding a new key at capacity; overwrites don't grow the map
	if _, exists := c.entries[key]; !exists && len(c.entries) >= c.maxSize {
		c.evictLRU()
	}

	c.entries[key] = &localEntry{
		value:      value,
		expiration: expiration,
		lastAccess: time.Now(),
	}
}

// evictLRU removes the least recently used entry. Caller must hold c.mu.
func (c *localCache) evictLRU() {
	var oldestKey string
	var oldestTime time.Time

	for k, entry := range c.entries {
		if oldestTime.IsZero() || entry.lastAccess.Before(oldestTime) {
			oldestKey = k
			oldestTime = entry.lastAccess
		}
	}

	if oldestKey != "" {
		slog.Debug("Evicting LRU cache item", "key", oldestKey, "lastAccess", oldestTime)
		delete(c.entries, oldestKey)
	}
}

// resolveAWSConfig returns the caller-supplied AWS config, or loads the
// default one. label names the backend in the error log.
func resolveAWSConfig(supplied aws.Config, label string) (aws.Config, error) {
	if supplied.Credentials != nil {
		return supplied, nil
	}
	cfg, err := config.LoadDefaultConfig(context.Background(),
		config.WithRetryMaxAttempts(Defaults.MaxRetries),
	)
	if err != nil {
		slog.Error("Failed to load AWS config for "+label, "error", err.Error())
		return aws.Config{}, fmt.Errorf("failed to load AWS config: %w", err)
	}
	return cfg, nil
}
