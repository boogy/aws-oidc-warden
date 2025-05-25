package cache

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/boogy/aws-oidc-warden/types"
)

// s3Cache implements the Cache interface using an S3 bucket
type s3Cache struct {
	client       *s3.Client
	bucketName   string
	prefix       string
	clientMu     sync.RWMutex             // Protects client during refresh operations
	memCache     map[string]*s3CacheEntry // Local in-memory cache for frequently accessed items
	memCacheMu   sync.RWMutex             // Protects the in-memory cache
	maxLocalSize int                      // Maximum number of items in local cache
	defaultTTL   time.Duration            // Default TTL for cache items
}

// s3CacheEntry  represents an item in the local memory cache
type s3CacheEntry struct {
	value      *types.JWKS
	expiration time.Time
	lastAccess time.Time // Used for LRU eviction
}

// s3CacheItem wraps the JWKS value with metadata for caching
type s3CacheItem struct {
	Value      *types.JWKS `json:"value"`
	Expiration time.Time   `json:"expiration"`
	CreatedAt  time.Time   `json:"created_at"`
	Size       int         `json:"size,omitempty"` // Size in bytes for monitoring
}

// s3CacheOptions configures the S3 cache behavior
type s3CacheOptions struct {
	maxLocalSize int           // Maximum number of items in local memory cache
	defaultTTL   time.Duration // Default TTL when not specified
	awsConfig    aws.Config    // Optional AWS configuration
}

// S3CacheOption is a function that configures the S3 cache
type S3CacheOption func(*s3CacheOptions)

// WithMaxLocalSize sets the maximum size of the local memory cache
func WithMaxLocalSize(size int) S3CacheOption {
	return func(o *s3CacheOptions) {
		o.maxLocalSize = size
	}
}

// WithDefaultTTL sets the default TTL for cache items
func WithDefaultTTL(ttl time.Duration) S3CacheOption {
	return func(o *s3CacheOptions) {
		o.defaultTTL = ttl
	}
}

// WithAWSConfig sets a custom AWS configuration
func WithAWSConfig(cfg aws.Config) S3CacheOption {
	return func(o *s3CacheOptions) {
		o.awsConfig = cfg
	}
}

// NewS3Cache creates a new S3 cache with the given client and bucket
func NewS3Cache(bucketName, prefix string, opts ...S3CacheOption) (Cache, error) {
	// Default options
	options := &s3CacheOptions{
		maxLocalSize: Defaults.MaxLocalSize,
		defaultTTL:   Defaults.TTL,
	}

	// Apply options
	for _, opt := range opts {
		opt(options)
	}

	var cfg aws.Config
	var err error

	// Use provided AWS config or load default
	if options.awsConfig.Credentials != nil {
		cfg = options.awsConfig
	} else {
		cfg, err = config.LoadDefaultConfig(context.TODO(),
			config.WithRetryMaxAttempts(Defaults.MaxRetries),
		)
		if err != nil {
			slog.Error("Failed to load AWS config", "error", err.Error())
			return nil, fmt.Errorf("failed to load AWS config: %w", err)
		}
	}

	client := s3.NewFromConfig(cfg)
	if client == nil {
		slog.Error("Failed to create S3 client")
		return nil, errors.New("failed to create S3 client")
	}

	return &s3Cache{
		client:       client,
		bucketName:   bucketName,
		prefix:       prefix,
		memCache:     make(map[string]*s3CacheEntry),
		maxLocalSize: options.maxLocalSize,
		defaultTTL:   options.defaultTTL,
	}, nil
}

// Get retrieves an item from the S3 cache
func (c *s3Cache) Get(key string) (*types.JWKS, bool) {
	// Try to get from local memory cache first
	if jwks, found := c.getFromLocalCache(key); found {
		slog.Debug("Local memory cache hit", "key", key)
		return jwks, true
	}

	// Not in local cache, try S3
	jwks, found := c.getFromS3(key)
	if found {
		// Store in local cache for faster future access
		c.storeInLocalCache(key, jwks, time.Time{}) // Time will be extracted from the S3 metadata
		return jwks, true
	}

	return nil, false
}

// getFromLocalCache checks the local memory cache
func (c *s3Cache) getFromLocalCache(key string) (*types.JWKS, bool) {
	c.memCacheMu.RLock()
	entry, found := c.memCache[key]
	c.memCacheMu.RUnlock()

	if !found {
		return nil, false
	}

	// Check if expired
	if time.Now().After(entry.expiration) {
		c.memCacheMu.Lock()
		delete(c.memCache, key)
		c.memCacheMu.Unlock()
		return nil, false
	}

	// Update last access time for LRU
	c.memCacheMu.Lock()
	entry.lastAccess = time.Now()
	c.memCacheMu.Unlock()

	return entry.value, true
}

// getFromS3 retrieves an item from S3
func (c *s3Cache) getFromS3(key string) (*types.JWKS, bool) {
	objectKey := c.formatKey(key)

	ctx, cancel := context.WithTimeout(context.Background(), Defaults.Timeout)
	defer cancel()

	c.clientMu.RLock()
	client := c.client
	c.clientMu.RUnlock()

	resp, err := client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(c.bucketName),
		Key:    aws.String(objectKey),
		// Add size limit for security
		Range: aws.String(fmt.Sprintf("bytes=0-%d", Defaults.S3MaxObjectSize)),
	})

	if err != nil {
		var noSuchKey *s3types.NoSuchKey
		if errors.As(err, &noSuchKey) {
			slog.Debug("Cache miss in S3", "key", key)
			return nil, false
		}

		slog.Error("Failed to get object from S3", "key", key, "error", err)
		return nil, false
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			slog.Error("Error closing S3 response body", "error", err)
		}
	}()

	// Check content length for safety
	if resp.ContentLength != nil && *resp.ContentLength > Defaults.MaxItemSize {
		slog.Warn("S3 cache item exceeds maximum allowed size",
			"key", key,
			"size", *resp.ContentLength,
			"maxAllowed", Defaults.MaxItemSize)
		return nil, false
	}

	// Limit read size regardless of content length header
	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, Defaults.MaxItemSize))
	if err != nil {
		slog.Error("Failed to read S3 object body", "key", key, "error", err)
		return nil, false
	}

	var item s3CacheItem
	if err := json.Unmarshal(bodyBytes, &item); err != nil {
		slog.Error("Failed to decode S3 cache item", "key", key, "error", err)
		return nil, false
	}

	if time.Now().After(item.Expiration) {
		slog.Debug("S3 cache entry expired", "key", key)
		// Delete the expired object asynchronously
		go c.deleteObject(objectKey)
		return nil, false
	}

	slog.Debug("S3 cache hit", "key", key)
	return item.Value, true
}

// Set stores an item in the S3 cache with the given TTL
func (c *s3Cache) Set(key string, value *types.JWKS, ttl time.Duration) {
	if ttl <= 0 {
		ttl = c.defaultTTL
	}

	// Store in local cache first for fast access
	c.storeInLocalCache(key, value, time.Now().Add(ttl))

	// Then store in S3 for persistence
	go c.storeInS3(key, value, ttl)
}

// storeInLocalCache adds or updates an item in the local memory cache
func (c *s3Cache) storeInLocalCache(key string, value *types.JWKS, expiration time.Time) {
	c.memCacheMu.Lock()
	defer c.memCacheMu.Unlock()

	// If the expiration time wasn't specified, use default
	if expiration.IsZero() {
		expiration = time.Now().Add(c.defaultTTL)
	}

	// Check if we need to evict items
	if len(c.memCache) >= c.maxLocalSize {
		c.evictLRU()
	}

	c.memCache[key] = &s3CacheEntry{
		value:      value,
		expiration: expiration,
		lastAccess: time.Now(),
	}
}

// evictLRU removes the least recently used item from cache
func (c *s3Cache) evictLRU() {
	var oldestKey string
	var oldestTime time.Time

	// Find the oldest accessed item
	for k, entry := range c.memCache {
		if oldestTime.IsZero() || entry.lastAccess.Before(oldestTime) {
			oldestKey = k
			oldestTime = entry.lastAccess
		}
	}

	// Remove it
	if oldestKey != "" {
		delete(c.memCache, oldestKey)
	}
}

// storeInS3 persists an item to S3
func (c *s3Cache) storeInS3(key string, value *types.JWKS, ttl time.Duration) {
	objectKey := c.formatKey(key)

	item := s3CacheItem{
		Value:      value,
		Expiration: time.Now().Add(ttl),
		CreatedAt:  time.Now(),
	}

	data, err := json.Marshal(item)
	if err != nil {
		slog.Error("Failed to marshal cache item", "key", key, "error", err)
		return
	}

	// Check size before uploading
	if int64(len(data)) > Defaults.S3MaxObjectSize {
		slog.Error("Cache item too large to store in S3",
			"key", key,
			"size", len(data),
			"maxAllowed", Defaults.S3MaxObjectSize)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), Defaults.Timeout)
	defer cancel()

	c.clientMu.RLock()
	client := c.client
	c.clientMu.RUnlock()

	_, err = client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:      aws.String(c.bucketName),
		Key:         aws.String(objectKey),
		Body:        bytes.NewReader(data),
		ContentType: aws.String("application/json"),
		Metadata: map[string]string{
			"Expiration": item.Expiration.Format(time.RFC3339),
			"CreatedAt":  item.CreatedAt.Format(time.RFC3339),
			"Size":       fmt.Sprintf("%d", len(data)),
		},
		CacheControl: aws.String("max-age=900"), // 15 minutes cache
	})

	if err != nil {
		slog.Error("Failed to put object in S3", "key", key, "error", err)
		return
	}

	slog.Debug("Cached value in S3", "key", key, "ttl", ttl, "size", len(data))
}

// formatKey creates a consistent S3 object key from the cache key
func (c *s3Cache) formatKey(key string) string {
	if c.prefix == "" {
		return key
	}
	return fmt.Sprintf("%s/%s", c.prefix, key)
}

// deleteObject removes an expired object from S3
func (c *s3Cache) deleteObject(key string) {
	ctx, cancel := context.WithTimeout(context.Background(), Defaults.Timeout)
	defer cancel()

	c.clientMu.RLock()
	client := c.client
	c.clientMu.RUnlock()

	_, err := client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(c.bucketName),
		Key:    aws.String(key),
	})

	if err != nil {
		slog.Error("Failed to delete expired object from S3", "key", key, "error", err)
	} else {
		slog.Debug("Deleted expired object from S3", "key", key)
	}
}

// RefreshClient recreates the S3 client - useful for Lambda environments
// where clients might need refreshing for long-running instances
func (c *s3Cache) RefreshClient() error {
	cfg, err := config.LoadDefaultConfig(context.TODO(),
		config.WithRetryMaxAttempts(Defaults.MaxRetries),
	)
	if err != nil {
		slog.Error("Failed to refresh AWS config for S3 cache", "error", err)
		return fmt.Errorf("failed to refresh AWS config: %w", err)
	}

	newClient := s3.NewFromConfig(cfg)

	c.clientMu.Lock()
	c.client = newClient
	c.clientMu.Unlock()

	slog.Info("Refreshed S3 client for cache")
	return nil
}

// cleanupLocalCache removes expired items from local cache
// func (c *s3Cache) cleanupLocalCache() {
// 	c.memCacheMu.Lock()
// 	defer c.memCacheMu.Unlock()

// 	now := time.Now()
// 	for key, entry := range c.memCache {
// 		if now.After(entry.expiration) {
// 			delete(c.memCache, key)
// 			slog.Debug("Removed expired item from local cache", "key", key)
// 		}
// 	}
// }
