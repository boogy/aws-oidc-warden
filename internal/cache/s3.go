package cache

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/boogy/aws-oidc-warden/internal/logevent"
	"github.com/boogy/aws-oidc-warden/internal/types"
)

// s3API is the subset of the S3 client used by the cache,
// extracted as an interface for testability
type s3API interface {
	GetObject(ctx context.Context, params *s3.GetObjectInput, optFns ...func(*s3.Options)) (*s3.GetObjectOutput, error)
	PutObject(ctx context.Context, params *s3.PutObjectInput, optFns ...func(*s3.Options)) (*s3.PutObjectOutput, error)
	DeleteObject(ctx context.Context, params *s3.DeleteObjectInput, optFns ...func(*s3.Options)) (*s3.DeleteObjectOutput, error)
}

// s3Cache implements the Cache interface using an S3 bucket
type s3Cache struct {
	client     s3API
	bucketName string
	prefix     string
	cleanup    bool        // Delete expired objects discovered on read
	local      *localCache // Local tier in front of S3
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
	cleanup      bool          // Delete expired objects discovered on read
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

// WithS3Cleanup enables deletion of expired objects discovered on read
func WithS3Cleanup(cleanup bool) S3CacheOption {
	return func(o *s3CacheOptions) {
		o.cleanup = cleanup
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

	cfg, err := resolveAWSConfig(context.Background(), options.awsConfig, backendS3)
	if err != nil {
		return nil, err
	}

	return &s3Cache{
		client:     s3.NewFromConfig(cfg),
		bucketName: bucketName,
		prefix:     prefix,
		cleanup:    options.cleanup,
		local:      newLocalCache(options.maxLocalSize, options.defaultTTL, backendLocal),
	}, nil
}

// Get retrieves an item from the S3 cache
func (c *s3Cache) Get(ctx context.Context, key string) (*types.JWKS, bool) {
	// Try to get from local memory cache first
	if jwks, found := c.getFromLocalCache(key); found {
		logevent.Debug(ctx, nil, logevent.CacheHit, "cache hit", cacheAttrs(backendLocal, key)...)
		return jwks, true
	}

	// Not in local cache, try S3
	jwks, expiration, found := c.getFromS3(ctx, key)
	if found {
		// Store in local cache with the item's real expiration
		c.storeInLocalCache(ctx, key, jwks, expiration)
		return jwks, true
	}

	return nil, false
}

// getFromLocalCache checks the local memory cache
func (c *s3Cache) getFromLocalCache(key string) (*types.JWKS, bool) {
	value, lookup := c.local.get(key)
	return value, lookup == localHit
}

// getFromS3 retrieves an item from S3, returning the cached JWKS and its
// expiration time
func (c *s3Cache) getFromS3(ctx context.Context, key string) (*types.JWKS, time.Time, bool) {
	objectKey := c.formatKey(key)

	ctx, cancel := context.WithTimeout(ctx, Defaults.Timeout)
	defer cancel()

	resp, err := c.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(c.bucketName),
		Key:    aws.String(objectKey),
		// Bound the transfer; oversized objects are rejected below
		Range: aws.String(fmt.Sprintf("bytes=0-%d", Defaults.MaxItemSize)),
	})

	if err != nil {
		var noSuchKey *s3types.NoSuchKey
		if errors.As(err, &noSuchKey) {
			logevent.Debug(ctx, nil, logevent.CacheMiss, "cache miss", cacheAttrs(backendS3, key)...)
			return nil, time.Time{}, false
		}

		logevent.Error(ctx, nil, logevent.CacheReadFailure, "failed to get object from S3",
			cacheAttrs(backendS3, key, slog.String("error", err.Error()))...)
		return nil, time.Time{}, false
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			logevent.Error(ctx, nil, logevent.CacheReadFailure, "failed to close S3 response body",
				cacheAttrs(backendS3, key, slog.String("error", err.Error()))...)
		}
	}()

	// Read at most one byte over the limit so truncation is detectable
	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, Defaults.MaxItemSize+1))
	if err != nil {
		logevent.Error(ctx, nil, logevent.CacheReadFailure, "failed to read S3 object body",
			cacheAttrs(backendS3, key, slog.String("error", err.Error()))...)
		return nil, time.Time{}, false
	}

	if int64(len(bodyBytes)) > Defaults.MaxItemSize {
		logevent.Warn(ctx, nil, logevent.CacheItemOversize, "cache item exceeds maximum allowed size",
			cacheAttrs(backendS3, key, slog.Int64("maxAllowed", Defaults.MaxItemSize))...)
		return nil, time.Time{}, false
	}

	var item s3CacheItem
	if err := json.Unmarshal(bodyBytes, &item); err != nil {
		logevent.Error(ctx, nil, logevent.CacheItemInvalid, "failed to decode S3 cache item",
			cacheAttrs(backendS3, key, slog.String("error", err.Error()))...)
		return nil, time.Time{}, false
	}

	if time.Now().After(item.Expiration) {
		logevent.Debug(ctx, nil, logevent.CacheExpired, "cache entry expired", cacheAttrs(backendS3, key)...)
		if c.cleanup {
			c.deleteObject(ctx, objectKey)
		}
		return nil, time.Time{}, false
	}

	logevent.Debug(ctx, nil, logevent.CacheHit, "cache hit", cacheAttrs(backendS3, key)...)
	return item.Value, item.Expiration, true
}

// Set stores an item in the S3 cache with the given TTL.
// The S3 write is synchronous: in Lambda the execution environment is frozen
// when the handler returns, so a background write could be lost.
func (c *s3Cache) Set(ctx context.Context, key string, value *types.JWKS, ttl time.Duration) {
	if ttl <= 0 {
		ttl = c.local.defaultTTL
	}

	// Store in local cache first for fast access
	c.storeInLocalCache(ctx, key, value, time.Now().Add(ttl))

	// Then store in S3 for persistence
	c.storeInS3(ctx, key, value, ttl)
}

// storeInLocalCache adds or updates an item in the local memory cache
func (c *s3Cache) storeInLocalCache(ctx context.Context, key string, value *types.JWKS, expiration time.Time) {
	c.local.put(ctx, key, value, expiration)
}

// storeInS3 persists an item to S3
func (c *s3Cache) storeInS3(ctx context.Context, key string, value *types.JWKS, ttl time.Duration) {
	objectKey := c.formatKey(key)

	item := s3CacheItem{
		Value:      value,
		Expiration: time.Now().Add(ttl),
		CreatedAt:  time.Now(),
	}

	data, err := json.Marshal(item)
	if err != nil {
		logevent.Error(ctx, nil, logevent.CacheWriteFailure, "failed to marshal cache item",
			cacheAttrs(backendS3, key, slog.String("error", err.Error()))...)
		return
	}

	// Reject items the read path would refuse, so writes and reads agree
	if int64(len(data)) > Defaults.MaxItemSize {
		logevent.Warn(ctx, nil, logevent.CacheItemOversize, "cache item too large to store in S3",
			cacheAttrs(backendS3, key, slog.Int("size", len(data)), slog.Int64("maxAllowed", Defaults.MaxItemSize))...)
		return
	}

	ctx, cancel := context.WithTimeout(ctx, Defaults.Timeout)
	defer cancel()

	_, err = c.client.PutObject(ctx, &s3.PutObjectInput{
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
		logevent.Error(ctx, nil, logevent.CacheWriteFailure, "failed to put object in S3",
			cacheAttrs(backendS3, key, slog.String("error", err.Error()))...)
		return
	}

	logevent.Debug(ctx, nil, logevent.CacheSet, "cache entry set",
		cacheAttrs(backendS3, key, slog.Int64("ttlMs", ttl.Milliseconds()), slog.Int("size", len(data)))...)
}

// formatKey creates a consistent S3 object key from the cache key
func (c *s3Cache) formatKey(key string) string {
	if c.prefix == "" {
		return key
	}
	return fmt.Sprintf("%s/%s", c.prefix, key)
}

// deleteObject removes an expired object from S3
func (c *s3Cache) deleteObject(ctx context.Context, key string) {
	ctx, cancel := context.WithTimeout(ctx, Defaults.Timeout)
	defer cancel()

	_, err := c.client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(c.bucketName),
		Key:    aws.String(key),
	})

	if err != nil {
		logevent.Warn(ctx, nil, logevent.CacheCleanupFailure, "failed to delete expired object from S3",
			cacheAttrs(backendS3, key, slog.String("error", err.Error()))...)
	} else {
		logevent.Debug(ctx, nil, logevent.CacheEvict, "deleted expired object from S3", cacheAttrs(backendS3, key)...)
	}
}
