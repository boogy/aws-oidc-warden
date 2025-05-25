package cache

import (
	"fmt"
	"time"

	"github.com/boogy/aws-oidc-warden/config"
	"github.com/boogy/aws-oidc-warden/types"
)

// CacheDefaults holds all default configuration values for cache implementations
// These constants are centralized here to ensure consistency across different cache types
type CacheDefaults struct {
	// General defaults
	MaxRetries   int
	Timeout      time.Duration
	TTL          time.Duration
	MaxLocalSize int

	// Size limits
	MaxItemSize int64 // Maximum size of a cache item

	// Cache-specific defaults
	DynamoDBMaxItemSize int64
	S3MaxObjectSize     int64
}

// Defaults provides the default configuration values for all cache implementations
var Defaults = CacheDefaults{
	MaxRetries:          3,                // Default number of retries for cache operations
	Timeout:             10 * time.Second, // Default timeout for cache operations
	TTL:                 10 * time.Minute, // Default TTL for cache entries
	MaxLocalSize:        100,              // Default max local size for in-memory caches
	MaxItemSize:         512 * 1024,       // Maximum size of a cache item (512KB) for general cache items
	DynamoDBMaxItemSize: 400 * 1024,       // Maximum item size for DynamoDB (400KB limit) (DynamoDB limit)
	S3MaxObjectSize:     1024 * 1024,      // Maximum object size for S3 objects (1MB)
}

// Cache interface defines the methods that all cache implementations must provide
type Cache interface {
	Get(key string) (*types.JWKS, bool)
	Set(key string, value *types.JWKS, ttl time.Duration)
}

// GetConfiguredTTL returns the TTL from config or the default if not specified
func GetConfiguredTTL(cfg *config.Config) time.Duration {
	if cfg != nil && cfg.Cache != nil && cfg.Cache.TTL > 0 {
		return cfg.Cache.TTL
	}
	return Defaults.TTL
}

// GetConfiguredMaxLocalSize returns the max local size from config or the default if not specified
func GetConfiguredMaxLocalSize(cfg *config.Config) int {
	if cfg != nil && cfg.Cache != nil && cfg.Cache.MaxLocalSize > 0 {
		return cfg.Cache.MaxLocalSize
	}
	return Defaults.MaxLocalSize
}

// NewCache creates a new cache implementation based on the configuration
func NewCache(cfg *config.Config) (Cache, error) {
	if cfg == nil || cfg.Cache == nil {
		return NewMemoryCache(), nil
	}

	cacheType := cfg.Cache.Type
	if cacheType == "" {
		cacheType = "memory"
	}

	switch cacheType {
	case "memory":
		return NewMemoryCache(), nil

	case "dynamodb":
		if cfg.Cache.DynamoDBTable == "" {
			return nil, fmt.Errorf("DynamoDB table name is required for DynamoDB cache")
		}

		// Configure the DynamoDB cache with TTL and local cache size from config
		return NewDynamoDBCache(
			cfg.Cache.DynamoDBTable,
			WithDynamoDBDefaultTTL(GetConfiguredTTL(cfg)),
			WithDynamoDBMaxLocalSize(GetConfiguredMaxLocalSize(cfg)),
		)

	case "s3":
		if cfg.Cache.S3Bucket == "" {
			return nil, fmt.Errorf("S3 bucket name is required for S3 cache")
		}
		if cfg.Cache.S3Prefix == "" {
			return nil, fmt.Errorf("S3 prefix is required for S3 cache")
		}

		// Configure the S3 cache with TTL and local cache size from config
		return NewS3Cache(
			cfg.Cache.S3Bucket,
			cfg.Cache.S3Prefix,
			WithDefaultTTL(GetConfiguredTTL(cfg)),
			WithMaxLocalSize(GetConfiguredMaxLocalSize(cfg)),
		)

	default:
		return nil, fmt.Errorf("unsupported cache type: %s", cacheType)
	}
}
