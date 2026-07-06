package cache

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	gTypes "github.com/boogy/aws-oidc-warden/internal/types"
)

// dynamoDBAPI is the subset of the DynamoDB client used by the cache,
// extracted as an interface for testability
type dynamoDBAPI interface {
	GetItem(ctx context.Context, params *dynamodb.GetItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error)
	PutItem(ctx context.Context, params *dynamodb.PutItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error)
}

// cacheEntry represents an entry in the local memory cache
type cacheEntry struct {
	value      *gTypes.JWKS // Cached JWKS value
	expiration time.Time    // Expiration time for the cache entry
	lastAccess time.Time    // Last access time for LRU eviction
}

// dynamoDBCache implements the Cache interface using DynamoDB
type dynamoDBCache struct {
	client       dynamoDBAPI            // DynamoDB client
	tableName    string                 // DynamoDB table name
	memCache     map[string]*cacheEntry // Local in-memory cache for frequently accessed items
	memCacheMu   sync.Mutex             // Protects the in-memory cache
	maxLocalSize int                    // Maximum number of items in local cache
	defaultTTL   time.Duration          // Default TTL for cache items
}

// dynamoDBCacheOptions configures the DynamoDB cache behavior
type dynamoDBCacheOptions struct {
	maxLocalSize int           // Maximum number of items in local memory cache
	defaultTTL   time.Duration // Default TTL when not specified
	awsConfig    aws.Config    // Optional AWS configuration
}

// DynamoDBCacheOption is a function that configures the DynamoDB cache
type DynamoDBCacheOption func(*dynamoDBCacheOptions)

// WithDynamoDBMaxLocalSize sets the maximum size of the local memory cache
func WithDynamoDBMaxLocalSize(size int) DynamoDBCacheOption {
	return func(o *dynamoDBCacheOptions) {
		o.maxLocalSize = size
	}
}

// WithDynamoDBDefaultTTL sets the default TTL for cache items
func WithDynamoDBDefaultTTL(ttl time.Duration) DynamoDBCacheOption {
	return func(o *dynamoDBCacheOptions) {
		o.defaultTTL = ttl
	}
}

// WithDynamoDBAWSConfig sets a custom AWS configuration
func WithDynamoDBAWSConfig(cfg aws.Config) DynamoDBCacheOption {
	return func(o *dynamoDBCacheOptions) {
		o.awsConfig = cfg
	}
}

// NewDynamoDBCache creates a new DynamoDB cache with the given table name
func NewDynamoDBCache(tableName string, opts ...DynamoDBCacheOption) (Cache, error) {
	// Default options
	options := &dynamoDBCacheOptions{
		maxLocalSize: Defaults.MaxLocalSize, // Default from central config
		defaultTTL:   Defaults.TTL,          // Default from central config
	}

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
			slog.Error("Failed to load AWS config for DynamoDB cache", "error", err.Error())
			return nil, fmt.Errorf("failed to load AWS config: %w", err)
		}
	}

	return &dynamoDBCache{
		client:       dynamodb.NewFromConfig(cfg),
		tableName:    tableName,
		memCache:     make(map[string]*cacheEntry),
		maxLocalSize: options.maxLocalSize,
		defaultTTL:   options.defaultTTL,
	}, nil
}

// Get retrieves an item from the DynamoDB cache
func (c *dynamoDBCache) Get(key string) (*gTypes.JWKS, bool) {
	// Try to get from local memory cache first
	if jwks, found := c.getFromLocalCache(key); found {
		slog.Debug("Local memory cache hit", "key", key)
		return jwks, true
	}

	// Not in local cache, try DynamoDB
	jwks, expiration, found := c.getFromDynamoDB(key)
	if found {
		// Store in local cache with the item's real expiration
		c.storeInLocalCache(key, jwks, expiration)
		return jwks, true
	}

	return nil, false
}

// getFromLocalCache checks the local memory cache
func (c *dynamoDBCache) getFromLocalCache(key string) (*gTypes.JWKS, bool) {
	c.memCacheMu.Lock()
	defer c.memCacheMu.Unlock()

	entry, found := c.memCache[key]
	if !found {
		return nil, false
	}

	// Check if the entry is expired
	if time.Now().After(entry.expiration) {
		delete(c.memCache, key)
		return nil, false
	}

	// Update last access time for LRU
	entry.lastAccess = time.Now()

	return entry.value, true
}

// getFromDynamoDB retrieves an item from DynamoDB, returning the cached JWKS
// and its expiration time
func (c *dynamoDBCache) getFromDynamoDB(key string) (*gTypes.JWKS, time.Time, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), Defaults.Timeout)
	defer cancel()

	input := &dynamodb.GetItemInput{
		TableName: aws.String(c.tableName),
		Key: map[string]types.AttributeValue{
			"Key": &types.AttributeValueMemberS{Value: key},
		},
	}

	result, err := c.client.GetItem(ctx, input)
	if err != nil {
		slog.Error("Failed to get item from DynamoDB",
			"key", key,
			"error", err.Error(),
			"table", c.tableName)
		return nil, time.Time{}, false
	}

	if result.Item == nil {
		slog.Debug("Cache miss in DynamoDB", "key", key)
		return nil, time.Time{}, false
	}

	valueAttr, ok := result.Item["Value"]
	if !ok {
		slog.Error("Invalid item format in DynamoDB - missing Value attribute", "key", key)
		return nil, time.Time{}, false
	}

	valueStr, ok := valueAttr.(*types.AttributeValueMemberS)
	if !ok {
		slog.Error("Value is not a string in DynamoDB", "key", key)
		return nil, time.Time{}, false
	}

	// Check size for security
	if len(valueStr.Value) > int(Defaults.MaxItemSize) {
		slog.Warn("DynamoDB cache item exceeds maximum allowed size",
			"key", key,
			"size", len(valueStr.Value),
			"maxAllowed", Defaults.MaxItemSize)
		return nil, time.Time{}, false
	}

	// A missing or malformed Expiration attribute is treated as expired
	// (fail closed) so such items cannot be served forever
	expiration, err := parseExpiration(result.Item["Expiration"])
	if err != nil {
		slog.Warn("Invalid Expiration attribute in DynamoDB cache item, treating as expired",
			"key", key,
			"error", err.Error())
		return nil, time.Time{}, false
	}
	if time.Now().After(expiration) {
		slog.Debug("DynamoDB cache entry expired", "key", key)
		return nil, time.Time{}, false
	}

	// Unmarshal JSON string back to JWKS struct
	var jwks gTypes.JWKS
	if err := json.Unmarshal([]byte(valueStr.Value), &jwks); err != nil {
		slog.Error("Failed to unmarshal JWKS from DynamoDB",
			"key", key,
			"error", err.Error())
		return nil, time.Time{}, false
	}

	slog.Debug("DynamoDB cache hit", "key", key)
	return &jwks, expiration, true
}

// parseExpiration extracts the RFC3339 expiration from a DynamoDB attribute
func parseExpiration(attr types.AttributeValue) (time.Time, error) {
	if attr == nil {
		return time.Time{}, fmt.Errorf("missing Expiration attribute")
	}
	expirationStr, ok := attr.(*types.AttributeValueMemberS)
	if !ok {
		return time.Time{}, fmt.Errorf("expiration attribute is not a string")
	}
	return time.Parse(time.RFC3339, expirationStr.Value)
}

// Set stores an item in the DynamoDB cache with the given TTL.
// The DynamoDB write is synchronous: in Lambda the execution environment is
// frozen when the handler returns, so a background write could be lost.
func (c *dynamoDBCache) Set(key string, value *gTypes.JWKS, ttl time.Duration) {
	if ttl <= 0 {
		ttl = c.defaultTTL
	}

	// Store in local cache first for fast access
	c.storeInLocalCache(key, value, time.Now().Add(ttl))

	// Then store in DynamoDB for persistence
	c.storeInDynamoDB(key, value, ttl)
}

// storeInLocalCache adds or updates an item in the local memory cache
func (c *dynamoDBCache) storeInLocalCache(key string, value *gTypes.JWKS, expiration time.Time) {
	c.memCacheMu.Lock()
	defer c.memCacheMu.Unlock()

	// If the expiration time wasn't specified, use default
	if expiration.IsZero() {
		expiration = time.Now().Add(c.defaultTTL)
	}

	// Evict only when adding a new key at capacity; overwrites don't grow the map
	if _, exists := c.memCache[key]; !exists && len(c.memCache) >= c.maxLocalSize {
		c.evictLRU()
	}

	c.memCache[key] = &cacheEntry{
		value:      value,
		expiration: expiration,
		lastAccess: time.Now(),
	}
}

// evictLRU removes the least recently used item from the local memory cache.
// Caller must hold c.memCacheMu.
func (c *dynamoDBCache) evictLRU() {
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

// storeInDynamoDB persists an item to DynamoDB
func (c *dynamoDBCache) storeInDynamoDB(key string, value *gTypes.JWKS, ttl time.Duration) {
	// Marshal JWKS to JSON string
	valueJSON, err := json.Marshal(value)
	if err != nil {
		slog.Error("Failed to marshal JWKS", "key", key, "error", err.Error())
		return
	}

	// Check for size limit
	// DynamoDB has a limit of 400KB for item size, but we use a smaller limit for safety
	if len(valueJSON) > int(Defaults.DynamoDBMaxItemSize) {
		slog.Error("Cache item too large to store in DynamoDB",
			"key", key,
			"size", len(valueJSON),
			"maxAllowed", Defaults.DynamoDBMaxItemSize)
		return
	}

	expiration := time.Now().Add(ttl).Format(time.RFC3339)
	// Calculate TTL timestamp for DynamoDB native TTL
	ttlTimestamp := time.Now().Add(ttl).Unix()

	ctx, cancel := context.WithTimeout(context.Background(), Defaults.Timeout)
	defer cancel()

	input := &dynamodb.PutItemInput{
		TableName: aws.String(c.tableName),
		Item: map[string]types.AttributeValue{
			"Key":        &types.AttributeValueMemberS{Value: key},
			"Value":      &types.AttributeValueMemberS{Value: string(valueJSON)},
			"Expiration": &types.AttributeValueMemberS{Value: expiration},
			"TTL":        &types.AttributeValueMemberN{Value: fmt.Sprintf("%d", ttlTimestamp)},
			"CreatedAt":  &types.AttributeValueMemberS{Value: time.Now().Format(time.RFC3339)},
			"Size":       &types.AttributeValueMemberN{Value: fmt.Sprintf("%d", len(valueJSON))},
		},
	}

	_, err = c.client.PutItem(ctx, input)
	if err != nil {
		slog.Error("Failed to set item in DynamoDB",
			"key", key,
			"error", err.Error(),
			"table", c.tableName)
		return
	}

	slog.Debug("Cached value in DynamoDB", "key", key, "ttl", ttl, "size", len(valueJSON))
}
