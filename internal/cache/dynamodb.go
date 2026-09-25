package cache

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/boogy/aws-oidc-warden/internal/logevent"
	gTypes "github.com/boogy/aws-oidc-warden/internal/types"
)

// dynamoDBAPI is the subset of the DynamoDB client used by the cache,
// extracted as an interface for testability
type dynamoDBAPI interface {
	GetItem(ctx context.Context, params *dynamodb.GetItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error)
	PutItem(ctx context.Context, params *dynamodb.PutItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error)
}

// dynamoDBCache implements the Cache interface using DynamoDB
type dynamoDBCache struct {
	client    dynamoDBAPI // DynamoDB client
	tableName string      // DynamoDB table name
	local     *localCache // Local tier in front of DynamoDB
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

	cfg, err := resolveAWSConfig(context.Background(), options.awsConfig, backendDynamoDB)
	if err != nil {
		return nil, err
	}

	return &dynamoDBCache{
		client:    dynamodb.NewFromConfig(cfg),
		tableName: tableName,
		local:     newLocalCache(options.maxLocalSize, options.defaultTTL, backendLocal),
	}, nil
}

// Get retrieves an item from the DynamoDB cache
func (c *dynamoDBCache) Get(ctx context.Context, key string) (*gTypes.JWKS, bool) {
	// Try to get from local memory cache first
	if jwks, found := c.getFromLocalCache(key); found {
		logevent.Debug(ctx, nil, logevent.CacheHit, "cache hit", cacheAttrs(backendLocal, key)...)
		return jwks, true
	}

	// Not in local cache, try DynamoDB
	jwks, expiration, found := c.getFromDynamoDB(ctx, key)
	if found {
		// Store in local cache with the item's real expiration
		c.storeInLocalCache(ctx, key, jwks, expiration)
		return jwks, true
	}

	return nil, false
}

// getFromLocalCache checks the local memory cache
func (c *dynamoDBCache) getFromLocalCache(key string) (*gTypes.JWKS, bool) {
	value, lookup := c.local.get(key)
	return value, lookup == localHit
}

// getFromDynamoDB retrieves an item from DynamoDB, returning the cached JWKS
// and its expiration time
func (c *dynamoDBCache) getFromDynamoDB(ctx context.Context, key string) (*gTypes.JWKS, time.Time, bool) {
	ctx, cancel := context.WithTimeout(ctx, Defaults.Timeout)
	defer cancel()

	input := &dynamodb.GetItemInput{
		TableName: aws.String(c.tableName),
		Key: map[string]types.AttributeValue{
			"Key": &types.AttributeValueMemberS{Value: key},
		},
	}

	result, err := c.client.GetItem(ctx, input)
	if err != nil {
		logevent.Error(ctx, nil, logevent.CacheReadFailure, "failed to get item from DynamoDB",
			cacheAttrs(backendDynamoDB, key, slog.String("error", err.Error()), slog.String("table", c.tableName))...)
		return nil, time.Time{}, false
	}

	if result.Item == nil {
		logevent.Debug(ctx, nil, logevent.CacheMiss, "cache miss", cacheAttrs(backendDynamoDB, key)...)
		return nil, time.Time{}, false
	}

	valueAttr, ok := result.Item["Value"]
	if !ok {
		logevent.Error(ctx, nil, logevent.CacheItemInvalid, "cache item missing Value attribute",
			cacheAttrs(backendDynamoDB, key)...)
		return nil, time.Time{}, false
	}

	valueStr, ok := valueAttr.(*types.AttributeValueMemberS)
	if !ok {
		logevent.Error(ctx, nil, logevent.CacheItemInvalid, "cache item Value attribute is not a string",
			cacheAttrs(backendDynamoDB, key)...)
		return nil, time.Time{}, false
	}

	// Check size for security
	if len(valueStr.Value) > int(Defaults.MaxItemSize) {
		logevent.Warn(ctx, nil, logevent.CacheItemOversize, "cache item exceeds maximum allowed size",
			cacheAttrs(backendDynamoDB, key,
				slog.Int("size", len(valueStr.Value)),
				slog.Int64("maxAllowed", Defaults.MaxItemSize))...)
		return nil, time.Time{}, false
	}

	// A missing or malformed Expiration attribute is treated as expired
	// (fail closed) so such items cannot be served forever
	expiration, err := parseExpiration(result.Item["Expiration"])
	if err != nil {
		logevent.Error(ctx, nil, logevent.CacheItemInvalid, "invalid Expiration attribute, treating item as expired",
			cacheAttrs(backendDynamoDB, key, slog.String("error", err.Error()))...)
		return nil, time.Time{}, false
	}
	if time.Now().After(expiration) {
		logevent.Debug(ctx, nil, logevent.CacheExpired, "cache entry expired", cacheAttrs(backendDynamoDB, key)...)
		return nil, time.Time{}, false
	}

	// Unmarshal JSON string back to JWKS struct
	var jwks gTypes.JWKS
	if err := json.Unmarshal([]byte(valueStr.Value), &jwks); err != nil {
		logevent.Error(ctx, nil, logevent.CacheItemInvalid, "failed to unmarshal JWKS from DynamoDB",
			cacheAttrs(backendDynamoDB, key, slog.String("error", err.Error()))...)
		return nil, time.Time{}, false
	}

	logevent.Debug(ctx, nil, logevent.CacheHit, "cache hit", cacheAttrs(backendDynamoDB, key)...)
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
func (c *dynamoDBCache) Set(ctx context.Context, key string, value *gTypes.JWKS, ttl time.Duration) {
	if ttl <= 0 {
		ttl = c.local.defaultTTL
	}

	// Store in local cache first for fast access
	c.storeInLocalCache(ctx, key, value, time.Now().Add(ttl))

	// Then store in DynamoDB for persistence
	c.storeInDynamoDB(ctx, key, value, ttl)
}

// storeInLocalCache adds or updates an item in the local memory cache
func (c *dynamoDBCache) storeInLocalCache(ctx context.Context, key string, value *gTypes.JWKS, expiration time.Time) {
	c.local.put(ctx, key, value, expiration)
}

// storeInDynamoDB persists an item to DynamoDB
func (c *dynamoDBCache) storeInDynamoDB(ctx context.Context, key string, value *gTypes.JWKS, ttl time.Duration) {
	// Marshal JWKS to JSON string
	valueJSON, err := json.Marshal(value)
	if err != nil {
		logevent.Error(ctx, nil, logevent.CacheWriteFailure, "failed to marshal JWKS",
			cacheAttrs(backendDynamoDB, key, slog.String("error", err.Error()))...)
		return
	}

	// Check for size limit
	// DynamoDB's hard item-size limit is 400KB; oversized entries are dropped
	// rather than written, since the PutItem would fail anyway.
	if len(valueJSON) > int(Defaults.DynamoDBMaxItemSize) {
		logevent.Warn(ctx, nil, logevent.CacheItemOversize, "cache item too large to store in DynamoDB",
			cacheAttrs(backendDynamoDB, key,
				slog.Int("size", len(valueJSON)),
				slog.Int64("maxAllowed", Defaults.DynamoDBMaxItemSize))...)
		return
	}

	expiration := time.Now().Add(ttl).Format(time.RFC3339)
	// Calculate TTL timestamp for DynamoDB native TTL
	ttlTimestamp := time.Now().Add(ttl).Unix()

	ctx, cancel := context.WithTimeout(ctx, Defaults.Timeout)
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
		logevent.Error(ctx, nil, logevent.CacheWriteFailure, "failed to set item in DynamoDB",
			cacheAttrs(backendDynamoDB, key, slog.String("error", err.Error()), slog.String("table", c.tableName))...)
		return
	}

	logevent.Debug(ctx, nil, logevent.CacheSet, "cache entry set",
		cacheAttrs(backendDynamoDB, key, slog.Int64("ttlMs", ttl.Milliseconds()), slog.Int("size", len(valueJSON)))...)
}
