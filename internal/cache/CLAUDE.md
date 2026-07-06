# Cache — Multi-Tier JWKS Cache

Extends [../../CLAUDE.md](../../CLAUDE.md). Caches JWKS to avoid re-fetching from the OIDC provider.

## Interface & factory

```go
type Cache interface {
    Get(key string) (*types.JWKS, bool)
    Set(key string, value *types.JWKS, ttl time.Duration)
}
```

`NewCache(cfg)` selects a backend by `cache.type`:

- `memory` (`NewMemoryCache`) — LRU, default. Fastest; lost on container recycle. Single instance.
- `dynamodb` (`NewDynamoDBCache`) — persistent, shared, TTL-based cleanup. Production.
- `s3` (`NewS3Cache`) — large/cold objects; `s3_cleanup: true` deletes expired objects discovered on read.

All backends honor `cache.ttl` and `cache.max_local_size`. The DynamoDB and S3 backends layer a local LRU tier over the persistent store; persistent writes are synchronous (Lambda freezes the environment on handler return, so background writes would be lost).

## Gotchas

- TTL is a Go duration (`"1h"`, `"4h30m"`); resolve via `GetConfiguredTTL(cfg)`.
- DynamoDB cleanup needs TTL enabled on the table attribute; a missing or malformed `Expiration` attribute is treated as expired (fail closed).
- `max_local_size` limits entry count, not bytes.
- Item size is capped at `Defaults.MaxItemSize` (512KB) on both read and write paths (DynamoDB writes at 400KB, the service's hard limit).
- The AWS clients are mocked in tests via the `dynamoDBAPI`/`s3API` interfaces.

IAM: DynamoDB backend needs GetItem/PutItem/DeleteItem; S3 backend needs GetObject/PutObject/DeleteObject/ListBucket.
