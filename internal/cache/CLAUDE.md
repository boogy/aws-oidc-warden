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
- `s3` (`NewS3Cache`) — large/cold objects; optional `s3_cleanup`.

## Gotchas

- TTL is a Go duration (`"1h"`, `"4h30m"`); resolve via `GetConfiguredTTL(cfg)`.
- DynamoDB cleanup needs TTL enabled on the table attribute.
- `max_local_size` limits entry count, not bytes.

IAM: DynamoDB backend needs GetItem/PutItem/DeleteItem; S3 backend needs GetObject/PutObject/DeleteObject/ListBucket.
