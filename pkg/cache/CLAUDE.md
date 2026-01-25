# Cache Package - Multi-Tier Caching System

**Technology**: Go, DynamoDB, S3, LRU
**Entry Point**: `cache.go` (interface), implementation files per backend
**Parent Context**: This extends [../../CLAUDE.md](../../CLAUDE.md)

---

## Development Commands

### From Package Directory

```bash
go test ./...              # Run cache tests
go test -v ./...           # Verbose output
```

### From Root

```bash
go test -v ./pkg/cache/    # Test this package
```

---

## Architecture

### Directory Structure

```
pkg/cache/
├── cache.go       # Cache interface definition
├── memory.go      # LRU in-memory implementation
├── dynamodb.go    # DynamoDB persistence
└── s3.go          # S3 large object cache
```

### Cache Selection Flow

```
Config.Cache.Type → Factory → Memory | DynamoDB | S3 implementation
```

---

## Cache Interface

```go
type Cache interface {
    Get(key string) (*types.JWKS, bool)
    Set(key string, value *types.JWKS, ttl time.Duration)
    Delete(key string)
    Clear()
}
```

---

## Implementation Patterns

### Memory Cache (Default)

LRU-based in-memory cache:

```go
// ✅ DO: Use for low-latency, single-instance scenarios
type MemoryCache struct {
    cache    *lru.Cache
    ttl      time.Duration
    maxSize  int
}

// Configuration
cache:
  type: "memory"
  ttl: "1h"
  max_local_size: 20
```

**Characteristics:**

- Fastest access (sub-millisecond)
- Lost on Lambda container recycling
- No external dependencies
- Best for: Low-traffic, single Lambda instance

### DynamoDB Cache

Persistent cache with TTL:

```go
// ✅ DO: Use for cross-instance persistence
type DynamoDBCache struct {
    client    *dynamodb.Client
    tableName string
    ttl       time.Duration
}

// Configuration
cache:
  type: "dynamodb"
  ttl: "4h"
  dynamodb_table: "aws-oidc-warden-cache"
```

**Characteristics:**

- Persistent across Lambda cold starts
- Shared across all instances
- Automatic TTL-based cleanup
- Best for: Production, high-traffic

**DynamoDB Table Schema:**

```
Primary Key: pk (String) - cache key (issuer URL)
TTL Attribute: ttl (Number) - Unix timestamp for expiration
Data Attribute: data (String) - JSON-encoded JWKS
```

### S3 Cache

Large object storage:

```go
// ✅ DO: Use for large cache items or cold storage
type S3Cache struct {
    client   *s3.Client
    bucket   string
    prefix   string
    ttl      time.Duration
    cleanup  bool
}

// Configuration
cache:
  type: "s3"
  ttl: "24h"
  s3_bucket: "aws-oidc-warden-cache"
  s3_prefix: "jwks-cache/"
  s3_cleanup: true
```

**Characteristics:**

- Unlimited storage
- Higher latency (50-200ms)
- Optional automatic cleanup
- Best for: Rarely-changing data, large objects

---

## Quick Search Commands

### Find Cache Implementations

```bash
# Find interface definition
rg -n "type Cache interface" pkg/cache/

# Find Get implementations
rg -n "func.*Get\(" pkg/cache/

# Find Set implementations
rg -n "func.*Set\(" pkg/cache/
```

### Find TTL Handling

```bash
# Find TTL logic
rg -n "ttl\|TTL\|Expir" pkg/cache/
```

---

## Common Gotchas

- **TTL Format**: Use Go duration strings (`"1h"`, `"30m"`, `"4h30m"`)
- **DynamoDB TTL**: Enable TTL on the table attribute for automatic cleanup
- **S3 Cleanup**: Set `s3_cleanup: true` to remove expired objects
- **Memory Size**: `max_local_size` limits entries, not bytes
- **Cold Starts**: Memory cache is empty after Lambda recycle

---

## Cache Selection Guide

| Scenario                    | Recommended Cache | Reason                   |
| --------------------------- | ----------------- | ------------------------ |
| Development                 | Memory            | Simplest, no setup       |
| Low traffic (<1000 req/day) | Memory            | Sufficient, no cost      |
| Production Lambda           | DynamoDB          | Persistence, sharing     |
| Multi-region                | S3 + DynamoDB     | Cross-region replication |
| Very large JWKS             | S3                | No size limits           |

---

## Testing Guidelines

### Mock Cache

```go
type MockCache struct {
    data map[string]*types.JWKS
}

func (m *MockCache) Get(key string) (*types.JWKS, bool) {
    jwks, found := m.data[key]
    return jwks, found
}

func (m *MockCache) Set(key string, value *types.JWKS, ttl time.Duration) {
    m.data[key] = value
}
```

### Unit Test Example

```go
func TestMemoryCache_SetGet(t *testing.T) {
    cache := NewMemoryCache(10, 1*time.Hour)

    jwks := &types.JWKS{Keys: []types.JWK{{KeyID: "test"}}}
    cache.Set("issuer", jwks, 1*time.Hour)

    result, found := cache.Get("issuer")

    assert.True(t, found)
    assert.Equal(t, "test", result.Keys[0].KeyID)
}

func TestMemoryCache_TTLExpiration(t *testing.T) {
    cache := NewMemoryCache(10, 1*time.Millisecond)

    cache.Set("issuer", &types.JWKS{}, 1*time.Millisecond)
    time.Sleep(10 * time.Millisecond)

    _, found := cache.Get("issuer")

    assert.False(t, found)
}
```

---

## Required IAM Permissions

### DynamoDB Cache

```json
{
  "Effect": "Allow",
  "Action": ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:DeleteItem"],
  "Resource": "arn:aws:dynamodb:*:*:table/aws-oidc-warden-cache"
}
```

### S3 Cache

```json
{
  "Effect": "Allow",
  "Action": [
    "s3:GetObject",
    "s3:PutObject",
    "s3:DeleteObject",
    "s3:ListBucket"
  ],
  "Resource": [
    "arn:aws:s3:::aws-oidc-warden-cache",
    "arn:aws:s3:::aws-oidc-warden-cache/*"
  ]
}
```
