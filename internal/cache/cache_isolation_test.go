package cache

import (
	"sync"
	"testing"
	"time"
)

// TestMemoryCacheConcurrentAccessRace stresses Get/Set/eviction from many
// goroutines at once. Run with -race. Proves the shared map is correctly
// mutex-guarded (no torn reads/writes of a JWKS entry).
func TestMemoryCacheConcurrentAccessRace(t *testing.T) {
	c := NewMemoryCache(WithMemoryMaxSize(5), WithMemoryDefaultTTL(50*time.Millisecond))

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(2)
		go func(i int) {
			defer wg.Done()
			key := "issuer-" + string(rune('a'+i%10))
			c.Set(key, testJWKS("kid"), time.Minute)
		}(i)
		go func(i int) {
			defer wg.Done()
			key := "issuer-" + string(rune('a'+i%10))
			c.Get(key)
		}(i)
	}
	wg.Wait()
}

// TestDynamoDBCacheConcurrentLocalTierRace stresses the local memory tier
// (memCache/memCacheMu) concurrently. Run with -race.
func TestDynamoDBCacheConcurrentLocalTierRace(t *testing.T) {
	mock := &mockDynamoDB{}
	c := newTestDynamoDBCache(mock)
	c.maxLocalSize = 5

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(2)
		go func(i int) {
			defer wg.Done()
			key := "issuer-" + string(rune('a'+i%10))
			c.storeInLocalCache(key, testJWKS("kid"), time.Now().Add(time.Minute))
		}(i)
		go func(i int) {
			defer wg.Done()
			key := "issuer-" + string(rune('a'+i%10))
			c.getFromLocalCache(key)
		}(i)
	}
	wg.Wait()
}

// TestS3CacheConcurrentLocalTierRace stresses the local memory tier
// concurrently. Run with -race.
func TestS3CacheConcurrentLocalTierRace(t *testing.T) {
	mock := &mockS3{}
	c := newTestS3Cache(mock)
	c.maxLocalSize = 5

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(2)
		go func(i int) {
			defer wg.Done()
			key := "issuer-" + string(rune('a'+i%10))
			c.storeInLocalCache(key, testJWKS("kid"), time.Now().Add(time.Minute))
		}(i)
		go func(i int) {
			defer wg.Done()
			key := "issuer-" + string(rune('a'+i%10))
			c.getFromLocalCache(key)
		}(i)
	}
	wg.Wait()
}

// TestCacheKeyIsolationAcrossIssuers proves the #1 risk area (cache key
// construction) is safe: the cache key is the exact issuer string, and two
// distinct issuer strings can never collide onto the same entry, even when
// one is a prefix of the other or they differ only by a trailing separator.
// If this test ever fails, issuer A's cached keys could be looked up under
// issuer B's identity -- a signature-forgery-class bug.
func TestCacheKeyIsolationAcrossIssuers(t *testing.T) {
	backends := map[string]Cache{
		"memory": NewMemoryCache(),
	}
	ddbMock := &mockDynamoDB{}
	backends["dynamodb"] = newTestDynamoDBCache(ddbMock)
	s3Mock := &mockS3{}
	backends["s3"] = newTestS3Cache(s3Mock)

	issuerA := "https://token.actions.githubusercontent.com"
	issuerB := "https://token.actions.githubusercontent.com/" // trailing slash
	issuerC := "https://evil.example.com/token.actions.githubusercontent.com"

	for name, c := range backends {
		t.Run(name, func(t *testing.T) {
			jwksA := testJWKS("kid-A")
			c.Set(issuerA, jwksA, time.Minute)

			// A different issuer string (even one that shares a long prefix,
			// or differs only by a trailing slash) must be a clean miss --
			// never resolve to issuer A's key material.
			if got, found := c.Get(issuerB); found {
				t.Fatalf("issuer with trailing slash resolved to another issuer's cached JWKS: %+v", got)
			}
			if got, found := c.Get(issuerC); found {
				t.Fatalf("unrelated issuer resolved to another issuer's cached JWKS: %+v", got)
			}

			// The real issuer must still resolve to its own keys.
			got, found := c.Get(issuerA)
			if !found || got.Keys[0].KeyID != "kid-A" {
				t.Fatalf("expected issuer A to hit its own entry, got found=%v val=%+v", found, got)
			}
		})
	}
}

// TestS3CacheFormatKeyNoTraversalEscape documents that S3 object keys are
// opaque strings (S3 has no filesystem-style path resolution), so a
// crafted issuer containing ".." cannot make formatKey produce a key
// outside the configured prefix via traversal -- it only ever influences
// the literal suffix appended after "<prefix>/".
func TestS3CacheFormatKeyNoTraversalEscape(t *testing.T) {
	c := &s3Cache{prefix: "jwks"}

	got := c.formatKey("../../other-prefix/secret")
	want := "jwks/../../other-prefix/secret"
	if got != want {
		t.Fatalf("formatKey = %q, want %q", got, want)
	}
	// The literal string still begins with the configured prefix segment;
	// S3 does not collapse "..", so IAM policies scoped by ARN prefix
	// (e.g. arn:aws:s3:::bucket/jwks/*) are not bypassed by this key.
}
