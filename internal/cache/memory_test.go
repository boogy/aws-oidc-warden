package cache

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/boogy/aws-oidc-warden/internal/types"
)

func testJWKS(kid string) *types.JWKS {
	return &types.JWKS{Keys: []types.JSONWebKey{{KeyID: kid, KeyType: "RSA"}}}
}

func TestMemoryCacheRoundtrip(t *testing.T) {
	c := NewMemoryCache()

	if _, found := c.Get("missing"); found {
		t.Fatal("expected miss for unknown key")
	}

	want := testJWKS("kid1")
	c.Set("key1", want, time.Minute)

	got, found := c.Get("key1")
	if !found {
		t.Fatal("expected hit after Set")
	}
	if got.Keys[0].KeyID != "kid1" {
		t.Fatalf("got kid %q, want kid1", got.Keys[0].KeyID)
	}
}

func TestMemoryCacheTTLExpiry(t *testing.T) {
	c := NewMemoryCache().(*memoryCache)

	c.Set("key1", testJWKS("kid1"), time.Nanosecond)
	time.Sleep(2 * time.Millisecond)

	if _, found := c.Get("key1"); found {
		t.Fatal("expected miss for expired entry")
	}

	c.mu.Lock()
	_, stillThere := c.data["key1"]
	c.mu.Unlock()
	if stillThere {
		t.Fatal("expired entry should be removed on Get")
	}
}

func TestMemoryCacheDefaultTTL(t *testing.T) {
	c := NewMemoryCache(WithMemoryDefaultTTL(time.Hour)).(*memoryCache)

	c.Set("key1", testJWKS("kid1"), 0) // no TTL -> default

	c.mu.Lock()
	item := c.data["key1"]
	c.mu.Unlock()

	if until := time.Until(item.expiration); until < 59*time.Minute {
		t.Fatalf("expected ~1h TTL from default, got %v", until)
	}
}

func TestMemoryCacheOptionsHonored(t *testing.T) {
	c := NewMemoryCache(WithMemoryMaxSize(1)).(*memoryCache)
	if c.maxSize != 1 {
		t.Fatalf("maxSize = %d, want 1", c.maxSize)
	}

	// Non-positive values fall back to defaults
	d := NewMemoryCache(WithMemoryMaxSize(0), WithMemoryDefaultTTL(0)).(*memoryCache)
	if d.maxSize != Defaults.MaxLocalSize || d.defaultTTL != Defaults.TTL {
		t.Fatalf("zero options should keep defaults, got maxSize=%d ttl=%v", d.maxSize, d.defaultTTL)
	}
}

func TestMemoryCacheLRUEviction(t *testing.T) {
	c := NewMemoryCache(WithMemoryMaxSize(2))

	c.Set("a", testJWKS("a"), time.Minute)
	time.Sleep(time.Millisecond)
	c.Set("b", testJWKS("b"), time.Minute)
	time.Sleep(time.Millisecond)

	// Touch "a" so "b" becomes least recently used
	if _, found := c.Get("a"); !found {
		t.Fatal("expected hit for a")
	}
	time.Sleep(time.Millisecond)

	c.Set("c", testJWKS("c"), time.Minute)

	if _, found := c.Get("b"); found {
		t.Fatal("expected b to be evicted as LRU")
	}
	if _, found := c.Get("a"); !found {
		t.Fatal("a should survive eviction")
	}
	if _, found := c.Get("c"); !found {
		t.Fatal("c should be present")
	}
}

func TestMemoryCacheNoEvictionOnOverwrite(t *testing.T) {
	c := NewMemoryCache(WithMemoryMaxSize(2))

	c.Set("a", testJWKS("a1"), time.Minute)
	c.Set("b", testJWKS("b"), time.Minute)

	// Overwrite at capacity must not evict the other key
	c.Set("a", testJWKS("a2"), time.Minute)

	if _, found := c.Get("b"); !found {
		t.Fatal("b should not be evicted by overwrite of a")
	}
	got, found := c.Get("a")
	if !found || got.Keys[0].KeyID != "a2" {
		t.Fatal("a should hold the overwritten value")
	}
}

func TestMemoryCacheConcurrentAccess(t *testing.T) {
	c := NewMemoryCache(WithMemoryMaxSize(8))

	var wg sync.WaitGroup
	for i := range 8 {
		wg.Add(2)
		key := fmt.Sprintf("key%d", i%4)
		go func() {
			defer wg.Done()
			for range 100 {
				c.Set(key, testJWKS(key), time.Millisecond)
			}
		}()
		go func() {
			defer wg.Done()
			for range 100 {
				c.Get(key)
			}
		}()
	}
	wg.Wait()
}
