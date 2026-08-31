package cache

// Covers the Cache interface, NewCache backend selection, and the
// cross-issuer isolation property every backend must hold.
import (
	"sync"
	"testing"
	"time"

	"github.com/boogy/aws-oidc-warden/internal/config"
)

func TestGetConfiguredTTL(t *testing.T) {
	if got := GetConfiguredTTL(nil); got != Defaults.TTL {
		t.Fatalf("nil config: got %v, want default %v", got, Defaults.TTL)
	}
	cfg := &config.Config{Cache: &config.Cache{TTL: time.Hour}}
	if got := GetConfiguredTTL(cfg); got != time.Hour {
		t.Fatalf("got %v, want 1h", got)
	}
}

func TestGetConfiguredMaxLocalSize(t *testing.T) {
	if got := GetConfiguredMaxLocalSize(nil); got != Defaults.MaxLocalSize {
		t.Fatalf("nil config: got %d, want default %d", got, Defaults.MaxLocalSize)
	}
	cfg := &config.Config{Cache: &config.Cache{MaxLocalSize: 42}}
	if got := GetConfiguredMaxLocalSize(cfg); got != 42 {
		t.Fatalf("got %d, want 42", got)
	}
}

func TestNewCacheBackendSelection(t *testing.T) {
	tests := []struct {
		name    string
		cfg     *config.Config
		wantErr bool
	}{
		{"nil config defaults to memory", nil, false},
		{"nil cache config defaults to memory", &config.Config{}, false},
		{"empty type defaults to memory", &config.Config{Cache: &config.Cache{}}, false},
		{"memory", &config.Config{Cache: &config.Cache{Type: "memory"}}, false},
		{"dynamodb without table", &config.Config{Cache: &config.Cache{Type: "dynamodb"}}, true},
		{"s3 without bucket", &config.Config{Cache: &config.Cache{Type: "s3"}}, true},
		{"s3 without prefix", &config.Config{Cache: &config.Cache{Type: "s3", S3Bucket: "b"}}, true},
		{"unsupported type", &config.Config{Cache: &config.Cache{Type: "redis"}}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := NewCache(tt.cfg)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if _, ok := c.(*memoryCache); !ok {
				t.Fatalf("expected *memoryCache, got %T", c)
			}
		})
	}
}

func TestNewCacheMemoryHonorsConfig(t *testing.T) {
	cfg := &config.Config{Cache: &config.Cache{
		Type:         "memory",
		TTL:          2 * time.Hour,
		MaxLocalSize: 7,
	}}

	c, err := NewCache(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	mc := c.(*memoryCache)
	if mc.local.maxSize != 7 {
		t.Fatalf("maxSize = %d, want 7 from config", mc.local.maxSize)
	}
	if mc.local.defaultTTL != 2*time.Hour {
		t.Fatalf("defaultTTL = %v, want 2h from config", mc.local.defaultTTL)
	}
}

// Run with -race: proves the shared map is correctly mutex-guarded.
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

// Run with -race; stresses the shared local tier concurrently.
func TestDynamoDBCacheConcurrentLocalTierRace(t *testing.T) {
	mock := &mockDynamoDB{}
	c := newTestDynamoDBCache(mock)
	c.local.maxSize = 5

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

// Run with -race.
func TestS3CacheConcurrentLocalTierRace(t *testing.T) {
	mock := &mockS3{}
	c := newTestS3Cache(mock)
	c.local.maxSize = 5

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

// A failure here means issuer A's cached keys could be looked up under
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

			if got, found := c.Get(issuerB); found {
				t.Fatalf("issuer with trailing slash resolved to another issuer's cached JWKS: %+v", got)
			}
			if got, found := c.Get(issuerC); found {
				t.Fatalf("unrelated issuer resolved to another issuer's cached JWKS: %+v", got)
			}

			got, found := c.Get(issuerA)
			if !found || got.Keys[0].KeyID != "kid-A" {
				t.Fatalf("expected issuer A to hit its own entry, got found=%v val=%+v", found, got)
			}
		})
	}
}

// S3 keys are opaque strings with no path resolution, so a crafted issuer
// containing ".." can't make formatKey escape the configured prefix.
func TestS3CacheFormatKeyNoTraversalEscape(t *testing.T) {
	c := &s3Cache{prefix: "jwks"}

	got := c.formatKey("../../other-prefix/secret")
	want := "jwks/../../other-prefix/secret"
	if got != want {
		t.Fatalf("formatKey = %q, want %q", got, want)
	}
	// S3 doesn't collapse "..", so IAM policies scoped by ARN prefix
	// (e.g. arn:aws:s3:::bucket/jwks/*) aren't bypassed by this key.
}
