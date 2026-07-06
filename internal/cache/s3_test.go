package cache

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	gTypes "github.com/boogy/aws-oidc-warden/internal/types"
)

type mockS3 struct {
	mu          sync.Mutex
	getFn       func(*s3.GetObjectInput) (*s3.GetObjectOutput, error)
	getCalls    int
	putCalls    int
	deleteCalls int
	lastPutKey  string
	lastDelKey  string
}

func (m *mockS3) GetObject(_ context.Context, params *s3.GetObjectInput, _ ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	m.mu.Lock()
	m.getCalls++
	fn := m.getFn
	m.mu.Unlock()
	if fn == nil {
		return nil, &s3types.NoSuchKey{}
	}
	return fn(params)
}

func (m *mockS3) PutObject(_ context.Context, params *s3.PutObjectInput, _ ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	m.mu.Lock()
	m.putCalls++
	m.lastPutKey = *params.Key
	m.mu.Unlock()
	return &s3.PutObjectOutput{}, nil
}

func (m *mockS3) DeleteObject(_ context.Context, params *s3.DeleteObjectInput, _ ...func(*s3.Options)) (*s3.DeleteObjectOutput, error) {
	m.mu.Lock()
	m.deleteCalls++
	m.lastDelKey = *params.Key
	m.mu.Unlock()
	return &s3.DeleteObjectOutput{}, nil
}

func newTestS3Cache(mock *mockS3) *s3Cache {
	return &s3Cache{
		client:       mock,
		bucketName:   "test-bucket",
		prefix:       "jwks",
		memCache:     make(map[string]*s3CacheEntry),
		maxLocalSize: 10,
		defaultTTL:   time.Minute,
	}
}

func s3ObjectBody(t *testing.T, jwks *gTypes.JWKS, expiration time.Time) io.ReadCloser {
	t.Helper()
	data, err := json.Marshal(s3CacheItem{Value: jwks, Expiration: expiration, CreatedAt: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	return io.NopCloser(bytes.NewReader(data))
}

func TestS3CacheLocalHitSkipsS3(t *testing.T) {
	mock := &mockS3{}
	c := newTestS3Cache(mock)

	c.storeInLocalCache("key1", testJWKS("kid1"), time.Now().Add(time.Minute))

	got, found := c.Get("key1")
	if !found || got.Keys[0].KeyID != "kid1" {
		t.Fatal("expected local cache hit")
	}
	if mock.getCalls != 0 {
		t.Fatalf("S3 called %d times, want 0", mock.getCalls)
	}
}

func TestS3CacheHitRepopulatesLocalWithRealExpiration(t *testing.T) {
	wantExpiration := time.Now().Add(30 * time.Second).UTC().Truncate(time.Second)
	mock := &mockS3{}
	mock.getFn = func(*s3.GetObjectInput) (*s3.GetObjectOutput, error) {
		return &s3.GetObjectOutput{Body: s3ObjectBody(t, testJWKS("kid1"), wantExpiration)}, nil
	}
	c := newTestS3Cache(mock)

	got, found := c.Get("key1")
	if !found || got.Keys[0].KeyID != "kid1" {
		t.Fatal("expected S3 cache hit")
	}

	// Local tier must carry the item's real expiration, not the default TTL
	c.memCacheMu.Lock()
	entry := c.memCache["key1"]
	c.memCacheMu.Unlock()
	if entry == nil {
		t.Fatal("expected item in local cache after S3 hit")
	}
	if !entry.expiration.Equal(wantExpiration) {
		t.Fatalf("local expiration = %v, want %v", entry.expiration, wantExpiration)
	}

	// Second Get is served locally
	if _, found := c.Get("key1"); !found {
		t.Fatal("expected local hit on second Get")
	}
	if mock.getCalls != 1 {
		t.Fatalf("S3 called %d times, want 1", mock.getCalls)
	}
}

func TestS3CacheMissAndErrors(t *testing.T) {
	tests := []struct {
		name  string
		getFn func(*s3.GetObjectInput) (*s3.GetObjectOutput, error)
	}{
		{"NoSuchKey", func(*s3.GetObjectInput) (*s3.GetObjectOutput, error) {
			return nil, &s3types.NoSuchKey{}
		}},
		{"generic error", func(*s3.GetObjectInput) (*s3.GetObjectOutput, error) {
			return nil, errors.New("access denied")
		}},
		{"oversized body", func(*s3.GetObjectInput) (*s3.GetObjectOutput, error) {
			body := io.NopCloser(strings.NewReader(strings.Repeat("x", int(Defaults.MaxItemSize)+1)))
			return &s3.GetObjectOutput{Body: body}, nil
		}},
		{"invalid JSON", func(*s3.GetObjectInput) (*s3.GetObjectOutput, error) {
			return &s3.GetObjectOutput{Body: io.NopCloser(strings.NewReader("{not json"))}, nil
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &mockS3{getFn: tt.getFn}
			c := newTestS3Cache(mock)

			if _, found := c.Get("key1"); found {
				t.Fatal("expected miss")
			}
		})
	}
}

func TestS3CacheExpiredObjectCleanup(t *testing.T) {
	tests := []struct {
		name            string
		cleanup         bool
		wantDeleteCalls int
	}{
		{"cleanup enabled deletes expired object", true, 1},
		{"cleanup disabled keeps expired object", false, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &mockS3{}
			mock.getFn = func(*s3.GetObjectInput) (*s3.GetObjectOutput, error) {
				return &s3.GetObjectOutput{
					Body: s3ObjectBody(t, testJWKS("kid1"), time.Now().Add(-time.Minute)),
				}, nil
			}
			c := newTestS3Cache(mock)
			c.cleanup = tt.cleanup

			if _, found := c.Get("key1"); found {
				t.Fatal("expected miss for expired object")
			}
			// Deletion is synchronous, so no waiting is needed
			if mock.deleteCalls != tt.wantDeleteCalls {
				t.Fatalf("DeleteObject called %d times, want %d", mock.deleteCalls, tt.wantDeleteCalls)
			}
			if tt.cleanup && mock.lastDelKey != "jwks/key1" {
				t.Fatalf("deleted key = %q, want jwks/key1", mock.lastDelKey)
			}
		})
	}
}

func TestS3CacheSetIsSynchronous(t *testing.T) {
	mock := &mockS3{}
	c := newTestS3Cache(mock)

	c.Set("key1", testJWKS("kid1"), time.Minute)

	// No sleep: the write must have completed before Set returned
	if mock.putCalls != 1 {
		t.Fatalf("PutObject called %d times before Set returned, want 1", mock.putCalls)
	}
	if mock.lastPutKey != "jwks/key1" {
		t.Fatalf("PutObject key = %q, want jwks/key1", mock.lastPutKey)
	}

	// Local tier is populated too
	if _, found := c.Get("key1"); !found {
		t.Fatal("expected local hit after Set")
	}
	if mock.getCalls != 0 {
		t.Fatal("Get after Set should not reach S3")
	}
}

func TestS3CacheWriteReadSizeLimitsAgree(t *testing.T) {
	// An item the write path accepts must be readable back; an item over the
	// shared limit must be rejected on write so it can never become
	// unreadable-but-stored
	mock := &mockS3{}
	c := newTestS3Cache(mock)

	over := &gTypes.JWKS{Keys: []gTypes.JSONWebKey{{
		KeyID: "kid1",
		N:     strings.Repeat("a", int(Defaults.MaxItemSize)+1),
	}}}
	c.Set("too-big", over, time.Minute)
	if mock.putCalls != 0 {
		t.Fatalf("oversized item must not be written, PutObject called %d times", mock.putCalls)
	}

	// Just-fitting item: stored, and the same bytes decode on the read path
	fits := &gTypes.JWKS{Keys: []gTypes.JSONWebKey{{
		KeyID: "kid1",
		N:     strings.Repeat("a", int(Defaults.MaxItemSize)-1024),
	}}}
	expiration := time.Now().Add(time.Minute)
	mock.getFn = func(*s3.GetObjectInput) (*s3.GetObjectOutput, error) {
		return &s3.GetObjectOutput{Body: s3ObjectBody(t, fits, expiration)}, nil
	}
	c.Set("fits", fits, time.Minute)
	if mock.putCalls != 1 {
		t.Fatalf("just-fitting item must be written, PutObject called %d times", mock.putCalls)
	}

	fresh := newTestS3Cache(mock) // empty local tier forces the S3 read path
	if _, found := fresh.Get("fits"); !found {
		t.Fatal("item accepted by the write path must be readable")
	}
}

func TestS3CacheFormatKey(t *testing.T) {
	c := &s3Cache{prefix: "jwks"}
	if got := c.formatKey("key1"); got != "jwks/key1" {
		t.Fatalf("formatKey = %q, want jwks/key1", got)
	}
	c.prefix = ""
	if got := c.formatKey("key1"); got != "key1" {
		t.Fatalf("formatKey without prefix = %q, want key1", got)
	}
}
