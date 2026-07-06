package cache

import (
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
	if mc.maxSize != 7 {
		t.Fatalf("maxSize = %d, want 7 from config", mc.maxSize)
	}
	if mc.defaultTTL != 2*time.Hour {
		t.Fatalf("defaultTTL = %v, want 2h from config", mc.defaultTTL)
	}
}
