package cache

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	ddbtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	gTypes "github.com/boogy/aws-oidc-warden/internal/types"
)

type mockDynamoDB struct {
	mu       sync.Mutex
	getFn    func(*dynamodb.GetItemInput) (*dynamodb.GetItemOutput, error)
	getCalls int
	putCalls int
	lastPut  *dynamodb.PutItemInput
}

func (m *mockDynamoDB) GetItem(_ context.Context, params *dynamodb.GetItemInput, _ ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error) {
	m.mu.Lock()
	m.getCalls++
	fn := m.getFn
	m.mu.Unlock()
	if fn == nil {
		return &dynamodb.GetItemOutput{}, nil
	}
	return fn(params)
}

func (m *mockDynamoDB) PutItem(_ context.Context, params *dynamodb.PutItemInput, _ ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error) {
	m.mu.Lock()
	m.putCalls++
	m.lastPut = params
	m.mu.Unlock()
	return &dynamodb.PutItemOutput{}, nil
}

func newTestDynamoDBCache(mock *mockDynamoDB) *dynamoDBCache {
	return &dynamoDBCache{
		client:       mock,
		tableName:    "test-table",
		memCache:     make(map[string]*cacheEntry),
		maxLocalSize: 10,
		defaultTTL:   time.Minute,
	}
}

func ddbItem(t *testing.T, jwks *gTypes.JWKS, expiration string) map[string]ddbtypes.AttributeValue {
	t.Helper()
	valueJSON, err := json.Marshal(jwks)
	if err != nil {
		t.Fatal(err)
	}
	item := map[string]ddbtypes.AttributeValue{
		"Key":   &ddbtypes.AttributeValueMemberS{Value: "key1"},
		"Value": &ddbtypes.AttributeValueMemberS{Value: string(valueJSON)},
	}
	if expiration != "" {
		item["Expiration"] = &ddbtypes.AttributeValueMemberS{Value: expiration}
	}
	return item
}

func TestDynamoDBCacheLocalHitSkipsDynamoDB(t *testing.T) {
	mock := &mockDynamoDB{}
	c := newTestDynamoDBCache(mock)

	c.storeInLocalCache("key1", testJWKS("kid1"), time.Now().Add(time.Minute))

	got, found := c.Get("key1")
	if !found || got.Keys[0].KeyID != "kid1" {
		t.Fatal("expected local cache hit")
	}
	if mock.getCalls != 0 {
		t.Fatalf("DynamoDB called %d times, want 0", mock.getCalls)
	}
}

func TestDynamoDBCacheHitRepopulatesLocalWithRealExpiration(t *testing.T) {
	wantExpiration := time.Now().Add(30 * time.Second).UTC().Truncate(time.Second)
	mock := &mockDynamoDB{}
	mock.getFn = func(*dynamodb.GetItemInput) (*dynamodb.GetItemOutput, error) {
		return &dynamodb.GetItemOutput{
			Item: ddbItem(t, testJWKS("kid1"), wantExpiration.Format(time.RFC3339)),
		}, nil
	}
	c := newTestDynamoDBCache(mock)

	got, found := c.Get("key1")
	if !found || got.Keys[0].KeyID != "kid1" {
		t.Fatal("expected DynamoDB cache hit")
	}

	// Local tier must carry the item's real expiration, not the default TTL
	c.memCacheMu.Lock()
	entry := c.memCache["key1"]
	c.memCacheMu.Unlock()
	if entry == nil {
		t.Fatal("expected item in local cache after DynamoDB hit")
	}
	if !entry.expiration.Equal(wantExpiration) {
		t.Fatalf("local expiration = %v, want %v", entry.expiration, wantExpiration)
	}

	// Second Get is served locally
	if _, found := c.Get("key1"); !found {
		t.Fatal("expected local hit on second Get")
	}
	if mock.getCalls != 1 {
		t.Fatalf("DynamoDB called %d times, want 1", mock.getCalls)
	}
}

func TestDynamoDBCacheExpirationHandling(t *testing.T) {
	tests := []struct {
		name string
		item func(t *testing.T) map[string]ddbtypes.AttributeValue
	}{
		{"expired item", func(t *testing.T) map[string]ddbtypes.AttributeValue {
			return ddbItem(t, testJWKS("kid1"), time.Now().Add(-time.Minute).Format(time.RFC3339))
		}},
		{"missing Expiration attribute", func(t *testing.T) map[string]ddbtypes.AttributeValue {
			return ddbItem(t, testJWKS("kid1"), "")
		}},
		{"malformed Expiration", func(t *testing.T) map[string]ddbtypes.AttributeValue {
			return ddbItem(t, testJWKS("kid1"), "not-a-timestamp")
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &mockDynamoDB{}
			mock.getFn = func(*dynamodb.GetItemInput) (*dynamodb.GetItemOutput, error) {
				return &dynamodb.GetItemOutput{Item: tt.item(t)}, nil
			}
			c := newTestDynamoDBCache(mock)

			if _, found := c.Get("key1"); found {
				t.Fatal("expected miss (fail closed)")
			}
		})
	}
}

func TestDynamoDBCacheMissAndErrors(t *testing.T) {
	tests := []struct {
		name  string
		getFn func(*dynamodb.GetItemInput) (*dynamodb.GetItemOutput, error)
	}{
		{"item not found", func(*dynamodb.GetItemInput) (*dynamodb.GetItemOutput, error) {
			return &dynamodb.GetItemOutput{}, nil
		}},
		{"GetItem error", func(*dynamodb.GetItemInput) (*dynamodb.GetItemOutput, error) {
			return nil, errors.New("throttled")
		}},
		{"oversized Value", func(*dynamodb.GetItemInput) (*dynamodb.GetItemOutput, error) {
			return &dynamodb.GetItemOutput{Item: map[string]ddbtypes.AttributeValue{
				"Key":        &ddbtypes.AttributeValueMemberS{Value: "key1"},
				"Value":      &ddbtypes.AttributeValueMemberS{Value: strings.Repeat("x", int(Defaults.MaxItemSize)+1)},
				"Expiration": &ddbtypes.AttributeValueMemberS{Value: time.Now().Add(time.Minute).Format(time.RFC3339)},
			}}, nil
		}},
		{"invalid JSON in Value", func(*dynamodb.GetItemInput) (*dynamodb.GetItemOutput, error) {
			return &dynamodb.GetItemOutput{Item: map[string]ddbtypes.AttributeValue{
				"Key":        &ddbtypes.AttributeValueMemberS{Value: "key1"},
				"Value":      &ddbtypes.AttributeValueMemberS{Value: "{not json"},
				"Expiration": &ddbtypes.AttributeValueMemberS{Value: time.Now().Add(time.Minute).Format(time.RFC3339)},
			}}, nil
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &mockDynamoDB{getFn: tt.getFn}
			c := newTestDynamoDBCache(mock)

			if _, found := c.Get("key1"); found {
				t.Fatal("expected miss")
			}
		})
	}
}

func TestDynamoDBCacheSetIsSynchronous(t *testing.T) {
	mock := &mockDynamoDB{}
	c := newTestDynamoDBCache(mock)

	c.Set("key1", testJWKS("kid1"), time.Minute)

	// No sleep: the write must have completed before Set returned
	if mock.putCalls != 1 {
		t.Fatalf("PutItem called %d times before Set returned, want 1", mock.putCalls)
	}
	if got := mock.lastPut.Item["Key"].(*ddbtypes.AttributeValueMemberS).Value; got != "key1" {
		t.Fatalf("PutItem key = %q, want key1", got)
	}

	// Local tier is populated too
	if _, found := c.Get("key1"); !found {
		t.Fatal("expected local hit after Set")
	}
	if mock.getCalls != 0 {
		t.Fatal("Get after Set should not reach DynamoDB")
	}
}

func TestDynamoDBCacheSetRejectsOversizedItem(t *testing.T) {
	mock := &mockDynamoDB{}
	c := newTestDynamoDBCache(mock)

	big := &gTypes.JWKS{Keys: []gTypes.JSONWebKey{{
		KeyID: "kid1",
		N:     strings.Repeat("a", int(Defaults.DynamoDBMaxItemSize)+1),
	}}}
	c.Set("key1", big, time.Minute)

	if mock.putCalls != 0 {
		t.Fatalf("oversized item must not be written, PutItem called %d times", mock.putCalls)
	}
}
