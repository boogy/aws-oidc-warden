package validator

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/boogy/aws-oidc-warden/internal/config"
)

func TestALBKeyFetchMemoizesFailures(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})

	var hits atomic.Int32
	var serveKey atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		if !serveKey.Load() {
			http.NotFound(w, nil)
			return
		}
		_, _ = w.Write(pubPEM)
	}))
	defer srv.Close()

	now := time.Unix(1_700_000_000, 0)
	a := NewALBExtractor(config.NewStaticProvider(&config.Config{}),
		WithALBKeyEndpoint(srv.URL+"/%s"), WithALBHTTPClient(srv.Client()))
	a.keyCache.now = func() time.Time { return now }
	ctx := context.Background()

	for range 20 {
		if _, err := a.fetchPublicKey(ctx, "us-east-1", "unknown-kid"); err == nil {
			t.Fatal("fetch of an unknown kid succeeded")
		}
	}
	if got := hits.Load(); got != 1 {
		t.Fatalf("20 lookups of one failing kid made %d fetches, want 1", got)
	}

	serveKey.Store(true)
	now = now.Add(albKeyFailureTTL - time.Millisecond)
	if _, err := a.fetchPublicKey(ctx, "us-east-1", "unknown-kid"); err == nil {
		t.Fatal("memoized failure not returned before its TTL")
	}

	now = now.Add(time.Millisecond)
	if _, err := a.fetchPublicKey(ctx, "us-east-1", "unknown-kid"); err != nil {
		t.Fatalf("fetch after failure TTL: %v", err)
	}
	if got := hits.Load(); got != 2 {
		t.Fatalf("fetches = %d, want 2 (one refetch after the failure TTL)", got)
	}
}

type gatedRoundTripper struct {
	hits atomic.Int32
	gate chan struct{}
	body []byte
}

func (g *gatedRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	g.hits.Add(1)
	<-g.gate
	return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(g.body)), Header: http.Header{}}, nil
}

func TestALBKeyFetchConcurrentLookupsShareOneFetch(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	body := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})

	synctest.Test(t, func(t *testing.T) {
		rt := &gatedRoundTripper{gate: make(chan struct{}), body: body}
		a := NewALBExtractor(config.NewStaticProvider(&config.Config{}),
			WithALBKeyEndpoint("http://keys.test/%s"), WithALBHTTPClient(&http.Client{Transport: rt}))

		const n = 8
		var wg sync.WaitGroup
		errs := make(chan error, n)
		for range n {
			wg.Go(func() {
				_, err := a.fetchPublicKey(context.Background(), "us-east-1", "kid-1")
				errs <- err
			})
		}
		synctest.Wait()
		close(rt.gate)
		wg.Wait()
		close(errs)
		for err := range errs {
			if err != nil {
				t.Fatalf("concurrent fetch: %v", err)
			}
		}
		if got := rt.hits.Load(); got != 1 {
			t.Fatalf("%d concurrent lookups of one kid made %d fetches, want 1", n, got)
		}
	})
}
