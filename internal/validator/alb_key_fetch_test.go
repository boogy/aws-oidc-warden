package validator

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
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

func newTestKeyPEM(t *testing.T) (*ecdsa.PrivateKey, []byte) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return priv, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}

func newGatedALB(body []byte) (*ALBExtractor, *gatedRoundTripper) {
	rt := &gatedRoundTripper{gate: make(chan struct{}), body: body}
	return NewALBExtractor(config.NewStaticProvider(&config.Config{}),
		WithALBKeyEndpoint("http://keys.test/%s"), WithALBHTTPClient(&http.Client{Transport: rt})), rt
}

func TestALBKeyFetchMemoizesFailures(t *testing.T) {
	_, pubPEM := newTestKeyPEM(t)

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

func (g *gatedRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	g.hits.Add(1)
	select {
	case <-g.gate:
	case <-req.Context().Done():
		return nil, req.Context().Err()
	}
	return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(g.body)), Header: http.Header{}}, nil
}

func TestALBKeyFetchConcurrentLookupsShareOneFetch(t *testing.T) {
	priv, body := newTestKeyPEM(t)

	synctest.Test(t, func(t *testing.T) {
		a, rt := newGatedALB(body)

		const n = 8
		var wg sync.WaitGroup
		keys := make([]*ecdsa.PublicKey, n)
		errs := make([]error, n)
		for i := range n {
			wg.Go(func() {
				keys[i], errs[i] = a.fetchPublicKey(context.Background(), "us-east-1", "kid-1")
			})
		}
		synctest.Wait()
		close(rt.gate)
		wg.Wait()
		for i := range n {
			if errs[i] != nil || keys[i] == nil || !keys[i].Equal(&priv.PublicKey) {
				t.Fatalf("caller %d: key %v, err %v", i, keys[i], errs[i])
			}
		}
		if got := rt.hits.Load(); got != 1 {
			t.Fatalf("%d concurrent lookups of one kid made %d fetches, want 1", n, got)
		}
	})
}

func TestALBKeyFetchCallerCancelDoesNotFailSharedFetch(t *testing.T) {
	priv, body := newTestKeyPEM(t)

	synctest.Test(t, func(t *testing.T) {
		a, rt := newGatedALB(body)
		release := sync.OnceFunc(func() { close(rt.gate) })
		defer release()

		ctx, cancel := context.WithCancel(context.Background())
		var errA, errB error
		var keyB *ecdsa.PublicKey
		var wg sync.WaitGroup
		wg.Go(func() { _, errA = a.fetchPublicKey(ctx, "us-east-1", "kid-1") })
		synctest.Wait()
		wg.Go(func() { keyB, errB = a.fetchPublicKey(context.Background(), "us-east-1", "kid-1") })
		synctest.Wait()
		cancel()
		synctest.Wait()
		if err := a.keyCache.failed("kid-1"); err != nil {
			t.Fatalf("failure memoized after a caller cancelled: %v", err)
		}
		var keyC *ecdsa.PublicKey
		var errC error
		wg.Go(func() { keyC, errC = a.fetchPublicKey(context.Background(), "us-east-1", "kid-1") })
		synctest.Wait()
		release()
		wg.Wait()

		if !errors.Is(errA, context.Canceled) {
			t.Fatalf("cancelled caller: err %v, want context.Canceled", errA)
		}
		if errB != nil || keyB == nil || !keyB.Equal(&priv.PublicKey) {
			t.Fatalf("sharing caller: key %v, err %v", keyB, errB)
		}
		if errC != nil || keyC == nil || !keyC.Equal(&priv.PublicKey) {
			t.Fatalf("caller joining after the cancel: key %v, err %v", keyC, errC)
		}
		if got := rt.hits.Load(); got != 1 {
			t.Fatalf("fetches = %d, want 1", got)
		}
	})
}
