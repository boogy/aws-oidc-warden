package logevent

import (
	"context"
	"testing"
)

func TestWithRequest_RoundTrips(t *testing.T) {
	want := Request{ID: "req-1", FrontendID: "fe-1", SourceIP: "203.0.113.7", SourceIPFrom: "x-forwarded-for"}
	ctx := WithRequest(context.Background(), want)

	got, ok := RequestFrom(ctx)
	if !ok {
		t.Fatal("RequestFrom() ok = false, want true after WithRequest")
	}
	if got != want {
		t.Errorf("RequestFrom() = %+v, want %+v", got, want)
	}
}

func TestRequestFrom_MissingReturnsFalse(t *testing.T) {
	got, ok := RequestFrom(context.Background())
	if ok {
		t.Error("RequestFrom() ok = true on a context with no Request, want false")
	}
	if got != (Request{}) {
		t.Errorf("RequestFrom() = %+v on miss, want zero value", got)
	}
}
