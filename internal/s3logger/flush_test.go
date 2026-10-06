package s3logger

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	gtvcfg "github.com/boogy/aws-oidc-warden/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// flakyS3 fails every PutObject while fail is set, and keeps each uploaded body.
type flakyS3 struct {
	mu     sync.Mutex
	fail   bool
	calls  int
	bodies [][]byte
	block  chan struct{}
}

func (f *flakyS3) PutObject(_ context.Context, in *s3.PutObjectInput, _ ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	if f.block != nil {
		<-f.block
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.fail {
		return nil, errors.New("s3 down")
	}
	b, _ := io.ReadAll(in.Body)
	f.bodies = append(f.bodies, b)
	return &s3.PutObjectOutput{}, nil
}

func (f *flakyS3) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func newFlakyLogger(t *testing.T, batchSize int) (*S3Logger, *flakyS3) {
	t.Helper()
	l := NewS3Logger(&gtvcfg.Config{LogToS3: true, LogBucket: "b"})
	f := &flakyS3{}
	l.SetS3Client(f)
	l.SetS3ConfigOption(WithBatchSize(batchSize))
	return l, f
}

func pending(l *S3Logger) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.logBatch)
}

func flushInFlight(l *S3Logger) bool {
	if l.flushMu.TryLock() {
		l.flushMu.Unlock()
		return false
	}
	return true
}

func gunzip(t *testing.T, b []byte) string {
	t.Helper()
	r, err := gzip.NewReader(bytes.NewReader(b))
	require.NoError(t, err)
	out, err := io.ReadAll(r)
	require.NoError(t, err)
	return string(out)
}

func TestFlushFailure_BackoffSkipsPerRequestRetries(t *testing.T) {
	l, f := newFlakyLogger(t, 2)
	l.flushBackoff = time.Hour
	f.fail = true

	require.NoError(t, l.BufferRecord([]byte("r0\n")))
	require.Error(t, l.BufferRecord([]byte("r1\n")), "first threshold flush reports the failure")
	for i := 2; i < 50; i++ {
		require.NoError(t, l.BufferRecord(fmt.Appendf(nil, "r%d\n", i)))
	}

	assert.Equal(t, 1, f.callCount(), "backoff must stop every request retrying the batch")
	assert.Equal(t, 50, pending(l), "failed records stay queued")
}

func TestFlushFailure_RecoversAfterBackoffAndKeepsOrder(t *testing.T) {
	l, f := newFlakyLogger(t, 2)
	l.flushBackoff = time.Millisecond
	f.fail = true

	require.NoError(t, l.BufferRecord([]byte("a\n")))
	require.Error(t, l.BufferRecord([]byte("b\n")))

	f.mu.Lock()
	f.fail = false
	f.mu.Unlock()
	time.Sleep(5 * time.Millisecond)
	require.NoError(t, l.BufferRecord([]byte("c\n")))

	require.Equal(t, 0, pending(l))
	require.Len(t, f.bodies, 1)
	assert.Equal(t, "a\nb\nc\n", gunzip(t, f.bodies[0]))
}

func TestFlushFailure_PendingIsCapped(t *testing.T) {
	l, f := newFlakyLogger(t, 1)
	l.flushBackoff = time.Hour
	f.fail = true

	total := maxPendingRecords + 100
	for i := range total {
		_ = l.BufferRecord(fmt.Appendf(nil, "r%d\n", i))
	}
	assert.Equal(t, maxPendingRecords, pending(l))

	l.mu.Lock()
	oldest, newest := string(l.logBatch[0]), string(l.logBatch[len(l.logBatch)-1])
	assert.Equal(t, 100, l.dropped)
	l.mu.Unlock()
	assert.Equal(t, "r100\n", oldest, "oldest records are dropped first")
	assert.Equal(t, fmt.Sprintf("r%d\n", total-1), newest)

	f.mu.Lock()
	f.fail = false
	f.mu.Unlock()
	require.NoError(t, l.Close())
	assert.Equal(t, 0, pending(l))
}

func TestClose_WaitsForInFlightFlush(t *testing.T) {
	l, f := newFlakyLogger(t, 1)
	f.block = make(chan struct{})

	done := make(chan error, 1)
	go func() { done <- l.BufferRecord([]byte("slow\n")) }()
	require.Eventually(t, func() bool { return flushInFlight(l) }, time.Second, time.Millisecond)

	closed := make(chan error, 1)
	go func() { closed <- l.Close() }()
	select {
	case <-closed:
		t.Fatal("Close returned while an upload was still in flight")
	case <-time.After(20 * time.Millisecond):
	}

	close(f.block)
	require.NoError(t, <-done)
	require.NoError(t, <-closed)
	assert.Equal(t, 1, f.callCount())
}

func TestBufferRecord_DoesNotBlockWhileUploadInFlight(t *testing.T) {
	l, f := newFlakyLogger(t, 1)
	f.block = make(chan struct{})

	go func() { _ = l.BufferRecord([]byte("slow\n")) }()
	require.Eventually(t, func() bool { return flushInFlight(l) }, time.Second, time.Millisecond)

	var returned atomic.Bool
	go func() {
		_ = l.BufferRecord([]byte("fast\n"))
		returned.Store(true)
	}()
	require.Eventually(t, returned.Load, time.Second, time.Millisecond, "BufferRecord stalled behind an in-flight upload")
	close(f.block)
}

func TestBufferRecord_CopiesCallerSlice(t *testing.T) {
	l, f := newFlakyLogger(t, 100)
	rec := []byte("original\n")
	require.NoError(t, l.BufferRecord(rec))
	copy(rec, "MUTATED!\n")
	require.NoError(t, l.Flush())

	require.Len(t, f.bodies, 1)
	assert.Equal(t, "original\n", gunzip(t, f.bodies[0]))
}

func TestCompressGzip_PooledWritersRoundTrip(t *testing.T) {
	var wg sync.WaitGroup
	for i := range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range 50 {
				in := strings.Repeat(fmt.Sprintf("{\"w\":%d,\"j\":%d}\n", i, j), j+1)
				out, err := compressGzip([]byte(in))
				if !assert.NoError(t, err) {
					return
				}
				assert.Equal(t, in, gunzip(t, out))
			}
		}()
	}
	wg.Wait()
}

func TestGenerateS3Key_UsesUTC(t *testing.T) {
	l := NewS3Logger(&gtvcfg.Config{LogBucket: "b", LogPrefix: "logs"})
	l.SetS3ConfigOption(WithIncludeUUID(false))
	l.SetTimeNow(func() time.Time {
		return time.Date(2026, 8, 21, 1, 30, 45, 0, time.FixedZone("CEST", 2*60*60))
	})
	assert.Equal(t, "logs/2026/08/20/20260820-233045.json.gz", l.generateS3Key())
}
