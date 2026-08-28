package s3logger

import (
	"bytes"
	"context"
	"errors"
	"net/url"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	gtvcfg "github.com/boogy/aws-oidc-warden/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// bucketCapturingS3 duplicates logger_test.go's mock because that type lives
// in the external s3logger_test package, which can't see unexported state.
type bucketCapturingS3 struct{ buckets []string }

func (b *bucketCapturingS3) PutObject(_ context.Context, in *s3.PutObjectInput, _ ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	b.buckets = append(b.buckets, *in.Bucket)
	return &s3.PutObjectOutput{}, nil
}

func TestWriteRecord_UsesLiveBucketAfterReload(t *testing.T) {
	boot := &gtvcfg.Config{LogToS3: true, LogBucket: "boot-bucket"}
	l := NewS3Logger(boot)

	live := &gtvcfg.Config{LogToS3: true, LogBucket: "rotated-bucket"}
	l.SetConfigSource(func() *gtvcfg.Config { return live })

	spy := &bucketCapturingS3{}
	l.SetS3Client(spy)

	require.NoError(t, l.WriteRecord(context.Background(), []byte(`{"decision":"allow"}`)))
	require.Equal(t, []string{"rotated-bucket"}, spy.buckets,
		"audit record went to the boot-time bucket, ignoring the rotated log_bucket")
}

func TestWriteRecord_FallsBackToSnapshotBucket(t *testing.T) {
	l := NewS3Logger(&gtvcfg.Config{LogToS3: true, LogBucket: "only-bucket"})

	spy := &bucketCapturingS3{}
	l.SetS3Client(spy)

	require.NoError(t, l.WriteRecord(context.Background(), []byte(`{"decision":"allow"}`)))
	require.Equal(t, []string{"only-bucket"}, spy.buckets)
}

func TestAudit_WriteRecord_SilentNoOpWhenOwnConfigDisablesS3(t *testing.T) {
	l := NewS3Logger(&gtvcfg.Config{LogToS3: false})

	if l.s3Client != nil {
		t.Fatalf("expected no S3 client when LogToS3=false")
	}

	err := l.WriteRecord(context.Background(), []byte(`{"decision":"allow"}`))
	t.Logf("WriteRecord returned err=%v (nothing was persisted)", err)
	if err == nil {
		t.Errorf("FAIL-OPEN: WriteRecord reported success without persisting the audit record")
	}

	if berr := l.BufferRecord([]byte(`{"decision":"allow"}`)); berr != nil {
		t.Logf("BufferRecord err=%v", berr)
	}
	t.Logf("logBatch length after BufferRecord = %d (record silently dropped)", len(l.logBatch))
}

func TestWriteRecord_BuildsClientLazilyAfterReloadEnablesS3(t *testing.T) {
	l := NewS3Logger(&gtvcfg.Config{LogToS3: false})
	require.Nil(t, l.s3Client, "no client should exist when the boot config disables S3 logging")

	live := &gtvcfg.Config{LogToS3: true, LogBucket: "audit-bucket"}
	l.SetConfigSource(func() *gtvcfg.Config { return live })

	spy := &bucketCapturingS3{}
	built := 0
	l.clientFactory = func(context.Context) (s3ClientInterface, error) {
		built++
		return spy, nil
	}

	require.NoError(t, l.WriteRecord(context.Background(), []byte(`{"decision":"allow"}`)),
		"WriteRecord failed after a reload enabled S3 logging: the audit trail is unwritable and every allow returns 500 until cold start")
	require.Equal(t, []string{"audit-bucket"}, spy.buckets)

	// Second record reuses the client rather than rebuilding it per write.
	require.NoError(t, l.WriteRecord(context.Background(), []byte(`{"decision":"allow"}`)))
	require.Equal(t, 1, built, "client should be built once and cached")
	require.Len(t, spy.buckets, 2)
}

func TestWriteRecord_DoesNotBuildClientWhenLiveConfigDisablesS3(t *testing.T) {
	l := NewS3Logger(&gtvcfg.Config{LogToS3: false})

	live := &gtvcfg.Config{LogToS3: false, LogBucket: "audit-bucket"}
	l.SetConfigSource(func() *gtvcfg.Config { return live })

	built := 0
	l.clientFactory = func(context.Context) (s3ClientInterface, error) {
		built++
		return &bucketCapturingS3{}, nil
	}

	err := l.WriteRecord(context.Background(), []byte(`{"decision":"allow"}`))
	require.Error(t, err, "FAIL-OPEN: WriteRecord reported success without persisting the audit record")
	require.Zero(t, built, "no S3 client should be built when the live config disables S3 audit logging")
}

func TestWriteRecord_ClientFactoryFailureFailsClosed(t *testing.T) {
	l := NewS3Logger(&gtvcfg.Config{LogToS3: true, LogBucket: "audit-bucket"})
	l.s3Client = nil // undo the constructor's real client

	l.clientFactory = func(context.Context) (s3ClientInterface, error) {
		return nil, errors.New("no AWS credentials")
	}

	err := l.WriteRecord(context.Background(), []byte(`{"decision":"allow"}`))
	require.Error(t, err)
	require.Contains(t, err.Error(), "no AWS credentials")
	require.Nil(t, l.s3Client)
}

// ctxCapturingS3 records the context and tagging string of each PutObject.
type ctxCapturingS3 struct {
	deadlines []time.Time
	hasDeadli []bool
	taggings  []string
	buckets   []string
}

func (c *ctxCapturingS3) PutObject(ctx context.Context, in *s3.PutObjectInput, _ ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	dl, ok := ctx.Deadline()
	c.deadlines = append(c.deadlines, dl)
	c.hasDeadli = append(c.hasDeadli, ok)
	if in.Tagging != nil {
		c.taggings = append(c.taggings, *in.Tagging)
	}
	c.buckets = append(c.buckets, *in.Bucket)
	return &s3.PutObjectOutput{}, nil
}

func TestWriteRecord_InheritsCallerDeadline(t *testing.T) {
	l := NewS3Logger(&gtvcfg.Config{LogToS3: true, LogBucket: "audit-bucket"})
	spy := &ctxCapturingS3{}
	l.SetS3Client(spy)

	callerDeadline := time.Now().Add(50 * time.Millisecond)
	ctx, cancel := context.WithDeadline(context.Background(), callerDeadline)
	defer cancel()

	require.NoError(t, l.WriteRecord(ctx, []byte(`{"decision":"allow"}`)))

	require.Len(t, spy.deadlines, 1)
	require.True(t, spy.hasDeadli[0], "PutObject context carried no deadline")
	assert.False(t, spy.deadlines[0].After(callerDeadline),
		"audit PutObject outlived the caller's deadline (got %v, caller %v)", spy.deadlines[0], callerDeadline)
}

func TestWriteRecord_AppliesOwnTimeoutWhenCallerHasNoDeadline(t *testing.T) {
	l := NewS3Logger(&gtvcfg.Config{LogToS3: true, LogBucket: "audit-bucket"})
	spy := &ctxCapturingS3{}
	l.SetS3Client(spy)

	require.NoError(t, l.WriteRecord(context.Background(), []byte(`{"decision":"allow"}`)))

	require.Len(t, spy.deadlines, 1)
	require.True(t, spy.hasDeadli[0], "PutObject context carried no deadline")
	assert.WithinDuration(t, time.Now().Add(DefaultTimeout), spy.deadlines[0], 2*time.Second)
}

func TestWriteLogToS3_UsesLiveConfigAfterReload(t *testing.T) {
	l := NewS3Logger(&gtvcfg.Config{LogToS3: false})
	require.Nil(t, l.s3Client, "no client should exist while the boot config disables S3")

	live := &gtvcfg.Config{LogToS3: true, LogBucket: "reloaded-bucket"}
	l.SetConfigSource(func() *gtvcfg.Config { return live })

	spy := &ctxCapturingS3{}
	l.clientFactory = func(context.Context) (s3ClientInterface, error) { return spy, nil }

	var buf bytes.Buffer
	buf.WriteString(`{"decision":"allow"}`)
	require.NoError(t, l.WriteLogToS3(buf))
	require.NoError(t, l.Flush())

	require.Equal(t, []string{"reloaded-bucket"}, spy.buckets,
		"best-effort record was dropped instead of written to the reloaded bucket")
}

func TestWriteLogToS3_NoOpWhenLiveConfigDisablesS3(t *testing.T) {
	l := NewS3Logger(&gtvcfg.Config{LogToS3: true, LogBucket: "boot-bucket"})
	live := &gtvcfg.Config{LogToS3: false}
	l.SetConfigSource(func() *gtvcfg.Config { return live })

	spy := &ctxCapturingS3{}
	l.SetS3Client(spy)

	var buf bytes.Buffer
	buf.WriteString(`{"decision":"allow"}`)
	require.NoError(t, l.WriteLogToS3(buf))
	require.NoError(t, l.Flush())

	assert.Empty(t, spy.buckets, "wrote to S3 while the live config disables S3 logging")
}

func TestWriteSingleLog_UsesLiveConfigAfterReload(t *testing.T) {
	l := NewS3Logger(&gtvcfg.Config{LogToS3: false})

	live := &gtvcfg.Config{LogToS3: true, LogBucket: "reloaded-bucket"}
	l.SetConfigSource(func() *gtvcfg.Config { return live })

	spy := &ctxCapturingS3{}
	l.clientFactory = func(context.Context) (s3ClientInterface, error) { return spy, nil }

	require.NoError(t, l.WriteSingleLog([]byte(`{"decision":"allow"}`)))
	require.Equal(t, []string{"reloaded-bucket"}, spy.buckets)
}

func TestWriteObject_TaggingIsURLEncoded(t *testing.T) {
	l := NewS3Logger(&gtvcfg.Config{LogToS3: true, LogBucket: "audit-bucket"})
	spy := &ctxCapturingS3{}
	l.SetS3Client(spy)

	plusTwo := time.FixedZone("CEST", 2*60*60)
	stamp := time.Date(2026, 8, 21, 12, 30, 45, 0, plusTwo)
	l.SetTimeNow(func() time.Time { return stamp })
	l.SetS3ConfigOption(WithExtraTag("incident", "sev1 & rising"))

	require.NoError(t, l.WriteRecord(context.Background(), []byte(`{"decision":"allow"}`)))

	require.Len(t, spy.taggings, 1)
	parsed, err := url.ParseQuery(spy.taggings[0])
	require.NoError(t, err, "tagging string is not a valid URL query string")
	assert.Equal(t, stamp.Format(time.RFC3339), parsed.Get("created-at"),
		"non-UTC created-at did not survive the round-trip")
	assert.Equal(t, "sev1 & rising", parsed.Get("incident"),
		"an extra tag containing a separator corrupted the tag set")
	assert.Equal(t, "aws-oidc-warden", parsed.Get("source"))
}
