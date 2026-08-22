package s3logger

import (
	"bytes"
	"context"
	"net/url"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	gtvcfg "github.com/boogy/aws-oidc-warden/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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

// TestWriteRecord_InheritsCallerDeadline: the enforced audit write gates
// credential issuance, so it must inherit the request's deadline. It used to
// derive its timeout from the logger's own background context, so a request
// with 50ms of budget left could still block for the full 10s S3 timeout on
// work whose result nobody would read.
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

// A caller with no deadline of its own still gets the logger's fixed timeout —
// inheriting the caller's context must not remove the bound.
func TestWriteRecord_AppliesOwnTimeoutWhenCallerHasNoDeadline(t *testing.T) {
	l := NewS3Logger(&gtvcfg.Config{LogToS3: true, LogBucket: "audit-bucket"})
	spy := &ctxCapturingS3{}
	l.SetS3Client(spy)

	require.NoError(t, l.WriteRecord(context.Background(), []byte(`{"decision":"allow"}`)))

	require.Len(t, spy.deadlines, 1)
	require.True(t, spy.hasDeadli[0], "PutObject context carried no deadline")
	assert.WithinDuration(t, time.Now().Add(DefaultTimeout), spy.deadlines[0], 2*time.Second)
}

// TestWriteLogToS3_UsesLiveConfigAfterReload: the best-effort batched path
// gated on the boot-time snapshot while targetBucket() read the live config —
// one object with two notions of "current config". A container that booted
// with log_to_s3 off silently dropped every buffered record after a reload
// turned it on.
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

// The best-effort path must stay a silent no-op when the LIVE config has S3
// logging off — the lazy build must never invent a destination.
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

// TestWriteSingleLog_UsesLiveConfigAfterReload mirrors the WriteLogToS3 case
// for the unbatched best-effort helper.
func TestWriteSingleLog_UsesLiveConfigAfterReload(t *testing.T) {
	l := NewS3Logger(&gtvcfg.Config{LogToS3: false})

	live := &gtvcfg.Config{LogToS3: true, LogBucket: "reloaded-bucket"}
	l.SetConfigSource(func() *gtvcfg.Config { return live })

	spy := &ctxCapturingS3{}
	l.clientFactory = func(context.Context) (s3ClientInterface, error) { return spy, nil }

	require.NoError(t, l.WriteSingleLog([]byte(`{"decision":"allow"}`)))
	require.Equal(t, []string{"reloaded-bucket"}, spy.buckets)
}

// TestWriteObject_TaggingIsURLEncoded: PutObjectInput.Tagging is a URL query
// string. created-at is RFC3339, whose non-UTC offsets contain a literal "+",
// which decodes as a space — so the raw concatenation stored a corrupted
// timestamp on any host not running UTC.
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
