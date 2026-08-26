package s3logger

// Unexported internals: the record writer and the object paths a config
// reload must recompute.
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

// bucketCapturingS3 records the bucket each PutObject targets. Defined here
// rather than reusing logger_test.go's MockS3Client: that file is in the
// external s3logger_test package, and these tests need the internal one to
// reach unexported state.
type bucketCapturingS3 struct{ buckets []string }

func (b *bucketCapturingS3) PutObject(_ context.Context, in *s3.PutObjectInput, _ ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	b.buckets = append(b.buckets, *in.Bucket)
	return &s3.PutObjectOutput{}, nil
}

// TestWriteRecord_UsesLiveBucketAfterReload proves a durable audit record goes
// to the bucket in the CURRENT config, not the one captured at construction.
//
// S3Logger is built once at bootstrap from a config snapshot, but the
// hot-reload provider swaps in a new *Config. Resolving the bucket from the
// snapshot meant rotating log_bucket (e.g. to a locked-down bucket during an
// incident) kept writing to the previous bucket while WriteRecord returned
// success — a write that "succeeded" somewhere the operator no longer intended.
func TestWriteRecord_UsesLiveBucketAfterReload(t *testing.T) {
	boot := &gtvcfg.Config{LogToS3: true, LogBucket: "boot-bucket"}
	l := NewS3Logger(boot)

	// Hot reload rotates the audit bucket.
	live := &gtvcfg.Config{LogToS3: true, LogBucket: "rotated-bucket"}
	l.SetConfigSource(func() *gtvcfg.Config { return live })

	spy := &bucketCapturingS3{}
	l.SetS3Client(spy)

	require.NoError(t, l.WriteRecord(context.Background(), []byte(`{"decision":"allow"}`)))
	require.Equal(t, []string{"rotated-bucket"}, spy.buckets,
		"audit record went to the boot-time bucket, ignoring the rotated log_bucket")
}

// With no live source wired (static/test setups) the constructor's bucket is
// still used — the fallback must not regress.
func TestWriteRecord_FallsBackToSnapshotBucket(t *testing.T) {
	l := NewS3Logger(&gtvcfg.Config{LogToS3: true, LogBucket: "only-bucket"})

	spy := &bucketCapturingS3{}
	l.SetS3Client(spy)

	require.NoError(t, l.WriteRecord(context.Background(), []byte(`{"decision":"allow"}`)))
	require.Equal(t, []string{"only-bucket"}, spy.buckets)
}

// TestAudit_WriteRecord_SilentNoOpWhenOwnConfigDisablesS3 pins the exact
// mechanism behind the handler-level fail-open: WriteRecord is documented to
// "fail closed" so callers enforcing audit_required can await durability, but
// it consults the config pointer the logger captured at construction. When
// that captured config has LogToS3=false, WriteRecord falls through to
// WriteSingleLog, which no-ops and returns nil — reporting success without
// persisting anything.
func TestAudit_WriteRecord_SilentNoOpWhenOwnConfigDisablesS3(t *testing.T) {
	// Boot-time config: S3 logging off (the default).
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

// TestWriteRecord_BuildsClientLazilyAfterReloadEnablesS3 pins the fix for a
// container that cold-started with S3 audit logging off.
//
// The S3 client used to be built exactly once, in NewS3Logger, from the
// boot-time snapshot, while Config.AuditEnforced() is re-derived from the live
// config on every request. An operator who enabled log_to_s3+log_bucket via
// hot reload therefore turned enforcement ON against a logger that could never
// write: every allow decision failed with ErrAuditWriteFailed until the next
// cold start. docs/LOGGING.md promises the opposite ("engages the fail-closed
// guarantee immediately, with no restart"), so the write path must build the
// client on demand.
func TestWriteRecord_BuildsClientLazilyAfterReloadEnablesS3(t *testing.T) {
	// Cold start with S3 audit logging off: no client is built.
	l := NewS3Logger(&gtvcfg.Config{LogToS3: false})
	require.Nil(t, l.s3Client, "no client should exist when the boot config disables S3 logging")

	// Hot reload turns durable auditing on.
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

	// A second record reuses the client rather than rebuilding it per write.
	require.NoError(t, l.WriteRecord(context.Background(), []byte(`{"decision":"allow"}`)))
	require.Equal(t, 1, built, "client should be built once and cached")
	require.Len(t, spy.buckets, 2)
}

// The lazy path must not turn "nothing was written" into success. When the
// live config does not enable S3 audit logging there is nothing to build, and
// WriteRecord must still fail closed — its caller releases credentials only if
// this returns nil.
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

// A clientFactory failure (e.g. AWS config resolution fails) must surface as an
// error, not leave a nil client behind a nil error.
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

// ---------- reload paths ----------

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
