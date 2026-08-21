package s3logger

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	gtvcfg "github.com/boogy/aws-oidc-warden/internal/config"
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
