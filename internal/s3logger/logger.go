package s3logger

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	gtvcfg "github.com/boogy/aws-oidc-warden/internal/config"
	"github.com/boogy/aws-oidc-warden/internal/logevent"
	"github.com/google/uuid"
)

const (
	DefaultTimeout      = 10 * time.Second
	DefaultRetries      = 3
	DefaultBatchSize    = 10
	DefaultMaxBatchWait = 30 * time.Second

	// maxPendingRecords caps the records held across failed flushes; the oldest are dropped past it.
	maxPendingRecords = 5000
	// flushBackoff is how long threshold-triggered flushes stand down after a failed upload.
	flushBackoff = 5 * time.Second
)

// s3ClientInterface is the subset of the S3 API used by this logger.
type s3ClientInterface interface {
	PutObject(context.Context, *s3.PutObjectInput, ...func(*s3.Options)) (*s3.PutObjectOutput, error)
}

// S3LoggerConfig configures the S3 logger.
type S3LoggerConfig struct {
	Bucket string
	Prefix string

	Timeout     time.Duration
	MaxRetries  int
	BatchSize   int
	MaxBatchAge time.Duration

	IncludeUUID   bool
	FileExtension string

	ExtraTags map[string]string
}

// S3Logger writes audit logs to S3.
type S3Logger struct {
	config *gtvcfg.Config
	// configSource is a live-config getter (e.g. config.Provider.Get); config
	// above is only the boot-time snapshot, which a hot reload can outdate.
	configSource func() *gtvcfg.Config
	s3Client     s3ClientInterface
	// initMu guards s3Client, batchTimer and closed. Never acquire mu while holding it.
	initMu sync.Mutex
	closed bool
	// clientFactory builds the S3 client; indirected so lazy init is testable
	// without reaching AWS.
	clientFactory func(context.Context) (s3ClientInterface, error)
	// mu guards logBatch only and is never held across I/O.
	mu       sync.Mutex
	logBatch [][]byte
	dropped  int // records dropped since the last AuditBatchDropped report
	// flushMu serializes uploads (so Close waits for an in-flight one) and guards retryAfter.
	flushMu      sync.Mutex
	retryAfter   time.Time
	flushBackoff time.Duration
	batchTimer   *time.Timer
	ctx          context.Context
	cancel       context.CancelFunc
	timeNow      func() time.Time // overridden in tests

	s3Config S3LoggerConfig
}

// NewS3Logger creates a new S3Logger with the given configuration.
func NewS3Logger(cfg *gtvcfg.Config) *S3Logger {
	ctx, cancel := context.WithCancel(context.Background())

	logger := &S3Logger{
		config:       cfg,
		flushBackoff: flushBackoff,
		ctx:          ctx,
		cancel:       cancel,
		timeNow:      time.Now,
		s3Config: S3LoggerConfig{
			Bucket:        cfg.LogBucket,
			Prefix:        cfg.LogPrefix,
			Timeout:       DefaultTimeout,
			MaxRetries:    DefaultRetries,
			BatchSize:     DefaultBatchSize,
			MaxBatchAge:   DefaultMaxBatchWait,
			IncludeUUID:   true,
			FileExtension: ".json.gz",
		},
	}

	logger.clientFactory = logger.loadS3Client

	// When S3 logging starts disabled, the client is instead built lazily on
	// first need (ensureDurableClient), so a later hot-reload enabling it
	// doesn't require a cold start.
	if cfg.LogToS3 && cfg.LogBucket != "" {
		logger.initS3Client()
	}

	return logger
}

// SetS3Client injects the S3 client; handler tests in other packages need it.
func (l *S3Logger) SetS3Client(client s3ClientInterface) {
	l.initMu.Lock()
	defer l.initMu.Unlock()
	l.s3Client = client
}

// SetConfigSource wires a live-config getter (e.g. config.Provider.Get) so
// runtime-changeable values are read per-write instead of from the boot-time
// snapshot. Optional: with none wired, the snapshot is used.
func (l *S3Logger) SetConfigSource(fn func() *gtvcfg.Config) { l.configSource = fn }

// liveConfig returns the active config, falling back to the construction-time
// snapshot when no source is wired or it yields nil.
func (l *S3Logger) liveConfig() *gtvcfg.Config {
	if l.configSource != nil {
		if c := l.configSource(); c != nil {
			return c
		}
	}
	return l.config
}

// targetBucket returns the live config's log_bucket over the boot snapshot,
// used by every write path so a hot-reload rotation never splits records
// across two buckets.
func (l *S3Logger) targetBucket() string {
	if c := l.liveConfig(); c != nil && c.LogBucket != "" {
		return c.LogBucket
	}
	return l.s3Config.Bucket
}

// loadS3Client is the production clientFactory.
func (l *S3Logger) loadS3Client(ctx context.Context) (s3ClientInterface, error) {
	awsConfig, err := config.LoadDefaultConfig(ctx, config.WithRetryMaxAttempts(l.s3Config.MaxRetries))
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config for S3 logger: %w", err)
	}
	return s3.NewFromConfig(awsConfig), nil
}

// initS3Client initializes the S3 client at construction time. A failure here
// is not fatal: ensureDurableClient retries for the enforced audit path, and
// the best-effort paths already tolerate a nil client.
func (l *S3Logger) initS3Client() {
	if err := l.ensureDurableClient(l.ctx); err != nil {
		logevent.Error(l.ctx, nil, logevent.AuditClientInitFailure, "failed to initialize S3 client for logging",
			slog.String("error", err.Error()))
	}
}

// ensureDurableClient lazily builds the S3 client used by the enforced audit
// path from the live config. A nil client must remain an error, never a
// silent no-op, since callers hand out credentials only if this succeeds.
func (l *S3Logger) ensureDurableClient(ctx context.Context) error {
	l.initMu.Lock()
	defer l.initMu.Unlock()

	if l.s3Client != nil {
		return nil
	}

	c := l.liveConfig()
	if c == nil || !c.LogToS3 || c.LogBucket == "" {
		return errors.New("s3 audit logger: S3 client not initialized and the live config does not enable S3 audit logging")
	}

	// Shared under initMu: a caller's cancelled ctx must not fail construction for everyone.
	client, err := l.clientFactory(l.ctx)
	if err != nil {
		return fmt.Errorf("s3 audit logger: %w", err)
	}
	l.s3Client = client
	// Started here (not in NewS3Logger) so a reload that enables S3 logging
	// also starts flushing records buffered since boot.
	l.startBatchTimerLocked()

	logevent.Info(ctx, nil, logevent.AuditClientInit, "S3 audit client initialized",
		slog.String("bucket", c.LogBucket))
	return nil
}

// client returns the S3 client under initMu, so a lazy build racing a write
// cannot be observed half-done.
func (l *S3Logger) client() s3ClientInterface {
	l.initMu.Lock()
	defer l.initMu.Unlock()
	return l.s3Client
}

// ensureBestEffortClient is ensureDurableClient for the batched, non-enforced
// paths, which no-op rather than propagate a failure.
func (l *S3Logger) ensureBestEffortClient() bool {
	if err := l.ensureDurableClient(l.ctx); err != nil {
		logevent.Debug(l.ctx, nil, logevent.AuditClientUnavailable, "S3 audit client unavailable for best-effort write",
			slog.String("error", err.Error()))
		return false
	}
	return true
}

// startBatchTimerLocked starts the batch-flush timer if not already running.
// Caller must hold initMu.
func (l *S3Logger) startBatchTimerLocked() {
	if l.batchTimer != nil || l.closed {
		return
	}
	l.batchTimer = time.AfterFunc(l.s3Config.MaxBatchAge, l.onBatchTimer)
}

// onBatchTimer flushes the batch and rearms the timer.
func (l *S3Logger) onBatchTimer() {
	if err := l.Flush(); err != nil {
		logevent.Error(l.ctx, nil, logevent.AuditFlushFailure, "failed to flush log batch on timer",
			slog.String("error", err.Error()))
	}
	l.initMu.Lock()
	defer l.initMu.Unlock()
	if l.closed {
		return
	}
	l.batchTimer = time.AfterFunc(l.s3Config.MaxBatchAge, l.onBatchTimer)
}

// writeLogToS3 batches a copy of data for S3. Best-effort: checked against the
// live config, not the boot snapshot, and no-ops (never errors) when disabled.
func (l *S3Logger) writeLogToS3(data []byte) error {
	if len(data) == 0 {
		return nil
	}
	if c := l.liveConfig(); c == nil || !c.LogToS3 {
		return nil
	}
	if !l.ensureBestEffortClient() {
		return nil
	}

	l.mu.Lock()
	l.logBatch = append(l.logBatch, slices.Clone(data))
	l.capPendingLocked()
	full := len(l.logBatch) >= l.s3Config.BatchSize
	l.mu.Unlock()

	if !full {
		return nil
	}
	// A flush already running, or a recent failure, covers this record: it stays queued.
	if !l.flushMu.TryLock() {
		return nil
	}
	defer l.flushMu.Unlock()
	if time.Now().Before(l.retryAfter) {
		return nil
	}
	return l.flushBatch()
}

// Flush forces all pending logs to be written to S3.
func (l *S3Logger) Flush() error {
	l.flushMu.Lock()
	defer l.flushMu.Unlock()

	return l.flushBatch()
}

// flushBatch uploads the pending batch outside mu; a failed batch is re-queued
// (capped) for the next attempt. Caller must hold flushMu.
func (l *S3Logger) flushBatch() error {
	l.mu.Lock()
	batch := l.logBatch
	l.logBatch = nil
	l.mu.Unlock()

	if len(batch) == 0 {
		return nil
	}

	size := 0
	for _, rec := range batch {
		size += len(rec) + 1
	}
	buf := bytes.NewBuffer(make([]byte, 0, size))
	for _, rec := range batch {
		buf.Write(rec)
		if rec[len(rec)-1] != '\n' {
			buf.WriteByte('\n')
		}
	}

	compressed, err := compressGzip(buf.Bytes())
	if err == nil {
		err = l.writeObject(l.ctx, l.targetBucket(), l.generateS3Key(), compressed, logevent.AuditFlushSuccess)
	} else {
		err = fmt.Errorf("failed to compress log data: %w", err)
	}
	if err != nil {
		l.requeue(batch)
		l.retryAfter = time.Now().Add(l.flushBackoff)
		return err
	}

	l.retryAfter = time.Time{}
	return nil
}

// requeue puts a failed batch back ahead of newer records, then reports any drops.
func (l *S3Logger) requeue(batch [][]byte) {
	l.mu.Lock()
	l.logBatch = slices.Concat(batch, l.logBatch)
	l.capPendingLocked()
	dropped := l.dropped
	l.dropped = 0
	l.mu.Unlock()

	if dropped > 0 {
		logevent.Error(l.ctx, nil, logevent.AuditBatchDropped, "dropped oldest audit records while S3 is unavailable",
			slog.Int("dropped", dropped),
			slog.Int("pending", maxPendingRecords))
	}
}

// capPendingLocked drops the oldest records past maxPendingRecords. Caller must hold mu.
func (l *S3Logger) capPendingLocked() {
	n := len(l.logBatch) - maxPendingRecords
	if n <= 0 {
		return
	}
	clear(l.logBatch[:n])
	l.logBatch = l.logBatch[n:]
	l.dropped += n
}

// generateS3Key generates a unique S3 key for the log file.
func (l *S3Logger) generateS3Key() string {
	now := l.timeNow().UTC()
	parts := []string{strings.Trim(l.s3Config.Prefix, "/")}

	year, month, day := now.Year(), now.Month(), now.Day()
	hour, minute, seconds := now.Hour(), now.Minute(), now.Second()

	parts = append(parts, fmt.Sprintf("%d/%02d/%02d", year, month, day))

	// <uuid>-year month day-hour minute second.ext
	filename := fmt.Sprintf("%d%02d%02d-%02d%02d%02d", year, month, day, hour, minute, seconds)

	if l.s3Config.IncludeUUID {
		filename = fmt.Sprintf("%s-%s", uuid.New().String(), filename)
	}

	filename = filename + l.s3Config.FileExtension

	parts = append(parts, filename)
	return strings.Join(parts, "/")
}

// writeObject writes under parent's deadline, capped by the write timeout, and logs successEvent.
func (l *S3Logger) writeObject(parent context.Context, s3Bucket, key string, body []byte, successEvent logevent.Event) error {
	client := l.client()
	if client == nil {
		return errors.New("S3 client not initialized")
	}

	if parent == nil {
		parent = l.ctx
	}
	ctx, cancel := context.WithTimeout(parent, l.s3Config.Timeout)
	defer cancel()

	metadata := map[string]string{
		"source":           "aws-oidc-warden",
		"created-at":       l.timeNow().Format(time.RFC3339),
		"content-type":     "application/json",
		"content-encoding": "gzip",
	}

	maps.Copy(metadata, l.s3Config.ExtraTags)

	// Tagging is a URL query string: values are escaped so a literal "+" in
	// the RFC3339 offset isn't decoded as a space.
	tags := url.Values{}
	for k, v := range metadata {
		tags.Set(k, v)
	}

	_, err := client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:            aws.String(s3Bucket),
		Key:               aws.String(key),
		Body:              bytes.NewReader(body),
		ContentType:       aws.String("application/json"),
		ContentEncoding:   aws.String("gzip"),
		ChecksumAlgorithm: types.ChecksumAlgorithmSha256,
		Tagging:           aws.String(tags.Encode()),
		Metadata:          metadata,
	})

	if err != nil {
		logevent.Error(ctx, nil, logevent.AuditWriteFailure, "failed to write logs to S3",
			slog.String("bucket", s3Bucket),
			slog.String("key", key),
			slog.String("error", err.Error()))
		return fmt.Errorf("failed to write logs to S3: %w", err)
	}

	logevent.Debug(ctx, nil, successEvent, "successfully wrote logs to S3",
		slog.String("bucket", s3Bucket),
		slog.String("key", key),
		slog.Int("bytes", len(body)))

	return nil
}

// Close stops the batch timer and flushes any remaining logs.
func (l *S3Logger) Close() error {
	l.initMu.Lock()
	l.closed = true
	if l.batchTimer != nil {
		l.batchTimer.Stop()
		l.batchTimer = nil
	}
	l.initMu.Unlock()

	err := l.Flush()
	l.cancel()
	return err
}

// WriteRecord implements handler.AuditSink (duck-typed). It persists a single
// audit record immediately, bypassing the batch, so enforcing callers can
// await durability before releasing credentials.
//
// It never no-ops: it gates on whether a durable
// client actually exists, not on the boot-time config snapshot, so a
// hot-reload that turns audit_required+log_to_s3 on can't silently skip the
// audit write while still releasing credentials.
func (l *S3Logger) WriteRecord(ctx context.Context, record []byte) error {
	if err := l.ensureDurableClient(ctx); err != nil {
		return err
	}

	compressedData, err := compressGzip(record)
	if err != nil {
		return fmt.Errorf("failed to compress audit record: %w", err)
	}

	return l.writeObject(ctx, l.targetBucket(), l.generateS3Key(), compressedData, logevent.AuditWriteSuccess)
}

// BufferRecord appends a record to the batch buffer writeLogToS3 flushes
// (BatchSize/MaxBatchAge or Close), for the best-effort path. No-ops when S3
// logging is disabled.
func (l *S3Logger) BufferRecord(record []byte) error {
	return l.writeLogToS3(record)
}

var gzipPool = sync.Pool{New: func() any { return gzip.NewWriter(io.Discard) }}

// compressGzip compresses the given data using gzip.
func compressGzip(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	gz := gzipPool.Get().(*gzip.Writer)
	gz.Reset(&buf)

	if _, err := gz.Write(data); err != nil {
		return nil, fmt.Errorf("failed to write to gzip writer: %w", err)
	}
	if err := gz.Close(); err != nil {
		return nil, fmt.Errorf("failed to close gzip writer: %w", err)
	}

	gz.Reset(io.Discard)
	gzipPool.Put(gz)
	return buf.Bytes(), nil
}
