package s3logger

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	gtvcfg "github.com/boogy/aws-oidc-warden/internal/config"
	"github.com/google/uuid"
)

const (
	DefaultTimeout      = 10 * time.Second
	DefaultRetries      = 3
	DefaultBatchSize    = 10
	DefaultMaxBatchWait = 30 * time.Second
)

// LoggerInterface defines the methods that must be implemented by any logger.
type LoggerInterface interface {
	WriteLogToS3(data bytes.Buffer) error
	WriteObject(s3Bucket, key string, body []byte) error
	Flush() error
	Close() error
	WriteSingleLog(logData []byte) error
}

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

	IncludeTimestamp bool
	IncludeUUID      bool
	FileExtension    string

	ExtraTags map[string]string
}

// S3Logger implements LoggerInterface, writing logs to S3.
type S3Logger struct {
	config *gtvcfg.Config
	// configSource is a live-config getter (e.g. config.Provider.Get); config
	// above is only the boot-time snapshot, which a hot reload can outdate.
	configSource func() *gtvcfg.Config
	s3Client     s3ClientInterface
	// initMu guards s3Client and batchTimer. Never acquire mu while holding it.
	initMu sync.Mutex
	// clientFactory builds the S3 client; indirected so lazy init is testable
	// without reaching AWS.
	clientFactory func(context.Context) (s3ClientInterface, error)
	batchBuffer   *bytes.Buffer
	logBatch      [][]byte
	mu            sync.Mutex
	batchTimer    *time.Timer
	ctx           context.Context
	cancel        context.CancelFunc
	timeNow       func() time.Time // overridden in tests

	s3Config S3LoggerConfig
}

// NewS3Logger creates a new S3Logger with the given configuration.
func NewS3Logger(cfg *gtvcfg.Config) *S3Logger {
	ctx, cancel := context.WithCancel(context.Background())

	logger := &S3Logger{
		config:      cfg,
		batchBuffer: &bytes.Buffer{},
		logBatch:    make([][]byte, 0),
		ctx:         ctx,
		cancel:      cancel,
		timeNow:     time.Now,
		s3Config: S3LoggerConfig{
			Bucket:           cfg.LogBucket,
			Prefix:           cfg.LogPrefix,
			Timeout:          DefaultTimeout,
			MaxRetries:       DefaultRetries,
			BatchSize:        DefaultBatchSize,
			MaxBatchAge:      DefaultMaxBatchWait,
			IncludeTimestamp: true,
			IncludeUUID:      true,
			FileExtension:    ".json.gz",
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
	if err := l.ensureDurableClient(); err != nil {
		slog.Error("Failed to initialize S3 client for logging",
			slog.String("error", err.Error()))
		return
	}

	slog.Debug("S3 client initialized for logging",
		slog.String("bucket", l.s3Config.Bucket),
		slog.String("prefix", l.s3Config.Prefix))
}

// ensureDurableClient lazily builds the S3 client used by the enforced audit
// path from the live config. A nil client must remain an error, never a
// silent no-op, since callers hand out credentials only if this succeeds.
func (l *S3Logger) ensureDurableClient() error {
	l.initMu.Lock()
	defer l.initMu.Unlock()

	if l.s3Client != nil {
		return nil
	}

	c := l.liveConfig()
	if c == nil || !c.LogToS3 || c.LogBucket == "" {
		return errors.New("s3 audit logger: S3 client not initialized and the live config does not enable S3 audit logging")
	}

	client, err := l.clientFactory(l.ctx)
	if err != nil {
		return fmt.Errorf("s3 audit logger: %w", err)
	}
	l.s3Client = client
	// Started here (not in NewS3Logger) so a reload that enables S3 logging
	// also starts flushing records buffered since boot.
	l.startBatchTimerLocked()

	slog.Info("S3 audit client initialized",
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
	if err := l.ensureDurableClient(); err != nil {
		slog.Debug("S3 audit client unavailable for best-effort write",
			slog.String("error", err.Error()))
		return false
	}
	return true
}

// startBatchTimerLocked starts the batch-flush timer if not already running.
// Caller must hold initMu.
func (l *S3Logger) startBatchTimerLocked() {
	if l.batchTimer != nil {
		return
	}
	l.batchTimer = time.AfterFunc(l.s3Config.MaxBatchAge, l.onBatchTimer)
}

// onBatchTimer flushes the batch and rearms the timer.
func (l *S3Logger) onBatchTimer() {
	if err := l.Flush(); err != nil {
		slog.Error("Failed to flush log batch on timer",
			slog.String("error", err.Error()))
	}
	l.initMu.Lock()
	defer l.initMu.Unlock()
	l.batchTimer = time.AfterFunc(l.s3Config.MaxBatchAge, l.onBatchTimer)
}

// WriteLogToS3 batches data for S3. Best-effort: checked against the live
// config, not the boot snapshot, and no-ops (never errors) when disabled.
func (l *S3Logger) WriteLogToS3(data bytes.Buffer) error {
	defer data.Reset()

	if c := l.liveConfig(); c == nil || !c.LogToS3 {
		return nil
	}
	if !l.ensureBestEffortClient() {
		return nil
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	if data.Len() == 0 {
		return nil
	}

	// Copy so the caller's buffer can be reused after this returns.
	dataCopy := make([]byte, data.Len())
	_, err := data.Read(dataCopy)
	if err != nil {
		return fmt.Errorf("failed to read log data: %w", err)
	}

	l.logBatch = append(l.logBatch, dataCopy)

	if len(l.logBatch) >= l.s3Config.BatchSize {
		return l.flushBatch()
	}

	return nil
}

// Flush forces all pending logs to be written to S3.
func (l *S3Logger) Flush() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	return l.flushBatch()
}

// flushBatch writes the current batch of logs to S3. Caller must hold mu.
func (l *S3Logger) flushBatch() error {
	if len(l.logBatch) == 0 {
		return nil
	}

	l.batchBuffer.Reset()

	for _, logData := range l.logBatch {
		l.batchBuffer.Write(logData)
		if !bytes.HasSuffix(logData, []byte("\n")) {
			l.batchBuffer.WriteString("\n")
		}
	}

	key := l.generateS3Key()

	compressedData, err := compressGzip(l.batchBuffer.Bytes())
	if err != nil {
		return fmt.Errorf("failed to compress log data: %w", err)
	}

	err = l.WriteObject(l.targetBucket(), key, compressedData)
	if err != nil {
		return err
	}

	l.logBatch = l.logBatch[:0]
	return nil
}

// generateS3Key generates a unique S3 key for the log file.
func (l *S3Logger) generateS3Key() string {
	now := l.timeNow()
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

// WriteObject writes data to S3 with retries, on the logger's own background
// context. Batched/best-effort callers use this since no request deadline
// applies to them.
func (l *S3Logger) WriteObject(s3Bucket, key string, body []byte) error {
	return l.writeObject(l.ctx, s3Bucket, key, body)
}

// writeObject is WriteObject with an explicit parent context. The enforced
// audit path passes the request context so credential issuance inherits its
// deadline; WithTimeout still caps a caller with no deadline of its own.
func (l *S3Logger) writeObject(parent context.Context, s3Bucket, key string, body []byte) error {
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
		slog.Error("Failed to write logs to S3",
			slog.String("bucket", s3Bucket),
			slog.String("key", key),
			slog.String("error", err.Error()))
		return fmt.Errorf("failed to write logs to S3: %w", err)
	}

	slog.Debug("Successfully wrote logs to S3",
		slog.String("bucket", s3Bucket),
		slog.String("key", key),
		slog.Int("bytes", len(body)))

	return nil
}

// Close stops the batch timer and flushes any remaining logs.
func (l *S3Logger) Close() error {
	l.initMu.Lock()
	if l.batchTimer != nil {
		l.batchTimer.Stop()
	}
	l.initMu.Unlock()

	err := l.Flush()
	l.cancel()
	return err
}

// WriteSingleLog writes a single log entry to S3 immediately, bypassing the
// batch, for critical logs.
func (l *S3Logger) WriteSingleLog(logData []byte) error {
	if c := l.liveConfig(); c == nil || !c.LogToS3 {
		return nil
	}
	if !l.ensureBestEffortClient() {
		return nil
	}

	compressedData, err := compressGzip(logData)
	if err != nil {
		return fmt.Errorf("failed to compress log data: %w", err)
	}

	key := l.generateS3Key()
	return l.WriteObject(l.targetBucket(), key, compressedData)
}

// WriteRecord implements handler.AuditSink (duck-typed). It persists a single
// audit record immediately, bypassing the batch, so enforcing callers can
// await durability before releasing credentials.
//
// Unlike WriteSingleLog, it never no-ops: it gates on whether a durable
// client actually exists, not on the boot-time config snapshot, so a
// hot-reload that turns audit_required+log_to_s3 on can't silently skip the
// audit write while still releasing credentials.
func (l *S3Logger) WriteRecord(ctx context.Context, record []byte) error {
	if err := l.ensureDurableClient(); err != nil {
		return err
	}

	compressedData, err := compressGzip(record)
	if err != nil {
		return fmt.Errorf("failed to compress audit record: %w", err)
	}

	return l.writeObject(ctx, l.targetBucket(), l.generateS3Key(), compressedData)
}

// BufferRecord appends a record to the batch buffer WriteLogToS3 flushes
// (BatchSize/MaxBatchAge or Close), for the best-effort path. No-ops when S3
// logging is disabled.
func (l *S3Logger) BufferRecord(record []byte) error {
	var buf bytes.Buffer
	buf.Write(record)
	return l.WriteLogToS3(buf)
}

// compressGzip compresses the given data using gzip.
func compressGzip(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	gzWriter := gzip.NewWriter(&buf)

	_, err := gzWriter.Write(data)
	if err != nil {
		return nil, fmt.Errorf("failed to write to gzip writer: %w", err)
	}

	if err := gzWriter.Close(); err != nil {
		return nil, fmt.Errorf("failed to close gzip writer: %w", err)
	}

	return buf.Bytes(), nil
}
