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
	// DefaultTimeout is the default timeout for S3 operations
	DefaultTimeout = 10 * time.Second

	// DefaultRetries is the default number of retries for S3 operations
	DefaultRetries = 3

	// DefaultBatchSize is the default number of logs to batch before writing to S3
	DefaultBatchSize = 10

	// DefaultMaxBatchWait is the default maximum time to wait before writing a batch
	DefaultMaxBatchWait = 30 * time.Second
)

// LoggerInterface defines the methods that must be implemented by any logger
type LoggerInterface interface {
	WriteLogToS3(data bytes.Buffer) error
	WriteObject(s3Bucket, key string, body []byte) error
	Flush() error
	Close() error
	WriteSingleLog(logData []byte) error
}

// s3ClientInterface defines the subset of S3 API methods used by this logger
type s3ClientInterface interface {
	PutObject(context.Context, *s3.PutObjectInput, ...func(*s3.Options)) (*s3.PutObjectOutput, error)
}

// S3LoggerConfig contains the configuration for the S3 logger
type S3LoggerConfig struct {
	// Required settings
	Bucket string
	Prefix string

	// Optional settings with defaults
	Timeout     time.Duration // Timeout for S3 operations
	MaxRetries  int           // Maximum number of retries for S3 operations
	BatchSize   int           // Number of logs to batch before writing to S3
	MaxBatchAge time.Duration // Maximum time to wait before writing a batch

	// Formatting options
	IncludeTimestamp bool   // Include timestamp in log key
	IncludeUUID      bool   // Include UUID in log key
	FileExtension    string // File extension for log files (.json, .log, etc.)

	// Additional metadata
	ExtraTags map[string]string // Extra tags to add to S3 objects
}

// S3Logger implements the LoggerInterface for writing logs to S3
type S3Logger struct {
	config *gtvcfg.Config
	// configSource is a live-config getter (config.Provider.Get), mirroring
	// AwsConsumer.SetConfigSource. config above is only the boot-time snapshot;
	// the hot-reload provider swaps in a new *Config, so anything read from the
	// snapshot silently keeps a value the operator has since changed.
	configSource func() *gtvcfg.Config
	s3Client     s3ClientInterface
	// initMu guards the lazily-built s3Client and the batch timer. Never
	// acquire mu while holding it; every path takes mu first (if at all),
	// then initMu.
	initMu sync.Mutex
	// clientFactory builds the S3 client. Indirected so the lazy
	// initialization path can be exercised without reaching AWS.
	clientFactory func(context.Context) (s3ClientInterface, error)
	batchBuffer   *bytes.Buffer   // Internal buffer for batching
	logBatch      [][]byte        // Batch of logs waiting to be written
	mu            sync.Mutex      // Mutex for thread safety
	batchTimer    *time.Timer     // Timer for batch flushing
	ctx           context.Context // Context for S3 operations
	cancel        context.CancelFunc
	timeNow       func() time.Time // For testing time-dependent code

	// Configuration options
	s3Config S3LoggerConfig
}

// NewS3Logger creates a new S3Logger with the given configuration
func NewS3Logger(cfg *gtvcfg.Config) *S3Logger {
	ctx, cancel := context.WithCancel(context.Background())

	logger := &S3Logger{
		config:      cfg,
		batchBuffer: &bytes.Buffer{},
		logBatch:    make([][]byte, 0),
		ctx:         ctx,
		cancel:      cancel,
		timeNow:     time.Now, // Default to actual time.Now
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

	// Initialize S3 client if logging to S3 is enabled. When it is not, the
	// client is built on first need instead (ensureDurableClient), so a hot
	// reload that turns S3 logging on does not need a cold start.
	if cfg.LogToS3 && cfg.LogBucket != "" {
		logger.initS3Client()
	}

	return logger
}

// SetConfigSource wires a live-config getter (e.g. config.Provider.Get) so
// values that can change at runtime are read per-write instead of from the
// boot-time snapshot. Optional: with no source wired the snapshot is used,
// which is correct for static and test setups.
func (l *S3Logger) SetConfigSource(fn func() *gtvcfg.Config) { l.configSource = fn }

// liveConfig returns the currently active config, falling back to the
// construction-time snapshot when no source is wired or it yields nil.
func (l *S3Logger) liveConfig() *gtvcfg.Config {
	if l.configSource != nil {
		if c := l.configSource(); c != nil {
			return c
		}
	}
	return l.config
}

// targetBucket returns the bucket every write goes to, preferring the live
// config's log_bucket over the snapshot captured at construction. Without this,
// rotating log_bucket via hot reload (e.g. to a locked-down bucket during an
// incident) kept writing to the previous bucket while the write reported
// success — it "succeeded" somewhere the operator no longer intended.
//
// Used by EVERY write path, not just the durable audit one: if only WriteRecord
// honored the live value, a rotation would split records across two buckets,
// which is worse for forensics than consistently using either one.
func (l *S3Logger) targetBucket() string {
	if c := l.liveConfig(); c != nil && c.LogBucket != "" {
		return c.LogBucket
	}
	return l.s3Config.Bucket
}

// loadS3Client is the production clientFactory: it resolves AWS configuration
// and builds a real S3 client.
func (l *S3Logger) loadS3Client(ctx context.Context) (s3ClientInterface, error) {
	awsConfig, err := config.LoadDefaultConfig(ctx, config.WithRetryMaxAttempts(l.s3Config.MaxRetries))
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config for S3 logger: %w", err)
	}
	return s3.NewFromConfig(awsConfig), nil
}

// initS3Client initializes the S3 client at construction time. A failure here
// is not fatal: the enforced audit path retries via ensureDurableClient, and
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

// ensureDurableClient resolves the S3 client used by the enforced audit path,
// building it on first need.
//
// The client used to be built exactly once, inside NewS3Logger, from the
// boot-time config snapshot. AuditEnforced() is re-derived from the LIVE
// config on every request, so the two could permanently disagree: a container
// that cold-started with log_to_s3 off had s3Client==nil forever, and an
// operator who then enabled log_to_s3+log_bucket via hot reload flipped
// enforcement on against a logger that could never write. Every allow decision
// then failed with ErrAuditWriteFailed — a permanent 500 on that warm
// container with no way to self-heal short of a restart, which is the opposite
// of what docs/LOGGING.md promises about reloading those keys.
//
// Building on demand makes the documented behavior true: the first enforced
// write after the reload creates the client and the audit trail starts working.
// It deliberately does NOT build a client when the live config has S3 logging
// off — "not initialized" must still be an error there, never a silent no-op,
// because the caller hands out credentials only if this path succeeds.
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
	// The batch timer is started here rather than in NewS3Logger so the
	// best-effort path also recovers from a reload: with S3 logging off at
	// boot there was no timer, so records buffered after the reload sat in
	// memory until a batch filled or Cleanup ran.
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
// paths: it builds the client when the live config wants one, but a failure is
// not the caller's problem — those paths no-op rather than propagate. Returns
// whether a usable client exists.
func (l *S3Logger) ensureBestEffortClient() bool {
	if err := l.ensureDurableClient(); err != nil {
		slog.Debug("S3 audit client unavailable for best-effort write",
			slog.String("error", err.Error()))
		return false
	}
	return true
}

// startBatchTimerLocked starts the batch-flush timer if it is not already
// running. Caller must hold initMu, which is also what makes the timer
// single-shot across a lazy client build.
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

// WriteLogToS3 writes the log buffer to S3.
//
// The enable check reads the LIVE config, not the construction-time snapshot.
// targetBucket() already read the live value, so gating on the snapshot meant
// one object holding two notions of "current config": after a reload turned
// log_to_s3 on, every buffered record was silently dropped while the bucket
// the writer would have used was the reloaded one. Best-effort still means a
// no-op (never an error) when the live config has S3 logging off.
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

	// If data buffer is empty, return
	if data.Len() == 0 {
		return nil
	}

	// Copy the data to prevent it from being modified
	dataCopy := make([]byte, data.Len())
	_, err := data.Read(dataCopy)
	if err != nil {
		return fmt.Errorf("failed to read log data: %w", err)
	}

	// Add to batch
	l.logBatch = append(l.logBatch, dataCopy)

	// If batch is full, write to S3
	if len(l.logBatch) >= l.s3Config.BatchSize {
		return l.flushBatch()
	}

	return nil
}

// Flush forces all pending logs to be written to S3
func (l *S3Logger) Flush() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	return l.flushBatch()
}

// flushBatch writes the current batch of logs to S3
// Caller must hold mutex
func (l *S3Logger) flushBatch() error {
	if len(l.logBatch) == 0 {
		return nil
	}

	// Reset batch buffer
	l.batchBuffer.Reset()

	// Combine all logs in batch
	for _, logData := range l.logBatch {
		l.batchBuffer.Write(logData)
		// Add newline between logs if needed
		if !bytes.HasSuffix(logData, []byte("\n")) {
			l.batchBuffer.WriteString("\n")
		}
	}

	// Generate S3 key
	key := l.generateS3Key()

	// Compress data using gzip
	compressedData, err := compressGzip(l.batchBuffer.Bytes())
	if err != nil {
		return fmt.Errorf("failed to compress log data: %w", err)
	}

	// Write compressed logs to S3
	err = l.WriteObject(l.targetBucket(), key, compressedData)
	if err != nil {
		return err
	}

	// Clear batch after successful write
	l.logBatch = l.logBatch[:0]
	return nil
}

// generateS3Key generates a unique S3 key for the log file
func (l *S3Logger) generateS3Key() string {
	now := l.timeNow()
	parts := []string{strings.Trim(l.s3Config.Prefix, "/")}

	year, month, day := now.Year(), now.Month(), now.Day()
	hour, minute, seconds := now.Hour(), now.Minute(), now.Second()

	// Add date components (always included)
	parts = append(parts, fmt.Sprintf("%d/%02d/%02d", year, month, day))

	// Build the filename part (ex: year/month/day/uuid-timestamp.json.gz)
	filename := fmt.Sprintf("%d%02d%02d-%02d%02d%02d", year, month, day, hour, minute, seconds)

	// Add UUID if configured (<uuid>-<filename>)
	if l.s3Config.IncludeUUID {
		filename = fmt.Sprintf("%s-%s", uuid.New().String(), filename)
	}

	// Add file extension
	filename = filename + l.s3Config.FileExtension

	// Combine all parts to form the full S3 key
	parts = append(parts, filename)
	return strings.Join(parts, "/")
}

// WriteObject writes data to S3 with retries, on the logger's own background
// context. Batched/best-effort callers use this: they are not awaited by a
// request, so there is no caller deadline to inherit.
func (l *S3Logger) WriteObject(s3Bucket, key string, body []byte) error {
	return l.writeObject(l.ctx, s3Bucket, key, body)
}

// writeObject is WriteObject with an explicit parent context.
//
// The enforced audit path passes the REQUEST context: that write gates
// credential issuance, so it must inherit the caller's cancellation and
// deadline. Deriving the timeout from l.ctx (background, cancelled only by
// Close) meant a request with 3s of Lambda budget left could still block for
// the full 10s S3 timeout on every retry — work whose result no one would ever
// read, since the runtime kills the process at the deadline. WithTimeout keeps
// whichever bound is nearer, so the fixed timeout still caps a caller that has
// no deadline of its own.
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

	// Add metadata
	metadata := map[string]string{
		"source":           "aws-oidc-warden",
		"created-at":       l.timeNow().Format(time.RFC3339),
		"content-type":     "application/json",
		"content-encoding": "gzip",
	}

	// Add any extra tags
	maps.Copy(metadata, l.s3Config.ExtraTags)

	// PutObjectInput.Tagging is a URL query string, so every key and value is
	// escaped rather than concatenated raw. This is not hypothetical even with
	// only built-in tags: created-at is RFC3339, and a non-UTC offset contains
	// a literal "+", which decodes as a space — the stored tag was already
	// wrong on any host that is not on UTC. Keys are sorted so the same
	// metadata always produces the same string.
	tags := url.Values{}
	for k, v := range metadata {
		tags.Set(k, v)
	}

	// Upload to S3 with metadata and tags
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

// Close stops the batch timer and flushes any remaining logs
func (l *S3Logger) Close() error {
	l.initMu.Lock()
	if l.batchTimer != nil {
		l.batchTimer.Stop()
	}
	l.initMu.Unlock()

	err := l.Flush()
	l.cancel() // Cancel context to stop any pending operations
	return err
}

// WriteSingleLog writes a single log entry to S3 immediately
// This is useful for critical logs that should not be batched
func (l *S3Logger) WriteSingleLog(logData []byte) error {
	// Live config, not the boot snapshot — same reasoning as WriteLogToS3.
	if c := l.liveConfig(); c == nil || !c.LogToS3 {
		return nil
	}
	if !l.ensureBestEffortClient() {
		return nil
	}

	// Compress the log data
	compressedData, err := compressGzip(logData)
	if err != nil {
		return fmt.Errorf("failed to compress log data: %w", err)
	}

	key := l.generateS3Key()
	return l.WriteObject(l.targetBucket(), key, compressedData)
}

// WriteRecord implements handler.AuditSink (duck-typed — no import of the
// handler package needed for this to satisfy that interface). It persists a
// single structured audit record immediately, bypassing the batch buffer, so
// callers enforcing audit_required can await durability before responding
// with credentials.
//
// Unlike WriteSingleLog (which silently no-ops when S3 logging is disabled or
// the client failed to initialize, since it also backs best-effort request
// logging), WriteRecord NEVER no-ops: reaching it means the caller is
// enforcing audit_required and will hand out credentials only if this returns
// nil, so "nothing was written" must surface as an error.
//
// The durability decision deliberately rests on whether an S3 client actually
// exists — NOT on l.config. l.config is the *config.Config captured when the
// logger was constructed at bootstrap; the hot-reload provider swaps in a NEW
// Config on refresh, so this snapshot can permanently disagree with the live
// config the processor reads. Gating on the stale snapshot's LogToS3 meant a
// reload that turned audit_required+log_to_s3 ON left this a silent no-op that
// returned success, and credentials were released with no audit record — the
// exact inverse of audit_required's fail-closed contract. It also bypasses
// WriteSingleLog for the same reason: that helper re-checks the same snapshot.
func (l *S3Logger) WriteRecord(ctx context.Context, record []byte) error {
	if err := l.ensureDurableClient(); err != nil {
		return err
	}

	compressedData, err := compressGzip(record)
	if err != nil {
		return fmt.Errorf("failed to compress audit record: %w", err)
	}

	// ctx is the request context: this write is awaited before credentials are
	// returned, so it inherits the caller's deadline (see writeObject).
	return l.writeObject(ctx, l.targetBucket(), l.generateS3Key(), compressedData)
}

// BufferRecord appends a structured audit record to the amortized batch buffer
// (the same buffer WriteLogToS3 feeds), for the best-effort path when
// audit_required is false. Unlike WriteRecord it does not force an immediate
// per-record S3 PutObject; the record is flushed with the batch (BatchSize /
// MaxBatchAge) or at Cleanup. No-ops when S3 logging is disabled.
func (l *S3Logger) BufferRecord(record []byte) error {
	var buf bytes.Buffer
	buf.Write(record)
	return l.WriteLogToS3(buf)
}

// compressGzip compresses the given data using gzip
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
