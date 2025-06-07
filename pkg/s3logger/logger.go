package s3logger

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	gtvcfg "github.com/boogy/aws-oidc-warden/pkg/config"
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
	config      *gtvcfg.Config
	s3Client    s3ClientInterface
	batchBuffer *bytes.Buffer   // Internal buffer for batching
	logBatch    [][]byte        // Batch of logs waiting to be written
	mu          sync.Mutex      // Mutex for thread safety
	batchTimer  *time.Timer     // Timer for batch flushing
	ctx         context.Context // Context for S3 operations
	cancel      context.CancelFunc
	timeNow     func() time.Time // For testing time-dependent code

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

	// Initialize S3 client if logging to S3 is enabled
	if cfg.LogToS3 && cfg.LogBucket != "" {
		logger.initS3Client()
		logger.startBatchTimer()
	}

	return logger
}

// initS3Client initializes the S3 client
func (l *S3Logger) initS3Client() {
	awsConfig, err := config.LoadDefaultConfig(l.ctx, config.WithRetryMaxAttempts(l.s3Config.MaxRetries))
	if err != nil {
		slog.Error("Failed to load AWS config for S3 logger",
			slog.String("error", err.Error()))
		return
	}

	l.s3Client = s3.NewFromConfig(awsConfig)
	slog.Debug("S3 client initialized for logging",
		slog.String("bucket", l.s3Config.Bucket),
		slog.String("prefix", l.s3Config.Prefix))
}

// startBatchTimer starts the timer for batch flushing
func (l *S3Logger) startBatchTimer() {
	l.batchTimer = time.AfterFunc(l.s3Config.MaxBatchAge, func() {
		if err := l.Flush(); err != nil {
			slog.Error("Failed to flush log batch on timer",
				slog.String("error", err.Error()))
		}
		l.startBatchTimer() // Restart timer
	})
}

// WriteLogToS3 writes the log buffer to S3
func (l *S3Logger) WriteLogToS3(data bytes.Buffer) error {
	defer data.Reset()

	if !l.config.LogToS3 || l.s3Client == nil {
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
	err = l.WriteObject(l.s3Config.Bucket, key, compressedData)
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

// WriteObject writes data to S3 with retries
func (l *S3Logger) WriteObject(s3Bucket, key string, body []byte) error {
	if l.s3Client == nil {
		return errors.New("S3 client not initialized")
	}

	// Create context with timeout
	ctx, cancel := context.WithTimeout(l.ctx, l.s3Config.Timeout)
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

	// Convert metadata to tag format
	tags := strings.Builder{}
	for k, v := range metadata {
		if tags.Len() > 0 {
			tags.WriteString("&")
		}
		tags.WriteString(fmt.Sprintf("%s=%s", k, v))
	}

	// Upload to S3 with metadata and tags
	_, err := l.s3Client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:            aws.String(s3Bucket),
		Key:               aws.String(key),
		Body:              bytes.NewReader(body),
		ContentType:       aws.String("application/json"),
		ContentEncoding:   aws.String("gzip"),
		ChecksumAlgorithm: types.ChecksumAlgorithmSha256,
		Tagging:           aws.String(tags.String()),
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
	if l.batchTimer != nil {
		l.batchTimer.Stop()
	}

	err := l.Flush()
	l.cancel() // Cancel context to stop any pending operations
	return err
}

// WriteSingleLog writes a single log entry to S3 immediately
// This is useful for critical logs that should not be batched
func (l *S3Logger) WriteSingleLog(logData []byte) error {
	if !l.config.LogToS3 || l.s3Client == nil {
		return nil
	}

	// Compress the log data
	compressedData, err := compressGzip(logData)
	if err != nil {
		return fmt.Errorf("failed to compress log data: %w", err)
	}

	key := l.generateS3Key()
	return l.WriteObject(l.s3Config.Bucket, key, compressedData)
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

// WithMaxRetries sets the maximum number of retries for S3 operations
func (l *S3Logger) WithMaxRetries(retries int) *S3Logger {
	l.s3Config.MaxRetries = retries
	return l
}

// WithBatchSize sets the number of logs to batch before writing to S3
func (l *S3Logger) WithBatchSize(size int) *S3Logger {
	l.s3Config.BatchSize = size
	return l
}

// WithMaxBatchAge sets the maximum time to wait before writing a batch
func (l *S3Logger) WithMaxBatchAge(age time.Duration) *S3Logger {
	l.s3Config.MaxBatchAge = age
	return l
}

// WithExtraTag adds an extra tag to S3 objects
func (l *S3Logger) WithExtraTag(key, value string) *S3Logger {
	if l.s3Config.ExtraTags == nil {
		l.s3Config.ExtraTags = make(map[string]string)
	}
	l.s3Config.ExtraTags[key] = value
	return l
}
