package s3logger_test

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	gtvcfg "github.com/boogy/aws-oidc-warden/config"
	s3logger "github.com/boogy/aws-oidc-warden/s3Logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockS3Client is a mock implementation of the S3 client
type MockS3Client struct {
	mock.Mock
}

func (m *MockS3Client) PutObject(ctx context.Context, params *s3.PutObjectInput, optFns ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	args := m.Called(ctx, params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*s3.PutObjectOutput), args.Error(1)
}

// Helper function to decompress gzip data
func decompressGzip(t *testing.T, data []byte) []byte {
	reader, err := gzip.NewReader(bytes.NewReader(data))
	assert.NoError(t, err)
	defer func() {
		if err := reader.Close(); err != nil {
			t.Logf("Failed to close gzip reader: %v", err)
		}
	}()
	decompressed, err := io.ReadAll(reader)
	assert.NoError(t, err)
	return decompressed
}

// createTestLogger creates a logger with common test configuration
func createTestLogger(t *testing.T, logToS3 bool) (*s3logger.S3Logger, *MockS3Client) {
	cfg := &gtvcfg.Config{
		LogToS3:   logToS3,
		LogBucket: "test-bucket",
		LogPrefix: "logs/",
	}
	logger := s3logger.NewS3Logger(cfg)
	mockClient := new(MockS3Client)
	logger.SetS3Client(mockClient)

	// Set fixed time for predictable testing
	logger.SetTimeNow(func() time.Time {
		return time.Date(2025, 5, 19, 12, 30, 45, 0, time.UTC)
	})

	return logger, mockClient
}

// TestNewS3Logger tests the creation of a new S3Logger
func TestNewS3Logger(t *testing.T) {
	// Test with logging disabled
	cfg := &gtvcfg.Config{
		LogToS3:   false,
		LogBucket: "test-bucket",
		LogPrefix: "logs/",
	}
	logger := s3logger.NewS3Logger(cfg)
	assert.NotNil(t, logger)
	assert.Equal(t, cfg, logger.GetConfig())
	assert.Equal(t, "test-bucket", logger.GetS3Config().Bucket)
	assert.Equal(t, "logs/", logger.GetS3Config().Prefix)
	assert.Equal(t, false, cfg.LogToS3)

	// Test with logging enabled
	cfg.LogToS3 = true
	logger = s3logger.NewS3Logger(cfg)
	assert.NotNil(t, logger)
	assert.Equal(t, cfg, logger.GetConfig())
	assert.Equal(t, true, cfg.LogToS3)
}

// TestGenerateS3Key tests the key generation logic
func TestGenerateS3Key(t *testing.T) {
	cfg := &gtvcfg.Config{
		LogToS3:   true,
		LogBucket: "test-bucket",
		LogPrefix: "logs",
	}
	logger := s3logger.NewS3Logger(cfg)

	// Set to use a fixed timestamp for testing
	logger.SetTimeNow(func() time.Time {
		return time.Date(2025, 5, 19, 12, 30, 45, 0, time.UTC)
	})

	// Test with UUID
	logger.SetS3ConfigOption(s3logger.WithIncludeUUID(true))
	key := logger.GenerateS3Key()

	// Should have format: logs/2025/05/19/uuid-20250519-123045.json.gz
	assert.True(t, strings.HasPrefix(key, "logs/2025/05/19/"))
	assert.True(t, strings.Contains(key, "-20250519-123045"))
	assert.True(t, strings.HasSuffix(key, ".json.gz"))

	// Test without UUID
	logger.SetS3ConfigOption(s3logger.WithIncludeUUID(false))
	key = logger.GenerateS3Key()

	// Should have format: logs/2025/05/19/20250519-123045.json.gz
	assert.Equal(t, "logs/2025/05/19/20250519-123045.json.gz", key)

	// Test with different prefix and extension
	logger.SetS3ConfigOption(s3logger.WithPrefix("custom/prefix"))
	logger.SetS3ConfigOption(s3logger.WithFileExtension(".log"))
	key = logger.GenerateS3Key()

	assert.Equal(t, "custom/prefix/2025/05/19/20250519-123045.log", key)
}

// TestLoggerWithOptions tests the WithX option methods
func TestLoggerWithOptions(t *testing.T) {
	cfg := &gtvcfg.Config{
		LogToS3:   true,
		LogBucket: "test-bucket",
		LogPrefix: "logs",
	}
	logger := s3logger.NewS3Logger(cfg)

	// Apply various options
	logger.SetS3ConfigOption(s3logger.WithMaxRetries(5))
	logger.SetS3ConfigOption(s3logger.WithBatchSize(20))
	logger.SetS3ConfigOption(s3logger.WithMaxBatchAge(2 * time.Minute))
	logger.SetS3ConfigOption(s3logger.WithFileExtension(".log.gz"))
	logger.SetS3ConfigOption(s3logger.WithExtraTag("env", "test"))
	logger.SetS3ConfigOption(s3logger.WithExtraTag("region", "us-west-2"))

	// Verify the options were applied
	s3Config := logger.GetS3Config()
	assert.Equal(t, 5, s3Config.MaxRetries)
	assert.Equal(t, 20, s3Config.BatchSize)
	assert.Equal(t, 2*time.Minute, s3Config.MaxBatchAge)
	assert.Equal(t, ".log.gz", s3Config.FileExtension)
	assert.Equal(t, "test", s3Config.ExtraTags["env"])
	assert.Equal(t, "us-west-2", s3Config.ExtraTags["region"])
}

// TestCompressGzip tests the compressGzip function
func TestCompressGzip(t *testing.T) {
	testData := []byte("test data for compression")

	// Get access to the private compressGzip function using the exported test helper
	compressed, err := s3logger.TestCompressGzip(testData)
	assert.NoError(t, err)
	assert.NotNil(t, compressed)

	// Verify the compressed data can be decompressed back to the original
	decompressed := decompressGzip(t, compressed)
	assert.Equal(t, testData, decompressed)
}

// TestLoggerWithDisabledLogging tests that the logger doesn't call S3 when logging is disabled
func TestLoggerWithDisabledLogging(t *testing.T) {
	cfg := &gtvcfg.Config{
		LogToS3:   false, // Logging disabled
		LogBucket: "test-bucket",
		LogPrefix: "logs",
	}
	logger := s3logger.NewS3Logger(cfg)

	// Create a mock S3 client
	mockClient := new(MockS3Client)
	logger.SetS3Client(mockClient)

	// Try to write a log
	buf := bytes.Buffer{}
	buf.WriteString("this log should not be sent to S3\n")
	err := logger.WriteLogToS3(buf)
	assert.NoError(t, err)

	// Try to flush
	err = logger.Flush()
	assert.NoError(t, err)

	// Try to write a single log
	err = logger.WriteSingleLog([]byte("this single log should not be sent to S3"))
	assert.NoError(t, err)

	// No S3 calls should have been made
	mockClient.AssertNotCalled(t, "PutObject")
}

// TestErrorHandling tests error handling in the S3Logger
func TestErrorHandling(t *testing.T) {
	cfg := &gtvcfg.Config{
		LogToS3:   true,
		LogBucket: "test-bucket",
		LogPrefix: "logs",
	}
	logger := s3logger.NewS3Logger(cfg)

	// Create a mock S3 client that returns errors
	mockClient := new(MockS3Client)
	logger.SetS3Client(mockClient)

	// Set up mock to return an error
	mockClient.On("PutObject", mock.Anything, mock.Anything).Return(nil, assert.AnError)

	// Test error handling in WriteSingleLog
	err := logger.WriteSingleLog([]byte("test log"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to write logs to S3")

	// Test error handling in WriteLogToS3 with batch size 1
	logger.SetS3ConfigOption(s3logger.WithBatchSize(1))
	buf := bytes.Buffer{}
	buf.WriteString("batch test log\n")
	err = logger.WriteLogToS3(buf)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to write logs to S3")

	// Test error handling in Flush
	err = logger.Flush()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to write logs to S3")
}

// TestEmptyBatchFlush tests that flushing an empty batch doesn't call S3
func TestEmptyBatchFlush(t *testing.T) {
	cfg := &gtvcfg.Config{
		LogToS3:   true,
		LogBucket: "test-bucket",
		LogPrefix: "logs",
	}
	logger := s3logger.NewS3Logger(cfg)

	// Create a mock S3 client
	mockClient := new(MockS3Client)
	logger.SetS3Client(mockClient)

	// Flush an empty batch
	err := logger.Flush()
	assert.NoError(t, err)

	// S3 should not be called
	mockClient.AssertNotCalled(t, "PutObject")
}

// TestWriteEmptyLog tests handling of empty log data
func TestWriteEmptyLog(t *testing.T) {
	cfg := &gtvcfg.Config{
		LogToS3:   true,
		LogBucket: "test-bucket",
		LogPrefix: "logs",
	}
	logger := s3logger.NewS3Logger(cfg)

	// Create a mock S3 client
	mockClient := new(MockS3Client)
	logger.SetS3Client(mockClient)

	// Write an empty log
	buf := bytes.Buffer{}
	err := logger.WriteLogToS3(buf)
	assert.NoError(t, err)

	// No S3 calls should be made
	mockClient.AssertNotCalled(t, "PutObject")
}

// TestSuccessfulLogDelivery tests that logs are correctly delivered to S3
func TestSuccessfulLogDelivery(t *testing.T) {
	logger, mockClient := createTestLogger(t, true)

	// Set up successful mock response
	mockClient.On("PutObject", mock.Anything, mock.MatchedBy(func(params *s3.PutObjectInput) bool {
		// Verify bucket and key format
		assert.Equal(t, "test-bucket", *params.Bucket)
		assert.True(t, strings.HasPrefix(*params.Key, "logs/2025/05/19/"))

		// Verify content type and encoding
		assert.Equal(t, "application/json", *params.ContentType)
		assert.Equal(t, "gzip", *params.ContentEncoding)

		// Check tags and metadata
		assert.Contains(t, *params.Tagging, "source=aws-oidc-warden")
		assert.Contains(t, *params.Tagging, "created-at=2025-05-19T12:30:45Z")
		assert.Contains(t, params.Metadata, "source")
		assert.Equal(t, "aws-oidc-warden", params.Metadata["source"])

		// Read and verify the content
		body, _ := io.ReadAll(params.Body)
		// We need to recreate the reader for subsequent reads
		params.Body = bytes.NewReader(body)

		// Decompress and check content
		reader, _ := gzip.NewReader(bytes.NewReader(body))
		content, _ := io.ReadAll(reader)
		assert.Contains(t, string(content), "test log message")

		return true
	})).Return(&s3.PutObjectOutput{}, nil)

	// Write a single log
	err := logger.WriteSingleLog([]byte("test log message"))
	assert.NoError(t, err)

	// Verify mock was called
	mockClient.AssertExpectations(t)
}

// TestBatchProcessing tests that logs are correctly batched and delivered
func TestBatchProcessing(t *testing.T) {
	logger, mockClient := createTestLogger(t, true)

	// Set batch size to 3
	logger.SetS3ConfigOption(s3logger.WithBatchSize(3))

	// Set up successful mock response
	mockClient.On("PutObject", mock.Anything, mock.MatchedBy(func(params *s3.PutObjectInput) bool {
		// Read and verify the content
		body, _ := io.ReadAll(params.Body)
		params.Body = bytes.NewReader(body) // Reset for subsequent reads

		// Decompress and check content
		reader, _ := gzip.NewReader(bytes.NewReader(body))
		content, _ := io.ReadAll(reader)

		// Should contain all three log messages with newlines
		for i := 1; i <= 3; i++ {
			assert.Contains(t, string(content),
				fmt.Sprintf("log message %d", i))
		}

		return true
	})).Return(&s3.PutObjectOutput{}, nil).Once()

	// Write logs but don't fill the batch yet
	for i := 1; i <= 2; i++ {
		buf := bytes.Buffer{}
		buf.WriteString(fmt.Sprintf("log message %d\n", i))
		err := logger.WriteLogToS3(buf)
		assert.NoError(t, err)
	}

	// No upload should have occurred yet
	mockClient.AssertNotCalled(t, "PutObject")

	// Add the final log to trigger the batch
	buf := bytes.Buffer{}
	buf.WriteString("log message 3\n")
	err := logger.WriteLogToS3(buf)
	assert.NoError(t, err)

	// Now S3 should have been called
	mockClient.AssertExpectations(t)
}

// TestFlushOnClose tests that logs are flushed when the logger is closed
func TestFlushOnClose(t *testing.T) {
	logger, mockClient := createTestLogger(t, true)

	// Set larger batch size so it won't flush automatically
	logger.SetS3ConfigOption(s3logger.WithBatchSize(10))

	// Set up successful mock response
	mockClient.On("PutObject", mock.Anything, mock.MatchedBy(func(params *s3.PutObjectInput) bool {
		// Read and verify the content
		body, _ := io.ReadAll(params.Body)
		params.Body = bytes.NewReader(body)

		// Decompress and verify
		reader, _ := gzip.NewReader(bytes.NewReader(body))
		content, _ := io.ReadAll(reader)
		assert.Contains(t, string(content), "log to be flushed on close")

		return true
	})).Return(&s3.PutObjectOutput{}, nil).Once()

	// Write a log (but not enough to trigger batch flush)
	buf := bytes.Buffer{}
	buf.WriteString("log to be flushed on close\n")
	err := logger.WriteLogToS3(buf)
	assert.NoError(t, err)

	// No upload yet
	mockClient.AssertNotCalled(t, "PutObject")

	// Close should trigger flush
	err = logger.Close()
	assert.NoError(t, err)

	// Verify flush occurred
	mockClient.AssertExpectations(t)
}

// TestRetryMechanism tests that retries work correctly
func TestRetryMechanism(t *testing.T) {
	logger, mockClient := createTestLogger(t, true)

	// Set up a sequence of responses: error followed by success
	mockClient.On("PutObject", mock.Anything, mock.Anything).
		Return(nil, errors.New("temporary S3 error")).Once()

	mockClient.On("PutObject", mock.Anything, mock.Anything).
		Return(&s3.PutObjectOutput{}, nil).Once()

	// First attempt should fail
	err := logger.WriteSingleLog([]byte("test retry message"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to write logs to S3")

	// Second attempt should succeed
	err = logger.WriteSingleLog([]byte("test retry message"))
	assert.NoError(t, err)

	// Verify both calls were made
	mockClient.AssertNumberOfCalls(t, "PutObject", 2)
}

// TestMetadataAndTags tests that metadata and tags are correctly added to S3 objects
func TestMetadataAndTags(t *testing.T) {
	logger, mockClient := createTestLogger(t, true)

	// Add custom tags
	logger.SetS3ConfigOption(s3logger.WithExtraTag("env", "test"))
	logger.SetS3ConfigOption(s3logger.WithExtraTag("app", "aws-oidc-warden"))

	// Set up mock expectations
	mockClient.On("PutObject", mock.Anything, mock.MatchedBy(func(params *s3.PutObjectInput) bool {
		// Check tags
		tagging := *params.Tagging
		assert.Contains(t, tagging, "env=test")
		assert.Contains(t, tagging, "app=aws-oidc-warden")
		assert.Contains(t, tagging, "source=aws-oidc-warden")

		// Check metadata
		assert.Equal(t, "test", params.Metadata["env"])
		assert.Equal(t, "aws-oidc-warden", params.Metadata["app"])
		assert.Equal(t, "aws-oidc-warden", params.Metadata["source"])
		assert.Contains(t, params.Metadata["created-at"], "2025-05-19T12:30:45Z")

		return true
	})).Return(&s3.PutObjectOutput{}, nil)

	// Write a log to trigger the check
	err := logger.WriteSingleLog([]byte("test metadata and tags"))
	assert.NoError(t, err)

	// Verify expectations
	mockClient.AssertExpectations(t)
}

// TestLogBatchFlush tests that logs can be manually flushed
func TestLogBatchFlush(t *testing.T) {
	logger, mockClient := createTestLogger(t, true)

	// Set large batch size so it won't flush automatically
	logger.SetS3ConfigOption(s3logger.WithBatchSize(100))

	// Setup mock
	mockClient.On("PutObject", mock.Anything, mock.Anything).
		Return(&s3.PutObjectOutput{}, nil).Once()

	// Write a log
	buf := bytes.Buffer{}
	buf.WriteString("log to be flushed manually\n")
	err := logger.WriteLogToS3(buf)
	assert.NoError(t, err)

	// No upload yet
	mockClient.AssertNotCalled(t, "PutObject")

	// Manually flush - this should trigger the upload
	err = logger.Flush()
	assert.NoError(t, err)

	// Verify the upload occurred
	mockClient.AssertExpectations(t)
}

// TestConcurrentLogWrites tests that the logger can handle concurrent writes safely
func TestConcurrentLogWrites(t *testing.T) {
	logger, mockClient := createTestLogger(t, true)

	// Set up mock to accept any calls
	mockClient.On("PutObject", mock.Anything, mock.Anything).
		Return(&s3.PutObjectOutput{}, nil).Maybe()

	// Set small batch size to trigger frequent flushes
	logger.SetS3ConfigOption(s3logger.WithBatchSize(3))

	// Run concurrent writes
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < 5; j++ {
				buf := bytes.Buffer{}
				buf.WriteString(fmt.Sprintf("concurrent log %d-%d\n", id, j))
				err := logger.WriteLogToS3(buf)
				assert.NoError(t, err)
			}
		}(i)
	}

	// Wait for all writes to complete
	wg.Wait()

	// Final flush to ensure all logs are written
	err := logger.Flush()
	assert.NoError(t, err)

	// Verify S3 was called at least once
	mockClient.AssertExpectations(t)
}

// TestHandleWriteObjectWithNilClient tests handling when S3 client is nil
func TestHandleWriteObjectWithNilClient(t *testing.T) {
	logger, _ := createTestLogger(t, true)

	// Set client to nil
	logger.SetS3Client(nil)

	// Try to write object
	err := logger.WriteObject("bucket", "key", []byte("test"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "S3 client not initialized")
}

// TestContextHandling tests the usage of contexts
func TestContextHandling(t *testing.T) {
	logger, mockClient := createTestLogger(t, true)

	// Set up a mock that verifies the context has a timeout
	mockClient.On("PutObject", mock.MatchedBy(func(ctx context.Context) bool {
		deadline, hasDeadline := ctx.Deadline()
		return hasDeadline && deadline.After(time.Now())
	}), mock.Anything).Return(&s3.PutObjectOutput{}, nil)

	// Write a log
	err := logger.WriteSingleLog([]byte("test context handling"))
	assert.NoError(t, err)

	// Verify mockClient was called with a context that has a deadline
	mockClient.AssertExpectations(t)
}
