package s3logger_test

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	gtvcfg "github.com/boogy/aws-oidc-warden/internal/config"
	s3logger "github.com/boogy/aws-oidc-warden/internal/s3logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

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

func createTestLogger(t *testing.T, logToS3 bool) (*s3logger.S3Logger, *MockS3Client) {
	cfg := &gtvcfg.Config{
		LogToS3:   logToS3,
		LogBucket: "test-bucket",
		LogPrefix: "logs/",
	}
	logger := s3logger.NewS3Logger(cfg)
	mockClient := new(MockS3Client)
	logger.SetS3Client(mockClient)

	logger.SetTimeNow(func() time.Time {
		return time.Date(2025, 5, 19, 12, 30, 45, 0, time.UTC)
	})

	return logger, mockClient
}

func TestNewS3Logger(t *testing.T) {
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

	cfg.LogToS3 = true
	logger = s3logger.NewS3Logger(cfg)
	assert.NotNil(t, logger)
	assert.Equal(t, cfg, logger.GetConfig())
	assert.Equal(t, true, cfg.LogToS3)
}

func TestGenerateS3Key(t *testing.T) {
	cfg := &gtvcfg.Config{
		LogToS3:   true,
		LogBucket: "test-bucket",
		LogPrefix: "logs",
	}
	logger := s3logger.NewS3Logger(cfg)

	logger.SetTimeNow(func() time.Time {
		return time.Date(2025, 5, 19, 12, 30, 45, 0, time.UTC)
	})

	logger.SetS3ConfigOption(s3logger.WithIncludeUUID(true))
	key := logger.GenerateS3Key()

	assert.True(t, strings.HasPrefix(key, "logs/2025/05/19/"))
	assert.True(t, strings.Contains(key, "-20250519-123045"))
	assert.True(t, strings.HasSuffix(key, ".json.gz"))

	logger.SetS3ConfigOption(s3logger.WithIncludeUUID(false))
	key = logger.GenerateS3Key()

	assert.Equal(t, "logs/2025/05/19/20250519-123045.json.gz", key)

	logger.SetS3ConfigOption(s3logger.WithPrefix("custom/prefix"))
	logger.SetS3ConfigOption(s3logger.WithFileExtension(".log"))
	key = logger.GenerateS3Key()

	assert.Equal(t, "custom/prefix/2025/05/19/20250519-123045.log", key)
}

func TestLoggerWithOptions(t *testing.T) {
	cfg := &gtvcfg.Config{
		LogToS3:   true,
		LogBucket: "test-bucket",
		LogPrefix: "logs",
	}
	logger := s3logger.NewS3Logger(cfg)

	logger.SetS3ConfigOption(s3logger.WithMaxRetries(5))
	logger.SetS3ConfigOption(s3logger.WithBatchSize(20))
	logger.SetS3ConfigOption(s3logger.WithMaxBatchAge(2 * time.Minute))
	logger.SetS3ConfigOption(s3logger.WithFileExtension(".log.gz"))
	logger.SetS3ConfigOption(s3logger.WithExtraTag("env", "test"))
	logger.SetS3ConfigOption(s3logger.WithExtraTag("region", "us-west-2"))

	s3Config := logger.GetS3Config()
	assert.Equal(t, 5, s3Config.MaxRetries)
	assert.Equal(t, 20, s3Config.BatchSize)
	assert.Equal(t, 2*time.Minute, s3Config.MaxBatchAge)
	assert.Equal(t, ".log.gz", s3Config.FileExtension)
	assert.Equal(t, "test", s3Config.ExtraTags["env"])
	assert.Equal(t, "us-west-2", s3Config.ExtraTags["region"])
}

func TestCompressGzip(t *testing.T) {
	testData := []byte("test data for compression")

	compressed, err := s3logger.TestCompressGzip(testData)
	assert.NoError(t, err)
	assert.NotNil(t, compressed)

	decompressed := decompressGzip(t, compressed)
	assert.Equal(t, testData, decompressed)
}

func TestLoggerWithDisabledLogging(t *testing.T) {
	cfg := &gtvcfg.Config{
		LogToS3:   false,
		LogBucket: "test-bucket",
		LogPrefix: "logs",
	}
	logger := s3logger.NewS3Logger(cfg)

	mockClient := new(MockS3Client)
	logger.SetS3Client(mockClient)

	buf := bytes.Buffer{}
	buf.WriteString("this log should not be sent to S3\n")
	err := logger.WriteLogToS3(buf)
	assert.NoError(t, err)

	err = logger.Flush()
	assert.NoError(t, err)

	err = logger.WriteSingleLog([]byte("this single log should not be sent to S3"))
	assert.NoError(t, err)

	mockClient.AssertNotCalled(t, "PutObject")
}

func TestErrorHandling(t *testing.T) {
	cfg := &gtvcfg.Config{
		LogToS3:   true,
		LogBucket: "test-bucket",
		LogPrefix: "logs",
	}
	logger := s3logger.NewS3Logger(cfg)

	mockClient := new(MockS3Client)
	logger.SetS3Client(mockClient)

	mockClient.On("PutObject", mock.Anything, mock.Anything).Return(nil, assert.AnError)

	err := logger.WriteSingleLog([]byte("test log"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to write logs to S3")

	logger.SetS3ConfigOption(s3logger.WithBatchSize(1))
	buf := bytes.Buffer{}
	buf.WriteString("batch test log\n")
	err = logger.WriteLogToS3(buf)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to write logs to S3")

	err = logger.Flush()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to write logs to S3")
}

func TestEmptyBatchFlush(t *testing.T) {
	cfg := &gtvcfg.Config{
		LogToS3:   true,
		LogBucket: "test-bucket",
		LogPrefix: "logs",
	}
	logger := s3logger.NewS3Logger(cfg)

	mockClient := new(MockS3Client)
	logger.SetS3Client(mockClient)

	err := logger.Flush()
	assert.NoError(t, err)

	mockClient.AssertNotCalled(t, "PutObject")
}

func TestWriteEmptyLog(t *testing.T) {
	cfg := &gtvcfg.Config{
		LogToS3:   true,
		LogBucket: "test-bucket",
		LogPrefix: "logs",
	}
	logger := s3logger.NewS3Logger(cfg)

	mockClient := new(MockS3Client)
	logger.SetS3Client(mockClient)

	buf := bytes.Buffer{}
	err := logger.WriteLogToS3(buf)
	assert.NoError(t, err)

	mockClient.AssertNotCalled(t, "PutObject")
}

func TestSuccessfulLogDelivery(t *testing.T) {
	logger, mockClient := createTestLogger(t, true)

	mockClient.On("PutObject", mock.Anything, mock.MatchedBy(func(params *s3.PutObjectInput) bool {
		assert.Equal(t, "test-bucket", *params.Bucket)
		assert.True(t, strings.HasPrefix(*params.Key, "logs/2025/05/19/"))

		assert.Equal(t, "application/json", *params.ContentType)
		assert.Equal(t, "gzip", *params.ContentEncoding)

		// Tagging is a URL query string, so it's parsed back rather than
		// string-matched: a string no S3 tag parser can decode would still
		// pass a raw-text assertion.
		parsedTags, tagErr := url.ParseQuery(*params.Tagging)
		assert.NoError(t, tagErr)
		assert.Equal(t, "aws-oidc-warden", parsedTags.Get("source"))
		assert.Equal(t, "2025-05-19T12:30:45Z", parsedTags.Get("created-at"))
		assert.Contains(t, params.Metadata, "source")
		assert.Equal(t, "aws-oidc-warden", params.Metadata["source"])

		body, _ := io.ReadAll(params.Body)
		params.Body = bytes.NewReader(body)

		reader, _ := gzip.NewReader(bytes.NewReader(body))
		content, _ := io.ReadAll(reader)
		assert.Contains(t, string(content), "test log message")

		return true
	})).Return(&s3.PutObjectOutput{}, nil)

	err := logger.WriteSingleLog([]byte("test log message"))
	assert.NoError(t, err)

	mockClient.AssertExpectations(t)
}

func TestBatchProcessing(t *testing.T) {
	logger, mockClient := createTestLogger(t, true)

	logger.SetS3ConfigOption(s3logger.WithBatchSize(3))

	mockClient.On("PutObject", mock.Anything, mock.MatchedBy(func(params *s3.PutObjectInput) bool {
		body, _ := io.ReadAll(params.Body)
		params.Body = bytes.NewReader(body)

		reader, _ := gzip.NewReader(bytes.NewReader(body))
		content, _ := io.ReadAll(reader)

		for i := 1; i <= 3; i++ {
			assert.Contains(t, string(content),
				fmt.Sprintf("log message %d", i))
		}

		return true
	})).Return(&s3.PutObjectOutput{}, nil).Once()

	for i := 1; i <= 2; i++ {
		buf := bytes.Buffer{}
		fmt.Fprintf(&buf, "log message %d\n", i)
		err := logger.WriteLogToS3(buf)
		assert.NoError(t, err)
	}

	mockClient.AssertNotCalled(t, "PutObject")

	buf := bytes.Buffer{}
	buf.WriteString("log message 3\n")
	err := logger.WriteLogToS3(buf)
	assert.NoError(t, err)

	mockClient.AssertExpectations(t)
}

func TestFlushOnClose(t *testing.T) {
	logger, mockClient := createTestLogger(t, true)

	logger.SetS3ConfigOption(s3logger.WithBatchSize(10))

	mockClient.On("PutObject", mock.Anything, mock.MatchedBy(func(params *s3.PutObjectInput) bool {
		body, _ := io.ReadAll(params.Body)
		params.Body = bytes.NewReader(body)

		reader, _ := gzip.NewReader(bytes.NewReader(body))
		content, _ := io.ReadAll(reader)
		assert.Contains(t, string(content), "log to be flushed on close")

		return true
	})).Return(&s3.PutObjectOutput{}, nil).Once()

	buf := bytes.Buffer{}
	buf.WriteString("log to be flushed on close\n")
	err := logger.WriteLogToS3(buf)
	assert.NoError(t, err)

	mockClient.AssertNotCalled(t, "PutObject")

	err = logger.Close()
	assert.NoError(t, err)

	mockClient.AssertExpectations(t)
}

func TestRetryMechanism(t *testing.T) {
	logger, mockClient := createTestLogger(t, true)

	mockClient.On("PutObject", mock.Anything, mock.Anything).
		Return(nil, errors.New("temporary S3 error")).Once()

	mockClient.On("PutObject", mock.Anything, mock.Anything).
		Return(&s3.PutObjectOutput{}, nil).Once()

	err := logger.WriteSingleLog([]byte("test retry message"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to write logs to S3")

	err = logger.WriteSingleLog([]byte("test retry message"))
	assert.NoError(t, err)

	mockClient.AssertNumberOfCalls(t, "PutObject", 2)
}

func TestMetadataAndTags(t *testing.T) {
	logger, mockClient := createTestLogger(t, true)

	logger.SetS3ConfigOption(s3logger.WithExtraTag("env", "test"))
	logger.SetS3ConfigOption(s3logger.WithExtraTag("app", "aws-oidc-warden"))

	mockClient.On("PutObject", mock.Anything, mock.MatchedBy(func(params *s3.PutObjectInput) bool {
		tagging := *params.Tagging
		assert.Contains(t, tagging, "env=test")
		assert.Contains(t, tagging, "app=aws-oidc-warden")
		assert.Contains(t, tagging, "source=aws-oidc-warden")

		assert.Equal(t, "test", params.Metadata["env"])
		assert.Equal(t, "aws-oidc-warden", params.Metadata["app"])
		assert.Equal(t, "aws-oidc-warden", params.Metadata["source"])
		assert.Contains(t, params.Metadata["created-at"], "2025-05-19T12:30:45Z")

		return true
	})).Return(&s3.PutObjectOutput{}, nil)

	err := logger.WriteSingleLog([]byte("test metadata and tags"))
	assert.NoError(t, err)

	mockClient.AssertExpectations(t)
}

func TestLogBatchFlush(t *testing.T) {
	logger, mockClient := createTestLogger(t, true)

	logger.SetS3ConfigOption(s3logger.WithBatchSize(100))

	mockClient.On("PutObject", mock.Anything, mock.Anything).
		Return(&s3.PutObjectOutput{}, nil).Once()

	buf := bytes.Buffer{}
	buf.WriteString("log to be flushed manually\n")
	err := logger.WriteLogToS3(buf)
	assert.NoError(t, err)

	mockClient.AssertNotCalled(t, "PutObject")

	err = logger.Flush()
	assert.NoError(t, err)

	mockClient.AssertExpectations(t)
}

func TestConcurrentLogWrites(t *testing.T) {
	logger, mockClient := createTestLogger(t, true)

	mockClient.On("PutObject", mock.Anything, mock.Anything).
		Return(&s3.PutObjectOutput{}, nil).Maybe()

	logger.SetS3ConfigOption(s3logger.WithBatchSize(3))

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < 5; j++ {
				buf := bytes.Buffer{}
				fmt.Fprintf(&buf, "concurrent log %d-%d\n", id, j)
				err := logger.WriteLogToS3(buf)
				assert.NoError(t, err)
			}
		}(i)
	}

	wg.Wait()

	err := logger.Flush()
	assert.NoError(t, err)

	mockClient.AssertExpectations(t)
}

func TestHandleWriteObjectWithNilClient(t *testing.T) {
	logger, _ := createTestLogger(t, true)

	logger.SetS3Client(nil)

	err := logger.WriteObject("bucket", "key", []byte("test"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "S3 client not initialized")
}

func TestContextHandling(t *testing.T) {
	logger, mockClient := createTestLogger(t, true)

	mockClient.On("PutObject", mock.MatchedBy(func(ctx context.Context) bool {
		deadline, hasDeadline := ctx.Deadline()
		return hasDeadline && deadline.After(time.Now())
	}), mock.Anything).Return(&s3.PutObjectOutput{}, nil)

	err := logger.WriteSingleLog([]byte("test context handling"))
	assert.NoError(t, err)

	mockClient.AssertExpectations(t)
}
