package s3logger

import (
	"time"
)

// These functions are exported for testing purposes only

// SetS3Client sets the S3 client for testing
func (l *S3Logger) SetS3Client(client s3ClientInterface) {
	l.s3Client = client
}

// SetTimeNow sets the time function for testing
func (l *S3Logger) SetTimeNow(timeFunc func() time.Time) {
	l.timeNow = timeFunc
}

// GetConfig returns the config for testing
func (l *S3Logger) GetConfig() interface{} {
	return l.config
}

// GetS3Config returns the S3 config for testing
func (l *S3Logger) GetS3Config() S3LoggerConfig {
	return l.s3Config
}

// GenerateS3Key makes the generateS3Key method accessible for testing
func (l *S3Logger) GenerateS3Key() string {
	return l.generateS3Key()
}

// SetS3ConfigOption applies a config option to the logger
func (l *S3Logger) SetS3ConfigOption(option func(*S3Logger) *S3Logger) {
	option(l)
}

// WithIncludeUUID sets whether to include UUID in the S3 key
func WithIncludeUUID(include bool) func(*S3Logger) *S3Logger {
	return func(l *S3Logger) *S3Logger {
		l.s3Config.IncludeUUID = include
		return l
	}
}

// WithPrefix sets the prefix for S3 keys
func WithPrefix(prefix string) func(*S3Logger) *S3Logger {
	return func(l *S3Logger) *S3Logger {
		l.s3Config.Prefix = prefix
		return l
	}
}

// WithFileExtension sets the file extension for S3 keys
func WithFileExtension(ext string) func(*S3Logger) *S3Logger {
	return func(l *S3Logger) *S3Logger {
		l.s3Config.FileExtension = ext
		return l
	}
}

// WithMaxRetries sets the maximum number of retries for S3 operations
func WithMaxRetries(retries int) func(*S3Logger) *S3Logger {
	return func(l *S3Logger) *S3Logger {
		l.s3Config.MaxRetries = retries
		return l
	}
}

// WithBatchSize sets the number of logs to batch before writing to S3
func WithBatchSize(size int) func(*S3Logger) *S3Logger {
	return func(l *S3Logger) *S3Logger {
		l.s3Config.BatchSize = size
		return l
	}
}

// WithMaxBatchAge sets the maximum time to wait before writing a batch
func WithMaxBatchAge(age time.Duration) func(*S3Logger) *S3Logger {
	return func(l *S3Logger) *S3Logger {
		l.s3Config.MaxBatchAge = age
		return l
	}
}

// WithExtraTag adds an extra tag to S3 objects
func WithExtraTag(key, value string) func(*S3Logger) *S3Logger {
	return func(l *S3Logger) *S3Logger {
		if l.s3Config.ExtraTags == nil {
			l.s3Config.ExtraTags = make(map[string]string)
		}
		l.s3Config.ExtraTags[key] = value
		return l
	}
}

// TestCompressGzip exposes the compressGzip function for testing
func TestCompressGzip(data []byte) ([]byte, error) {
	return compressGzip(data)
}
