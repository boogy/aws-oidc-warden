package s3logger

import (
	"time"
)

// These functions are exported for testing purposes only

func (l *S3Logger) SetS3Client(client s3ClientInterface) {
	l.s3Client = client
}

func (l *S3Logger) SetTimeNow(timeFunc func() time.Time) {
	l.timeNow = timeFunc
}

func (l *S3Logger) GetConfig() interface{} {
	return l.config
}

func (l *S3Logger) GetS3Config() S3LoggerConfig {
	return l.s3Config
}

func (l *S3Logger) GenerateS3Key() string {
	return l.generateS3Key()
}

func (l *S3Logger) SetS3ConfigOption(option func(*S3Logger) *S3Logger) {
	option(l)
}

func WithIncludeUUID(include bool) func(*S3Logger) *S3Logger {
	return func(l *S3Logger) *S3Logger {
		l.s3Config.IncludeUUID = include
		return l
	}
}

func WithPrefix(prefix string) func(*S3Logger) *S3Logger {
	return func(l *S3Logger) *S3Logger {
		l.s3Config.Prefix = prefix
		return l
	}
}

func WithFileExtension(ext string) func(*S3Logger) *S3Logger {
	return func(l *S3Logger) *S3Logger {
		l.s3Config.FileExtension = ext
		return l
	}
}

func WithMaxRetries(retries int) func(*S3Logger) *S3Logger {
	return func(l *S3Logger) *S3Logger {
		l.s3Config.MaxRetries = retries
		return l
	}
}

func WithBatchSize(size int) func(*S3Logger) *S3Logger {
	return func(l *S3Logger) *S3Logger {
		l.s3Config.BatchSize = size
		return l
	}
}

func WithMaxBatchAge(age time.Duration) func(*S3Logger) *S3Logger {
	return func(l *S3Logger) *S3Logger {
		l.s3Config.MaxBatchAge = age
		return l
	}
}

func WithExtraTag(key, value string) func(*S3Logger) *S3Logger {
	return func(l *S3Logger) *S3Logger {
		if l.s3Config.ExtraTags == nil {
			l.s3Config.ExtraTags = make(map[string]string)
		}
		l.s3Config.ExtraTags[key] = value
		return l
	}
}

func TestCompressGzip(data []byte) ([]byte, error) {
	return compressGzip(data)
}
