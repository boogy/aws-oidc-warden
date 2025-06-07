package aws

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// AwsServiceWrapperInterface allows to test AWS specific code based on the AWS services
type AwsServiceWrapperInterface interface {
	GetS3Object(bucket, key string) (io.ReadCloser, error)
	AssumeRole(input *sts.AssumeRoleInput) (*sts.AssumeRoleOutput, error)
	GetRole(input *iam.GetRoleInput) (*iam.GetRoleOutput, error)
	RefreshClients()
}

var (
	initOnce sync.Once
	wrapper  *AwsServiceWrapper
)

// AwsServiceWrapper is the implementation of AwsServiceWrapperInterface
// it wraps the actual AWS service call but has no additional functionality implemented
type AwsServiceWrapper struct {
	cfg       aws.Config
	s3Client  *s3.Client
	stsClient *sts.Client
	iamClient *iam.Client

	// Security settings
	maxS3ObjectSize int64         // Maximum allowed size for S3 objects
	defaultTimeout  time.Duration // Default timeout for AWS operations
}

func NewAwsServiceWrapper() *AwsServiceWrapper {
	initOnce.Do(func() {
		cfg, err := config.LoadDefaultConfig(context.TODO(),
			config.WithRetryMaxAttempts(3),
		)
		if err != nil {
			slog.Error("Failed to load AWS config", "error", err)
			panic(err)
		}

		// Initialize all service clients once
		wrapper = &AwsServiceWrapper{
			cfg:             cfg,
			s3Client:        s3.NewFromConfig(cfg),
			stsClient:       sts.NewFromConfig(cfg),
			iamClient:       iam.NewFromConfig(cfg),
			maxS3ObjectSize: 5 * 1024 * 1024,  // 5MB max size for config files
			defaultTimeout:  30 * time.Second, // 30 second default timeout
		}
	})

	return wrapper
}

// RefreshClients recreates AWS service clients, useful for long-running Lambda environments
// where clients might need refreshing periodically
func (s *AwsServiceWrapper) RefreshClients() {
	slog.Info("Refreshing AWS clients") // Refresh the config to pick up any environment changes
	cfg, err := config.LoadDefaultConfig(context.TODO(),
		config.WithRetryMaxAttempts(3),
	)
	if err != nil {
		slog.Error("Failed to refresh AWS config, keeping existing clients", slog.String("error", err.Error()))
		return
	}

	// Recreate all clients with new configuration
	s.cfg = cfg
	s.s3Client = s3.NewFromConfig(cfg)
	s.stsClient = sts.NewFromConfig(cfg)
	s.iamClient = iam.NewFromConfig(cfg)

	slog.Info("AWS clients successfully refreshed")
}

func (s *AwsServiceWrapper) GetS3Object(bucket, key string) (io.ReadCloser, error) {
	ctx, cancel := context.WithTimeout(context.Background(), s.defaultTimeout)
	defer cancel()

	slog.Debug("Fetching S3 object",
		"bucket", bucket,
		"key", key,
	)

	input := &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
		// We expect objects below maxS3ObjectSize (5MB)
		Range: aws.String(fmt.Sprintf("bytes=0-%d", s.maxS3ObjectSize)),
	}

	result, err := s.s3Client.GetObject(ctx, input)
	if err != nil {
		slog.Error("Error fetching S3 object",
			slog.String("bucket", bucket),
			slog.String("key", key),
			slog.String("error", err.Error()),
		)
		return nil, err
	}

	// Check if content size is too large
	if result.ContentLength != nil && *result.ContentLength > s.maxS3ObjectSize {
		slog.Warn("S3 object exceeds maximum allowed size",
			slog.Int64("size", *result.ContentLength),
			slog.Int64("maxAllowed", s.maxS3ObjectSize),
			slog.String("bucket", bucket),
			slog.String("key", key),
		)
		// Return the object anyway, but it will be truncated due to the Range header
	}

	return result.Body, nil
}

func (s *AwsServiceWrapper) AssumeRole(input *sts.AssumeRoleInput) (*sts.AssumeRoleOutput, error) {
	ctx, cancel := context.WithTimeout(context.Background(), s.defaultTimeout)
	defer cancel()

	slog.Info("Assuming role",
		slog.String("roleArn", *input.RoleArn),
		slog.String("sessionName", *input.RoleSessionName),
	)

	// Ensure we have a reasonable duration set
	if input.DurationSeconds == nil || *input.DurationSeconds == 0 {
		defaultDuration := int32(3600) // 1 hour default
		input.DurationSeconds = &defaultDuration
	}

	// Security: Validate external ID if provided
	if input.ExternalId != nil && len(*input.ExternalId) < 2 {
		slog.Warn("Suspicious short external ID provided",
			slog.String("externalId", *input.ExternalId),
			slog.String("roleArn", *input.RoleArn))
		return nil, fmt.Errorf("invalid external ID length")
	}

	output, err := s.stsClient.AssumeRole(ctx, input)
	if err != nil {
		slog.Error("Error assuming role",
			slog.String("roleArn", *input.RoleArn),
			slog.String("error", err.Error()),
		)
		return nil, err
	}

	// Don't log sensitive information like credentials, but indicate success
	slog.Info("Successfully assumed role", "roleArn", *input.RoleArn)
	return output, nil
}

func (s *AwsServiceWrapper) GetRole(input *iam.GetRoleInput) (*iam.GetRoleOutput, error) {
	ctx, cancel := context.WithTimeout(context.Background(), s.defaultTimeout)
	defer cancel()

	slog.Debug("Getting IAM role", "roleName", *input.RoleName)

	// Sanitize role name input if needed (though AWS SDK should do this)
	if len(*input.RoleName) > 64 {
		truncatedName := (*input.RoleName)[:64]
		slog.Warn("Role name exceeds maximum length, truncating",
			"originalLength", len(*input.RoleName),
			"truncatedName", truncatedName)
		input.RoleName = &truncatedName
	}

	output, err := s.iamClient.GetRole(ctx, input)
	if err != nil {
		slog.Error("Error getting IAM role",
			"roleName", *input.RoleName,
			"error", err,
		)
		return nil, err
	}

	slog.Debug("Successfully retrieved role", "roleName", *input.RoleName)
	return output, nil
}
