package aws

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/boogy/aws-oidc-warden/internal/logevent"
)

// AwsServiceWrapperInterface allows to test AWS specific code based on the AWS services
type AwsServiceWrapperInterface interface {
	GetS3Object(ctx context.Context, bucket, key string) (io.ReadCloser, error)
	AssumeRole(ctx context.Context, input *sts.AssumeRoleInput) (*sts.AssumeRoleOutput, error)
	GetRole(ctx context.Context, input *iam.GetRoleInput) (*iam.GetRoleOutput, error)
	GetCallerAccount(ctx context.Context) (string, error)
	GetCallerIdentityInfo(ctx context.Context) (account string, isRoleSession bool, err error)
	GetRoleAs(ctx context.Context, input *iam.GetRoleInput, creds aws.CredentialsProvider) (*iam.GetRoleOutput, error)
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

	maxS3ObjectSize int64
	defaultTimeout  time.Duration

	// Cached hub identity (from STS GetCallerIdentity)
	callerMu      sync.Mutex
	callerAccount string
	callerArn     string

	// getCallerIdentityFn allows tests to inject a fake STS GetCallerIdentity call.
	// When nil, s.stsClient.GetCallerIdentity is used.
	getCallerIdentityFn func(ctx context.Context) (*sts.GetCallerIdentityOutput, error)
}

func NewAwsServiceWrapper() *AwsServiceWrapper {
	initOnce.Do(func() {
		cfg, err := config.LoadDefaultConfig(context.Background(),
			config.WithRetryMaxAttempts(3),
		)
		if err != nil {
			logevent.Error(context.Background(), nil, logevent.AppInitFailure, "failed to load AWS config",
				slog.String("component", "aws_config"),
				slog.String("error", err.Error()))
			panic(err)
		}

		wrapper = &AwsServiceWrapper{
			cfg:             cfg,
			s3Client:        s3.NewFromConfig(cfg),
			stsClient:       sts.NewFromConfig(cfg),
			iamClient:       iam.NewFromConfig(cfg),
			maxS3ObjectSize: 5 * 1024 * 1024,
			defaultTimeout:  30 * time.Second,
		}
	})

	return wrapper
}

// RefreshClients recreates AWS service clients, useful for long-running Lambda environments
// where clients might need refreshing periodically
func (s *AwsServiceWrapper) RefreshClients() {
	logevent.Debug(context.Background(), nil, logevent.AWSClientsRefreshStart, "refreshing AWS clients")
	cfg, err := config.LoadDefaultConfig(context.Background(),
		config.WithRetryMaxAttempts(3),
	)
	if err != nil {
		logevent.Error(context.Background(), nil, logevent.AWSClientsRefreshFailure, "failed to refresh AWS config, keeping existing clients",
			slog.String("error", err.Error()))
		return
	}

	s.cfg = cfg
	s.s3Client = s3.NewFromConfig(cfg)
	s.stsClient = sts.NewFromConfig(cfg)
	s.iamClient = iam.NewFromConfig(cfg)

	logevent.Info(context.Background(), nil, logevent.AWSClientsRefreshSuccess, "AWS clients successfully refreshed")
}

func (s *AwsServiceWrapper) GetS3Object(ctx context.Context, bucket, key string) (io.ReadCloser, error) {
	ctx, cancel := context.WithTimeout(ctx, s.defaultTimeout)
	defer cancel()

	input := &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
		// We expect objects below maxS3ObjectSize (5MB)
		Range: aws.String(fmt.Sprintf("bytes=0-%d", s.maxS3ObjectSize)),
	}

	result, err := s.s3Client.GetObject(ctx, input)
	if err != nil {
		logevent.Error(ctx, nil, logevent.AWSS3GetFailure, "error fetching S3 object",
			slog.String("bucket", bucket),
			slog.String("key", key),
			slog.String("error", err.Error()),
		)
		return nil, err
	}

	if result.ContentLength != nil && *result.ContentLength > s.maxS3ObjectSize {
		logevent.Warn(ctx, nil, logevent.AWSS3ObjectOversize, "S3 object exceeds maximum allowed size",
			slog.Int64("size", *result.ContentLength),
			slog.Int64("maxAllowed", s.maxS3ObjectSize),
			slog.String("bucket", bucket),
			slog.String("key", key),
		)
		// Returned anyway; the Range header above already truncated it.
	}

	successAttrs := []slog.Attr{slog.String("bucket", bucket), slog.String("key", key)}
	if result.ContentLength != nil {
		successAttrs = append(successAttrs, slog.Int64("sizeBytes", *result.ContentLength))
	}
	logevent.Debug(ctx, nil, logevent.AWSS3GetSuccess, "successfully fetched S3 object", successAttrs...)

	return result.Body, nil
}

func (s *AwsServiceWrapper) AssumeRole(ctx context.Context, input *sts.AssumeRoleInput) (*sts.AssumeRoleOutput, error) {
	ctx, cancel := context.WithTimeout(ctx, s.defaultTimeout)
	defer cancel()

	if input.DurationSeconds == nil || *input.DurationSeconds == 0 {
		defaultDuration := int32(3600)
		input.DurationSeconds = &defaultDuration
	}

	if input.ExternalId != nil && len(*input.ExternalId) < 2 {
		// Log the length, never the value: ExternalId is a shared secret.
		logevent.Warn(ctx, nil, logevent.STSExternalIDSuspicious, "suspicious short external ID provided",
			slog.Int("externalIdLength", len(*input.ExternalId)),
			slog.String("roleArn", *input.RoleArn))
		return nil, fmt.Errorf("invalid external ID length")
	}

	start := time.Now()
	output, err := s.stsClient.AssumeRole(ctx, input)
	if err != nil {
		logevent.Error(ctx, nil, logevent.STSAssumeRoleFailure, "error assuming role",
			slog.String("roleArn", *input.RoleArn),
			slog.String("stsErrorCode", stsErrorCode(err)),
			slog.String("error", err.Error()),
			slog.Int64("durationMs", time.Since(start).Milliseconds()),
		)
		return nil, err
	}

	attrs := []slog.Attr{
		slog.String("roleArn", *input.RoleArn),
		slog.Int64("durationMs", time.Since(start).Milliseconds()),
	}
	if u := output.AssumedRoleUser; u != nil && u.AssumedRoleId != nil {
		attrs = append(attrs, slog.String("assumedRoleId", *u.AssumedRoleId))
	}
	logevent.Info(ctx, nil, logevent.STSAssumeRoleSuccess, "assumed role", attrs...)

	return output, nil
}

// validateRoleNameLength enforces IAM's 64-character cap on a role NAME,
// measured after the last '/' since the cap excludes any path prefix
// (`/team/sub/Name`, up to 512 chars) — matching ParseRoleARN. Rejects rather
// than truncating, since truncating would silently look up a different role.
func validateRoleNameLength(roleName string) error {
	name := roleName
	if i := strings.LastIndexByte(name, '/'); i >= 0 {
		name = name[i+1:]
	}
	if len(name) > 64 {
		return fmt.Errorf("role name %q exceeds the IAM maximum of 64 characters (got %d)", name, len(name))
	}
	return nil
}

func (s *AwsServiceWrapper) GetRole(ctx context.Context, input *iam.GetRoleInput) (*iam.GetRoleOutput, error) {
	ctx, cancel := context.WithTimeout(ctx, s.defaultTimeout)
	defer cancel()

	if err := validateRoleNameLength(*input.RoleName); err != nil {
		return nil, err
	}

	output, err := s.iamClient.GetRole(ctx, input)
	if err != nil {
		logevent.Error(ctx, nil, logevent.AWSIAMGetRoleFailure, "error getting IAM role",
			slog.String("roleName", *input.RoleName),
			slog.String("error", err.Error()),
		)
		return nil, err
	}

	logevent.Debug(ctx, nil, logevent.AWSIAMGetRoleSuccess, "successfully retrieved role", slog.String("roleName", *input.RoleName))
	return output, nil
}

// GetCallerIdentityInfo returns the account ID and role-session status of the
// warden's own (hub) identity, fetched via STS GetCallerIdentity and cached
// (a failed lookup is not cached, so a later call retries).
func (s *AwsServiceWrapper) GetCallerIdentityInfo(ctx context.Context) (account string, isRoleSession bool, err error) {
	s.callerMu.Lock()
	defer s.callerMu.Unlock()

	if s.callerAccount != "" {
		return s.callerAccount, strings.Contains(s.callerArn, ":assumed-role/"), nil
	}

	ctx, cancel := context.WithTimeout(ctx, s.defaultTimeout)
	defer cancel()

	fetch := s.getCallerIdentityFn
	if fetch == nil {
		fetch = func(ctx context.Context) (*sts.GetCallerIdentityOutput, error) {
			return s.stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
		}
	}

	out, ferr := fetch(ctx)
	if ferr != nil {
		logevent.Error(ctx, nil, logevent.STSCallerIdentityFailure, "error getting caller identity", slog.String("error", ferr.Error()))
		return "", false, ferr
	}
	if out.Account == nil || out.Arn == nil {
		return "", false, fmt.Errorf("sts GetCallerIdentity returned incomplete identity")
	}

	s.callerAccount = *out.Account
	s.callerArn = *out.Arn
	return s.callerAccount, strings.Contains(s.callerArn, ":assumed-role/"), nil
}

// GetCallerAccount returns the account ID of the warden's own (hub) identity.
func (s *AwsServiceWrapper) GetCallerAccount(ctx context.Context) (string, error) {
	account, _, err := s.GetCallerIdentityInfo(ctx)
	return account, err
}

// GetRoleAs performs iam:GetRole using the supplied credentials provider.
func (s *AwsServiceWrapper) GetRoleAs(ctx context.Context, input *iam.GetRoleInput, creds aws.CredentialsProvider) (*iam.GetRoleOutput, error) {
	// A nil provider would silently fall back to hub credentials and read a
	// same-named role in the wrong (hub) account — a confused-deputy risk.
	if creds == nil {
		return nil, errors.New("GetRoleAs requires explicit credentials; refusing to fall back to hub credentials")
	}

	ctx, cancel := context.WithTimeout(ctx, s.defaultTimeout)
	defer cancel()
	client := iam.NewFromConfig(s.cfg, func(o *iam.Options) { o.Credentials = creds })
	return client.GetRole(ctx, input)
}
