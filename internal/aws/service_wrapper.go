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
)

// AwsServiceWrapperInterface allows to test AWS specific code based on the AWS services
type AwsServiceWrapperInterface interface {
	GetS3Object(bucket, key string) (io.ReadCloser, error)
	AssumeRole(input *sts.AssumeRoleInput) (*sts.AssumeRoleOutput, error)
	GetRole(input *iam.GetRoleInput) (*iam.GetRoleOutput, error)
	GetCallerAccount() (string, error)
	GetCallerIdentityInfo() (account string, isRoleSession bool, err error)
	GetRoleAs(input *iam.GetRoleInput, creds aws.CredentialsProvider) (*iam.GetRoleOutput, error)
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
		// Log the length, never the value: ExternalId is a shared secret. The
		// value is worthless at this length, but printing a configured secret
		// is a pattern that must not be copied to a path where it isn't.
		slog.Warn("Suspicious short external ID provided",
			slog.Int("externalIdLength", len(*input.ExternalId)),
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

// validateRoleNameLength enforces IAM's 64-character cap on a role NAME.
//
// The cap applies to the name only — a role identifier may carry a path
// (`/team/sub/Name`, up to 512 chars), and the name is the final segment. So
// the length is measured after the last '/', exactly as ParseRoleARN derives
// the name; measuring the whole string would reject a perfectly valid role
// with a deep path and a short name.
//
// The previous behavior TRUNCATED an over-long value to 64 characters and
// looked that up instead, reading the tags of a DIFFERENT role than the caller
// named — the wrong reflex on a security-relevant lookup, since tag-based
// authorization reads these tags. Reject rather than coerce, mirroring the rule
// BuildSessionTags already follows.
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

func (s *AwsServiceWrapper) GetRole(input *iam.GetRoleInput) (*iam.GetRoleOutput, error) {
	ctx, cancel := context.WithTimeout(context.Background(), s.defaultTimeout)
	defer cancel()

	slog.Debug("Getting IAM role", "roleName", *input.RoleName)

	if err := validateRoleNameLength(*input.RoleName); err != nil {
		return nil, err
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

// GetCallerIdentityInfo returns the account ID and role-session status of the
// warden's own (hub) identity, fetched via STS GetCallerIdentity and cached.
// A failed lookup is not cached, so a later call retries instead of failing forever.
func (s *AwsServiceWrapper) GetCallerIdentityInfo() (account string, isRoleSession bool, err error) {
	s.callerMu.Lock()
	defer s.callerMu.Unlock()

	if s.callerAccount != "" {
		return s.callerAccount, strings.Contains(s.callerArn, ":assumed-role/"), nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), s.defaultTimeout)
	defer cancel()

	fetch := s.getCallerIdentityFn
	if fetch == nil {
		fetch = func(ctx context.Context) (*sts.GetCallerIdentityOutput, error) {
			return s.stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
		}
	}

	out, ferr := fetch(ctx)
	if ferr != nil {
		slog.Error("Error getting caller identity", slog.String("error", ferr.Error()))
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
func (s *AwsServiceWrapper) GetCallerAccount() (string, error) {
	account, _, err := s.GetCallerIdentityInfo()
	return account, err
}

// GetRoleAs performs iam:GetRole using the supplied credentials provider.
func (s *AwsServiceWrapper) GetRoleAs(input *iam.GetRoleInput, creds aws.CredentialsProvider) (*iam.GetRoleOutput, error) {
	// A nil provider would leave the hub credentials in place and silently read
	// a same-named role in the HUB account while the caller believes it read a
	// member account's — the confused deputy GetRoleTags guards against. Its one
	// caller only reaches here with non-nil creds, so this is unreachable today;
	// it is enforced here so the guarantee does not depend on that caller.
	if creds == nil {
		return nil, errors.New("GetRoleAs requires explicit credentials; refusing to fall back to hub credentials")
	}

	ctx, cancel := context.WithTimeout(context.Background(), s.defaultTimeout)
	defer cancel()
	client := iam.NewFromConfig(s.cfg, func(o *iam.Options) { o.Credentials = creds })
	return client.GetRole(ctx, input)
}
