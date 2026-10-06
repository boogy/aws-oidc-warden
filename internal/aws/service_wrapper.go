package aws

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	smithyhttp "github.com/aws/smithy-go/transport/http"
	"github.com/boogy/aws-oidc-warden/internal/logevent"
	"github.com/boogy/aws-oidc-warden/internal/utils"
)

// AwsServiceWrapperInterface allows to test AWS specific code based on the AWS services
type AwsServiceWrapperInterface interface {
	GetS3Object(ctx context.Context, bucket, key string) (io.ReadCloser, error)
	GetS3ObjectIfChanged(ctx context.Context, bucket, key, prevETag, expectedOwner string) (data []byte, etag string, err error)
	AssumeRole(ctx context.Context, input *sts.AssumeRoleInput) (*sts.AssumeRoleOutput, error)
	AssumeRoleWithWebIdentity(ctx context.Context, in *sts.AssumeRoleWithWebIdentityInput) (*sts.AssumeRoleWithWebIdentityOutput, error)
	GetRole(ctx context.Context, input *iam.GetRoleInput) (*iam.GetRoleOutput, error)
	GetCallerAccount(ctx context.Context) (string, error)
	GetCallerIdentityInfo(ctx context.Context) (account string, isRoleSession bool, err error)
	GetRoleAs(ctx context.Context, input *iam.GetRoleInput, creds aws.CredentialsProvider) (*iam.GetRoleOutput, error)
}

type s3GetObjectAPI interface {
	GetObject(ctx context.Context, in *s3.GetObjectInput, opts ...func(*s3.Options)) (*s3.GetObjectOutput, error)
}

var (
	initOnce sync.Once
	wrapper  *AwsServiceWrapper
)

// AwsServiceWrapper is the implementation of AwsServiceWrapperInterface
// it wraps the actual AWS service call but has no additional functionality implemented
type AwsServiceWrapper struct {
	cfg       aws.Config
	s3Client  s3GetObjectAPI
	stsClient *sts.Client
	iamClient *iam.Client
	kms       *kms.Client

	maxS3ObjectSize int64
	defaultTimeout  time.Duration

	iamMu      sync.Mutex
	iamClients map[aws.CredentialsProvider]*iam.Client // GetRoleAs clients by credentials

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
			kms:             kms.NewFromConfig(cfg),
			maxS3ObjectSize: 5 * 1024 * 1024,
			defaultTimeout:  30 * time.Second,
		}
	})

	return wrapper
}

// KMS returns the KMS client.
func (s *AwsServiceWrapper) KMS() *kms.Client { return s.kms }

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

	// Read before cancel runs: the body is bound to ctx.
	defer func() { _ = result.Body.Close() }()
	body, err := utils.ReadAllCapped(result.Body, utils.MaxConfigBytes, fmt.Sprintf("s3://%s/%s", bucket, key))
	if err != nil {
		return nil, err
	}
	return io.NopCloser(bytes.NewReader(body)), nil
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
			slog.String("stsErrorCode", STSErrorCode(err)),
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

// AssumeRoleWithWebIdentity calls STS unsigned; the SDK selects the anonymous auth scheme for this operation.
func (s *AwsServiceWrapper) AssumeRoleWithWebIdentity(ctx context.Context, in *sts.AssumeRoleWithWebIdentityInput) (*sts.AssumeRoleWithWebIdentityOutput, error) {
	ctx, cancel := context.WithTimeout(ctx, s.defaultTimeout)
	defer cancel()
	return s.stsClient.AssumeRoleWithWebIdentity(ctx, in)
}

// validateRoleNameLength enforces IAM's 64-character cap on a role NAME,
// measured after the last '/' since the cap excludes any path prefix
// (`/team/sub/Name`, up to 512 chars) — matching utils.ParseRoleARN. Rejects rather
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
	return s.iamClientFor(creds).GetRole(ctx, input)
}

// maxCachedIAMClients bounds iamClients; spoke credentials rotate, so old entries go stale.
const maxCachedIAMClients = 64

// iamClientFor returns an IAM client bound to creds, reusing one per provider value.
func (s *AwsServiceWrapper) iamClientFor(creds aws.CredentialsProvider) *iam.Client {
	build := func() *iam.Client {
		return iam.NewFromConfig(s.cfg, func(o *iam.Options) { o.Credentials = creds })
	}
	if !reflect.TypeOf(creds).Comparable() {
		return build()
	}
	s.iamMu.Lock()
	defer s.iamMu.Unlock()
	if c, ok := s.iamClients[creds]; ok {
		return c
	}
	if s.iamClients == nil || len(s.iamClients) >= maxCachedIAMClients {
		s.iamClients = make(map[aws.CredentialsProvider]*iam.Client)
	}
	c := build()
	s.iamClients[creds] = c
	return c
}

// GetS3ObjectIfChanged reads an owner-pinned object; a 304 returns (nil, prevETag, nil).
func (s *AwsServiceWrapper) GetS3ObjectIfChanged(ctx context.Context, bucket, key, prevETag, expectedOwner string) (data []byte, etag string, err error) {
	ctx, cancel := context.WithTimeout(ctx, s.defaultTimeout)
	defer cancel()

	in := &s3.GetObjectInput{Bucket: aws.String(bucket), Key: aws.String(key), ExpectedBucketOwner: aws.String(expectedOwner)}
	if prevETag != "" {
		in.IfNoneMatch = aws.String(prevETag)
	}

	out, err := s.s3Client.GetObject(ctx, in)
	if err != nil {
		var re *smithyhttp.ResponseError
		if prevETag != "" && errors.As(err, &re) && re.HTTPStatusCode() == http.StatusNotModified {
			return nil, prevETag, nil
		}
		logevent.Error(ctx, nil, logevent.AWSS3GetFailure, "error fetching S3 object",
			slog.String("bucket", bucket),
			slog.String("key", key),
			slog.String("error", err.Error()),
		)
		return nil, "", err
	}
	defer func() {
		if cerr := out.Body.Close(); cerr != nil && err == nil {
			data, etag, err = nil, "", cerr
		}
	}()

	data, err = utils.ReadAllCapped(out.Body, utils.MaxConfigBytes, fmt.Sprintf("s3://%s/%s", bucket, key))
	if err != nil {
		return nil, "", err
	}
	return data, aws.ToString(out.ETag), nil
}
