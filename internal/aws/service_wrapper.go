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
	"strconv"
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
	GetS3Object(ctx context.Context, bucket, key string, maxBytes int) (io.ReadCloser, error)
	GetS3ObjectIfChanged(ctx context.Context, bucket, key, prevETag, expectedOwner string, maxBytes int) (data []byte, etag string, err error)
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

// AwsServiceWrapper implements AwsServiceWrapperInterface over the AWS SDK clients.
type AwsServiceWrapper struct {
	cfg       aws.Config
	s3Client  s3GetObjectAPI
	stsClient *sts.Client
	iamClient *iam.Client
	kms       *kms.Client

	defaultTimeout time.Duration

	iamMu      sync.Mutex
	iamClients map[aws.CredentialsProvider]*iam.Client // GetRoleAs clients by credentials

	// Cached hub identity (from STS GetCallerIdentity)
	callerMu      sync.Mutex
	callerAccount string
	callerArn     string

	// getCallerIdentityFn overrides stsClient.GetCallerIdentity in tests.
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
			cfg:            cfg,
			s3Client:       s3.NewFromConfig(cfg),
			stsClient:      sts.NewFromConfig(cfg),
			iamClient:      iam.NewFromConfig(cfg),
			kms:            kms.NewFromConfig(cfg),
			defaultTimeout: 30 * time.Second,
		}
	})

	return wrapper
}

// KMS returns the KMS client.
func (s *AwsServiceWrapper) KMS() *kms.Client { return s.kms }

func (s *AwsServiceWrapper) GetS3Object(ctx context.Context, bucket, key string, maxBytes int) (io.ReadCloser, error) {
	ctx, cancel := context.WithTimeout(ctx, s.defaultTimeout)
	defer cancel()

	input := &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
		Range:  aws.String(fmt.Sprintf("bytes=0-%d", maxBytes)),
	}

	result, err := s.s3Client.GetObject(ctx, input)
	if STSErrorCode(err) == "InvalidRange" { // a range starting at 0 is unsatisfiable only on an empty object
		return io.NopCloser(bytes.NewReader(nil)), nil
	}
	if err != nil {
		logevent.Error(ctx, nil, logevent.AWSS3GetFailure, "error fetching S3 object",
			slog.String("bucket", bucket),
			slog.String("key", key),
			slog.String("error", err.Error()),
		)
		return nil, err
	}

	if size := objectSize(result); size > int64(maxBytes) {
		_ = result.Body.Close()
		logevent.Warn(ctx, nil, logevent.AWSS3ObjectOversize, "S3 object exceeds maximum allowed size",
			slog.Int64("size", size),
			slog.Int("maxAllowed", maxBytes),
			slog.String("bucket", bucket),
			slog.String("key", key),
		)
		return nil, fmt.Errorf("s3://%s/%s exceeds %d bytes", bucket, key, maxBytes)
	}

	successAttrs := []slog.Attr{slog.String("bucket", bucket), slog.String("key", key)}
	if result.ContentLength != nil {
		successAttrs = append(successAttrs, slog.Int64("sizeBytes", *result.ContentLength))
	}
	logevent.Debug(ctx, nil, logevent.AWSS3GetSuccess, "successfully fetched S3 object", successAttrs...)

	// Read before cancel runs: the body is bound to ctx.
	defer func() { _ = result.Body.Close() }()
	body, err := utils.ReadAllCapped(result.Body, int64(maxBytes), fmt.Sprintf("s3://%s/%s", bucket, key))
	if err != nil {
		return nil, err
	}
	return io.NopCloser(bytes.NewReader(body)), nil
}

// objectSize is the full object size from a ranged response's Content-Range, else its ContentLength.
func objectSize(out *s3.GetObjectOutput) int64 {
	cr := aws.ToString(out.ContentRange)
	if i := strings.LastIndexByte(cr, '/'); i >= 0 {
		if n, err := strconv.ParseInt(cr[i+1:], 10, 64); err == nil {
			return n
		}
	}
	return aws.ToInt64(out.ContentLength)
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

// validateRoleNameLength enforces the 64-char cap on the name after the last '/'; it rejects, never truncates.
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

// GetCallerIdentityInfo returns the hub account and role-session status, cached; failures are not cached.
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
	// A nil provider would fall back to hub credentials and read a same-named hub role.
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
func (s *AwsServiceWrapper) GetS3ObjectIfChanged(ctx context.Context, bucket, key, prevETag, expectedOwner string, maxBytes int) (data []byte, etag string, err error) {
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

	data, err = utils.ReadAllCapped(out.Body, int64(maxBytes), fmt.Sprintf("s3://%s/%s", bucket, key))
	if err != nil {
		return nil, "", err
	}
	return data, aws.ToString(out.ETag), nil
}
