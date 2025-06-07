package aws

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"regexp"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/aws-sdk-go-v2/service/sts/types"
	gtvcfg "github.com/boogy/aws-oidc-warden/pkg/config"
	gtypes "github.com/boogy/aws-oidc-warden/pkg/types"
)

// AwsConsumerInterface encapsulates all actions performs with the AWS services
type AwsConsumerInterface interface {
	ReadS3Configuration() error
	AssumeRole(roleARN, sessionName string, sessionPolicy *string, duration *int32, claims *gtypes.GithubClaims) (*types.Credentials, error)
	GetS3Object(bucket, key string) (io.ReadCloser, error)
	GetRole(role string) (*iam.GetRoleOutput, error)
}

// AwsConsumer is the implementation of AwsConsumerInterface
type AwsConsumer struct {
	AWS    AwsServiceWrapperInterface
	Config *gtvcfg.Config
}

// NewAwsConsumer creates a new AwsConsumer
func NewAwsConsumer(cfg *gtvcfg.Config) *AwsConsumer {
	return &AwsConsumer{
		AWS:    NewAwsServiceWrapper(),
		Config: cfg,
	}
}

// SessionName cleans the session name to be valid
func (a *AwsConsumer) SessionName(name string) string {
	invalidChars := regexp.MustCompile(`[^[:word:]+=,.@-]`)
	name = invalidChars.ReplaceAllLiteralString(name, "")

	if len(name) > 64 {
		return name[len(name)-64:]
	}
	return name
}

// AssumeRole assumes the specified AWS IAM role and returns temporary credentials
// It also applies session tags based on GitHub claims for better traceability and security
func (a *AwsConsumer) AssumeRole(roleArn, sessionName string, sessionPolicy *string, duration *int32, claims *gtypes.GithubClaims) (*types.Credentials, error) {
	if roleArn == "" {
		return nil, errors.New("roleArn cannot be empty")
	}

	if sessionName == "" {
		return nil, errors.New("sessionName cannot be empty")
	}

	cleanSessionName := a.SessionName(sessionName)

	var durationSeconds int32 = 3600 // Default to 1 hour
	if duration != nil && *duration > 0 {
		// AWS has a minimum of 900 seconds (15 minutes) and maximum of 12 hours
		if *duration < 900 {
			slog.Warn("Duration is less than minimum allowed value (900 seconds), using 900 seconds",
				"requestedDuration", *duration)
			durationSeconds = 900
		} else if *duration > 43200 {
			slog.Warn("Duration exceeds maximum allowed value (43200 seconds/12 hours), using 43200 seconds",
				"requestedDuration", *duration)
			durationSeconds = 43200
		} else {
			durationSeconds = *duration
		}
	}

	var assumeRoleInput sts.AssumeRoleInput
	assumeRoleInput.RoleArn = &roleArn
	assumeRoleInput.RoleSessionName = &cleanSessionName
	assumeRoleInput.DurationSeconds = &durationSeconds

	// Allow for a session policy to be passed in optionally to restrict the permissions of the assumed role
	if sessionPolicy != nil && *sessionPolicy != "" {
		assumeRoleInput.Policy = sessionPolicy
		slog.Debug("Using provided session policy for role assumption",
			"roleArn", roleArn,
			"sessionName", cleanSessionName)
	}

	// Add session tags based on GitHub claims for enhanced security and traceability
	if claims != nil {
		tags := CreateSessionTags(claims)
		if len(tags) > 0 {
			assumeRoleInput.Tags = tags
			slog.Debug("Added session tags from GitHub claims",
				"roleArn", roleArn,
				"sessionName", cleanSessionName,
				"tagCount", len(tags))
		}
	}

	result, err := a.AWS.AssumeRole(&assumeRoleInput)
	if err != nil {
		return nil, fmt.Errorf("unable to perform sts.AssumeRole: %w", err)
	}

	if result.Credentials == nil {
		return nil, errors.New("no credentials returned from assumed role")
	}

	return result.Credentials, nil
}

// CreateSessionTags creates session tags from GitHub claims for enhanced security and audit trail
// Session tags are limited to 50 tags with a combined size limit of 2048 characters
func CreateSessionTags(claims *gtypes.GithubClaims) []types.Tag {
	if claims == nil {
		return nil
	}

	var tags []types.Tag

	// Add key GitHub claims as session tags for security and audit purposes
	// These tags help with:
	// 1. Security monitoring and detection of unusual activity
	// 2. Audit trails for compliance and forensics
	// 3. Access control policies based on session tags

	// Extract repository name (without owner) from full repository path
	repoName := ""
	if claims.Repository != "" {
		// Repository format is "owner/repo", extract just the repo name
		if idx := len(claims.Repository) - 1; idx >= 0 {
			for i := len(claims.Repository) - 1; i >= 0; i-- {
				if claims.Repository[i] == '/' {
					repoName = claims.Repository[i+1:]
					break
				}
			}
			// If no slash found, use the entire string as repo name
			if repoName == "" {
				repoName = claims.Repository
			}
		}
	}

	tagMappings := map[string]string{
		"repo":       repoName,
		"actor":      claims.Actor,
		"ref":        claims.Ref,
		"event-name": claims.EventName,
		"repo-owner": claims.RepositoryOwner,
		"ref-type":   claims.RefType,
	}

	for key, value := range tagMappings {
		if value != "" {
			// AWS session tag keys and values have length limits and character restrictions
			// Key: 1-128 characters, alphanumeric + certain special chars
			// Value: 0-256 characters, same restrictions
			cleanKey := sanitizeTagValue(key, 128)
			cleanValue := sanitizeTagValue(value, 256)

			if cleanKey != "" && cleanValue != "" {
				tags = append(tags, types.Tag{
					Key:   &cleanKey,
					Value: &cleanValue,
				})
			}
		}
	}

	// Limit to AWS maximum of 50 session tags
	if len(tags) > 50 {
		slog.Warn("Too many session tags generated, truncating to 50",
			"originalCount", len(tags))
		tags = tags[:50]
	}

	return tags
}

// sanitizeTagValue sanitizes a tag value to comply with AWS session tag requirements
func sanitizeTagValue(value string, maxLength int) string {
	if value == "" {
		return ""
	}

	// AWS session tags allow alphanumeric characters plus: + - = . _ : / @
	// Remove any characters that are not allowed
	validChars := regexp.MustCompile(`[^[:alnum:]+=._:/@-]`)
	sanitized := validChars.ReplaceAllLiteralString(value, "")

	// Truncate to maximum length if necessary
	if len(sanitized) > maxLength {
		return sanitized[:maxLength]
	}

	return sanitized
}

// ReadS3Configuration reads the configured S3 Bucket and returns Config
func (a *AwsConsumer) ReadS3Configuration() error {
	if a.Config.S3ConfigBucket == "" || a.Config.S3ConfigPath == "" {
		return errors.New("S3ConfigBucket and S3ConfigPath options must be set")
	}

	content, err := a.AWS.GetS3Object(a.Config.S3ConfigBucket, a.Config.S3ConfigPath)
	if err != nil {
		return fmt.Errorf("failed to get S3 configuration object: %w", err)
	}
	defer func() {
		if cerr := content.Close(); cerr != nil {
			slog.Error("Error closing S3 configuration object", "error", cerr)
		}
	}()

	decoder := json.NewDecoder(content)
	if err := decoder.Decode(a.Config); err != nil {
		return fmt.Errorf("unable to decode configuration from S3: %w", err)
	}

	slog.Debug("Successfully imported config", slog.String("config", fmt.Sprintf("%+v", a.Config)))
	return nil
}

// GetRole retrieves information about the specified AWS IAM role
func (a *AwsConsumer) GetRole(role string) (*iam.GetRoleOutput, error) {
	if role == "" {
		return nil, errors.New("role name cannot be empty")
	}

	return a.AWS.GetRole(&iam.GetRoleInput{
		RoleName: aws.String(role),
	})
}

// RoleHasTag checks if an IAM role has a specific tag key and value
func (a *AwsConsumer) RoleHasTag(role string, tagKey, tagValue string) (bool, error) {
	if role == "" {
		return false, errors.New("role name cannot be empty")
	}

	if tagKey == "" {
		return false, errors.New("tag key cannot be empty")
	}

	roleOutput, err := a.GetRole(role)
	if err != nil {
		return false, fmt.Errorf("unable to get role: %w", err)
	}

	if roleOutput.Role == nil {
		return false, errors.New("role information not available")
	}

	for _, tag := range roleOutput.Role.Tags {
		if tag.Key == nil || tag.Value == nil {
			continue
		}

		if *tag.Key == tagKey && *tag.Value == tagValue {
			return true, nil
		}
	}

	// Tag not found
	slog.Debug("Tag not found on role",
		"role", role,
		"tagKey", tagKey,
		"tagValue", tagValue)
	return false, nil
}

// GetS3Object retrieves an object from S3
func (a *AwsConsumer) GetS3Object(bucket, key string) (io.ReadCloser, error) {
	if bucket == "" {
		return nil, errors.New("bucket name cannot be empty")
	}

	if key == "" {
		return nil, errors.New("object key cannot be empty")
	}

	return a.AWS.GetS3Object(bucket, key)
}

// GetSessionPolicyFromS3 retrieves the IAM session policy from S3
func (a *AwsConsumer) GetSessionPolicyFromS3(bucket, prefix string) (string, error) {
	if bucket == "" {
		return "", errors.New("bucket name cannot be empty")
	}

	if prefix == "" {
		return "", errors.New("object prefix cannot be empty")
	}

	content, err := a.AWS.GetS3Object(bucket, prefix)
	if err != nil {
		return "", fmt.Errorf("failed to get session policy from S3: %w", err)
	}
	defer func() {
		if cerr := content.Close(); cerr != nil {
			slog.Error("Error closing S3 session policy object", "error", cerr)
		}
	}()

	data, err := io.ReadAll(content)
	if err != nil {
		return "", fmt.Errorf("unable to read policy from S3: %w", err)
	}

	if len(data) == 0 {
		return "", errors.New("empty policy document retrieved from S3")
	}

	return string(data), nil
}
