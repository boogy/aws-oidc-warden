package aws

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"regexp"
	"slices"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/aws-sdk-go-v2/service/sts/types"
	gtvcfg "github.com/boogy/aws-oidc-warden/internal/config"
	gtypes "github.com/boogy/aws-oidc-warden/internal/types"
)

// maxConfigSize bounds how many bytes are read from a remote configuration
// object (S3) to guard against an oversized or malicious payload.
const maxConfigSize = 1024 * 1024 // 1MB

// AwsConsumerInterface encapsulates all actions performs with the AWS services
type AwsConsumerInterface interface {
	ReadS3Configuration() error
	AssumeRole(roleARN, sessionName string, sessionPolicy *string, duration *int32, claims *gtypes.Claims) (*types.Credentials, error)
	GetS3Object(bucket, key string) (io.ReadCloser, error)
	GetRole(role string) (*iam.GetRoleOutput, error)
	GetRoleTags(roleARN string) (map[string]string, error)
	IsTargetAccountAllowed(roleArn string) (bool, error)
}

// cachedCreds holds spoke credentials for an account until shortly before expiry.
type cachedCreds struct {
	provider aws.CredentialsProvider
	expires  time.Time
}

// cachedTags holds a role's IAM tags for a short TTL to cut IAM calls.
type cachedTags struct {
	tags    map[string]string
	expires time.Time
}

// AwsConsumer is the implementation of AwsConsumerInterface
type AwsConsumer struct {
	AWS    AwsServiceWrapperInterface
	Config *gtvcfg.Config

	configSource func() *gtvcfg.Config // live-config getter; nil falls back to Config
	now          func() time.Time
	mu           sync.Mutex
	spokeCache   map[string]cachedCreds // keyed by account ID
	roleTagCache map[string]cachedTags  // keyed by role ARN
}

// cfg returns the live configuration. When a config source is wired (the
// hot-reload provider's Get), it is read per-call so reloaded changes take
// effect on the consumer's enforcement paths; otherwise the construction-time
// Config is used (static and test setups).
func (a *AwsConsumer) cfg() *gtvcfg.Config {
	if a.configSource != nil {
		if c := a.configSource(); c != nil {
			return c
		}
	}
	return a.Config
}

// SetConfigSource wires a live-config getter (e.g. config.Provider.Get) so the
// consumer always enforces the currently active configuration after hot-reload.
func (a *AwsConsumer) SetConfigSource(fn func() *gtvcfg.Config) { a.configSource = fn }

// NewAwsConsumer creates a new AwsConsumer
func NewAwsConsumer(cfg *gtvcfg.Config) *AwsConsumer {
	return &AwsConsumer{
		AWS:          NewAwsServiceWrapper(),
		Config:       cfg,
		now:          time.Now,
		spokeCache:   make(map[string]cachedCreds),
		roleTagCache: make(map[string]cachedTags),
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

// spokeCredsFor resolves credentials for operating in the given account. It
// returns (nil, nil) when tag-auth is disabled or the account is the warden's
// own (hub) account — callers then use the default hub clients. For a different
// account it assumes the convention-named spoke role and caches the result
// until shortly before expiry.
func (a *AwsConsumer) spokeCredsFor(account string) (aws.CredentialsProvider, error) {
	cfg := a.cfg()
	if cfg == nil || cfg.TagAuth == nil || !cfg.TagAuth.Enabled {
		return nil, nil
	}
	hub, err := a.AWS.GetCallerAccount()
	if err != nil {
		return nil, fmt.Errorf("resolve hub account: %w", err)
	}
	if account == hub {
		return nil, nil
	}
	if !a.accountAllowed(account, hub) {
		return nil, fmt.Errorf("target account %s is not in tag_auth.allowed_accounts", account)
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	if c, ok := a.spokeCache[account]; ok && a.now().Before(c.expires) {
		return c.provider, nil
	}

	ta := cfg.TagAuth
	spokeArn := fmt.Sprintf("arn:aws:iam::%s:role/%s", account, ta.SpokeRoleName)
	sessionName := "aow-broker"
	dur := int32(ta.SpokeSessionDuration.Seconds())
	if dur < 900 {
		dur = 900
	}
	input := &sts.AssumeRoleInput{
		RoleArn:         &spokeArn,
		RoleSessionName: &sessionName,
		DurationSeconds: &dur,
	}
	if ta.ExternalID != "" {
		input.ExternalId = &ta.ExternalID
	}
	out, err := a.AWS.AssumeRole(input)
	if err != nil {
		return nil, fmt.Errorf("assume spoke role %s: %w", spokeArn, err)
	}
	if out.Credentials == nil {
		return nil, fmt.Errorf("spoke role %s returned no credentials", spokeArn)
	}
	cr := out.Credentials
	provider := credentials.NewStaticCredentialsProvider(*cr.AccessKeyId, *cr.SecretAccessKey, *cr.SessionToken)
	expires := a.now().Add(time.Hour)
	if cr.Expiration != nil {
		expires = cr.Expiration.Add(-5 * time.Minute) // refresh margin
	}
	a.spokeCache[account] = cachedCreds{provider: provider, expires: expires}
	return provider, nil
}

// AssumeRole assumes the specified AWS IAM role and returns temporary credentials
// It also applies session tags based on GitHub claims for better traceability and security
func (a *AwsConsumer) AssumeRole(roleArn, sessionName string, sessionPolicy *string, duration *int32, claims *gtypes.Claims) (*types.Credentials, error) {
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

	// Mark identity-bearing session tags transitive so ABAC survives any further
	// role chaining by the target role (immutable downstream).
	if cfg := a.cfg(); cfg != nil && cfg.TagAuth != nil && cfg.TagAuth.TransitiveSessionTags {
		if keys := selectTransitiveKeys(assumeRoleInput.Tags); len(keys) > 0 {
			assumeRoleInput.TransitiveTagKeys = keys
		}
	}

	// Route cross-account targets through the spoke role; same-account and
	// tag-auth-disabled paths use the default hub identity (creds == nil).
	var creds aws.CredentialsProvider
	if account, _, perr := ParseRoleARN(roleArn); perr == nil {
		var cerr error
		if creds, cerr = a.spokeCredsFor(account); cerr != nil {
			return nil, fmt.Errorf("resolve credentials for %s: %w", roleArn, cerr)
		}
	}

	// Cross-account assume is role chaining; AWS caps chained sessions at 1h.
	if creds != nil && durationSeconds > 3600 {
		slog.Warn("cross-account role chaining caps the session at 1h; clamping duration",
			"requestedDuration", durationSeconds)
		durationSeconds = 3600
		assumeRoleInput.DurationSeconds = &durationSeconds
	}

	var (
		result *sts.AssumeRoleOutput
		err    error
	)
	if creds == nil {
		result, err = a.AWS.AssumeRole(&assumeRoleInput)
	} else {
		result, err = a.AWS.AssumeRoleAs(&assumeRoleInput, creds)
	}
	if err != nil {
		return nil, fmt.Errorf("unable to perform sts.AssumeRole: %w", err)
	}

	if result.Credentials == nil {
		return nil, errors.New("no credentials returned from assumed role")
	}

	return result.Credentials, nil
}

// transitiveSessionTagKeys are the session-tag keys marked transitive when
// tag_auth.transitive_session_tags is enabled. Kept minimal on purpose:
// transitive tags are immutable through the entire role chain.
var transitiveSessionTagKeys = []string{"repo", "ref", "actor"}

// selectTransitiveKeys returns the subset of tag keys present in tags that are
// eligible to be transitive.
func selectTransitiveKeys(tags []types.Tag) []string {
	keys := make([]string, 0, len(transitiveSessionTagKeys))
	for _, t := range tags {
		if t.Key != nil && slices.Contains(transitiveSessionTagKeys, *t.Key) {
			keys = append(keys, *t.Key)
		}
	}
	return keys
}

// CreateSessionTags creates session tags from GitHub claims for enhanced security and audit trail
// Session tags are limited to 50 tags with a combined size limit of 2048 characters
func CreateSessionTags(claims *gtypes.Claims) []types.Tag {
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

// accountAllowed reports whether the warden may assume a role in account. The
// hub account is always allowed; an empty allow-list permits any account.
func (a *AwsConsumer) accountAllowed(account, hub string) bool {
	cfg := a.cfg()
	if cfg == nil {
		return true
	}
	if account == hub {
		return true
	}
	ta := cfg.TagAuth
	if ta == nil || len(ta.AllowedAccounts) == 0 {
		return true
	}
	return slices.Contains(ta.AllowedAccounts, account)
}

// IsTargetAccountAllowed checks the requested role ARN's account against the
// tag_auth.allowed_accounts list. Returns true when tag-auth is disabled (no
// cross-account path exists) or the account is permitted.
func (a *AwsConsumer) IsTargetAccountAllowed(roleArn string) (bool, error) {
	account, _, err := ParseRoleARN(roleArn)
	if err != nil {
		return false, err
	}
	if cfg := a.cfg(); cfg == nil || cfg.TagAuth == nil || !cfg.TagAuth.Enabled {
		return true, nil
	}
	hub, err := a.AWS.GetCallerAccount()
	if err != nil {
		return false, fmt.Errorf("resolve hub account: %w", err)
	}
	return a.accountAllowed(account, hub), nil
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

	// Bound the read to guard against an oversized object.
	data, err := io.ReadAll(io.LimitReader(content, maxConfigSize))
	if err != nil {
		return fmt.Errorf("unable to read configuration from S3: %w", err)
	}

	// Overlay using the documented snake_case schema (same as the YAML config)
	// and re-validate so repo_role_mappings regex patterns get compiled.
	if err := a.Config.MergeBytes(data, gtvcfg.FormatFromPath(a.Config.S3ConfigPath)); err != nil {
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

// roleTagCacheTTL bounds how long role tags are cached to cut IAM calls under
// burst load while keeping tags reasonably fresh.
const roleTagCacheTTL = 60 * time.Second

// GetRoleTags returns the IAM tags of the role identified by roleARN as a
// key→value map. When the role lives in a different account than the warden,
// the read is performed with spoke credentials assumed in that account.
func (a *AwsConsumer) GetRoleTags(roleARN string) (map[string]string, error) {
	a.mu.Lock()
	if c, ok := a.roleTagCache[roleARN]; ok && a.now().Before(c.expires) {
		a.mu.Unlock()
		return c.tags, nil
	}
	a.mu.Unlock()

	account, roleName, err := ParseRoleARN(roleARN)
	if err != nil {
		return nil, err
	}
	creds, err := a.spokeCredsFor(account)
	if err != nil {
		return nil, err
	}

	input := &iam.GetRoleInput{RoleName: aws.String(roleName)}
	var out *iam.GetRoleOutput
	if creds == nil {
		out, err = a.AWS.GetRole(input)
	} else {
		out, err = a.AWS.GetRoleAs(input, creds)
	}
	if err != nil {
		return nil, fmt.Errorf("get role %s: %w", roleName, err)
	}
	if out.Role == nil {
		return nil, errors.New("role information not available")
	}

	tags := make(map[string]string, len(out.Role.Tags))
	for _, tag := range out.Role.Tags {
		if tag.Key != nil && tag.Value != nil {
			tags[*tag.Key] = *tag.Value
		}
	}

	a.mu.Lock()
	a.roleTagCache[roleARN] = cachedTags{tags: tags, expires: a.now().Add(roleTagCacheTTL)}
	a.mu.Unlock()
	return tags, nil
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
