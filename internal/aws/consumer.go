package aws

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
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
	"github.com/boogy/aws-oidc-warden/internal/utils"
)

// maxConfigSize bounds how many bytes are read from a remote (S3) config object.
const maxConfigSize = 1024 * 1024 // 1MB

// AwsConsumerInterface encapsulates all actions performs with the AWS services
type AwsConsumerInterface interface {
	ReadS3Configuration() error
	AssumeRole(roleARN, sessionName string, sessionPolicy *string, duration *int32, claims *gtypes.Claims, sessionTags map[string]string) (*types.Credentials, error)
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

// cfg returns the live config if a source is wired (hot-reload), else the
// construction-time Config.
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

// invalidSessionNameChars matches everything outside STS's accepted
// RoleSessionName charset. Package-level so it is compiled once rather than
// on every SessionName call.
var invalidSessionNameChars = regexp.MustCompile(`[^[:word:]+=,.@-]`)

// SessionName cleans name to be valid for STS (64 chars max, [\w+=,.@-]),
// substituting disallowed characters rather than deleting them, since
// deletion can collapse two distinct identities onto one session name.
func (a *AwsConsumer) SessionName(name string) string {
	original := name
	name = invalidSessionNameChars.ReplaceAllLiteralString(name, "-")

	if len(name) > 64 {
		// Keep the tail: two names sharing a 64-char suffix still collide, so warn.
		slog.Warn("session name exceeds STS's 64-character limit and was truncated; "+
			"CloudTrail will show the truncated name",
			slog.String("original", original),
			slog.Int("originalLength", len(original)))
		return name[len(name)-64:]
	}
	return name
}

// spokeCredsFor resolves credentials for operating in the given account,
// returning (nil, nil) when cross-account transport is disabled or the
// account is the hub's own (callers then use the default hub clients).
// Otherwise it assumes the convention-named spoke role and caches the result
// until shortly before expiry.
func (a *AwsConsumer) spokeCredsFor(account string) (aws.CredentialsProvider, error) {
	cfg := a.cfg()
	if cfg == nil || cfg.CrossAccount == nil || !cfg.CrossAccount.Enabled {
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
		return nil, fmt.Errorf("target account %s is not in cross_account.allowed_accounts", account)
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	if c, ok := a.spokeCache[account]; ok && a.now().Before(c.expires) {
		return c.provider, nil
	}

	ca := cfg.CrossAccount
	spokeArn := fmt.Sprintf("arn:aws:iam::%s:role/%s", account, ca.SpokeRoleName)
	sessionName := "aow-broker"
	dur := int32(ca.SpokeSessionDuration.Seconds())
	if dur < 900 {
		dur = 900
	}
	// Role chaining caps chained sessions at 1h and STS fails rather than
	// clamps, so cap unconditionally (spoke sessions are short-lived anyway).
	if dur > 3600 {
		slog.Warn("spoke_session_duration exceeds the 1h role-chaining cap; clamping",
			"requestedSeconds", dur)
		dur = 3600
	}
	input := &sts.AssumeRoleInput{
		RoleArn:         &spokeArn,
		RoleSessionName: &sessionName,
		DurationSeconds: &dur,
	}
	if ca.ExternalID != "" {
		input.ExternalId = &ca.ExternalID
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

	// Only audit signal for a hub->spoke assumption (cached ~1h, no request
	// context to correlate); logs identifiers only, never credential material.
	slog.Info("Assumed spoke role for cross-account operation",
		"spokeArn", spokeArn,
		"sessionName", sessionName,
		"expires", expires)

	a.spokeCache[account] = cachedCreds{provider: provider, expires: expires}
	return provider, nil
}

// AssumeRole assumes the specified AWS IAM role and returns temporary credentials.
// sessionTags is the issuer's configured session_tags spec (STS tag key -> raw
// claim name, see config.Config.IssuerSessionTags); it drives which of the
// verified token's raw claims get attached as STS session tags.
func (a *AwsConsumer) AssumeRole(roleArn, sessionName string, sessionPolicy *string, duration *int32, claims *gtypes.Claims, sessionTags map[string]string) (*types.Credentials, error) {
	if roleArn == "" {
		return nil, errors.New("roleArn cannot be empty")
	}

	if sessionName == "" {
		return nil, errors.New("sessionName cannot be empty")
	}

	cleanSessionName := a.SessionName(sessionName)

	var durationSeconds int32 = 3600
	if duration != nil && *duration > 0 {
		// STS bounds: 900s (15min) minimum, 43200s (12h) maximum.
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

	if sessionPolicy != nil && *sessionPolicy != "" {
		assumeRoleInput.Policy = sessionPolicy
		slog.Debug("Using provided session policy for role assumption",
			"roleArn", roleArn,
			"sessionName", cleanSessionName)
	}

	if claims != nil && claims.Raw != nil {
		tags := BuildSessionTags(claims.Raw, sessionTags)
		if len(tags) > 0 {
			assumeRoleInput.Tags = tags
			slog.Debug("Added session tags from verified claims",
				"roleArn", roleArn,
				"sessionName", cleanSessionName,
				"tagCount", len(tags))
		}
	}

	// Mark identity-bearing session tags transitive so ABAC survives any further
	// role chaining by the target role (immutable downstream).
	if cfg := a.cfg(); cfg != nil && cfg.TransitiveSessionTags() {
		if keys := selectTransitiveKeys(assumeRoleInput.Tags); len(keys) > 0 {
			assumeRoleInput.TransitiveTagKeys = keys
		}
	}

	// Always goes direct hub -> target (1 hop); the spoke role is only used
	// for cross-account GetRoleTags reads.
	account, _, err := ParseRoleARN(roleArn)
	if err != nil {
		return nil, err
	}

	hub, isRoleSession, err := a.AWS.GetCallerIdentityInfo()
	if err != nil {
		return nil, fmt.Errorf("resolve caller identity: %w", err)
	}

	if account != hub {
		cfg := a.cfg()
		if cfg == nil || cfg.CrossAccount == nil || !cfg.CrossAccount.Enabled {
			return nil, fmt.Errorf("cross-account is disabled (cross_account.enabled=false); refusing to assume role in account %s", account)
		}
		if !a.accountAllowed(account, hub) {
			return nil, fmt.Errorf("target account %s is not in cross_account.allowed_accounts", account)
		}
	}

	// Role chaining caps sessions at 1h regardless of account == hub: it's a
	// property of the source creds, and STS fails rather than clamps.
	if isRoleSession && durationSeconds > 3600 {
		slog.Warn("source credentials are a role session; role chaining caps sessions at 1h; clamping duration",
			"requestedDuration", durationSeconds)
		durationSeconds = 3600
		assumeRoleInput.DurationSeconds = &durationSeconds
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

// selectTransitiveKeys returns the keys of every attached session tag, since
// tag names are operator-configured per issuer and a hardcoded list would
// silently drop custom-named identity tags.
func selectTransitiveKeys(tags []types.Tag) []string {
	keys := make([]string, 0, len(tags))
	for _, t := range tags {
		if t.Key != nil {
			keys = append(keys, *t.Key)
		}
	}
	return keys
}

// Session-tag limits enforced by AWS STS, plus the shared key/value charset
// (alphanumeric plus space and _.:/=+@-).
const (
	maxSessionTags      = 50
	maxSessionTagKeyLen = 128
	maxSessionTagValLen = 256
)

var sessionTagCharsetPattern = regexp.MustCompile(`^[A-Za-z0-9 _.:/=+@-]*$`)

// BuildSessionTags builds STS session tags from tagSpec (STS tag key -> raw
// claim name) using rawClaims, the token's verified claims. An invalid key or
// value (wrong charset, over the STS length limit) is skipped and logged,
// never sanitized or truncated. Keys are processed in sorted order so
// truncation at the 50-tag STS cap is deterministic.
func BuildSessionTags(rawClaims map[string]any, tagSpec map[string]string) []types.Tag {
	if len(rawClaims) == 0 || len(tagSpec) == 0 {
		return nil
	}

	keys := make([]string, 0, len(tagSpec))
	for k := range tagSpec {
		keys = append(keys, k)
	}
	slices.Sort(keys)

	var tags []types.Tag
	for _, tagKey := range keys {
		claimName := tagSpec[tagKey]
		raw, ok := rawClaims[claimName]
		if !ok || raw == nil {
			continue
		}
		value := utils.FormatClaimValue(raw)
		if value == "" {
			continue
		}

		if len(tagKey) > maxSessionTagKeyLen || !sessionTagCharsetPattern.MatchString(tagKey) {
			slog.Warn("skipping session tag: key fails STS charset/length limits",
				"tagKey", tagKey, "claim", claimName)
			continue
		}
		if len(value) > maxSessionTagValLen || !sessionTagCharsetPattern.MatchString(value) {
			slog.Warn("skipping session tag: value fails STS charset/length limits",
				"tagKey", tagKey, "claim", claimName)
			continue
		}

		if len(tags) >= maxSessionTags {
			slog.Warn("session tag limit reached; dropping remaining tags",
				"limit", maxSessionTags, "tagKey", tagKey)
			break
		}
		tags = append(tags, types.Tag{
			Key:   aws.String(tagKey),
			Value: aws.String(value),
		})
	}

	return tags
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
	ca := cfg.CrossAccount
	if ca == nil || len(ca.AllowedAccounts) == 0 {
		return true
	}
	return slices.Contains(ca.AllowedAccounts, account)
}

// IsTargetAccountAllowed checks the requested role ARN's account against the
// cross_account.allowed_accounts list. When cross-account transport is
// disabled, only the hub account is allowed (there is no spoke path to reach
// any other account); otherwise the account must be the hub or in the
// allow-list (empty allow-list permits any account).
func (a *AwsConsumer) IsTargetAccountAllowed(roleArn string) (bool, error) {
	account, _, err := ParseRoleARN(roleArn)
	if err != nil {
		return false, err
	}
	hub, err := a.AWS.GetCallerAccount()
	if err != nil {
		return false, fmt.Errorf("resolve hub account: %w", err)
	}
	if cfg := a.cfg(); cfg == nil || cfg.CrossAccount == nil || !cfg.CrossAccount.Enabled {
		return account == hub, nil
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
	// and re-validate so role_mappings regex patterns get compiled.
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
	// Deliberately checked against the LIVE config BEFORE the cache: a cached
	// entry must never outlive a revoked account's authorization.
	allowed, err := a.IsTargetAccountAllowed(roleARN)
	if err != nil {
		return nil, err
	}
	if !allowed {
		return nil, fmt.Errorf("refusing to read tags for role %s: target account is not allowed", roleARN)
	}

	a.mu.Lock()
	if c, ok := a.roleTagCache[roleARN]; ok && a.now().Before(c.expires) {
		// Copy before releasing the lock: handing out the cached map itself
		// would let a mutating caller poison every later authorization decision.
		tags := maps.Clone(c.tags)
		a.mu.Unlock()
		return tags, nil
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
	if creds == nil {
		hub, herr := a.AWS.GetCallerAccount()
		if herr != nil {
			return nil, herr
		}
		if account != hub {
			return nil, fmt.Errorf("cross-account is disabled; refusing to read role tags in account %s (would read a same-named hub role)", account)
		}
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

	// Copy here too: `tags` now lives in the cache, so the caller must not
	// get a mutable alias to it.
	return maps.Clone(tags), nil
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
