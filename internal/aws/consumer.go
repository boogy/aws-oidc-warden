package aws

import (
	"context"
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
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/aws-sdk-go-v2/service/sts/types"
	gtvcfg "github.com/boogy/aws-oidc-warden/internal/config"
	"github.com/boogy/aws-oidc-warden/internal/logevent"
	"github.com/boogy/aws-oidc-warden/internal/utils"
	"golang.org/x/sync/singleflight"
)

// AwsConsumerInterface encapsulates all actions performs with the AWS services
type AwsConsumerInterface interface {
	AssumeRole(ctx context.Context, roleARN, sessionName string, sessionPolicy *string, duration *int32, tags []types.Tag) (*types.Credentials, error)
	AssumeRoleWithWebIdentity(ctx context.Context, roleARN, sessionName, token string, policy *string, duration int32) (*types.Credentials, error)
	GetS3Object(ctx context.Context, bucket, key string) (io.ReadCloser, error)
	GetS3ObjectIfChanged(ctx context.Context, bucket, key, prevETag, expectedOwner string) (data []byte, etag string, err error)
	GetRoleTags(ctx context.Context, roleARN string) (map[string]string, error)
	IsTargetAccountAllowed(ctx context.Context, roleArn string) (bool, error)
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

	configSource  func() *gtvcfg.Config // live-config getter; nil falls back to Config
	now           func() time.Time
	mu            sync.Mutex
	spokeCache    map[string]cachedCreds // keyed by account ID
	spokeFlight   singleflight.Group     // keyed by account ID
	roleTagCache  map[string]cachedTags  // keyed by role ARN
	roleMissCache map[string]cachedMiss  // keyed by role ARN
}

// cfg returns the live config if a source is wired, else the construction-time Config.
func (a *AwsConsumer) cfg() *gtvcfg.Config {
	if a.configSource != nil {
		if c := a.configSource(); c != nil {
			return c
		}
	}
	return a.Config
}

// SetConfigSource wires a live-config getter so the consumer enforces the active config after hot-reload.
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

// invalidSessionNameChars matches everything outside the STS RoleSessionName charset.
var invalidSessionNameChars = regexp.MustCompile(`[^[:word:]+=,.@-]`)

// validSessionName reports whether s is entirely [\w+=,.@-] (ASCII; any UTF-8 byte is invalid).
func validSessionName(s string) bool {
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z', '0' <= c && c <= '9':
		case c == '_', c == '+', c == '=', c == ',', c == '.', c == '@', c == '-':
		default:
			return false
		}
	}
	return true
}

// SessionName substitutes (never deletes) disallowed chars so distinct identities cannot collide.
func (a *AwsConsumer) SessionName(ctx context.Context, name string) string {
	if len(name) <= utils.MaxSTSNameLen && validSessionName(name) {
		return name
	}
	original := name
	name = invalidSessionNameChars.ReplaceAllLiteralString(name, "-")

	if len(name) > utils.MaxSTSNameLen {
		// Keep the tail: two names sharing a 64-char suffix still collide, so warn.
		logevent.Warn(ctx, nil, logevent.STSSessionNameTruncated,
			"session name exceeds STS's 64-character limit and was truncated; CloudTrail will show the truncated name",
			slog.String("original", original),
			slog.Int("originalLength", len(original)))
		return name[len(name)-utils.MaxSTSNameLen:]
	}
	return name
}

// spokeCredsFor returns cached spoke-role credentials for account; (nil, nil) for the hub or with cross-account off.
func (a *AwsConsumer) spokeCredsFor(ctx context.Context, account string) (aws.CredentialsProvider, error) {
	cfg := a.cfg()
	if cfg == nil || cfg.CrossAccount == nil || !cfg.CrossAccount.Enabled {
		return nil, nil
	}
	hub, err := a.AWS.GetCallerAccount(ctx)
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
	c, ok := a.spokeCache[account]
	a.mu.Unlock()
	if ok && a.now().Before(c.expires) {
		return c.provider, nil
	}

	// Detached so one caller's cancellation can't fail the others sharing the flight.
	flightCtx := context.WithoutCancel(ctx)
	ch := a.spokeFlight.DoChan(account, func() (any, error) {
		a.mu.Lock()
		c, ok := a.spokeCache[account]
		a.mu.Unlock()
		if ok && a.now().Before(c.expires) {
			return c.provider, nil
		}
		return a.assumeSpoke(flightCtx, cfg, account)
	})
	select {
	case res := <-ch:
		if res.Err != nil {
			return nil, res.Err
		}
		return res.Val.(aws.CredentialsProvider), nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// assumeSpoke assumes the convention-named spoke role in account and caches the result.
func (a *AwsConsumer) assumeSpoke(ctx context.Context, cfg *gtvcfg.Config, account string) (aws.CredentialsProvider, error) {
	ca := cfg.CrossAccount
	spokeArn := fmt.Sprintf("arn:aws:iam::%s:role/%s", account, ca.SpokeRoleName)
	sessionName := "aow-broker"
	dur := int32(ca.SpokeSessionDuration.Seconds())
	if dur < utils.MinSTSSessionSecs {
		dur = utils.MinSTSSessionSecs
	}
	// STS fails rather than clamps a chained session over 1h.
	if dur > utils.RoleChainingMaxSecs {
		logevent.Warn(ctx, nil, logevent.STSDurationClamped, "spoke_session_duration exceeds the 1h role-chaining cap; clamping",
			slog.Int64("requestedSeconds", int64(dur)),
			slog.String("clampReason", "role_chaining_cap"))
		dur = utils.RoleChainingMaxSecs
	}
	input := &sts.AssumeRoleInput{
		RoleArn:         &spokeArn,
		RoleSessionName: &sessionName,
		DurationSeconds: &dur,
	}
	if ca.ExternalID != "" {
		input.ExternalId = &ca.ExternalID
	}
	out, err := a.AWS.AssumeRole(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("assume spoke role %s: %w", spokeArn, err)
	}
	if out.Credentials == nil {
		return nil, fmt.Errorf("spoke role %s returned no credentials", spokeArn)
	}
	cr := out.Credentials
	static := credentials.NewStaticCredentialsProvider(*cr.AccessKeyId, *cr.SecretAccessKey, *cr.SessionToken)
	provider := &static // pointer identity keys the wrapper's IAM client cache
	expires := a.now().Add(time.Hour)
	if cr.Expiration != nil {
		expires = cr.Expiration.Add(-5 * time.Minute) // refresh margin
	}

	// Identifiers only, never credential material.
	logevent.Info(ctx, nil, logevent.STSSpokeAssumed, "assumed spoke role for cross-account operation",
		slog.String("roleArn", spokeArn),
		slog.String("sessionName", sessionName),
		slog.Time("expires", expires))

	a.mu.Lock()
	a.spokeCache[account] = cachedCreds{provider: provider, expires: expires}
	a.mu.Unlock()
	return provider, nil
}

// AssumeRoleWithWebIdentity exchanges an OIDC token for credentials without SigV4 signing.
func (a *AwsConsumer) AssumeRoleWithWebIdentity(ctx context.Context, roleARN, sessionName, token string, policy *string, duration int32) (*types.Credentials, error) {
	if roleARN == "" {
		return nil, errors.New("roleARN cannot be empty")
	}
	if sessionName == "" {
		return nil, errors.New("sessionName cannot be empty")
	}
	if token == "" {
		return nil, errors.New("token cannot be empty")
	}
	// Unsigned call: the warden's IAM permissions don't bound the target account.
	allowed, err := a.IsTargetAccountAllowed(ctx, roleARN)
	if err != nil {
		return nil, err
	}
	if !allowed {
		return nil, fmt.Errorf("%w: %s", ErrAccountNotAllowed, roleARN)
	}

	in := &sts.AssumeRoleWithWebIdentityInput{
		RoleArn:          aws.String(roleARN),
		RoleSessionName:  aws.String(sessionName),
		WebIdentityToken: aws.String(token),
		DurationSeconds:  aws.Int32(duration),
	}
	if policy != nil && *policy != "" {
		in.Policy = policy
	}

	out, err := a.AWS.AssumeRoleWithWebIdentity(ctx, in)
	if err != nil {
		return nil, classifyWebIdentityError(err)
	}
	if out.Credentials == nil {
		return nil, errors.New("sts.AssumeRoleWithWebIdentity returned no credentials")
	}
	return out.Credentials, nil
}

// AssumeRole assumes roleArn with the caller-built session tags attached as given.
func (a *AwsConsumer) AssumeRole(ctx context.Context, roleArn, sessionName string, sessionPolicy *string, duration *int32, tags []types.Tag) (*types.Credentials, error) {
	if roleArn == "" {
		return nil, errors.New("roleArn cannot be empty")
	}

	if sessionName == "" {
		return nil, errors.New("sessionName cannot be empty")
	}

	cleanSessionName := a.SessionName(ctx, sessionName)

	var durationSeconds int32 = utils.DefaultSTSSessionSecs
	if duration != nil && *duration > 0 {
		if *duration < utils.MinSTSSessionSecs {
			logevent.Warn(ctx, nil, logevent.STSDurationClamped, "duration is below the STS minimum; using the minimum",
				slog.Int64("requestedSeconds", int64(*duration)),
				slog.String("clampReason", "below_minimum"))
			durationSeconds = utils.MinSTSSessionSecs
		} else if *duration > utils.MaxSTSSessionSecs {
			logevent.Warn(ctx, nil, logevent.STSDurationClamped, "duration exceeds the STS maximum; using the maximum",
				slog.Int64("requestedSeconds", int64(*duration)),
				slog.String("clampReason", "above_maximum"))
			durationSeconds = utils.MaxSTSSessionSecs
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
	}

	if len(tags) > 0 {
		assumeRoleInput.Tags = tags
	}

	// Transitive so ABAC survives further role chaining by the target role.
	if cfg := a.cfg(); cfg != nil && cfg.TransitiveSessionTags() {
		if keys := selectTransitiveKeys(assumeRoleInput.Tags); len(keys) > 0 {
			assumeRoleInput.TransitiveTagKeys = keys
		}
	}

	// Always hub -> target in one hop; the spoke role is only for GetRoleTags.
	account, _, err := utils.ParseRoleARN(roleArn)
	if err != nil {
		return nil, err
	}

	hub, isRoleSession, err := a.AWS.GetCallerIdentityInfo(ctx)
	if err != nil {
		return nil, fmt.Errorf("resolve caller identity: %w", err)
	}

	if !a.targetAllowed(account, hub) {
		return nil, fmt.Errorf("%w: %s", ErrAccountNotAllowed, roleArn)
	}

	// Role chaining caps at 1h even when account == hub; STS fails rather than clamps.
	if isRoleSession && durationSeconds > utils.RoleChainingMaxSecs {
		logevent.Warn(ctx, nil, logevent.STSDurationClamped, "source credentials are a role session; role chaining caps sessions at 1h; clamping duration",
			slog.Int64("requestedSeconds", int64(durationSeconds)),
			slog.String("clampReason", "role_chaining_cap"))
		durationSeconds = utils.RoleChainingMaxSecs
		assumeRoleInput.DurationSeconds = &durationSeconds
	}

	result, err := a.AWS.AssumeRole(ctx, &assumeRoleInput)
	if err != nil {
		return nil, fmt.Errorf("unable to perform sts.AssumeRole: %w", classifyAssumeRoleError(err))
	}

	if result.Credentials == nil {
		return nil, errors.New("no credentials returned from assumed role")
	}

	return result.Credentials, nil
}

// selectTransitiveKeys returns every attached tag key; tag names are operator-configured.
func selectTransitiveKeys(tags []types.Tag) []string {
	keys := make([]string, 0, len(tags))
	for _, t := range tags {
		if t.Key != nil {
			keys = append(keys, *t.Key)
		}
	}
	return keys
}

// Session-tag limits enforced by AWS STS, plus the shared key/value charset.
const (
	maxSessionTags      = 50
	maxSessionTagKeyLen = 128
	maxSessionTagValLen = 256
)

// validSessionTagString reports whether s is entirely [A-Za-z0-9 _.:/=+@-] (ASCII; any UTF-8 byte is invalid).
func validSessionTagString(s string) bool {
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z', '0' <= c && c <= '9':
		case c == ' ', c == '_', c == '.', c == ':', c == '/', c == '=', c == '+', c == '@', c == '-':
		default:
			return false
		}
	}
	return true
}

// BuildSessionTags maps tagSpec (STS key -> claim name) over rawClaims; invalid entries are skipped and logged, never altered.
func BuildSessionTags(ctx context.Context, rawClaims map[string]any, tagSpec map[string]string) []types.Tag {
	if len(rawClaims) == 0 || len(tagSpec) == 0 {
		return nil
	}

	tags := make([]types.Tag, 0, min(len(tagSpec), maxSessionTags))
	for _, tagKey := range utils.SortedKeys(tagSpec) {
		claimName := tagSpec[tagKey]
		raw, ok := rawClaims[claimName]
		if !ok || raw == nil {
			continue
		}
		value := utils.FormatClaimValue(raw)
		if value == "" {
			continue
		}

		if len(tagKey) > maxSessionTagKeyLen || !validSessionTagString(tagKey) {
			logevent.Warn(ctx, nil, logevent.STSSessionTagDropped, "skipping session tag: key fails STS charset/length limits",
				slog.String("tagKey", tagKey), slog.String("claim", claimName),
				slog.String("dropReason", "invalid_key"))
			continue
		}
		if len(value) > maxSessionTagValLen || !validSessionTagString(value) {
			logevent.Warn(ctx, nil, logevent.STSSessionTagDropped, "skipping session tag: value fails STS charset/length limits",
				slog.String("tagKey", tagKey), slog.String("claim", claimName),
				slog.String("dropReason", "invalid_value"))
			continue
		}

		if len(tags) >= maxSessionTags {
			logevent.Warn(ctx, nil, logevent.STSSessionTagDropped, "session tag limit reached; dropping remaining tags",
				slog.Int("limit", maxSessionTags), slog.String("tagKey", tagKey),
				slog.String("dropReason", "limit_reached"))
			break
		}
		tags = append(tags, types.Tag{
			Key:   aws.String(tagKey),
			Value: aws.String(value),
		})
	}

	if len(tags) == 0 {
		return nil
	}
	return tags
}

// accountAllowed reports whether account is the hub or allow-listed; an empty list permits any.
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

// IsTargetAccountAllowed reports whether roleArn's account passes the cross_account rule.
func (a *AwsConsumer) IsTargetAccountAllowed(ctx context.Context, roleArn string) (bool, error) {
	account, _, err := utils.ParseRoleARN(roleArn)
	if err != nil {
		return false, err
	}
	hub, err := a.AWS.GetCallerAccount(ctx)
	if err != nil {
		return false, fmt.Errorf("resolve hub account: %w", err)
	}
	return a.targetAllowed(account, hub), nil
}

// targetAllowed is the cross_account rule: disabled means hub-only.
func (a *AwsConsumer) targetAllowed(account, hub string) bool {
	if cfg := a.cfg(); cfg == nil || cfg.CrossAccount == nil || !cfg.CrossAccount.Enabled {
		return account == hub
	}
	return a.accountAllowed(account, hub)
}

// roleTagCacheTTL bounds how long role tags are cached.
const roleTagCacheTTL = 60 * time.Second

const (
	// roleMissTTL bounds how long a definitive NoSuchEntity is remembered.
	roleMissTTL = 30 * time.Second
	// maxRoleMisses caps roleMissCache; it is cleared when full.
	maxRoleMisses = 4096
)

// cachedMiss is a remembered NoSuchEntity result for a role ARN.
type cachedMiss struct {
	err     error
	expires time.Time
}

// GetRoleTags returns roleARN's IAM tags, read with spoke credentials when cross-account.
func (a *AwsConsumer) GetRoleTags(ctx context.Context, roleARN string) (map[string]string, error) {
	// Checked against the live config before the cache so a revoked account is refused immediately.
	allowed, err := a.IsTargetAccountAllowed(ctx, roleARN)
	if err != nil {
		return nil, err
	}
	if !allowed {
		return nil, fmt.Errorf("refusing to read tags for role %s: target account is not allowed", roleARN)
	}

	a.mu.Lock()
	if c, ok := a.roleTagCache[roleARN]; ok && a.now().Before(c.expires) {
		// Clone so a mutating caller cannot poison the cache.
		tags := maps.Clone(c.tags)
		a.mu.Unlock()
		return tags, nil
	}
	if m, ok := a.roleMissCache[roleARN]; ok {
		if a.now().Before(m.expires) {
			a.mu.Unlock()
			return nil, m.err
		}
		delete(a.roleMissCache, roleARN)
	}
	a.mu.Unlock()

	account, roleName, err := utils.ParseRoleARN(roleARN)
	if err != nil {
		return nil, err
	}
	creds, err := a.spokeCredsFor(ctx, account)
	if err != nil {
		return nil, err
	}
	if creds == nil {
		hub, herr := a.AWS.GetCallerAccount(ctx)
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
		out, err = a.AWS.GetRole(ctx, input)
	} else {
		out, err = a.AWS.GetRoleAs(ctx, input, creds)
	}
	if err != nil {
		err = fmt.Errorf("get role %s: %w", roleName, err)
		// Only a definitive NoSuchEntity is cached; throttling, network and AccessDenied are not.
		var nse *iamtypes.NoSuchEntityException
		if errors.As(err, &nse) {
			a.mu.Lock()
			if a.roleMissCache == nil || len(a.roleMissCache) >= maxRoleMisses {
				a.roleMissCache = make(map[string]cachedMiss)
			}
			a.roleMissCache[roleARN] = cachedMiss{err: err, expires: a.now().Add(roleMissTTL)}
			a.mu.Unlock()
		}
		return nil, err
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

	// Clone: tags now lives in the cache.
	return maps.Clone(tags), nil
}

// GetS3Object retrieves an object from S3
func (a *AwsConsumer) GetS3Object(ctx context.Context, bucket, key string) (io.ReadCloser, error) {
	if bucket == "" {
		return nil, errors.New("bucket name cannot be empty")
	}

	if key == "" {
		return nil, errors.New("object key cannot be empty")
	}

	return a.AWS.GetS3Object(ctx, bucket, key)
}

// GetS3ObjectIfChanged reads a config object pinned to expectedOwner.
func (a *AwsConsumer) GetS3ObjectIfChanged(ctx context.Context, bucket, key, prevETag, expectedOwner string) ([]byte, string, error) {
	if bucket == "" {
		return nil, "", errors.New("bucket name cannot be empty")
	}
	if key == "" {
		return nil, "", errors.New("object key cannot be empty")
	}
	if expectedOwner == "" {
		return nil, "", errors.New("expected bucket owner cannot be empty")
	}
	return a.AWS.GetS3ObjectIfChanged(ctx, bucket, key, prevETag, expectedOwner)
}
