package aws

// AssumeRole: adversarial verification of session tags, role-name length, and confused-deputy protections.
import (
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
	gtvcfg "github.com/boogy/aws-oidc-warden/internal/config"
	gtypes "github.com/boogy/aws-oidc-warden/internal/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

const hubAcct = "111111111111"
const memberAcct = "222222222222"

// vFake is a hand-rolled AwsServiceWrapperInterface that records what would
// have been sent to STS/IAM.
type vFake struct {
	lastAssume    *sts.AssumeRoleInput
	assumeCalls   int
	isRoleSession bool
	roleTags      []iamtypes.Tag
	getRoleAsUsed bool
}

func (f *vFake) GetS3Object(string, string) (io.ReadCloser, error) { return nil, errors.New("nope") }
func (f *vFake) AssumeRole(in *sts.AssumeRoleInput) (*sts.AssumeRoleOutput, error) {
	f.lastAssume = in
	f.assumeCalls++
	return &sts.AssumeRoleOutput{Credentials: &ststypes.Credentials{
		AccessKeyId:     aws.String("AKIA"),
		SecretAccessKey: aws.String("secret"),
		SessionToken:    aws.String("token"),
	}}, nil
}
func (f *vFake) GetRole(*iam.GetRoleInput) (*iam.GetRoleOutput, error) {
	return &iam.GetRoleOutput{Role: &iamtypes.Role{Tags: f.roleTags}}, nil
}
func (f *vFake) GetRoleAs(*iam.GetRoleInput, aws.CredentialsProvider) (*iam.GetRoleOutput, error) {
	f.getRoleAsUsed = true
	return &iam.GetRoleOutput{Role: &iamtypes.Role{Tags: f.roleTags}}, nil
}
func (f *vFake) GetCallerAccount() (string, error) { return hubAcct, nil }
func (f *vFake) GetCallerIdentityInfo() (string, bool, error) {
	return hubAcct, f.isRoleSession, nil
}
func (f *vFake) RefreshClients() {}

func vconsumer(t *testing.T, cfg *gtvcfg.Config) (*AwsConsumer, *vFake) {
	t.Helper()
	f := &vFake{}
	c := NewAwsConsumer(cfg)
	c.AWS = f
	return c, f
}

func vbaseCfg() *gtvcfg.Config {
	return &gtvcfg.Config{RoleSessionName: "aow"}
}

// ---------- A1: cross-account fail-closed ----------

func TestCrossAccountDisabledFailsClosed(t *testing.T) {
	c, f := vconsumer(t, vbaseCfg()) // CrossAccount nil == disabled
	memberRole := "arn:aws:iam::" + memberAcct + ":role/Target"

	if ok, err := c.IsTargetAccountAllowed(memberRole); err != nil || ok {
		t.Errorf("GUARD BYPASS: member account allowed with cross-account disabled (ok=%v err=%v)", ok, err)
	}
	if _, err := c.AssumeRole(memberRole, "aow", nil, nil, nil, nil); err == nil {
		t.Error("FAIL-OPEN: assumed a member-account role with cross-account disabled")
	}
	if f.assumeCalls != 0 {
		t.Errorf("STS was called %d times despite the guard denying", f.assumeCalls)
	}
	if ok, err := c.IsTargetAccountAllowed("arn:aws:iam::" + hubAcct + ":role/Target"); err != nil || !ok {
		t.Errorf("hub account should be allowed: ok=%v err=%v", ok, err)
	}
}

func TestCrossAccountAllowListEnforced(t *testing.T) {
	cfg := vbaseCfg()
	cfg.CrossAccount = &gtvcfg.CrossAccount{Enabled: true, AllowedAccounts: []string{"333333333333"}}
	c, f := vconsumer(t, cfg)

	notAllowed := "arn:aws:iam::" + memberAcct + ":role/Target"
	if ok, _ := c.IsTargetAccountAllowed(notAllowed); ok {
		t.Error("ALLOW-LIST BYPASS: account outside allowed_accounts permitted")
	}
	if _, err := c.AssumeRole(notAllowed, "aow", nil, nil, nil, nil); err == nil {
		t.Error("FAIL-OPEN: assumed a role outside allowed_accounts")
	}
	if f.assumeCalls != 0 {
		t.Error("STS called despite allow-list denial")
	}
	allowed := "arn:aws:iam::333333333333:role/Target"
	if ok, _ := c.IsTargetAccountAllowed(allowed); !ok {
		t.Error("allow-listed account should be permitted")
	}
	if _, err := c.AssumeRole(allowed, "aow", nil, nil, nil, nil); err != nil {
		t.Errorf("allow-listed assume failed: %v", err)
	}
}

func TestMalformedARNFailsClosed(t *testing.T) {
	c, f := vconsumer(t, vbaseCfg())
	for _, bad := range []string{
		"",
		"not-an-arn",
		"arn:aws:iam::" + memberAcct + ":user/bob",
		"arn:aws:sts::" + memberAcct + ":assumed-role/x/y",
		"arn:aws:iam::" + memberAcct + ":role/",
		"arn:aws:iam:::role/Target", // no account
		"arn:aws:s3:::bucket/key",
	} {
		if ok, err := c.IsTargetAccountAllowed(bad); ok && err == nil {
			t.Errorf("GUARD BYPASS: malformed ARN %q passed the account check", bad)
		}
		if _, err := c.AssumeRole(bad, "aow", nil, nil, nil, nil); err == nil {
			t.Errorf("FAIL-OPEN: assumed malformed ARN %q", bad)
		}
	}
	if f.assumeCalls != 0 {
		t.Error("STS called for a malformed ARN")
	}
}

func TestGetRoleTagsCrossAccountFailsClosed(t *testing.T) {
	c, f := vconsumer(t, vbaseCfg())
	f.roleTags = []iamtypes.Tag{{Key: aws.String("aow/subject"), Value: aws.String("myorg/repo")}}
	if _, err := c.GetRoleTags("arn:aws:iam::" + memberAcct + ":role/Target"); err == nil {
		t.Error("CONFUSED DEPUTY: read tags for a member-account role with cross-account disabled")
	}
	if f.getRoleAsUsed {
		t.Error("spoke path used with cross-account disabled")
	}
}

// ---------- A2: session policy is passed through verbatim ----------

func TestSessionPolicyReachesSTSVerbatim(t *testing.T) {
	c, f := vconsumer(t, vbaseCfg())
	policy := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}`
	role := "arn:aws:iam::" + hubAcct + ":role/Target"

	if _, err := c.AssumeRole(role, "aow", &policy, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	if f.lastAssume.Policy == nil || *f.lastAssume.Policy != policy {
		t.Fatalf("session policy mangled or dropped: %v", f.lastAssume.Policy)
	}

	// A nil policy must not become an empty string (STS would reject empty).
	if _, err := c.AssumeRole(role, "aow", nil, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	if f.lastAssume.Policy != nil {
		t.Errorf("nil policy became %q", *f.lastAssume.Policy)
	}
	empty := ""
	if _, err := c.AssumeRole(role, "aow", &empty, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	if f.lastAssume.Policy != nil {
		t.Error("empty policy string was forwarded to STS")
	}
}

// ---------- A3: session tags ----------

func TestSessionTagsOnlyFromIssuerSpec(t *testing.T) {
	c, f := vconsumer(t, vbaseCfg())
	claims := &gtypes.Claims{Raw: map[string]any{
		"repository": "myorg/repo",
		"actor":      "alice",
		"secret":     "should-never-be-tagged",
		"aow/admin":  "true",
	}}
	spec := map[string]string{"repo": "repository"}

	if _, err := c.AssumeRole("arn:aws:iam::"+hubAcct+":role/T", "aow", nil, nil, claims, spec); err != nil {
		t.Fatal(err)
	}
	if len(f.lastAssume.Tags) != 1 {
		t.Fatalf("expected exactly 1 session tag, got %d: %v", len(f.lastAssume.Tags), f.lastAssume.Tags)
	}
	if *f.lastAssume.Tags[0].Key != "repo" || *f.lastAssume.Tags[0].Value != "myorg/repo" {
		t.Fatalf("wrong tag: %s=%s", *f.lastAssume.Tags[0].Key, *f.lastAssume.Tags[0].Value)
	}
	if _, err := c.AssumeRole("arn:aws:iam::"+hubAcct+":role/T", "aow", nil, nil, claims, nil); err != nil {
		t.Fatal(err)
	}
	if len(f.lastAssume.Tags) != 0 {
		t.Errorf("TAG INJECTION: tags attached with no issuer spec: %v", f.lastAssume.Tags)
	}
}

// Bad tag values must be dropped, never truncated/rewritten, or ABAC could trust a mutated value.
func TestBadSessionTagValuesSkipped(t *testing.T) {
	long := strings.Repeat("a", 257)
	raw := map[string]any{
		"good":     "myorg/repo",
		"badchar":  "value\nwith*bad#chars",
		"toolong":  long,
		"empty":    "",
		"nilclaim": nil,
		"numeric":  42,
	}
	spec := map[string]string{
		"Good": "good", "BadChar": "badchar", "TooLong": "toolong",
		"Empty": "empty", "NilClaim": "nilclaim", "Numeric": "numeric",
	}
	tags := BuildSessionTags(raw, spec)
	got := map[string]string{}
	for _, tg := range tags {
		got[*tg.Key] = *tg.Value
	}
	if got["Good"] != "myorg/repo" {
		t.Errorf("valid tag dropped: %v", got)
	}
	if got["Numeric"] != "42" {
		t.Errorf("numeric claim should stringify: %v", got)
	}
	for _, k := range []string{"BadChar", "TooLong", "Empty", "NilClaim"} {
		if v, ok := got[k]; ok {
			t.Errorf("SANITIZATION BUG: tag %q should have been skipped, got %q (len %d)", k, v, len(v))
		}
	}
	if tt := BuildSessionTags(map[string]any{"c": "v"}, map[string]string{"bad\nkey": "c"}); len(tt) != 0 {
		t.Errorf("invalid tag key not skipped: %v", tt)
	}
	bigRaw := map[string]any{}
	bigSpec := map[string]string{}
	for i := 0; i < 60; i++ {
		k := string(rune('a'+i%26)) + string(rune('a'+i/26))
		bigRaw[k] = "v"
		bigSpec["T"+k] = k
	}
	if n := len(BuildSessionTags(bigRaw, bigSpec)); n > 50 {
		t.Errorf("STS 50-tag cap exceeded: %d", n)
	}
}

func TestTransitiveTagsOptIn(t *testing.T) {
	claims := &gtypes.Claims{Raw: map[string]any{"repository": "myorg/repo"}}
	spec := map[string]string{"repo": "repository"}
	role := "arn:aws:iam::" + hubAcct + ":role/T"

	c, f := vconsumer(t, vbaseCfg())
	if _, err := c.AssumeRole(role, "aow", nil, nil, claims, spec); err != nil {
		t.Fatal(err)
	}
	if len(f.lastAssume.TransitiveTagKeys) != 0 {
		t.Error("transitive tags applied without opt-in")
	}

	cfg := vbaseCfg()
	cfg.SessionTagsTransitive = true
	c2, f2 := vconsumer(t, cfg)
	if _, err := c2.AssumeRole(role, "aow", nil, nil, claims, spec); err != nil {
		t.Fatal(err)
	}
	if len(f2.lastAssume.TransitiveTagKeys) != 1 || f2.lastAssume.TransitiveTagKeys[0] != "repo" {
		t.Errorf("transitive keys wrong: %v", f2.lastAssume.TransitiveTagKeys)
	}
}

// ---------- A4: duration handling ----------

func TestDurationClampedForRoleSession(t *testing.T) {
	c, f := vconsumer(t, vbaseCfg())
	f.isRoleSession = true // always true on Lambda
	role := "arn:aws:iam::" + hubAcct + ":role/T"
	twelveH := int32(43200)
	if _, err := c.AssumeRole(role, "aow", nil, &twelveH, nil, nil); err != nil {
		t.Fatal(err)
	}
	if *f.lastAssume.DurationSeconds != 3600 {
		t.Errorf("chained session not clamped to 1h: %d", *f.lastAssume.DurationSeconds)
	}
	// Below the STS minimum is raised to 900, never sent as-is.
	tiny := int32(60)
	if _, err := c.AssumeRole(role, "aow", nil, &tiny, nil, nil); err != nil {
		t.Fatal(err)
	}
	if *f.lastAssume.DurationSeconds != 900 {
		t.Errorf("sub-minimum duration not raised: %d", *f.lastAssume.DurationSeconds)
	}
}

func TestSessionNameSanitized(t *testing.T) {
	c, f := vconsumer(t, vbaseCfg())
	role := "arn:aws:iam::" + hubAcct + ":role/T"
	if _, err := c.AssumeRole(role, "bad name/with*chars", nil, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	got := *f.lastAssume.RoleSessionName
	if strings.ContainsAny(got, " /*") {
		t.Errorf("session name not sanitized: %q", got)
	}
	if _, err := c.AssumeRole(role, strings.Repeat("x", 200), nil, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	if len(*f.lastAssume.RoleSessionName) > 64 {
		t.Errorf("session name over 64 chars: %d", len(*f.lastAssume.RoleSessionName))
	}
}

// ---------- session tags ----------

func TestGetRoleTags_SameAccount(t *testing.T) {
	m := new(MockAwsServiceWrapper)
	m.On("GetCallerAccount").Return("111111111111", nil)
	m.On("GetRole", mock.MatchedBy(func(in *iam.GetRoleInput) bool {
		return *in.RoleName == "app"
	})).Return(&iam.GetRoleOutput{Role: &iamtypes.Role{
		Tags: []iamtypes.Tag{
			{Key: aws.String("aow/repo"), Value: aws.String("acme/api")},
			{Key: aws.String("Team"), Value: aws.String("platform")},
		},
	}}, nil).Once()

	c := newTagAuthConsumer(m) // helper from consumer_spoke_test.go
	tags, err := c.GetRoleTags("arn:aws:iam::111111111111:role/app")
	require.NoError(t, err)
	assert.Equal(t, "acme/api", tags["aow/repo"])
	assert.Equal(t, "platform", tags["Team"])
	// cached second call → GetRole still Once
	_, err = c.GetRoleTags("arn:aws:iam::111111111111:role/app")
	require.NoError(t, err)
	m.AssertExpectations(t)
}

func TestGetRoleTags_CrossAccount_UsesSpokeCreds(t *testing.T) {
	m := new(MockAwsServiceWrapper)
	m.On("GetCallerAccount").Return("111111111111", nil)
	exp := time.Now().Add(time.Hour)
	m.On("AssumeRole", mock.MatchedBy(func(in *sts.AssumeRoleInput) bool {
		return *in.RoleArn == "arn:aws:iam::222222222222:role/aow-spoke"
	})).Return(&sts.AssumeRoleOutput{Credentials: &ststypes.Credentials{
		AccessKeyId: aws.String("AK"), SecretAccessKey: aws.String("SK"),
		SessionToken: aws.String("ST"), Expiration: &exp,
	}}, nil).Once()
	m.On("GetRoleAs", mock.MatchedBy(func(in *iam.GetRoleInput) bool {
		return *in.RoleName == "app"
	}), mock.Anything).Return(&iam.GetRoleOutput{Role: &iamtypes.Role{
		Tags: []iamtypes.Tag{{Key: aws.String("aow/repo"), Value: aws.String("acme/api")}},
	}}, nil).Once()

	c := newTagAuthConsumer(m)
	tags, err := c.GetRoleTags("arn:aws:iam::222222222222:role/app")
	require.NoError(t, err)
	assert.Equal(t, "acme/api", tags["aow/repo"])
	m.AssertExpectations(t)
}

// ---------- role name length ----------

// IAM's 64-char cap applies to the role NAME (after the last '/'), not the whole path.
func TestValidateRoleNameLength_PathIsNotCountedTowardTheNameCap(t *testing.T) {
	name64 := strings.Repeat("a", 64)
	name65 := strings.Repeat("a", 65)
	deepPath := "/" + strings.Repeat("segment/", 20) // 160 chars of path alone

	cases := []struct {
		desc    string
		input   string
		wantErr bool
	}{
		{"plain name at the cap", name64, false},
		{"plain name one over the cap", name65, true},
		{"short name behind a deep path", deepPath + "Deploy", false},
		{"name at the cap behind a deep path", deepPath + name64, false},
		{"name over the cap behind a deep path", deepPath + name65, true},
		{"single path segment, short name", "team/Deploy", false},
		{"empty (rejected earlier by the caller, not here)", "", false},
		{"trailing slash yields an empty name", "team/", false},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			err := validateRoleNameLength(tc.input)
			if tc.wantErr && err == nil {
				t.Fatalf("expected rejection for %q (len %d)", tc.input, len(tc.input))
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected rejection for %q (len %d): %v", tc.input, len(tc.input), err)
			}
		})
	}
}

func TestValidateRoleNameLength_RejectionNamesTheRole(t *testing.T) {
	over := strings.Repeat("b", 70)
	err := validateRoleNameLength("path/to/" + over)
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), over) {
		t.Fatalf("error should identify the role name, got: %v", err)
	}
	if strings.Contains(err.Error(), "path/to/") {
		t.Fatalf("error should report the NAME, not the full path, got: %v", err)
	}
}

// ---------- confused deputy ----------

// GetRoleAs must refuse nil credentials rather than fall back to hub creds (confused deputy).
func TestGetRoleAs_RejectsNilCredentials(t *testing.T) {
	s := &AwsServiceWrapper{defaultTimeout: time.Second}

	// A nil iamClient would panic if reached, proving the guard returns before any client use.
	out, err := s.GetRoleAs(&iam.GetRoleInput{RoleName: aws.String("deploy")}, nil)

	require.Error(t, err, "nil credentials must be refused")
	assert.Nil(t, out)
	assert.Contains(t, err.Error(), "refusing to fall back to hub credentials")
}

// GetRoleTags must return a COPY; returning the cached map lets a caller's mutation poison later authorization decisions.
func TestGetRoleTags_CachedMapIsNotAliased(t *testing.T) {
	m := new(MockAwsServiceWrapper)
	m.On("GetCallerAccount").Return("111111111111", nil)
	// .Once(): a second IAM read would mean the cache was missed.
	m.On("GetRole", mock.Anything).Return(&iam.GetRoleOutput{Role: &iamtypes.Role{
		Tags: []iamtypes.Tag{{Key: aws.String("aow/subject"), Value: aws.String("acme/app")}},
	}}, nil).Once()

	cfg := &gtvcfg.Config{TagAuth: &gtvcfg.TagAuth{Enabled: true, TagPrefix: "aow/"}}
	c := NewAwsConsumer(cfg)
	c.SetConfigSource(func() *gtvcfg.Config { return cfg })
	c.AWS = m
	c.now = time.Now

	const arn = "arn:aws:iam::111111111111:role/app"

	first, err := c.GetRoleTags(arn)
	require.NoError(t, err)
	require.Equal(t, "acme/app", first["aow/subject"])

	// Poison the returned map as a careless consumer might.
	first["aow/subject"] = "attacker/repo"
	delete(first, "aow/subject")
	first["aow/issuer"] = "https://evil.example"

	// The next read is a cache hit and must be unaffected.
	second, err := c.GetRoleTags(arn)
	require.NoError(t, err)
	assert.Equal(t, "acme/app", second["aow/subject"],
		"mutating a returned map corrupted the cached tags")
	assert.NotContains(t, second, "aow/issuer",
		"a key injected into a returned map leaked into the cache")

	m.AssertExpectations(t)
}
