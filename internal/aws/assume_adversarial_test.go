package aws

// Adversarial verification of role assumption: cross-account fail-closed
// paths, ARN guard bypass attempts, session policy/tag handling, and duration
// clamping. Asserts on exactly what would have been sent to STS.

import (
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
	gtvcfg "github.com/boogy/aws-oidc-warden/internal/config"
	gtypes "github.com/boogy/aws-oidc-warden/internal/types"
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
	// Hub account still works.
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

// TestMalformedARNFailsClosed proves the account guard cannot be
// bypassed with an ARN that does not parse as an IAM role.
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

// TestGetRoleTagsCrossAccountFailsClosed proves tag-auth cannot be
// tricked into reading a SAME-NAMED HUB role's tags when the requested role
// lives in another account and cross-account is off.
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

	// A nil policy must NOT become an empty-string policy (STS would reject)
	// and must leave the field unset.
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
	spec := map[string]string{"repo": "repository"} // only one tag configured

	if _, err := c.AssumeRole("arn:aws:iam::"+hubAcct+":role/T", "aow", nil, nil, claims, spec); err != nil {
		t.Fatal(err)
	}
	if len(f.lastAssume.Tags) != 1 {
		t.Fatalf("expected exactly 1 session tag, got %d: %v", len(f.lastAssume.Tags), f.lastAssume.Tags)
	}
	if *f.lastAssume.Tags[0].Key != "repo" || *f.lastAssume.Tags[0].Value != "myorg/repo" {
		t.Fatalf("wrong tag: %s=%s", *f.lastAssume.Tags[0].Key, *f.lastAssume.Tags[0].Value)
	}
	// No spec -> no tags at all.
	if _, err := c.AssumeRole("arn:aws:iam::"+hubAcct+":role/T", "aow", nil, nil, claims, nil); err != nil {
		t.Fatal(err)
	}
	if len(f.lastAssume.Tags) != 0 {
		t.Errorf("TAG INJECTION: tags attached with no issuer spec: %v", f.lastAssume.Tags)
	}
}

// TestBadSessionTagValuesSkippedNotSanitized is the key ABAC property:
// a value that violates the STS charset/length must be DROPPED, never
// truncated or rewritten into a different value an ABAC policy might trust.
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
	// Invalid tag KEY is skipped too.
	if tt := BuildSessionTags(map[string]any{"c": "v"}, map[string]string{"bad\nkey": "c"}); len(tt) != 0 {
		t.Errorf("invalid tag key not skipped: %v", tt)
	}
	// 50-tag cap.
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
	cfg.TagAuth = &gtvcfg.TagAuth{TransitiveSessionTags: true}
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

// TestSessionNameSanitized proves the session name cannot carry
// characters STS rejects, and is length-bounded.
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
