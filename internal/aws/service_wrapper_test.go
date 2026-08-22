package aws

// The shared SDK clients built once in service_wrapper.go, and the cache
// keying that decides when a client or object may be reused.
import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
	gtvcfg "github.com/boogy/aws-oidc-warden/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// MockAwsServiceWrapper implements AwsServiceWrapperInterface for testing
type MockAwsServiceWrapper struct {
	mock.Mock
}

func (m *MockAwsServiceWrapper) GetS3Object(bucket, key string) (io.ReadCloser, error) {
	args := m.Called(bucket, key)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(io.ReadCloser), args.Error(1)
}

func (m *MockAwsServiceWrapper) AssumeRole(input *sts.AssumeRoleInput) (*sts.AssumeRoleOutput, error) {
	args := m.Called(input)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*sts.AssumeRoleOutput), args.Error(1)
}

func (m *MockAwsServiceWrapper) GetRole(input *iam.GetRoleInput) (*iam.GetRoleOutput, error) {
	args := m.Called(input)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*iam.GetRoleOutput), args.Error(1)
}

func (m *MockAwsServiceWrapper) RefreshClients() {
	m.Called()
}

func (m *MockAwsServiceWrapper) GetCallerAccount() (string, error) {
	args := m.Called()
	return args.String(0), args.Error(1)
}

func (m *MockAwsServiceWrapper) GetCallerIdentityInfo() (string, bool, error) {
	args := m.Called()
	return args.String(0), args.Bool(1), args.Error(2)
}

func (m *MockAwsServiceWrapper) GetRoleAs(input *iam.GetRoleInput, creds aws.CredentialsProvider) (*iam.GetRoleOutput, error) {
	args := m.Called(input, creds)
	if out, ok := args.Get(0).(*iam.GetRoleOutput); ok {
		return out, args.Error(1)
	}
	return nil, args.Error(1)
}

// MockReadCloser is a mock implementation of io.ReadCloser for testing
type MockReadCloser struct {
	*bytes.Reader
	CloseFunc func() error
}

func (m MockReadCloser) Close() error {
	if m.CloseFunc != nil {
		return m.CloseFunc()
	}
	return nil
}

func NewMockReadCloser(content string) MockReadCloser {
	return MockReadCloser{
		Reader: bytes.NewReader([]byte(content)),
	}
}

// TestMockAwsServiceWrapper_GetS3Object tests the GetS3Object method
func TestMockAwsServiceWrapper_GetS3Object(t *testing.T) {
	mockWrapper := new(MockAwsServiceWrapper)
	bucket := "test-bucket"
	key := "test-key"
	content := "test content"

	mockWrapper.On("GetS3Object", bucket, key).Return(
		NewMockReadCloser(content), nil,
	).Once()

	reader, err := mockWrapper.GetS3Object(bucket, key)
	assert.NoError(t, err)
	assert.NotNil(t, reader)

	data, err := io.ReadAll(reader)
	assert.NoError(t, err)
	assert.Equal(t, content, string(data))

	mockWrapper.AssertExpectations(t)
}

// TestMockAwsServiceWrapper_AssumeRole tests the AssumeRole method
func TestMockAwsServiceWrapper_AssumeRole(t *testing.T) {
	mockWrapper := new(MockAwsServiceWrapper)
	roleArn := "arn:aws:iam::123456789012:role/test-role"
	sessionName := "test-session"

	input := &sts.AssumeRoleInput{
		RoleArn:         aws.String(roleArn),
		RoleSessionName: aws.String(sessionName),
	}

	output := &sts.AssumeRoleOutput{
		Credentials: &ststypes.Credentials{
			AccessKeyId:     aws.String("AKIATEST"),
			SecretAccessKey: aws.String("test-secret"),
			SessionToken:    aws.String("test-token"),
		},
	}

	mockWrapper.On("AssumeRole", input).Return(output, nil).Once()

	result, err := mockWrapper.AssumeRole(input)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, "AKIATEST", *result.Credentials.AccessKeyId)
	assert.Equal(t, "test-secret", *result.Credentials.SecretAccessKey)
	assert.Equal(t, "test-token", *result.Credentials.SessionToken)

	mockWrapper.AssertExpectations(t)
}

// TestMockAwsServiceWrapper_GetRole tests the GetRole method
func TestMockAwsServiceWrapper_GetRole(t *testing.T) {
	mockWrapper := new(MockAwsServiceWrapper)
	roleName := "test-role"

	input := &iam.GetRoleInput{
		RoleName: aws.String(roleName),
	}

	output := &iam.GetRoleOutput{
		Role: &iamtypes.Role{
			RoleName: aws.String(roleName),
			Arn:      aws.String("arn:aws:iam::123456789012:role/test-role"),
		},
	}

	mockWrapper.On("GetRole", input).Return(output, nil).Once()

	result, err := mockWrapper.GetRole(input)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, roleName, *result.Role.RoleName)

	mockWrapper.AssertExpectations(t)
}

// TestMockAwsServiceWrapper_RefreshClients tests the RefreshClients method
func TestMockAwsServiceWrapper_RefreshClients(t *testing.T) {
	mockWrapper := new(MockAwsServiceWrapper)
	mockWrapper.On("RefreshClients").Return().Once()
	mockWrapper.RefreshClients()
	mockWrapper.AssertExpectations(t)
}

// TestGetS3ObjectErrorCase tests an error case for GetS3Object
func TestGetS3ObjectErrorCase(t *testing.T) {
	mockWrapper := new(MockAwsServiceWrapper)
	bucket := "test-bucket"
	key := "error-key"
	expectedErr := errors.New("access denied")

	mockWrapper.On("GetS3Object", bucket, key).Return(nil, expectedErr).Once()

	reader, err := mockWrapper.GetS3Object(bucket, key)
	assert.Error(t, err)
	assert.Nil(t, reader)
	assert.Equal(t, expectedErr, err)

	mockWrapper.AssertExpectations(t)
}

// TestGetCallerIdentityInfo_RetryAfterFailure verifies a failed GetCallerIdentity
// call is not cached: the next call retries and, on success, caches the result.
func TestGetCallerIdentityInfo_RetryAfterFailure(t *testing.T) {
	callCount := 0
	expectedErr := errors.New("throttled")

	w := &AwsServiceWrapper{
		defaultTimeout: time.Second,
		getCallerIdentityFn: func(ctx context.Context) (*sts.GetCallerIdentityOutput, error) {
			callCount++
			if callCount == 1 {
				return nil, expectedErr
			}
			return &sts.GetCallerIdentityOutput{
				Account: aws.String("111111111111"),
				Arn:     aws.String("arn:aws:sts::111111111111:assumed-role/aow/lambda"),
			}, nil
		},
	}

	account, isRoleSession, err := w.GetCallerIdentityInfo()
	assert.Error(t, err)
	assert.Equal(t, expectedErr, err)
	assert.Empty(t, account)
	assert.False(t, isRoleSession)

	account, isRoleSession, err = w.GetCallerIdentityInfo()
	assert.NoError(t, err)
	assert.Equal(t, "111111111111", account)
	assert.True(t, isRoleSession)
	assert.Equal(t, 2, callCount)

	// Subsequent calls use the cache, not the injected fetch function.
	account, isRoleSession, err = w.GetCallerIdentityInfo()
	assert.NoError(t, err)
	assert.Equal(t, "111111111111", account)
	assert.True(t, isRoleSession)
	assert.Equal(t, 2, callCount)
}

// TestGetCallerIdentityInfo_ArnDetection verifies role-session vs. IAM-user ARNs.
func TestGetCallerIdentityInfo_ArnDetection(t *testing.T) {
	tests := []struct {
		name            string
		arn             string
		wantRoleSession bool
	}{
		{
			name:            "assumed role session",
			arn:             "arn:aws:sts::111111111111:assumed-role/aow/lambda",
			wantRoleSession: true,
		},
		{
			name:            "iam user",
			arn:             "arn:aws:iam::111111111111:user/bogdan",
			wantRoleSession: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := &AwsServiceWrapper{
				defaultTimeout: time.Second,
				getCallerIdentityFn: func(ctx context.Context) (*sts.GetCallerIdentityOutput, error) {
					return &sts.GetCallerIdentityOutput{
						Account: aws.String("111111111111"),
						Arn:     aws.String(tt.arn),
					}, nil
				},
			}

			account, isRoleSession, err := w.GetCallerIdentityInfo()
			assert.NoError(t, err)
			assert.Equal(t, "111111111111", account)
			assert.Equal(t, tt.wantRoleSession, isRoleSession)
		})
	}
}

// TestServiceWrapperImplementation tests the real implementation of AwsServiceWrapper
// These tests are skipped by default as they would require real AWS credentials
func TestServiceWrapperImplementation(t *testing.T) {
	t.Skip("Skipping tests that require real AWS credentials")

	wrapper := NewAwsServiceWrapper()
	assert.NotNil(t, wrapper)

	// Test RefreshClients
	t.Run("RefreshClients", func(t *testing.T) {
		wrapper.RefreshClients() // Just verify it doesn't panic
	})

	// Test GetS3Object with a non-existent object (should return error)
	t.Run("GetS3Object_NonExistent", func(t *testing.T) {
		bucket := "non-existent-bucket-name-123456789012"
		key := "non-existent-key"

		reader, err := wrapper.GetS3Object(bucket, key)
		assert.Error(t, err)
		assert.Nil(t, reader)
	})

	// Test AssumeRole with a specific role (skipped by default)
	t.Run("AssumeRole_Integration", func(t *testing.T) {
		t.Skip("Skipping AssumeRole test that requires real AWS credentials")

		// This test requires valid AWS credentials and permissions to assume a role
		// Replace these values with actual test role ARN in your account
		roleArn := "arn:aws:iam::123456789012:role/test-role"
		sessionName := "aws-oidc-warden-test"

		input := &sts.AssumeRoleInput{
			RoleArn:         aws.String(roleArn),
			RoleSessionName: aws.String(sessionName),
			DurationSeconds: aws.Int32(900), // 15 minutes
		}

		output, err := wrapper.AssumeRole(input)
		if err != nil {
			t.Logf("AssumeRole error (expected if no permissions): %v", err)
			return
		}

		// Verify the response contains credentials
		assert.NotNil(t, output)
		assert.NotNil(t, output.Credentials)
		assert.NotEmpty(t, *output.Credentials.AccessKeyId)
		assert.NotEmpty(t, *output.Credentials.SecretAccessKey)
		assert.NotEmpty(t, *output.Credentials.SessionToken)
		assert.False(t, output.Credentials.Expiration.IsZero())

		t.Logf("Successfully assumed role with session: %s", sessionName)
	})

	// Test GetRole with a specific role (skipped by default)
	t.Run("GetRole_Integration", func(t *testing.T) {
		t.Skip("Skipping GetRole test that requires real AWS credentials")

		// This test requires valid AWS credentials and permissions to get role info
		// Replace with an actual role name in your account
		roleName := "aws-oidc-warden-test-role"

		input := &iam.GetRoleInput{
			RoleName: aws.String(roleName),
		}

		output, err := wrapper.GetRole(input)
		if err != nil {
			t.Logf("GetRole error (expected if no permissions): %v", err)
			return
		}

		// Verify the response contains role details
		assert.NotNil(t, output)
		assert.NotNil(t, output.Role)
		assert.Equal(t, roleName, *output.Role.RoleName)
		assert.NotEmpty(t, *output.Role.Arn)
		assert.NotEmpty(t, *output.Role.Path)
		assert.False(t, output.Role.CreateDate.IsZero())

		t.Logf("Successfully retrieved role: %s", roleName)
	})
}

// ---------- cache keying ----------

// TestAudit_RoleTagCacheNoCrossAccountCollision is the central claim of this
// audit: role "deploy" in account 111 (hub) and role "deploy" in account 222
// must never share a roleTagCache entry. If the cache were keyed by role NAME,
// the hub role's tags would authorize assumption of the member-account role.
func TestAudit_RoleTagCacheNoCrossAccountCollision(t *testing.T) {
	m := new(MockAwsServiceWrapper)
	m.On("GetCallerAccount").Return("111111111111", nil)

	// Hub read: same-account path -> GetRole with hub clients.
	m.On("GetRole", mock.MatchedBy(func(in *iam.GetRoleInput) bool {
		return *in.RoleName == "deploy"
	})).Return(&iam.GetRoleOutput{Role: &iamtypes.Role{
		Tags: []iamtypes.Tag{{Key: aws.String("aow/repo"), Value: aws.String("acme/hub")}},
	}}, nil).Once()

	// Spoke assume for 222 + cross-account read.
	exp := time.Now().Add(time.Hour)
	m.On("AssumeRole", mock.MatchedBy(func(in *sts.AssumeRoleInput) bool {
		return *in.RoleArn == "arn:aws:iam::222222222222:role/aow-spoke"
	})).Return(&sts.AssumeRoleOutput{Credentials: &ststypes.Credentials{
		AccessKeyId: aws.String("AK"), SecretAccessKey: aws.String("SK"),
		SessionToken: aws.String("ST"), Expiration: &exp,
	}}, nil).Once()
	m.On("GetRoleAs", mock.MatchedBy(func(in *iam.GetRoleInput) bool {
		return *in.RoleName == "deploy"
	}), mock.Anything).Return(&iam.GetRoleOutput{Role: &iamtypes.Role{
		Tags: []iamtypes.Tag{{Key: aws.String("aow/repo"), Value: aws.String("acme/member")}},
	}}, nil).Once()

	c := newTagAuthConsumer(m)

	hubTags, err := c.GetRoleTags("arn:aws:iam::111111111111:role/deploy")
	require.NoError(t, err)
	assert.Equal(t, "acme/hub", hubTags["aow/repo"])

	memberTags, err := c.GetRoleTags("arn:aws:iam::222222222222:role/deploy")
	require.NoError(t, err)
	assert.Equal(t, "acme/member", memberTags["aow/repo"],
		"member-account role must NOT be served the hub role's cached tags")

	// Both entries coexist, keyed by full ARN.
	assert.Len(t, c.roleTagCache, 2)
	_, okHub := c.roleTagCache["arn:aws:iam::111111111111:role/deploy"]
	_, okMember := c.roleTagCache["arn:aws:iam::222222222222:role/deploy"]
	assert.True(t, okHub && okMember, "cache keys must be full ARNs, not role names")
	_, okName := c.roleTagCache["deploy"]
	assert.False(t, okName, "no bare role-name key may exist")

	m.AssertExpectations(t)
}

// TestAudit_RoleTagCacheExpiryEnforcedOnRead proves stale tags cannot outlive
// roleTagCacheTTL: after the clock advances past the TTL the role is re-read
// and the new (revoked) tag set is what the caller sees.
func TestAudit_RoleTagCacheExpiryEnforcedOnRead(t *testing.T) {
	m := new(MockAwsServiceWrapper)
	m.On("GetCallerAccount").Return("111111111111", nil)

	call := 0
	m.On("GetRole", mock.Anything).Return(&iam.GetRoleOutput{Role: &iamtypes.Role{
		Tags: []iamtypes.Tag{{Key: aws.String("aow/repo"), Value: aws.String("acme/api")}},
	}}, nil).Run(func(mock.Arguments) { call++ }).Once()
	m.On("GetRole", mock.Anything).Return(&iam.GetRoleOutput{Role: &iamtypes.Role{
		Tags: nil, // tags revoked
	}}, nil).Run(func(mock.Arguments) { call++ }).Once()

	c := newTagAuthConsumer(m)
	base := time.Now()
	clock := base
	c.now = func() time.Time { return clock }

	tags, err := c.GetRoleTags("arn:aws:iam::111111111111:role/app")
	require.NoError(t, err)
	require.Equal(t, "acme/api", tags["aow/repo"])

	// Still inside the TTL -> cached.
	clock = base.Add(roleTagCacheTTL - time.Second)
	tags, err = c.GetRoleTags("arn:aws:iam::111111111111:role/app")
	require.NoError(t, err)
	assert.Equal(t, "acme/api", tags["aow/repo"])
	assert.Equal(t, 1, call, "within TTL must be served from cache")

	// Past the TTL -> re-read, revoked tags observed.
	clock = base.Add(roleTagCacheTTL + time.Second)
	tags, err = c.GetRoleTags("arn:aws:iam::111111111111:role/app")
	require.NoError(t, err)
	assert.Empty(t, tags, "revoked tags must be observed once the TTL lapses")
	assert.Equal(t, 2, call)
	assert.Equal(t, 60*time.Second, roleTagCacheTTL, "stale-tag window is bounded at 60s")
}

// TestAudit_SpokeCacheNoCrossAccountReuse proves spoke credentials minted for
// one account are never handed back for a different account, and that each
// account's spoke assume targets that account's own spoke role ARN.
func TestAudit_SpokeCacheNoCrossAccountReuse(t *testing.T) {
	m := new(MockAwsServiceWrapper)
	m.On("GetCallerAccount").Return("111111111111", nil)

	exp := time.Now().Add(time.Hour)
	var seenArns []string
	// Encode the target account into the access key so provider identity is
	// distinguishable; one expectation per account ARN.
	for _, acct := range []string{"222222222222", "333333333333"} {
		arn := "arn:aws:iam::" + acct + ":role/aow-spoke"
		m.On("AssumeRole", mock.MatchedBy(func(in *sts.AssumeRoleInput) bool {
			return *in.RoleArn == arn
		})).Return(&sts.AssumeRoleOutput{Credentials: &ststypes.Credentials{
			AccessKeyId: aws.String("AK-" + acct), SecretAccessKey: aws.String("SK"),
			SessionToken: aws.String("ST"), Expiration: &exp,
		}}, nil).Run(func(args mock.Arguments) {
			seenArns = append(seenArns, *args.Get(0).(*sts.AssumeRoleInput).RoleArn)
		}).Once()
	}

	c := NewAwsConsumer(&gtvcfg.Config{
		CrossAccount: &gtvcfg.CrossAccount{
			Enabled: true, SpokeRoleName: "aow-spoke",
			SpokeSessionDuration: 15 * time.Minute,
			ExternalID:           "ext-secret-123",
		},
	})
	c.AWS = m

	p222, err := c.spokeCredsFor("222222222222")
	require.NoError(t, err)
	p333, err := c.spokeCredsFor("333333333333")
	require.NoError(t, err)

	cr222, err := p222.Retrieve(t.Context())
	require.NoError(t, err)
	cr333, err := p333.Retrieve(t.Context())
	require.NoError(t, err)
	assert.Equal(t, "AK-222222222222", cr222.AccessKeyID)
	assert.Equal(t, "AK-333333333333", cr333.AccessKeyID,
		"account 333 must not receive account 222's cached spoke credentials")

	assert.Equal(t, []string{
		"arn:aws:iam::222222222222:role/aow-spoke",
		"arn:aws:iam::333333333333:role/aow-spoke",
	}, seenArns)
	assert.Len(t, c.spokeCache, 2)
}

// TestAudit_SpokeExternalIDAndDuration pins that the configured ExternalID is
// attached to the hub->spoke assume and the session is bounded.
func TestAudit_SpokeExternalIDAndDuration(t *testing.T) {
	m := new(MockAwsServiceWrapper)
	m.On("GetCallerAccount").Return("111111111111", nil)
	exp := time.Now().Add(time.Hour)
	var captured *sts.AssumeRoleInput
	m.On("AssumeRole", mock.MatchedBy(func(in *sts.AssumeRoleInput) bool {
		captured = in
		return true
	})).Return(&sts.AssumeRoleOutput{Credentials: &ststypes.Credentials{
		AccessKeyId: aws.String("AK"), SecretAccessKey: aws.String("SK"),
		SessionToken: aws.String("ST"), Expiration: &exp,
	}}, nil).Once()

	c := NewAwsConsumer(&gtvcfg.Config{
		CrossAccount: &gtvcfg.CrossAccount{
			Enabled: true, SpokeRoleName: "aow-spoke",
			SpokeSessionDuration: 15 * time.Minute,
			ExternalID:           "ext-secret-123",
		},
	})
	c.AWS = m

	_, err := c.spokeCredsFor("222222222222")
	require.NoError(t, err)
	require.NotNil(t, captured)
	require.NotNil(t, captured.ExternalId)
	assert.Equal(t, "ext-secret-123", *captured.ExternalId)
	assert.Equal(t, int32(900), *captured.DurationSeconds)
}

// TestAudit_SpokeCredsExpiryEnforced proves a cached spoke provider is not
// reused past its refresh margin (Expiration - 5m).
func TestAudit_SpokeCredsExpiryEnforced(t *testing.T) {
	m := new(MockAwsServiceWrapper)
	m.On("GetCallerAccount").Return("111111111111", nil)

	base := time.Now()
	clock := base
	n := 0
	// Each spoke session lasts 15m from the moment it is minted; the cache
	// entry is meant to lapse 5m earlier (refresh margin).
	e1 := base.Add(15 * time.Minute)
	e2 := base.Add(11*time.Minute + 15*time.Minute)
	for _, e := range []time.Time{e1, e2} {
		m.On("AssumeRole", mock.Anything).Return(&sts.AssumeRoleOutput{Credentials: &ststypes.Credentials{
			AccessKeyId: aws.String("AK"), SecretAccessKey: aws.String("SK"),
			SessionToken: aws.String("ST"), Expiration: &e,
		}}, nil).Run(func(mock.Arguments) { n++ }).Once()
	}

	c := NewAwsConsumer(&gtvcfg.Config{
		CrossAccount: &gtvcfg.CrossAccount{
			Enabled: true, SpokeRoleName: "aow-spoke",
			SpokeSessionDuration: 15 * time.Minute,
		},
	})
	c.AWS = m
	c.now = func() time.Time { return clock }

	_, err := c.spokeCredsFor("222222222222")
	require.NoError(t, err)
	assert.Equal(t, 1, n)

	clock = base.Add(9 * time.Minute) // inside margin (expires at base+10m)
	_, err = c.spokeCredsFor("222222222222")
	require.NoError(t, err)
	assert.Equal(t, 1, n, "still cached inside the refresh margin")

	clock = base.Add(11 * time.Minute) // past margin, before real expiry
	_, err = c.spokeCredsFor("222222222222")
	require.NoError(t, err)
	assert.Equal(t, 2, n, "must re-assume once the refresh margin lapses")
}

// TestAudit_SpokeCacheHitStillRevalidatesAllowList proves that revoking an
// account from cross_account.allowed_accounts takes effect immediately even
// though warm spoke credentials for it are cached (allow-list check precedes
// the cache lookup).
func TestAudit_SpokeCacheHitStillRevalidatesAllowList(t *testing.T) {
	m := new(MockAwsServiceWrapper)
	m.On("GetCallerAccount").Return("111111111111", nil)
	exp := time.Now().Add(time.Hour)
	m.On("AssumeRole", mock.Anything).Return(&sts.AssumeRoleOutput{Credentials: &ststypes.Credentials{
		AccessKeyId: aws.String("AK"), SecretAccessKey: aws.String("SK"),
		SessionToken: aws.String("ST"), Expiration: &exp,
	}}, nil).Once()

	live := &gtvcfg.Config{
		CrossAccount: &gtvcfg.CrossAccount{
			Enabled: true, SpokeRoleName: "aow-spoke",
			SpokeSessionDuration: 15 * time.Minute,
			AllowedAccounts:      []string{"222222222222"},
		},
	}
	c := NewAwsConsumer(live)
	c.SetConfigSource(func() *gtvcfg.Config { return live })

	c.AWS = m
	_, err := c.spokeCredsFor("222222222222")
	require.NoError(t, err)
	require.NotEmpty(t, c.spokeCache, "credentials are warm in the cache")

	// Hot-reload: 222 revoked.
	live = &gtvcfg.Config{
		CrossAccount: &gtvcfg.CrossAccount{
			Enabled: true, SpokeRoleName: "aow-spoke",
			SpokeSessionDuration: 15 * time.Minute,
			AllowedAccounts:      []string{"333333333333"},
		},
	}
	_, err = c.spokeCredsFor("222222222222")
	require.Error(t, err, "warm cache must not bypass the allow-list re-check")
}

// TestAudit_RoleTagCacheHitBypassesAccountChecks documents that a warm
// roleTagCache entry must NOT be served once the account that permitted it has
// been revoked. The account is authorized against the live config before the
// cache is consulted, so revocation takes effect on the next request rather
// than lingering for the cache TTL — and this layer no longer depends on the
// processor happening to call IsTargetAccountAllowed earlier in the pipeline.
func TestAudit_RoleTagCacheRevocationIsImmediate(t *testing.T) {
	m := new(MockAwsServiceWrapper)
	m.On("GetCallerAccount").Return("111111111111", nil)
	exp := time.Now().Add(time.Hour)
	m.On("AssumeRole", mock.Anything).Return(&sts.AssumeRoleOutput{Credentials: &ststypes.Credentials{
		AccessKeyId: aws.String("AK"), SecretAccessKey: aws.String("SK"),
		SessionToken: aws.String("ST"), Expiration: &exp,
	}}, nil).Once()
	m.On("GetRoleAs", mock.Anything, mock.Anything).Return(&iam.GetRoleOutput{Role: &iamtypes.Role{
		Tags: []iamtypes.Tag{{Key: aws.String("aow/repo"), Value: aws.String("acme/api")}},
	}}, nil).Once()

	live := &gtvcfg.Config{
		TagAuth: &gtvcfg.TagAuth{Enabled: true, TagPrefix: "aow/"},
		CrossAccount: &gtvcfg.CrossAccount{
			Enabled: true, SpokeRoleName: "aow-spoke",
			SpokeSessionDuration: 15 * time.Minute,
			AllowedAccounts:      []string{"222222222222"},
		},
	}
	c := NewAwsConsumer(live)
	c.SetConfigSource(func() *gtvcfg.Config { return live })
	c.AWS = m

	base := time.Now()
	clock := base
	c.now = func() time.Time { return clock }

	_, err := c.GetRoleTags("arn:aws:iam::222222222222:role/app")
	require.NoError(t, err)

	// Revoke the account entirely (cross-account off).
	live = &gtvcfg.Config{TagAuth: &gtvcfg.TagAuth{Enabled: true, TagPrefix: "aow/"}}

	// The cache is still warm and well inside its TTL, so only the account
	// re-check can reject this.
	_, err = c.GetRoleTags("arn:aws:iam::222222222222:role/app")
	require.Error(t, err, "a revoked account must not be served from a warm cache entry")
	assert.Contains(t, err.Error(), "target account is not allowed")

	// Still rejected after the TTL, i.e. the entry never becomes serveable again.
	clock = base.Add(roleTagCacheTTL + time.Second)
	_, err = c.GetRoleTags("arn:aws:iam::222222222222:role/app")
	require.Error(t, err, "revoked account must stay rejected past the TTL")
}

// Revoking cross-account must not break tag reads for the warden's OWN account:
// IsTargetAccountAllowed permits the hub whether or not cross-account is on.
func TestAudit_RoleTagHubAccountUnaffectedByCrossAccountRevocation(t *testing.T) {
	m := new(MockAwsServiceWrapper)
	m.On("GetCallerAccount").Return("111111111111", nil)
	m.On("GetRole", mock.Anything).Return(&iam.GetRoleOutput{Role: &iamtypes.Role{
		Tags: []iamtypes.Tag{{Key: aws.String("aow/repo"), Value: aws.String("acme/hub")}},
	}}, nil).Once()

	// Cross-account is OFF from the start.
	live := &gtvcfg.Config{TagAuth: &gtvcfg.TagAuth{Enabled: true, TagPrefix: "aow/"}}
	c := NewAwsConsumer(live)
	c.SetConfigSource(func() *gtvcfg.Config { return live })
	c.AWS = m
	c.now = time.Now

	tags, err := c.GetRoleTags("arn:aws:iam::111111111111:role/deploy")
	require.NoError(t, err, "hub-account tag reads must work with cross-account disabled")
	assert.Equal(t, "acme/hub", tags["aow/repo"])
}
