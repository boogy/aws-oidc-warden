package aws

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/aws-sdk-go-v2/service/sts/types"
	gtvcfg "github.com/boogy/aws-oidc-warden/pkg/config"
	gtypes "github.com/boogy/aws-oidc-warden/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestAwsConsumer_SessionName(t *testing.T) {
	consumer := NewAwsConsumer(&gtvcfg.Config{})

	tests := []struct {
		name        string
		inputName   string
		expectedOut string
	}{
		{
			name:        "Valid session name",
			inputName:   "github-actions-workflow",
			expectedOut: "github-actions-workflow",
		},
		{
			name:        "Session name with invalid characters",
			inputName:   "github/actions*workflow$",
			expectedOut: "githubactionsworkflow",
		},
		{
			name:        "Session name exceeding 64 characters",
			inputName:   strings.Repeat("abcdefghij", 7),     // 70 characters
			expectedOut: strings.Repeat("abcdefghij", 7)[6:], // Last 64 characters
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := consumer.SessionName(tt.inputName)
			assert.Equal(t, tt.expectedOut, result)
		})
	}
}

func TestAwsConsumer_AssumeRole(t *testing.T) {
	mockAWS := new(MockAwsServiceWrapper)
	consumer := &AwsConsumer{
		AWS:    mockAWS,
		Config: &gtvcfg.Config{},
	}

	testRoleArn := "arn:aws:iam::123456789012:role/test-role"
	testSessionName := "test-session"
	testPolicy := aws.String(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:ListBucket","Resource":"*"}]}`)
	testDuration := int32(3600)

	// Test case: Successful role assumption
	mockAWS.On("AssumeRole", mock.MatchedBy(func(input *sts.AssumeRoleInput) bool {
		return *input.RoleArn == testRoleArn && *input.RoleSessionName == testSessionName
	})).Return(&sts.AssumeRoleOutput{
		Credentials: &types.Credentials{
			AccessKeyId:     aws.String("AKIATEST"),
			SecretAccessKey: aws.String("SECRET"),
			SessionToken:    aws.String("TOKEN"),
			Expiration:      nil,
		},
	}, nil).Once()

	creds, err := consumer.AssumeRole(testRoleArn, testSessionName, nil, &testDuration, nil)
	assert.NoError(t, err)
	assert.NotNil(t, creds)
	assert.Equal(t, "AKIATEST", *creds.AccessKeyId)

	// Test case: Empty role ARN
	creds, err = consumer.AssumeRole("", testSessionName, nil, &testDuration, nil)
	assert.Error(t, err)
	assert.Nil(t, creds)
	assert.Contains(t, err.Error(), "roleArn cannot be empty")

	// Test case: Empty session name
	creds, err = consumer.AssumeRole(testRoleArn, "", nil, &testDuration, nil)
	assert.Error(t, err)
	assert.Nil(t, creds)
	assert.Contains(t, err.Error(), "sessionName cannot be empty")

	// Test case: With session policy
	mockAWS.On("AssumeRole", mock.MatchedBy(func(input *sts.AssumeRoleInput) bool {
		return *input.RoleArn == testRoleArn && *input.Policy == *testPolicy
	})).Return(&sts.AssumeRoleOutput{
		Credentials: &types.Credentials{
			AccessKeyId:     aws.String("AKIATEST2"),
			SecretAccessKey: aws.String("SECRET2"),
			SessionToken:    aws.String("TOKEN2"),
			Expiration:      nil,
		},
	}, nil).Once()

	creds, err = consumer.AssumeRole(testRoleArn, testSessionName, testPolicy, &testDuration, nil)
	assert.NoError(t, err)
	assert.NotNil(t, creds)
	assert.Equal(t, "AKIATEST2", *creds.AccessKeyId)

	// Test case: Short duration (less than minimum)
	shortDuration := int32(500) // Less than minimum 900
	mockAWS.On("AssumeRole", mock.MatchedBy(func(input *sts.AssumeRoleInput) bool {
		return *input.DurationSeconds == 900 // Should be adjusted to minimum
	})).Return(&sts.AssumeRoleOutput{
		Credentials: &types.Credentials{
			AccessKeyId:     aws.String("AKIATEST3"),
			SecretAccessKey: aws.String("SECRET3"),
			SessionToken:    aws.String("TOKEN3"),
			Expiration:      nil,
		},
	}, nil).Once()

	creds, err = consumer.AssumeRole(testRoleArn, testSessionName, nil, &shortDuration, nil)
	assert.NoError(t, err)
	assert.NotNil(t, creds)

	// Test case: Long duration (more than maximum)
	longDuration := int32(50000) // More than maximum 43200 (12 hours)
	mockAWS.On("AssumeRole", mock.MatchedBy(func(input *sts.AssumeRoleInput) bool {
		return *input.DurationSeconds == 43200 // Should be adjusted to maximum
	})).Return(&sts.AssumeRoleOutput{
		Credentials: &types.Credentials{
			AccessKeyId:     aws.String("AKIATEST4"),
			SecretAccessKey: aws.String("SECRET4"),
			SessionToken:    aws.String("TOKEN4"),
			Expiration:      nil,
		},
	}, nil).Once()

	creds, err = consumer.AssumeRole(testRoleArn, testSessionName, nil, &longDuration, nil)
	assert.NoError(t, err)
	assert.NotNil(t, creds)

	// Test case: AWS service error
	mockAWS.On("AssumeRole", mock.MatchedBy(func(input *sts.AssumeRoleInput) bool {
		return *input.RoleArn == "arn:aws:iam::123456789012:role/nonexistent"
	})).Return(nil, errors.New("access denied")).Once()

	creds, err = consumer.AssumeRole("arn:aws:iam::123456789012:role/nonexistent", testSessionName, nil, &testDuration, nil)
	assert.Error(t, err)
	assert.Nil(t, creds)
	assert.Contains(t, err.Error(), "access denied")

	// Test case: No credentials returned
	mockAWS.On("AssumeRole", mock.MatchedBy(func(input *sts.AssumeRoleInput) bool {
		return *input.RoleArn == "arn:aws:iam::123456789012:role/empty-creds"
	})).Return(&sts.AssumeRoleOutput{
		Credentials: nil,
	}, nil).Once()

	creds, err = consumer.AssumeRole("arn:aws:iam::123456789012:role/empty-creds", testSessionName, nil, &testDuration, nil)
	assert.Error(t, err)
	assert.Nil(t, creds)
	assert.Contains(t, err.Error(), "no credentials returned")

	// Verify all expectations were met
	mockAWS.AssertExpectations(t)
}

func TestAwsConsumer_AssumeRole_WithSessionTags(t *testing.T) {
	mockAWS := new(MockAwsServiceWrapper)
	consumer := &AwsConsumer{
		AWS:    mockAWS,
		Config: &gtvcfg.Config{},
	}

	testRoleArn := "arn:aws:iam::123456789012:role/test-role"
	testSessionName := "test-session"
	testDuration := int32(3600)

	// Create test GitHub claims
	testClaims := &gtypes.GithubClaims{
		Repository:      "owner/repo",
		Actor:           "testuser",
		Ref:             "refs/heads/main",
		Workflow:        "CI",
		EventName:       "push",
		RunID:           "12345",
		RunNumber:       "1",
		RepositoryOwner: "owner",
		Sha:             "abcd1234",
		RefType:         "branch",
	}

	// Set up mock to capture the input and verify tags are present
	mockAWS.On("AssumeRole", mock.MatchedBy(func(input *sts.AssumeRoleInput) bool {
		// For the first call (with claims), verify tags are present
		if *input.RoleArn == testRoleArn && *input.RoleSessionName == testSessionName {
			// If this is a call with claims, we expect tags
			if input.Tags != nil && len(input.Tags) > 0 {
				// Verify at least some key tags are present
				tagMap := make(map[string]string)
				for _, tag := range input.Tags {
					if tag.Key != nil && tag.Value != nil {
						tagMap[*tag.Key] = *tag.Value
					}
				}

				// Check for at least the most important tags
				if tagMap["GitHubRepository"] == "owner/repo" &&
					tagMap["GitHubActor"] == "testuser" &&
					tagMap["GitHubRef"] == "refs/heads/main" {
					return true
				}
			}
		}
		return true // Accept all other calls for this test
	})).Return(&sts.AssumeRoleOutput{
		Credentials: &types.Credentials{
			AccessKeyId:     aws.String("AKIATEST"),
			SecretAccessKey: aws.String("SECRET"),
			SessionToken:    aws.String("TOKEN"),
			Expiration:      nil,
		},
	}, nil).Once()

	// Call AssumeRole with GitHub claims
	creds, err := consumer.AssumeRole(testRoleArn, testSessionName, nil, &testDuration, testClaims)
	assert.NoError(t, err)
	assert.NotNil(t, creds)
	assert.Equal(t, "AKIATEST", *creds.AccessKeyId)

	// Test case: Nil claims (should work without tags)
	mockAWS.On("AssumeRole", mock.MatchedBy(func(input *sts.AssumeRoleInput) bool {
		// Verify no tags are set when claims are nil
		return input.Tags == nil && *input.RoleArn == testRoleArn
	})).Return(&sts.AssumeRoleOutput{
		Credentials: &types.Credentials{
			AccessKeyId:     aws.String("AKIATEST2"),
			SecretAccessKey: aws.String("SECRET2"),
			SessionToken:    aws.String("TOKEN2"),
			Expiration:      nil,
		},
	}, nil).Once()

	creds, err = consumer.AssumeRole(testRoleArn, testSessionName, nil, &testDuration, nil)
	assert.NoError(t, err)
	assert.NotNil(t, creds)
	assert.Equal(t, "AKIATEST2", *creds.AccessKeyId)

	// Verify all expectations were met
	mockAWS.AssertExpectations(t)
}

func TestCreateSessionTags(t *testing.T) {
	// Test case: Valid claims
	claims := &gtypes.GithubClaims{
		Repository:      "owner/repo",
		Actor:           "testuser",
		Ref:             "refs/heads/main",
		EventName:       "push",
		RepositoryOwner: "owner",
		RefType:         "branch",
	}

	tags := CreateSessionTags(claims)
	assert.NotNil(t, tags)
	assert.Greater(t, len(tags), 0)

	// Convert to map for easier testing
	tagMap := make(map[string]string)
	for _, tag := range tags {
		if tag.Key != nil && tag.Value != nil {
			tagMap[*tag.Key] = *tag.Value
		}
	}

	// Verify expected tags are present with new mappings
	assert.Equal(t, "repo", tagMap["repo"])           // repository name only
	assert.Equal(t, "testuser", tagMap["actor"])      // actor
	assert.Equal(t, "refs/heads/main", tagMap["ref"]) // ref
	assert.Equal(t, "push", tagMap["event-name"])     // event_name
	assert.Equal(t, "owner", tagMap["repo-owner"])    // repository owner
	assert.Equal(t, "branch", tagMap["ref-type"])     // ref_type

	// Test case: Nil claims
	tags = CreateSessionTags(nil)
	assert.Nil(t, tags)

	// Test case: Empty claims
	emptyClaims := &gtypes.GithubClaims{}
	tags = CreateSessionTags(emptyClaims)
	assert.Equal(t, 0, len(tags)) // Should have no tags since all fields are empty

	// Test case: Repository name extraction
	claimsWithDifferentRepo := &gtypes.GithubClaims{
		Repository:      "my-org/my-awesome-repo",
		Actor:           "developer",
		RepositoryOwner: "my-org",
	}
	tags = CreateSessionTags(claimsWithDifferentRepo)
	tagMap = make(map[string]string)
	for _, tag := range tags {
		if tag.Key != nil && tag.Value != nil {
			tagMap[*tag.Key] = *tag.Value
		}
	}
	assert.Equal(t, "my-awesome-repo", tagMap["repo"]) // should extract only repo name
	assert.Equal(t, "my-org", tagMap["repo-owner"])    // should have full owner
	assert.Equal(t, "developer", tagMap["actor"])      // should have actor

	// Test case: Repository without slash (edge case)
	claimsNoSlash := &gtypes.GithubClaims{
		Repository: "standalone-repo",
		Actor:      "user",
	}
	tags = CreateSessionTags(claimsNoSlash)
	tagMap = make(map[string]string)
	for _, tag := range tags {
		if tag.Key != nil && tag.Value != nil {
			tagMap[*tag.Key] = *tag.Value
		}
	}
	assert.Equal(t, "standalone-repo", tagMap["repo"]) // should use entire string as repo name
}

func TestSanitizeTagValue(t *testing.T) {
	// Test case: Valid characters
	result := sanitizeTagValue("valid-tag_value123", 50)
	assert.Equal(t, "valid-tag_value123", result)

	// Test case: Invalid characters (should be removed)
	result = sanitizeTagValue("invalid$tag&value*", 50)
	assert.Equal(t, "invalidtagvalue", result)

	// Test case: Length truncation
	longValue := "this-is-a-very-long-tag-value-that-exceeds-the-maximum-length-allowed"
	result = sanitizeTagValue(longValue, 20)
	assert.Equal(t, 20, len(result))
	assert.Equal(t, "this-is-a-very-long-", result)

	// Test case: Empty value
	result = sanitizeTagValue("", 50)
	assert.Equal(t, "", result)

	// Test case: Special AWS allowed characters
	result = sanitizeTagValue("value+with=special:chars/@-.", 50)
	assert.Equal(t, "value+with=special:chars/@-.", result)
}

func TestAwsConsumer_ReadS3Configuration(t *testing.T) {
	// Test the error cases first
	t.Run("Missing config parameters", func(t *testing.T) {
		mockAWS := new(MockAwsServiceWrapper)

		// Test missing S3ConfigBucket
		consumer1 := &AwsConsumer{
			AWS: mockAWS,
			Config: &gtvcfg.Config{
				S3ConfigPath: "test/config.json",
			},
		}

		err := consumer1.ReadS3Configuration()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "S3ConfigBucket and S3ConfigPath options must be set")

		// Test missing S3ConfigPath
		consumer2 := &AwsConsumer{
			AWS: mockAWS,
			Config: &gtvcfg.Config{
				S3ConfigBucket: "test-bucket",
			},
		}

		err = consumer2.ReadS3Configuration()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "S3ConfigBucket and S3ConfigPath options must be set")
	})

	t.Run("S3 GetObject error", func(t *testing.T) {
		mockAWS := new(MockAwsServiceWrapper)
		mockAWS.On("GetS3Object", "test-bucket", "test/config.json").Return(
			nil, errors.New("access denied"),
		).Once()

		consumer := &AwsConsumer{
			AWS: mockAWS,
			Config: &gtvcfg.Config{
				S3ConfigBucket: "test-bucket",
				S3ConfigPath:   "test/config.json",
			},
		}

		err := consumer.ReadS3Configuration()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to get S3 configuration object")

		mockAWS.AssertExpectations(t)
	})

	t.Run("Invalid JSON in S3 config", func(t *testing.T) {
		mockAWS := new(MockAwsServiceWrapper)
		mockAWS.On("GetS3Object", "test-bucket", "test/config.json").Return(
			NewMockReadCloser("{invalid json}"), nil,
		).Once()

		consumer := &AwsConsumer{
			AWS: mockAWS,
			Config: &gtvcfg.Config{
				S3ConfigBucket: "test-bucket",
				S3ConfigPath:   "test/config.json",
			},
		}

		err := consumer.ReadS3Configuration()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unable to decode configuration from S3")

		mockAWS.AssertExpectations(t)
	})

	t.Run("Success case", func(t *testing.T) {
		mockAWS := new(MockAwsServiceWrapper)

		// Valid configuration JSON for S3
		validConfigJSON := `{
			"issuer": "https://test-issuer.com",
			"audience": "test-audience"
		}`

		mockAWS.On("GetS3Object", "test-bucket", "test/config.json").Return(
			NewMockReadCloser(validConfigJSON), nil,
		).Once()

		consumer := &AwsConsumer{
			AWS: mockAWS,
			Config: &gtvcfg.Config{
				S3ConfigBucket: "test-bucket",
				S3ConfigPath:   "test/config.json",
			},
		}

		err := consumer.ReadS3Configuration()
		assert.NoError(t, err)
		assert.Equal(t, "https://test-issuer.com", consumer.Config.Issuer)
		assert.Equal(t, "test-audience", consumer.Config.Audience)

		mockAWS.AssertExpectations(t)
	})
}

func TestAwsConsumer_GetRole(t *testing.T) {
	mockAWS := new(MockAwsServiceWrapper)
	consumer := &AwsConsumer{
		AWS:    mockAWS,
		Config: &gtvcfg.Config{},
	}

	roleName := "test-role"
	roleArn := "arn:aws:iam::123456789012:role/test-role"

	// Success case
	mockAWS.On("GetRole", &iam.GetRoleInput{
		RoleName: aws.String(roleName),
	}).Return(&iam.GetRoleOutput{
		Role: &iamtypes.Role{
			RoleName: aws.String(roleName),
			Arn:      aws.String(roleArn),
		},
	}, nil).Once()

	role, err := consumer.GetRole(roleName)
	assert.NoError(t, err)
	assert.NotNil(t, role)
	assert.Equal(t, roleName, *role.Role.RoleName)
	assert.Equal(t, roleArn, *role.Role.Arn)

	// Error case - empty role name
	role, err = consumer.GetRole("")
	assert.Error(t, err)
	assert.Nil(t, role)
	assert.Contains(t, err.Error(), "role name cannot be empty")

	// Error case - AWS error
	mockAWS.On("GetRole", &iam.GetRoleInput{
		RoleName: aws.String("nonexistent-role"),
	}).Return(nil, errors.New("role not found")).Once()

	role, err = consumer.GetRole("nonexistent-role")
	assert.Error(t, err)
	assert.Nil(t, role)
	assert.Contains(t, err.Error(), "role not found")

	mockAWS.AssertExpectations(t)
}

func TestAwsConsumer_RoleHasTag(t *testing.T) {
	mockAWS := new(MockAwsServiceWrapper)
	consumer := &AwsConsumer{
		AWS:    mockAWS,
		Config: &gtvcfg.Config{},
	}

	roleName := "test-role"
	roleArn := "arn:aws:iam::123456789012:role/test-role"

	// Setup mock for role with matching tag
	mockAWS.On("GetRole", &iam.GetRoleInput{
		RoleName: aws.String(roleName),
	}).Return(&iam.GetRoleOutput{
		Role: &iamtypes.Role{
			RoleName: aws.String(roleName),
			Arn:      aws.String(roleArn),
			Tags: []iamtypes.Tag{
				{
					Key:   aws.String("Environment"),
					Value: aws.String("Production"),
				},
				{
					Key:   aws.String("Project"),
					Value: aws.String("AWS-OIDC-Warden"),
				},
			},
		},
	}, nil).Once()

	// Test with matching tag
	hasTag, err := consumer.RoleHasTag(roleName, "Environment", "Production")
	assert.NoError(t, err)
	assert.True(t, hasTag)

	// Setup mock for role with no matching tag
	mockAWS.On("GetRole", &iam.GetRoleInput{
		RoleName: aws.String(roleName),
	}).Return(&iam.GetRoleOutput{
		Role: &iamtypes.Role{
			RoleName: aws.String(roleName),
			Arn:      aws.String(roleArn),
			Tags: []iamtypes.Tag{
				{
					Key:   aws.String("Environment"),
					Value: aws.String("Production"),
				},
			},
		},
	}, nil).Once()

	// Test with non-matching tag
	hasTag, err = consumer.RoleHasTag(roleName, "NonExistent", "Value")
	assert.NoError(t, err)
	assert.False(t, hasTag)

	// Error case - empty role name
	hasTag, err = consumer.RoleHasTag("", "TagKey", "TagValue")
	assert.Error(t, err)
	assert.False(t, hasTag)
	assert.Contains(t, err.Error(), "role name cannot be empty")

	// Error case - empty tag key
	hasTag, err = consumer.RoleHasTag(roleName, "", "TagValue")
	assert.Error(t, err)
	assert.False(t, hasTag)
	assert.Contains(t, err.Error(), "tag key cannot be empty")

	// Error case - AWS error
	mockAWS.On("GetRole", &iam.GetRoleInput{
		RoleName: aws.String("error-role"),
	}).Return(nil, errors.New("role not found")).Once()

	hasTag, err = consumer.RoleHasTag("error-role", "TagKey", "TagValue")
	assert.Error(t, err)
	assert.False(t, hasTag)
	assert.Contains(t, err.Error(), "unable to get role")

	// Error case - nil role in response
	mockAWS.On("GetRole", &iam.GetRoleInput{
		RoleName: aws.String("nil-role"),
	}).Return(&iam.GetRoleOutput{
		Role: nil,
	}, nil).Once()

	hasTag, err = consumer.RoleHasTag("nil-role", "TagKey", "TagValue")
	assert.Error(t, err)
	assert.False(t, hasTag)
	assert.Contains(t, err.Error(), "role information not available")

	mockAWS.AssertExpectations(t)
}

func TestAwsConsumer_GetS3Object(t *testing.T) {
	mockAWS := new(MockAwsServiceWrapper)
	consumer := &AwsConsumer{
		AWS:    mockAWS,
		Config: &gtvcfg.Config{},
	}

	bucket := "test-bucket"
	key := "test-key"
	content := "test content"

	// Success case
	mockAWS.On("GetS3Object", bucket, key).Return(
		NewMockReadCloser(content), nil,
	).Once()

	reader, err := consumer.GetS3Object(bucket, key)
	assert.NoError(t, err)
	assert.NotNil(t, reader)

	data, err := io.ReadAll(reader)
	assert.NoError(t, err)
	assert.Equal(t, content, string(data))

	// Error case - empty bucket
	reader, err = consumer.GetS3Object("", key)
	assert.Error(t, err)
	assert.Nil(t, reader)
	assert.Contains(t, err.Error(), "bucket name cannot be empty")

	// Error case - empty key
	reader, err = consumer.GetS3Object(bucket, "")
	assert.Error(t, err)
	assert.Nil(t, reader)
	assert.Contains(t, err.Error(), "object key cannot be empty")

	// Error case - AWS error
	mockAWS.On("GetS3Object", bucket, "error-key").Return(
		nil, errors.New("access denied"),
	).Once()

	reader, err = consumer.GetS3Object(bucket, "error-key")
	assert.Error(t, err)
	assert.Nil(t, reader)
	assert.Contains(t, err.Error(), "access denied")

	mockAWS.AssertExpectations(t)
}

func TestAwsConsumer_GetSessionPolicyFromS3(t *testing.T) {
	mockAWS := new(MockAwsServiceWrapper)
	consumer := &AwsConsumer{
		AWS:    mockAWS,
		Config: &gtvcfg.Config{},
	}

	bucket := "policy-bucket"
	prefix := "policies/test-policy.json"
	policyJSON := `{
		"Version": "2012-10-17",
		"Statement": [
			{
				"Effect": "Allow",
				"Action": "s3:ListBucket",
				"Resource": "*"
			}
		]
	}`

	// Success case
	mockAWS.On("GetS3Object", bucket, prefix).Return(
		NewMockReadCloser(policyJSON), nil,
	).Once()

	policy, err := consumer.GetSessionPolicyFromS3(bucket, prefix)
	assert.NoError(t, err)
	assert.Equal(t, policyJSON, policy)

	// Error case - empty bucket
	policy, err = consumer.GetSessionPolicyFromS3("", prefix)
	assert.Error(t, err)
	assert.Empty(t, policy)
	assert.Contains(t, err.Error(), "bucket name cannot be empty")

	// Error case - empty prefix
	policy, err = consumer.GetSessionPolicyFromS3(bucket, "")
	assert.Error(t, err)
	assert.Empty(t, policy)
	assert.Contains(t, err.Error(), "object prefix cannot be empty")

	// Error case - AWS error
	mockAWS.On("GetS3Object", bucket, "error-policy").Return(
		nil, errors.New("access denied"),
	).Once()

	policy, err = consumer.GetSessionPolicyFromS3(bucket, "error-policy")
	assert.Error(t, err)
	assert.Empty(t, policy)
	assert.Contains(t, err.Error(), "failed to get session policy from S3")

	// Error case - read error
	mockReadCloser := MockReadCloser{
		Reader: bytes.NewReader([]byte{}),
		CloseFunc: func() error {
			return nil
		},
	}
	mockAWS.On("GetS3Object", bucket, "read-error").Return(
		mockReadCloser, nil,
	).Once()

	policy, err = consumer.GetSessionPolicyFromS3(bucket, "read-error")
	assert.Error(t, err)
	assert.Empty(t, policy)
	assert.Contains(t, err.Error(), "empty policy document retrieved from S3")

	mockAWS.AssertExpectations(t)
}
