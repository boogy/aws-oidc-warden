package aws

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/aws-sdk-go-v2/service/sts/types"
	gtvcfg "github.com/boogy/aws-oidc-warden/internal/config"
	gtypes "github.com/boogy/aws-oidc-warden/internal/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
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

	creds, err := consumer.AssumeRole(testRoleArn, testSessionName, nil, &testDuration, nil, nil)
	assert.NoError(t, err)
	assert.NotNil(t, creds)
	assert.Equal(t, "AKIATEST", *creds.AccessKeyId)

	// Test case: Empty role ARN
	creds, err = consumer.AssumeRole("", testSessionName, nil, &testDuration, nil, nil)
	assert.Error(t, err)
	assert.Nil(t, creds)
	assert.Contains(t, err.Error(), "roleArn cannot be empty")

	// Test case: Empty session name
	creds, err = consumer.AssumeRole(testRoleArn, "", nil, &testDuration, nil, nil)
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

	creds, err = consumer.AssumeRole(testRoleArn, testSessionName, testPolicy, &testDuration, nil, nil)
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

	creds, err = consumer.AssumeRole(testRoleArn, testSessionName, nil, &shortDuration, nil, nil)
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

	creds, err = consumer.AssumeRole(testRoleArn, testSessionName, nil, &longDuration, nil, nil)
	assert.NoError(t, err)
	assert.NotNil(t, creds)

	// Test case: AWS service error
	mockAWS.On("AssumeRole", mock.MatchedBy(func(input *sts.AssumeRoleInput) bool {
		return *input.RoleArn == "arn:aws:iam::123456789012:role/nonexistent"
	})).Return(nil, errors.New("access denied")).Once()

	creds, err = consumer.AssumeRole("arn:aws:iam::123456789012:role/nonexistent", testSessionName, nil, &testDuration, nil, nil)
	assert.Error(t, err)
	assert.Nil(t, creds)
	assert.Contains(t, err.Error(), "access denied")

	// Test case: No credentials returned
	mockAWS.On("AssumeRole", mock.MatchedBy(func(input *sts.AssumeRoleInput) bool {
		return *input.RoleArn == "arn:aws:iam::123456789012:role/empty-creds"
	})).Return(&sts.AssumeRoleOutput{
		Credentials: nil,
	}, nil).Once()

	creds, err = consumer.AssumeRole("arn:aws:iam::123456789012:role/empty-creds", testSessionName, nil, &testDuration, nil, nil)
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

	testClaims := &gtypes.Claims{
		Repository: "owner/repo",
		Actor:      "testuser",
		Ref:        "refs/heads/main",
		Raw: map[string]any{
			"repository": "owner/repo",
			"actor":      "testuser",
			"ref":        "refs/heads/main",
		},
	}
	testSpec := map[string]string{
		"repo":  "repository",
		"actor": "actor",
		"ref":   "ref",
	}

	// With claims + a session_tags spec, verify the expected tags are attached.
	mockAWS.On("AssumeRole", mock.MatchedBy(func(input *sts.AssumeRoleInput) bool {
		if *input.RoleArn != testRoleArn || *input.RoleSessionName != testSessionName {
			return false
		}
		tagMap := make(map[string]string)
		for _, tag := range input.Tags {
			if tag.Key != nil && tag.Value != nil {
				tagMap[*tag.Key] = *tag.Value
			}
		}
		return tagMap["repo"] == "owner/repo" &&
			tagMap["actor"] == "testuser" &&
			tagMap["ref"] == "refs/heads/main"
	})).Return(&sts.AssumeRoleOutput{
		Credentials: &types.Credentials{
			AccessKeyId:     aws.String("AKIATEST"),
			SecretAccessKey: aws.String("SECRET"),
			SessionToken:    aws.String("TOKEN"),
			Expiration:      nil,
		},
	}, nil).Once()

	creds, err := consumer.AssumeRole(testRoleArn, testSessionName, nil, &testDuration, testClaims, testSpec)
	assert.NoError(t, err)
	assert.NotNil(t, creds)
	assert.Equal(t, "AKIATEST", *creds.AccessKeyId)

	// Nil claims: no tags attached even though a spec is passed.
	mockAWS.On("AssumeRole", mock.MatchedBy(func(input *sts.AssumeRoleInput) bool {
		return input.Tags == nil && *input.RoleArn == testRoleArn
	})).Return(&sts.AssumeRoleOutput{
		Credentials: &types.Credentials{
			AccessKeyId:     aws.String("AKIATEST2"),
			SecretAccessKey: aws.String("SECRET2"),
			SessionToken:    aws.String("TOKEN2"),
			Expiration:      nil,
		},
	}, nil).Once()

	creds, err = consumer.AssumeRole(testRoleArn, testSessionName, nil, &testDuration, nil, testSpec)
	assert.NoError(t, err)
	assert.NotNil(t, creds)
	assert.Equal(t, "AKIATEST2", *creds.AccessKeyId)

	// Verify all expectations were met
	mockAWS.AssertExpectations(t)
}

func TestBuildSessionTags(t *testing.T) {
	t.Run("valid spec produces correct tags", func(t *testing.T) {
		raw := map[string]any{
			"repository": "owner/repo",
			"actor":      "testuser",
			"ref":        "refs/heads/main",
			"run_number": 7, // non-string claim, must be stringified
		}
		spec := map[string]string{
			"repo":  "repository",
			"actor": "actor",
			"ref":   "ref",
			"run":   "run_number",
		}

		tags := BuildSessionTags(raw, spec)
		tagMap := make(map[string]string)
		for _, tag := range tags {
			tagMap[*tag.Key] = *tag.Value
		}

		assert.Equal(t, map[string]string{
			"repo":  "owner/repo",
			"actor": "testuser",
			"ref":   "refs/heads/main",
			"run":   "7",
		}, tagMap)
	})

	t.Run("nil/empty rawClaims or tagSpec produces no tags", func(t *testing.T) {
		assert.Nil(t, BuildSessionTags(nil, map[string]string{"repo": "repository"}))
		assert.Nil(t, BuildSessionTags(map[string]any{"repository": "owner/repo"}, nil))
	})

	t.Run("missing or empty claim value is skipped, never mangled", func(t *testing.T) {
		raw := map[string]any{
			"repository": "owner/repo",
			"actor":      "", // empty
			// "ref" absent entirely
		}
		spec := map[string]string{
			"repo":  "repository",
			"actor": "actor",
			"ref":   "ref",
		}

		tags := BuildSessionTags(raw, spec)
		require.Len(t, tags, 1)
		assert.Equal(t, "repo", *tags[0].Key)
		assert.Equal(t, "owner/repo", *tags[0].Value)
	})

	t.Run("illegal charset value is skipped, never sanitized or truncated", func(t *testing.T) {
		raw := map[string]any{
			"repository": "owner/repo",
			"actor":      "bad;actor$value", // ';' and '$' are outside the STS charset
		}
		spec := map[string]string{
			"repo":  "repository",
			"actor": "actor",
		}

		tags := BuildSessionTags(raw, spec)
		tagMap := make(map[string]string)
		for _, tag := range tags {
			tagMap[*tag.Key] = *tag.Value
		}

		// The invalid tag must be entirely absent, not sanitized/truncated.
		_, present := tagMap["actor"]
		assert.False(t, present, "tag with illegal-charset value must be skipped, not mangled")
		assert.Equal(t, "owner/repo", tagMap["repo"])
	})

	t.Run("illegal charset key is skipped", func(t *testing.T) {
		raw := map[string]any{"claim": "value"}
		spec := map[string]string{"bad key!": "claim"}

		tags := BuildSessionTags(raw, spec)
		assert.Empty(t, tags)
	})

	t.Run("over-length value is skipped", func(t *testing.T) {
		raw := map[string]any{"claim": strings.Repeat("a", maxSessionTagValLen+1)}
		spec := map[string]string{"tag": "claim"}

		tags := BuildSessionTags(raw, spec)
		assert.Empty(t, tags)
	})

	t.Run("more than 50 tags is bounded to 50", func(t *testing.T) {
		raw := make(map[string]any, 60)
		spec := make(map[string]string, 60)
		for i := range 60 {
			claim := fmt.Sprintf("claim%02d", i)
			raw[claim] = fmt.Sprintf("value%02d", i)
			spec[fmt.Sprintf("tag%02d", i)] = claim
		}

		tags := BuildSessionTags(raw, spec)
		assert.Len(t, tags, maxSessionTags)
	})
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

		// Valid configuration JSON for S3 (v2 issuers[] schema)
		validConfigJSON := `{
			"issuers": [
				{
					"issuer": "https://test-issuer.com",
					"provider": "generic",
					"audiences": ["test-audience"],
					"claim_mappings": {"subject": "sub"}
				}
			]
		}`

		mockAWS.On("GetS3Object", "test-bucket", "test/config.json").Return(
			NewMockReadCloser(validConfigJSON), nil,
		).Once()

		consumer := &AwsConsumer{
			AWS: mockAWS,
			Config: &gtvcfg.Config{
				// RoleSessionName is normally present from defaults before the
				// S3 overlay; include it so Validate() passes.
				RoleSessionName: "aws-oidc-warden",
				S3ConfigBucket:  "test-bucket",
				S3ConfigPath:    "test/config.json",
			},
		}

		err := consumer.ReadS3Configuration()
		assert.NoError(t, err)
		require.Len(t, consumer.Config.Issuers, 1)
		assert.Equal(t, "https://test-issuer.com", consumer.Config.Issuers[0].Issuer)
		assert.Equal(t, []string{"test-audience"}, consumer.Config.Issuers[0].Audiences)

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
