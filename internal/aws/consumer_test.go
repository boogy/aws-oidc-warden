package aws

// The AWS consumer: construction, config source, cross-account spoke hop, transitive session tags.
import (
	"errors"
	"fmt"
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
			expectedOut: "github-actions-workflow-",
		},
		{
			name:        "Session name exceeding 64 characters",
			inputName:   strings.Repeat("abcdefghij", 7),
			expectedOut: strings.Repeat("abcdefghij", 7)[6:],
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

	mockAWS.On("GetCallerIdentityInfo").Return("123456789012", false, nil)

	mockAWS.On("AssumeRole", mock.MatchedBy(func(input *sts.AssumeRoleInput) bool {
		return *input.RoleArn == testRoleArn && *input.RoleSessionName == testSessionName
	})).Return(&sts.AssumeRoleOutput{
		Credentials: &ststypes.Credentials{
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
		Credentials: &ststypes.Credentials{
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
		Credentials: &ststypes.Credentials{
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
		Credentials: &ststypes.Credentials{
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

	mockAWS.On("GetCallerIdentityInfo").Return("123456789012", false, nil)

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
		Credentials: &ststypes.Credentials{
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
		Credentials: &ststypes.Credentials{
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

func TestAwsConsumer_AssumeRole_TransitiveSessionTags(t *testing.T) {
	mockAWS := new(MockAwsServiceWrapper)
	consumer := &AwsConsumer{
		AWS: mockAWS,
		Config: &gtvcfg.Config{
			SessionTagsTransitive: true,
		},
	}

	testRoleArn := "arn:aws:iam::123456789012:role/test-role"
	testSessionName := "test-session"
	testDuration := int32(3600)

	testClaims := &gtypes.Claims{
		Raw: map[string]any{
			"repository": "owner/repo",
			"project_id": "my-project",
		},
	}
	// A custom-named tag ("project") alongside the well-known ones: all of
	// them are operator-configured identity tags and must be marked
	// transitive, not just the historical repo/ref/actor set.
	testSpec := map[string]string{
		"repo":    "repository",
		"project": "project_id",
	}

	mockAWS.On("GetCallerIdentityInfo").Return("123456789012", false, nil)

	mockAWS.On("AssumeRole", mock.MatchedBy(func(input *sts.AssumeRoleInput) bool {
		return *input.RoleArn == testRoleArn &&
			len(input.TransitiveTagKeys) == 2 &&
			assert.ElementsMatch(t, []string{"repo", "project"}, input.TransitiveTagKeys)
	})).Return(&sts.AssumeRoleOutput{
		Credentials: &ststypes.Credentials{
			AccessKeyId:     aws.String("AKIATEST"),
			SecretAccessKey: aws.String("SECRET"),
			SessionToken:    aws.String("TOKEN"),
			Expiration:      nil,
		},
	}, nil).Once()

	creds, err := consumer.AssumeRole(testRoleArn, testSessionName, nil, &testDuration, testClaims, testSpec)
	assert.NoError(t, err)
	assert.NotNil(t, creds)

	// TransitiveSessionTags off: no transitive keys are set, even with tags present.
	consumer.Config.SessionTagsTransitive = false
	mockAWS.On("AssumeRole", mock.MatchedBy(func(input *sts.AssumeRoleInput) bool {
		return *input.RoleArn == testRoleArn && input.TransitiveTagKeys == nil && len(input.Tags) == 2
	})).Return(&sts.AssumeRoleOutput{
		Credentials: &ststypes.Credentials{
			AccessKeyId:     aws.String("AKIATEST2"),
			SecretAccessKey: aws.String("SECRET2"),
			SessionToken:    aws.String("TOKEN2"),
			Expiration:      nil,
		},
	}, nil).Once()

	creds, err = consumer.AssumeRole(testRoleArn, testSessionName, nil, &testDuration, testClaims, testSpec)
	assert.NoError(t, err)
	assert.NotNil(t, creds)

	mockAWS.AssertExpectations(t)
}

// TestAssumeRole_TransitiveFromTopLevelKey pins that transitivity is driven by
// the top-level session_tags_transitive key, independently of tag_auth: the
// deprecated tag_auth.transitive_session_tags fallback keeps working, and
// either source turning it on wins.
func TestAssumeRole_TransitiveFromTopLevelKey(t *testing.T) {
	testRoleArn := "arn:aws:iam::123456789012:role/test-role"
	testDuration := int32(3600)
	testClaims := &gtypes.Claims{Raw: map[string]any{"repository": "owner/repo"}}
	testSpec := map[string]string{"repo": "repository"}

	for _, tc := range []struct {
		name           string
		topLevel       bool
		tagAuth        *gtvcfg.TagAuth
		wantTransitive bool
	}{
		{"top-level on, tag_auth absent", true, nil, true},
		{"top-level off, tag_auth absent", false, nil, false},
		// The deprecated key is the subject under test here, not an oversight.
		//nolint:staticcheck // SA1019: asserts the tag_auth fallback still resolves.
		{"deprecated tag_auth key still honored", false, &gtvcfg.TagAuth{TransitiveSessionTags: true}, true},
		//nolint:staticcheck // SA1019: asserts the top-level key overrides the fallback.
		{"top-level on wins over tag_auth off", true, &gtvcfg.TagAuth{TransitiveSessionTags: false}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mockAWS := new(MockAwsServiceWrapper)
			consumer := &AwsConsumer{
				AWS: mockAWS,
				Config: &gtvcfg.Config{
					SessionTagsTransitive: tc.topLevel,
					TagAuth:               tc.tagAuth,
				},
			}
			mockAWS.On("GetCallerIdentityInfo").Return("123456789012", false, nil)

			var captured *sts.AssumeRoleInput
			mockAWS.On("AssumeRole", mock.MatchedBy(func(input *sts.AssumeRoleInput) bool {
				captured = input
				return *input.RoleArn == testRoleArn
			})).Return(&sts.AssumeRoleOutput{
				Credentials: &ststypes.Credentials{
					AccessKeyId:     aws.String("AKIATEST"),
					SecretAccessKey: aws.String("SECRET"),
					SessionToken:    aws.String("TOKEN"),
				},
			}, nil).Once()

			_, err := consumer.AssumeRole(testRoleArn, "test-session", nil, &testDuration, testClaims, testSpec)
			require.NoError(t, err)

			if tc.wantTransitive {
				assert.Equal(t, []string{"repo"}, captured.TransitiveTagKeys)
			} else {
				assert.Empty(t, captured.TransitiveTagKeys)
			}
		})
	}
}

func TestSelectTransitiveKeys(t *testing.T) {
	tests := []struct {
		name string
		tags []ststypes.Tag
		want []string
	}{
		{
			name: "no tags",
			tags: nil,
			want: []string{},
		},
		{
			name: "well-known and custom-named tags are all included",
			tags: []ststypes.Tag{
				{Key: aws.String("repo"), Value: aws.String("owner/repo")},
				{Key: aws.String("ref"), Value: aws.String("refs/heads/main")},
				{Key: aws.String("actor"), Value: aws.String("testuser")},
				{Key: aws.String("project"), Value: aws.String("my-project")},
			},
			want: []string{"repo", "ref", "actor", "project"},
		},
		{
			name: "nil keys are skipped",
			tags: []ststypes.Tag{
				{Key: nil, Value: aws.String("ignored")},
				{Key: aws.String("project"), Value: aws.String("my-project")},
			},
			want: []string{"project"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := selectTransitiveKeys(tt.tags)
			assert.ElementsMatch(t, tt.want, got)
		})
	}
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

// ---------- config source ----------

// TestConfigSource_ReflectsLiveConfig verifies the consumer enforces the
// currently active configuration (e.g. after hot-reload) rather than the
// construction-time snapshot. Without this, tightening allowed_accounts or
// toggling tag-auth via reload would silently fail to take effect.
func TestConfigSource_ReflectsLiveConfig(t *testing.T) {
	member := "arn:aws:iam::222222222222:role/app"

	// Construction-time config allows the member account.
	base := &gtvcfg.Config{CrossAccount: &gtvcfg.CrossAccount{
		Enabled: true, SpokeRoleName: "aow-spoke",
		AllowedAccounts: []string{"222222222222"},
	}}

	// Live config (post-reload) removes the member account.
	live := &gtvcfg.Config{CrossAccount: &gtvcfg.CrossAccount{
		Enabled: true, SpokeRoleName: "aow-spoke",
		AllowedAccounts: []string{"333333333333"},
	}}

	m := new(MockAwsServiceWrapper)
	m.On("GetCallerAccount").Return("111111111111", nil)

	c := NewAwsConsumer(base)
	c.AWS = m

	// Before wiring a source, the base config governs: member allowed.
	ok, err := c.IsTargetAccountAllowed(member)
	require.NoError(t, err)
	assert.True(t, ok, "base config should allow the member account")

	// Wire a live-config getter that returns the reloaded (tighter) config.
	c.SetConfigSource(func() *gtvcfg.Config { return live })

	ok, err = c.IsTargetAccountAllowed(member)
	require.NoError(t, err)
	assert.False(t, ok, "live config removed the member account; must be rejected")
}

// TestConfigSource_ToggleEnabled verifies enabling/disabling cross-account via
// the live getter is reflected by the consumer's cross-account gate.
func TestConfigSource_ToggleEnabled(t *testing.T) {
	member := "arn:aws:iam::222222222222:role/app"

	disabled := &gtvcfg.Config{CrossAccount: &gtvcfg.CrossAccount{Enabled: false}}
	enabled := &gtvcfg.Config{CrossAccount: &gtvcfg.CrossAccount{
		Enabled: true, SpokeRoleName: "aow-spoke",
		AllowedAccounts: []string{"333333333333"},
	}}

	m := new(MockAwsServiceWrapper)
	m.On("GetCallerAccount").Return("111111111111", nil)

	current := disabled
	c := NewAwsConsumer(&gtvcfg.Config{})
	c.AWS = m
	c.SetConfigSource(func() *gtvcfg.Config { return current })

	// Disabled: no cross-account path exists, so a member-account target is
	// rejected (fail closed; only the hub account is reachable).
	ok, err := c.IsTargetAccountAllowed(member)
	require.NoError(t, err)
	assert.False(t, ok)

	// Reload enables cross-account with an allow-list excluding the member.
	current = enabled
	ok, err = c.IsTargetAccountAllowed(member)
	require.NoError(t, err)
	assert.False(t, ok, "after enabling cross-account, member not in allow-list must be rejected")
}

// TestConfigSource_FallsBackToConfig verifies that with no source wired the
// consumer behaves exactly as before (uses the construction-time Config).
func TestConfigSource_FallsBackToConfig(t *testing.T) {
	m := new(MockAwsServiceWrapper)
	m.On("GetCallerAccount").Return("111111111111", nil)

	c := consumerWithAllowed(m, []string{"333333333333"})
	// nil configSource → fall back to a.Config.
	ok, err := c.IsTargetAccountAllowed("arn:aws:iam::222222222222:role/app")
	require.NoError(t, err)
	assert.False(t, ok)
}

// ---------- cross-account accounts ----------

func consumerWithAllowed(m *MockAwsServiceWrapper, allowed []string) *AwsConsumer {
	cfg := &gtvcfg.Config{
		TagAuth:      &gtvcfg.TagAuth{Enabled: true, TagPrefix: "aow/"},
		CrossAccount: &gtvcfg.CrossAccount{Enabled: true, SpokeRoleName: "aow-spoke", AllowedAccounts: allowed},
	}
	c := NewAwsConsumer(cfg)
	c.AWS = m
	return c
}

func TestIsTargetAccountAllowed(t *testing.T) {
	cases := []struct {
		name    string
		allowed []string
		arn     string
		want    bool
	}{
		{"hub always allowed", []string{"222222222222"}, "arn:aws:iam::111111111111:role/app", true},
		{"member in list", []string{"222222222222"}, "arn:aws:iam::222222222222:role/app", true},
		{"member not in list", []string{"333333333333"}, "arn:aws:iam::222222222222:role/app", false},
		{"empty list allows any", nil, "arn:aws:iam::222222222222:role/app", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := new(MockAwsServiceWrapper)
			m.On("GetCallerAccount").Return("111111111111", nil)
			c := consumerWithAllowed(m, tc.allowed)
			ok, err := c.IsTargetAccountAllowed(tc.arn)
			require.NoError(t, err)
			assert.Equal(t, tc.want, ok)
		})
	}
}

// TestIsTargetAccountAllowed_EmptyListFailsOpen documents (and locks in) the
// fail-open default: cross-account enabled with an empty allowed_accounts
// permits ANY non-hub member account. Config validation only warns; operators
// must populate allowed_accounts in production. A future change must not
// silently flip this.
func TestIsTargetAccountAllowed_EmptyListFailsOpen(t *testing.T) {
	m := new(MockAwsServiceWrapper)
	m.On("GetCallerAccount").Return("111111111111", nil)
	c := consumerWithAllowed(m, nil) // enabled, empty allow-list
	ok, err := c.IsTargetAccountAllowed("arn:aws:iam::222222222222:role/anything")
	require.NoError(t, err)
	assert.True(t, ok, "empty allowed_accounts must fail open (any account allowed)")
}

// TestIsTargetAccountAllowedDisabled locks in the new fail-closed semantics:
// with cross-account transport disabled, only the hub account is allowed
// (there is no spoke path to reach any other account).
func TestIsTargetAccountAllowedDisabled(t *testing.T) {
	m := new(MockAwsServiceWrapper)
	m.On("GetCallerAccount").Return("111111111111", nil)
	c := NewAwsConsumer(&gtvcfg.Config{}) // CrossAccount nil
	c.AWS = m

	ok, err := c.IsTargetAccountAllowed("arn:aws:iam::111111111111:role/app")
	require.NoError(t, err)
	assert.True(t, ok, "hub account must be allowed even when cross-account is disabled")

	ok, err = c.IsTargetAccountAllowed("arn:aws:iam::222222222222:role/app")
	require.NoError(t, err)
	assert.False(t, ok, "member account must be disallowed when cross-account is disabled")
}

func TestIsTargetAccountAllowed_BadARN(t *testing.T) {
	m := new(MockAwsServiceWrapper)
	c := consumerWithAllowed(m, []string{"222222222222"})
	ok, err := c.IsTargetAccountAllowed("not-an-arn")
	require.Error(t, err) // ParseRoleARN error propagated
	assert.False(t, ok)
}

func TestSpokeCredsFor_BlockedAccount(t *testing.T) {
	cfg := &gtvcfg.Config{CrossAccount: &gtvcfg.CrossAccount{
		Enabled: true, SpokeRoleName: "aow-spoke", AllowedAccounts: []string{"333333333333"},
		SpokeSessionDuration: 15 * time.Minute,
	}}

	// Hub account is always allowed → (nil, nil), no spoke assume.
	mHub := new(MockAwsServiceWrapper)
	mHub.On("GetCallerAccount").Return("111111111111", nil)
	cHub := NewAwsConsumer(cfg)
	cHub.AWS = mHub
	creds, err := cHub.spokeCredsFor("111111111111")
	require.NoError(t, err)
	assert.Nil(t, creds)

	// Non-hub account not in the allow-list → defense-in-depth guard errors.
	mBlocked := new(MockAwsServiceWrapper)
	mBlocked.On("GetCallerAccount").Return("111111111111", nil)
	cBlocked := NewAwsConsumer(cfg)
	cBlocked.AWS = mBlocked
	creds, err = cBlocked.spokeCredsFor("222222222222")
	require.Error(t, err)
	assert.Nil(t, creds)

	// Allowed member proceeds to assume the spoke role.
	mAllowed := new(MockAwsServiceWrapper)
	mAllowed.On("GetCallerAccount").Return("111111111111", nil)
	exp := time.Now().Add(time.Hour)
	mAllowed.On("AssumeRole", mock.MatchedBy(func(in *sts.AssumeRoleInput) bool {
		return *in.RoleArn == "arn:aws:iam::333333333333:role/aow-spoke"
	})).Return(&sts.AssumeRoleOutput{Credentials: &ststypes.Credentials{
		AccessKeyId: aws.String("AK"), SecretAccessKey: aws.String("SK"),
		SessionToken: aws.String("ST"), Expiration: &exp,
	}}, nil).Once()
	cAllowed := NewAwsConsumer(cfg)
	cAllowed.AWS = mAllowed
	creds, err = cAllowed.spokeCredsFor("333333333333")
	require.NoError(t, err)
	require.NotNil(t, creds)
	mAllowed.AssertExpectations(t)
}

// ---------- spoke hop ----------

func newTagAuthConsumer(m *MockAwsServiceWrapper) *AwsConsumer {
	cfg := &gtvcfg.Config{
		TagAuth: &gtvcfg.TagAuth{Enabled: true, TagPrefix: "aow/"},
		CrossAccount: &gtvcfg.CrossAccount{
			Enabled: true, SpokeRoleName: "aow-spoke",
			SpokeSessionDuration: 15 * time.Minute,
		},
	}
	c := NewAwsConsumer(cfg)
	c.AWS = m
	return c
}

func TestSpokeCredsFor_SameAccount_ReturnsNil(t *testing.T) {
	m := new(MockAwsServiceWrapper)
	m.On("GetCallerAccount").Return("111111111111", nil)
	c := newTagAuthConsumer(m)
	creds, err := c.spokeCredsFor("111111111111")
	require.NoError(t, err)
	assert.Nil(t, creds)
}

func TestSpokeCredsFor_CrossAccount_AssumesSpokeAndCaches(t *testing.T) {
	m := new(MockAwsServiceWrapper)
	m.On("GetCallerAccount").Return("111111111111", nil)
	exp := time.Now().Add(time.Hour)
	m.On("AssumeRole", mock.MatchedBy(func(in *sts.AssumeRoleInput) bool {
		return *in.RoleArn == "arn:aws:iam::222222222222:role/aow-spoke"
	})).Return(&sts.AssumeRoleOutput{Credentials: &ststypes.Credentials{
		AccessKeyId: aws.String("AK"), SecretAccessKey: aws.String("SK"),
		SessionToken: aws.String("ST"), Expiration: &exp,
	}}, nil).Once()

	c := newTagAuthConsumer(m)
	creds1, err := c.spokeCredsFor("222222222222")
	require.NoError(t, err)
	require.NotNil(t, creds1)
	// Second call served from cache → AssumeRole still called Once.
	creds2, err := c.spokeCredsFor("222222222222")
	require.NoError(t, err)
	require.NotNil(t, creds2)
	m.AssertExpectations(t)
}

func TestSpokeCredsFor_Disabled_ReturnsNil(t *testing.T) {
	m := new(MockAwsServiceWrapper)
	c := NewAwsConsumer(&gtvcfg.Config{}) // CrossAccount nil
	c.AWS = m
	creds, err := c.spokeCredsFor("222222222222")
	require.NoError(t, err)
	assert.Nil(t, creds)
}

func TestSpokeCredsFor_CrossAccountOnly_TagAuthDisabled(t *testing.T) {
	// The spoke transport must work with tag-auth off: explicit role_mappings
	// can target member accounts without enabling the tag-auth fallback.
	m := new(MockAwsServiceWrapper)
	m.On("GetCallerAccount").Return("111111111111", nil)
	exp := time.Now().Add(time.Hour)
	m.On("AssumeRole", mock.MatchedBy(func(in *sts.AssumeRoleInput) bool {
		return *in.RoleArn == "arn:aws:iam::222222222222:role/aow-spoke"
	})).Return(&sts.AssumeRoleOutput{Credentials: &ststypes.Credentials{
		AccessKeyId: aws.String("AK"), SecretAccessKey: aws.String("SK"),
		SessionToken: aws.String("ST"), Expiration: &exp,
	}}, nil).Once()

	c := NewAwsConsumer(&gtvcfg.Config{
		CrossAccount: &gtvcfg.CrossAccount{
			Enabled: true, SpokeRoleName: "aow-spoke",
			SpokeSessionDuration: 15 * time.Minute,
		},
	})
	c.AWS = m
	creds, err := c.spokeCredsFor("222222222222")
	require.NoError(t, err)
	require.NotNil(t, creds)
	m.AssertExpectations(t)
}

// TestAssumeRole_CrossAccount_DirectTransport verifies that a cross-account
// assume (enabled + allowed) goes directly from hub to target with hub creds
// in a single STS AssumeRole call — the spoke role is never involved in
// AssumeRole, only in GetRoleTags reads.
func TestAssumeRole_CrossAccount_DirectTransport(t *testing.T) {
	m := new(MockAwsServiceWrapper)
	m.On("GetCallerIdentityInfo").Return("111111111111", false, nil)

	var captured *sts.AssumeRoleInput
	targetExp := time.Now().Add(time.Hour)
	m.On("AssumeRole", mock.MatchedBy(func(in *sts.AssumeRoleInput) bool {
		captured = in
		return *in.RoleArn == "arn:aws:iam::222222222222:role/app"
	})).Return(&sts.AssumeRoleOutput{Credentials: &ststypes.Credentials{
		AccessKeyId: aws.String("AK2"), SecretAccessKey: aws.String("SK2"),
		SessionToken: aws.String("ST2"), Expiration: &targetExp,
	}}, nil).Once()

	c := newTagAuthConsumer(m)
	creds, err := c.AssumeRole("arn:aws:iam::222222222222:role/app", "sess", nil, nil, nil, nil)
	require.NoError(t, err)
	assert.Equal(t, "AK2", *creds.AccessKeyId)
	require.NotNil(t, captured)
	assert.Equal(t, "arn:aws:iam::222222222222:role/app", *captured.RoleArn, "no spoke-role ARN should ever appear in an AssumeRole input")
	m.AssertExpectations(t) // exactly one AssumeRole call (Once()), so no spoke-role assume happened
}

// TestAssumeRoleCrossAccountDisabledFailsClosed verifies that AssumeRole hard-
// errors on a non-hub-account target when cross-account transport is
// disabled (or unconfigured) — it must never fall through to a direct assume.
func TestAssumeRoleCrossAccountDisabledFailsClosed(t *testing.T) {
	for name, cfg := range map[string]*gtvcfg.Config{
		"CrossAccount nil":            {},
		"CrossAccount explicit false": {CrossAccount: &gtvcfg.CrossAccount{Enabled: false}},
	} {
		t.Run(name, func(t *testing.T) {
			m := new(MockAwsServiceWrapper)
			m.On("GetCallerIdentityInfo").Return("111111111111", false, nil)
			c := NewAwsConsumer(cfg)
			c.AWS = m

			_, err := c.AssumeRole("arn:aws:iam::222222222222:role/app", "sess", nil, nil, nil, nil)
			require.Error(t, err)
			m.AssertNotCalled(t, "AssumeRole", mock.Anything)
		})
	}
}

// TestAssumeRoleUnparseableARNFailsClosed verifies a malformed role ARN is
// rejected before any STS call is made.
func TestAssumeRoleUnparseableARNFailsClosed(t *testing.T) {
	m := new(MockAwsServiceWrapper)
	c := NewAwsConsumer(&gtvcfg.Config{})
	c.AWS = m

	_, err := c.AssumeRole("not-an-arn", "sess", nil, nil, nil, nil)
	require.Error(t, err)
	m.AssertNotCalled(t, "AssumeRole", mock.Anything)
	m.AssertNotCalled(t, "GetCallerIdentityInfo")
}

// TestSpokeCredsFor_ClampsDurationOver1h verifies the hub->spoke assume never
// requests more than 3600s: the spoke hop is role chaining on Lambda and STS
// fails (not clamps) chained sessions over 1h, which would silently break
// cross-account tag-auth.
func TestSpokeCredsFor_ClampsDurationOver1h(t *testing.T) {
	m := new(MockAwsServiceWrapper)
	m.On("GetCallerAccount").Return("111111111111", nil)
	exp := time.Now().Add(time.Hour)
	var captured *sts.AssumeRoleInput
	m.On("AssumeRole", mock.MatchedBy(func(in *sts.AssumeRoleInput) bool {
		captured = in
		return *in.RoleArn == "arn:aws:iam::222222222222:role/aow-spoke"
	})).Return(&sts.AssumeRoleOutput{Credentials: &ststypes.Credentials{
		AccessKeyId: aws.String("AK"), SecretAccessKey: aws.String("SK"),
		SessionToken: aws.String("ST"), Expiration: &exp,
	}}, nil).Once()

	c := NewAwsConsumer(&gtvcfg.Config{
		CrossAccount: &gtvcfg.CrossAccount{
			Enabled: true, SpokeRoleName: "aow-spoke",
			SpokeSessionDuration: 2 * time.Hour,
		},
	})
	c.AWS = m
	_, err := c.spokeCredsFor("222222222222")
	require.NoError(t, err)
	require.NotNil(t, captured)
	assert.Equal(t, int32(3600), *captured.DurationSeconds)
}

// TestAssumeRoleCrossAccountNotAllowedFailsClosed verifies the consumer-level
// defense-in-depth allow-list check: enabled cross-account with a target
// account outside allowed_accounts must error before any STS call, even
// though the processor guards the same condition upstream.
func TestAssumeRoleCrossAccountNotAllowedFailsClosed(t *testing.T) {
	m := new(MockAwsServiceWrapper)
	m.On("GetCallerIdentityInfo").Return("111111111111", true, nil)
	c := NewAwsConsumer(&gtvcfg.Config{
		CrossAccount: &gtvcfg.CrossAccount{
			Enabled: true, SpokeRoleName: "aow-spoke",
			SpokeSessionDuration: 15 * time.Minute,
			AllowedAccounts:      []string{"333333333333"},
		},
	})
	c.AWS = m

	_, err := c.AssumeRole("arn:aws:iam::222222222222:role/app", "sess", nil, nil, nil, nil)
	require.Error(t, err)
	m.AssertNotCalled(t, "AssumeRole", mock.Anything)
}

// TestAssumeRoleClampBoundary pins the clamp threshold: with role-session
// creds, exactly 3600 passes through untouched and 3601 clamps to 3600.
func TestAssumeRoleClampBoundary(t *testing.T) {
	for name, tc := range map[string]struct {
		requested int32
		want      int32
	}{
		"exactly 3600 not clamped": {requested: 3600, want: 3600},
		"3601 clamped":             {requested: 3601, want: 3600},
	} {
		t.Run(name, func(t *testing.T) {
			m := new(MockAwsServiceWrapper)
			m.On("GetCallerIdentityInfo").Return("111111111111", true, nil)
			exp := time.Now().Add(time.Hour)
			var captured *sts.AssumeRoleInput
			m.On("AssumeRole", mock.MatchedBy(func(in *sts.AssumeRoleInput) bool {
				captured = in
				return true
			})).Return(&sts.AssumeRoleOutput{Credentials: &ststypes.Credentials{
				AccessKeyId: aws.String("AK"), SecretAccessKey: aws.String("SK"),
				SessionToken: aws.String("ST"), Expiration: &exp,
			}}, nil).Once()

			c := NewAwsConsumer(&gtvcfg.Config{})
			c.AWS = m
			dur := tc.requested
			_, err := c.AssumeRole("arn:aws:iam::111111111111:role/app", "sess", nil, &dur, nil, nil)
			require.NoError(t, err)
			require.NotNil(t, captured)
			assert.Equal(t, tc.want, *captured.DurationSeconds)
		})
	}
}

// TestGetRoleTagsCrossAccountDisabledFailsClosed verifies GetRoleTags refuses
// to read a member-account role's tags when cross-account transport is
// disabled — it must never silently read a same-named role in the hub
// account. Calling it twice must error both times with zero GetRole calls,
// confirming nothing was cached on the failure path.
func TestGetRoleTagsCrossAccountDisabledFailsClosed(t *testing.T) {
	m := new(MockAwsServiceWrapper)
	m.On("GetCallerAccount").Return("111111111111", nil)
	c := NewAwsConsumer(&gtvcfg.Config{}) // CrossAccount nil
	c.AWS = m

	_, err := c.GetRoleTags("arn:aws:iam::222222222222:role/app")
	require.Error(t, err)
	_, err = c.GetRoleTags("arn:aws:iam::222222222222:role/app")
	require.Error(t, err)

	m.AssertNotCalled(t, "GetRole", mock.Anything)
	m.AssertNotCalled(t, "GetRoleAs", mock.Anything, mock.Anything)
}

// ---------- transitive tags ----------

func TestAssumeRole_TransitiveTags_SameAccount(t *testing.T) {
	m := new(MockAwsServiceWrapper)
	m.On("GetCallerIdentityInfo").Return("111111111111", false, nil)
	var captured *sts.AssumeRoleInput
	m.On("AssumeRole", mock.MatchedBy(func(in *sts.AssumeRoleInput) bool {
		captured = in
		return true
	})).Return(&sts.AssumeRoleOutput{Credentials: &ststypes.Credentials{
		AccessKeyId: aws.String("AK"), SecretAccessKey: aws.String("SK"), SessionToken: aws.String("ST"),
	}}, nil).Once()

	cfg := &gtvcfg.Config{SessionTagsTransitive: true, TagAuth: &gtvcfg.TagAuth{Enabled: true, TagPrefix: "aow/"}}
	c := NewAwsConsumer(cfg)
	c.AWS = m
	claims := &gtypes.Claims{
		Repository: "acme/api", Actor: "deploy-bot", Ref: "refs/heads/main", EventName: "push",
		Raw: map[string]any{"repository": "acme/api", "actor": "deploy-bot", "ref": "refs/heads/main", "event_name": "push"},
	}

	_, err := c.AssumeRole("arn:aws:iam::111111111111:role/app", "sess", nil, nil, claims, defaultGitHubSessionTagsForTest)
	require.NoError(t, err)
	require.NotNil(t, captured)
	// All configured session tags are marked transitive, not just repo/ref/actor:
	// key names are operator-defined per issuer (repo-owner/ref-type are absent
	// here only because their source claims are empty on this test's Claims).
	assert.ElementsMatch(t, []string{"repo", "ref", "actor", "event-name"}, captured.TransitiveTagKeys)
}

// defaultGitHubSessionTagsForTest mirrors config.defaultGitHubIssuer's
// SessionTags spec (STS tag key -> raw claim name), used by tests that need
// BuildSessionTags to actually produce repo/ref/actor tags.
var defaultGitHubSessionTagsForTest = map[string]string{
	"repo":       "repository",
	"repo-owner": "repository_owner",
	"ref":        "ref",
	"ref-type":   "ref_type",
	"actor":      "actor",
	"event-name": "event_name",
}

func TestAssumeRole_TransitiveTags_DisabledByDefault(t *testing.T) {
	m := new(MockAwsServiceWrapper)
	m.On("GetCallerIdentityInfo").Return("111111111111", false, nil)
	var captured *sts.AssumeRoleInput
	m.On("AssumeRole", mock.MatchedBy(func(in *sts.AssumeRoleInput) bool {
		captured = in
		return true
	})).Return(&sts.AssumeRoleOutput{Credentials: &ststypes.Credentials{
		AccessKeyId: aws.String("AK"), SecretAccessKey: aws.String("SK"), SessionToken: aws.String("ST"),
	}}, nil).Once()

	cfg := &gtvcfg.Config{TagAuth: &gtvcfg.TagAuth{Enabled: true, TagPrefix: "aow/"}} // transitive off
	c := NewAwsConsumer(cfg)
	c.AWS = m
	claims := &gtypes.Claims{
		Repository: "acme/api", Actor: "deploy-bot", Ref: "refs/heads/main",
		Raw: map[string]any{"repository": "acme/api", "actor": "deploy-bot", "ref": "refs/heads/main"},
	}

	_, err := c.AssumeRole("arn:aws:iam::111111111111:role/app", "sess", nil, nil, claims, defaultGitHubSessionTagsForTest)
	require.NoError(t, err)
	require.NotNil(t, captured)
	assert.Empty(t, captured.TransitiveTagKeys)
}

// TestAssumeRoleClampRoleSession verifies that when the warden's own creds
// are a role session, a requested duration over 1h is clamped to 3600 —
// regardless of whether the target account is the hub or a cross-account
// member. Role chaining is a property of the source creds, not the target
// account: AssumeRole always goes direct hub -> target (1 hop) with hub
// creds, so the clamp must apply the same way in both cases.
func TestAssumeRoleClampRoleSession(t *testing.T) {
	t.Run("same account", func(t *testing.T) {
		m := new(MockAwsServiceWrapper)
		m.On("GetCallerIdentityInfo").Return("111111111111", true, nil)
		var captured *sts.AssumeRoleInput
		m.On("AssumeRole", mock.MatchedBy(func(in *sts.AssumeRoleInput) bool {
			captured = in
			return true
		})).Return(&sts.AssumeRoleOutput{Credentials: &ststypes.Credentials{
			AccessKeyId: aws.String("AK"), SecretAccessKey: aws.String("SK"), SessionToken: aws.String("ST"),
		}}, nil).Once()

		cfg := &gtvcfg.Config{TagAuth: &gtvcfg.TagAuth{Enabled: true, TagPrefix: "aow/"}}
		c := NewAwsConsumer(cfg)
		c.AWS = m

		var requested int32 = 7200
		_, err := c.AssumeRole("arn:aws:iam::111111111111:role/app", "sess", nil, &requested, nil, nil)
		require.NoError(t, err)
		require.NotNil(t, captured)
		require.NotNil(t, captured.DurationSeconds)
		assert.Equal(t, int32(3600), *captured.DurationSeconds)
	})

	t.Run("cross account", func(t *testing.T) {
		m := new(MockAwsServiceWrapper)
		m.On("GetCallerIdentityInfo").Return("111111111111", true, nil)
		var captured *sts.AssumeRoleInput
		m.On("AssumeRole", mock.MatchedBy(func(in *sts.AssumeRoleInput) bool {
			captured = in
			return *in.RoleArn == "arn:aws:iam::222222222222:role/app"
		})).Return(&sts.AssumeRoleOutput{Credentials: &ststypes.Credentials{
			AccessKeyId: aws.String("AK2"), SecretAccessKey: aws.String("SK2"), SessionToken: aws.String("ST2"),
		}}, nil).Once()

		cfg := &gtvcfg.Config{
			TagAuth: &gtvcfg.TagAuth{Enabled: true, TagPrefix: "aow/"},
			CrossAccount: &gtvcfg.CrossAccount{
				Enabled: true, SpokeRoleName: "aow-spoke",
				SpokeSessionDuration: 15 * time.Minute,
			},
		}
		c := NewAwsConsumer(cfg)
		c.AWS = m

		var requested int32 = 7200 // > 1h; must be clamped
		_, err := c.AssumeRole("arn:aws:iam::222222222222:role/app", "sess", nil, &requested, nil, nil)
		require.NoError(t, err)
		require.NotNil(t, captured)
		require.NotNil(t, captured.DurationSeconds)
		assert.Equal(t, int32(3600), *captured.DurationSeconds)
	})
}

// TestAssumeRoleNoClampIAMUser verifies the clamp does not apply when the
// warden's own creds are an IAM user (local mode, not role-chained): the
// requested duration is preserved for both same-account and cross-account
// (enabled+allowed) targets.
func TestAssumeRoleNoClampIAMUser(t *testing.T) {
	t.Run("same account", func(t *testing.T) {
		m := new(MockAwsServiceWrapper)
		m.On("GetCallerIdentityInfo").Return("111111111111", false, nil)
		var captured *sts.AssumeRoleInput
		m.On("AssumeRole", mock.MatchedBy(func(in *sts.AssumeRoleInput) bool {
			captured = in
			return true
		})).Return(&sts.AssumeRoleOutput{Credentials: &ststypes.Credentials{
			AccessKeyId: aws.String("AK"), SecretAccessKey: aws.String("SK"), SessionToken: aws.String("ST"),
		}}, nil).Once()

		cfg := &gtvcfg.Config{TagAuth: &gtvcfg.TagAuth{Enabled: true, TagPrefix: "aow/"}}
		c := NewAwsConsumer(cfg)
		c.AWS = m

		var requested int32 = 7200
		_, err := c.AssumeRole("arn:aws:iam::111111111111:role/app", "sess", nil, &requested, nil, nil)
		require.NoError(t, err)
		require.NotNil(t, captured)
		require.NotNil(t, captured.DurationSeconds)
		assert.Equal(t, int32(7200), *captured.DurationSeconds)
	})

	t.Run("cross account", func(t *testing.T) {
		m := new(MockAwsServiceWrapper)
		m.On("GetCallerIdentityInfo").Return("111111111111", false, nil)
		var captured *sts.AssumeRoleInput
		m.On("AssumeRole", mock.MatchedBy(func(in *sts.AssumeRoleInput) bool {
			captured = in
			return *in.RoleArn == "arn:aws:iam::222222222222:role/app"
		})).Return(&sts.AssumeRoleOutput{Credentials: &ststypes.Credentials{
			AccessKeyId: aws.String("AK2"), SecretAccessKey: aws.String("SK2"), SessionToken: aws.String("ST2"),
		}}, nil).Once()

		cfg := &gtvcfg.Config{
			TagAuth: &gtvcfg.TagAuth{Enabled: true, TagPrefix: "aow/"},
			CrossAccount: &gtvcfg.CrossAccount{
				Enabled: true, SpokeRoleName: "aow-spoke",
				SpokeSessionDuration: 15 * time.Minute,
			},
		}
		c := NewAwsConsumer(cfg)
		c.AWS = m

		var requested int32 = 7200
		_, err := c.AssumeRole("arn:aws:iam::222222222222:role/app", "sess", nil, &requested, nil, nil)
		require.NoError(t, err)
		require.NotNil(t, captured)
		require.NotNil(t, captured.DurationSeconds)
		assert.Equal(t, int32(7200), *captured.DurationSeconds)
	})
}
