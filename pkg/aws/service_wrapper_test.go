package aws

import (
	"bytes"
	"errors"
	"io"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
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
