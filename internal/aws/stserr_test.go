package aws

import (
	"errors"
	"fmt"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/sts"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
	"github.com/aws/smithy-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func apiErr(code string) error {
	return &smithy.GenericAPIError{Code: code, Message: "not authorized to perform: sts:AssumeRole"}
}

func TestClassifyAssumeRoleError(t *testing.T) {
	tests := []struct {
		name   string
		err    error
		denied bool
	}{
		{"trust policy refusal", apiErr("AccessDenied"), true},
		{"exception spelling", apiErr("AccessDeniedException"), true},
		{"case variant, as the SDK itself tolerates", apiErr("accessDenied"), true},
		{"already wrapped by the SDK", fmt.Errorf("operation error STS: %w", apiErr("AccessDenied")), true},
		{"throttling is retryable, not a denial", apiErr("ThrottlingException"), false},
		{"expired broker credentials", apiErr("ExpiredToken"), false},
		{"modelled policy fault", &ststypes.MalformedPolicyDocumentException{}, false},
		{"transport failure", errors.New("dial tcp: i/o timeout"), false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := classifyAssumeRoleError(tc.err)
			assert.Equal(t, tc.denied, errors.Is(got, ErrAssumeRoleDenied))
			// The original STS error must stay reachable either way: it is the
			// only thing that separates a trust-policy refusal from a missing
			// sts:TagSession on the broker's own role.
			assert.ErrorIs(t, got, tc.err)
		})
	}
}

func TestSTSErrorCode(t *testing.T) {
	assert.Equal(t, "AccessDenied", stsErrorCode(fmt.Errorf("wrapped: %w", apiErr("AccessDenied"))))
	assert.Equal(t, "MalformedPolicyDocument", stsErrorCode(&ststypes.MalformedPolicyDocumentException{}))
	assert.Empty(t, stsErrorCode(errors.New("plain")))
}

// failingFake overrides vFake.AssumeRole with an injected STS failure.
type failingFake struct {
	*vFake
	err error
}

func (f *failingFake) AssumeRole(*sts.AssumeRoleInput) (*sts.AssumeRoleOutput, error) {
	f.assumeCalls++
	return nil, f.err
}

func assumeWithSTSError(t *testing.T, stsErr error) error {
	t.Helper()
	c := NewAwsConsumer(vbaseCfg())
	c.AWS = &failingFake{vFake: &vFake{}, err: stsErr}
	_, err := c.AssumeRole("arn:aws:iam::"+hubAcct+":role/Target", "aow", nil, nil, nil, nil)
	require.Error(t, err)
	return err
}

func TestAssumeRolePropagatesDenial(t *testing.T) {
	err := assumeWithSTSError(t, apiErr("AccessDenied"))
	assert.ErrorIs(t, err, ErrAssumeRoleDenied)
	assert.Contains(t, err.Error(), "unable to perform sts.AssumeRole")
}

func TestAssumeRoleInfraErrorIsNotADenial(t *testing.T) {
	err := assumeWithSTSError(t, apiErr("ThrottlingException"))
	assert.NotErrorIs(t, err, ErrAssumeRoleDenied)
}
