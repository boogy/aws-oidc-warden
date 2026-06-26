package aws

import (
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
	gtvcfg "github.com/boogy/aws-oidc-warden/pkg/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func newTagAuthConsumer(m *MockAwsServiceWrapper) *AwsConsumer {
	cfg := &gtvcfg.Config{TagAuth: &gtvcfg.TagAuth{
		Enabled: true, TagPrefix: "aow/", SpokeRoleName: "aow-spoke",
		SpokeSessionDuration: 15 * time.Minute,
	}}
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
	c := NewAwsConsumer(&gtvcfg.Config{}) // TagAuth nil
	c.AWS = m
	creds, err := c.spokeCredsFor("222222222222")
	require.NoError(t, err)
	assert.Nil(t, creds)
}
