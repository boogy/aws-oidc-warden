package aws

import (
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

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
