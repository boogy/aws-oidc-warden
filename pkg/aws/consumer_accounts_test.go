package aws

import (
	"testing"

	gtvcfg "github.com/boogy/aws-oidc-warden/pkg/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func consumerWithAllowed(m *MockAwsServiceWrapper, allowed []string) *AwsConsumer {
	cfg := &gtvcfg.Config{TagAuth: &gtvcfg.TagAuth{
		Enabled: true, TagPrefix: "aow/", SpokeRoleName: "aow-spoke", AllowedAccounts: allowed,
	}}
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

func TestIsTargetAccountAllowed_TagAuthDisabled(t *testing.T) {
	m := new(MockAwsServiceWrapper)
	c := NewAwsConsumer(&gtvcfg.Config{}) // TagAuth nil
	c.AWS = m
	ok, err := c.IsTargetAccountAllowed("arn:aws:iam::222222222222:role/app")
	require.NoError(t, err)
	assert.True(t, ok) // no cross-account possible; nothing to gate
}
