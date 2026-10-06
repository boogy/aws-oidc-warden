package aws

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

const missRole = "arn:aws:iam::111111111111:role/gone"

func newMissConsumer(m *MockAwsServiceWrapper) (*AwsConsumer, *time.Time) {
	m.On("GetCallerAccount", mock.Anything).Return("111111111111", nil)
	c := newTagAuthConsumer(m)
	clock := time.Now()
	c.now = func() time.Time { return clock }
	return c, &clock
}

func TestGetRoleTags_NoSuchEntityIsNegativelyCached(t *testing.T) {
	m := new(MockAwsServiceWrapper)
	c, clock := newMissConsumer(m)
	nse := &iamtypes.NoSuchEntityException{Message: errStr("no such role")}
	m.On("GetRole", mock.Anything, mock.Anything).Return(nil, nse)

	for range 3 {
		_, err := c.GetRoleTags(context.Background(), missRole)
		var got *iamtypes.NoSuchEntityException
		require.ErrorAs(t, err, &got)
	}
	m.AssertNumberOfCalls(t, "GetRole", 1)

	*clock = clock.Add(roleMissTTL + time.Second)
	_, err := c.GetRoleTags(context.Background(), missRole)
	require.Error(t, err)
	m.AssertNumberOfCalls(t, "GetRole", 2)
}

func TestGetRoleTags_TransientErrorsAreNotCached(t *testing.T) {
	tests := []struct {
		name string
		err  error
	}{
		{"throttling", errors.New("Throttling: rate exceeded")},
		{"network", errors.New("dial tcp: i/o timeout")},
		{"service failure", &iamtypes.ServiceFailureException{Message: errStr("boom")}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := new(MockAwsServiceWrapper)
			c, _ := newMissConsumer(m)
			m.On("GetRole", mock.Anything, mock.Anything).Return(nil, tt.err)

			for range 2 {
				_, err := c.GetRoleTags(context.Background(), missRole)
				require.Error(t, err)
			}
			m.AssertNumberOfCalls(t, "GetRole", 2)
			assert.Empty(t, c.roleMissCache)
		})
	}
}

func TestGetRoleTags_NegativeCacheDoesNotBypassAccountCheck(t *testing.T) {
	m := new(MockAwsServiceWrapper)
	c, clock := newMissConsumer(m)
	c.Config.CrossAccount.AllowedAccounts = []string{"999999999999"}
	const blocked = "arn:aws:iam::222222222222:role/gone"
	c.roleMissCache = map[string]cachedMiss{blocked: {err: errors.New("cached miss"), expires: clock.Add(time.Minute)}}

	_, err := c.GetRoleTags(context.Background(), blocked)
	require.ErrorContains(t, err, "not allowed")
	m.AssertNotCalled(t, "GetRole", mock.Anything, mock.Anything)
}

func TestGetRoleTags_NegativeCacheIsBounded(t *testing.T) {
	m := new(MockAwsServiceWrapper)
	c, clock := newMissConsumer(m)
	c.roleMissCache = make(map[string]cachedMiss)
	for i := range maxRoleMisses {
		c.roleMissCache[fmt.Sprintf("arn:aws:iam::111111111111:role/r%d", i)] = cachedMiss{err: errors.New("x"), expires: clock.Add(time.Hour)}
	}
	m.On("GetRole", mock.Anything, mock.Anything).Return(nil, &iamtypes.NoSuchEntityException{Message: errStr("no")}).Once()

	_, err := c.GetRoleTags(context.Background(), missRole)
	require.Error(t, err)
	assert.Len(t, c.roleMissCache, 1, "map is cleared when full, then holds only the new miss")
	assert.Contains(t, c.roleMissCache, missRole)
}

func errStr(s string) *string { return &s }
