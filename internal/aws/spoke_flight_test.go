package aws

import (
	"context"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// gatedSTS blocks AssumeRole for gated accounts until release is closed.
type gatedSTS struct {
	*MockAwsServiceWrapper
	calls   atomic.Int32
	entered chan string
	release chan struct{}
	gated   string
}

func (g *gatedSTS) GetCallerAccount(context.Context) (string, error) { return "111111111111", nil }

func (g *gatedSTS) AssumeRole(_ context.Context, in *sts.AssumeRoleInput) (*sts.AssumeRoleOutput, error) {
	g.calls.Add(1)
	if g.gated != "" && strings.Contains(*in.RoleArn, ":"+g.gated+":") {
		g.entered <- g.gated
		<-g.release
	}
	exp := time.Now().Add(time.Hour)
	return &sts.AssumeRoleOutput{Credentials: &ststypes.Credentials{
		AccessKeyId: aws.String("AK"), SecretAccessKey: aws.String("SK"),
		SessionToken: aws.String("ST"), Expiration: &exp,
	}}, nil
}

func TestSpokeCredsFor_ConcurrentCallersShareOneAssume(t *testing.T) {
	g := &gatedSTS{MockAwsServiceWrapper: new(MockAwsServiceWrapper), entered: make(chan string, 64), release: make(chan struct{}), gated: "222222222222"}
	c := newTagAuthConsumer(g.MockAwsServiceWrapper)
	c.AWS = g

	const n = 20
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p, err := c.spokeCredsFor(context.Background(), "222222222222")
			if err == nil && p == nil {
				err = assert.AnError
			}
			errs <- err
		}()
	}
	<-g.entered
	time.Sleep(20 * time.Millisecond)
	close(g.release)
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}
	assert.Equal(t, int32(1), g.calls.Load(), "callers stampeded STS instead of sharing one AssumeRole")
}

func TestSpokeCredsFor_CacheHitsNotBlockedByInFlightAssume(t *testing.T) {
	g := &gatedSTS{MockAwsServiceWrapper: new(MockAwsServiceWrapper), entered: make(chan string, 4), release: make(chan struct{})}
	c := newTagAuthConsumer(g.MockAwsServiceWrapper)
	c.AWS = g

	_, err := c.spokeCredsFor(context.Background(), "333333333333")
	require.NoError(t, err)

	g.gated = "222222222222"
	done := make(chan error, 1)
	go func() {
		_, err := c.spokeCredsFor(context.Background(), "222222222222")
		done <- err
	}()
	<-g.entered

	hit := make(chan error, 1)
	go func() {
		_, err := c.spokeCredsFor(context.Background(), "333333333333")
		hit <- err
	}()
	select {
	case err := <-hit:
		require.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("cache hit blocked behind another account's in-flight AssumeRole")
	}
	close(g.release)
	require.NoError(t, <-done)
}

func TestSpokeCredsFor_CancelledCallerDoesNotFailOthers(t *testing.T) {
	g := &gatedSTS{MockAwsServiceWrapper: new(MockAwsServiceWrapper), entered: make(chan string, 4), release: make(chan struct{}), gated: "222222222222"}
	c := newTagAuthConsumer(g.MockAwsServiceWrapper)
	c.AWS = g

	cctx, cancel := context.WithCancel(context.Background())
	first := make(chan error, 1)
	go func() {
		_, err := c.spokeCredsFor(cctx, "222222222222")
		first <- err
	}()
	<-g.entered

	second := make(chan error, 1)
	go func() {
		_, err := c.spokeCredsFor(context.Background(), "222222222222")
		second <- err
	}()
	time.Sleep(20 * time.Millisecond)
	cancel()
	require.ErrorIs(t, <-first, context.Canceled)

	close(g.release)
	require.NoError(t, <-second)
	assert.Equal(t, int32(1), g.calls.Load())
}

type sliceCreds struct{ parts []string }

func (sliceCreds) Retrieve(context.Context) (aws.Credentials, error) { return aws.Credentials{}, nil }

func TestIAMClientFor_ReusesClientPerCredentials(t *testing.T) {
	w := &AwsServiceWrapper{}
	static := func(ak string) aws.CredentialsProvider {
		p := credentials.NewStaticCredentialsProvider(ak, "SK", "ST")
		return &p
	}
	a, b := static("AK"), static("AK2")

	assert.Same(t, w.iamClientFor(a), w.iamClientFor(a), "the same provider should reuse its client")
	assert.NotSame(t, w.iamClientFor(a), w.iamClientFor(b))
	assert.NotSame(t, w.iamClientFor(a), w.iamClientFor(credentials.NewStaticCredentialsProvider("AK", "SK", "ST")),
		"value providers are not comparable and are not cached")

	assert.NotPanics(t, func() { w.iamClientFor(sliceCreds{parts: []string{"x"}}) })
	assert.NotSame(t, w.iamClientFor(sliceCreds{}), w.iamClientFor(sliceCreds{}), "non-comparable providers are not cached")
}

func TestIAMClientFor_CacheIsBounded(t *testing.T) {
	w := &AwsServiceWrapper{}
	for i := range 3 * maxCachedIAMClients {
		p := credentials.NewStaticCredentialsProvider(strconv.Itoa(i), "SK", "ST")
		w.iamClientFor(&p)
	}
	assert.LessOrEqual(t, len(w.iamClients), maxCachedIAMClients)
}
