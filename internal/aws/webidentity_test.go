package aws

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"
	gtvcfg "github.com/boogy/aws-oidc-warden/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const webIdentityOK = `<AssumeRoleWithWebIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><AssumeRoleWithWebIdentityResult>
<Credentials><AccessKeyId>AKIAEXAMPLE</AccessKeyId><SecretAccessKey>SECRETEXAMPLEwJalr</SecretAccessKey><SessionToken>SESSIONTOKENEXAMPLEFwoG</SessionToken><Expiration>2030-01-01T00:00:00Z</Expiration></Credentials>
</AssumeRoleWithWebIdentityResult></AssumeRoleWithWebIdentityResponse>`

const webIdentityNoCreds = `<AssumeRoleWithWebIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><AssumeRoleWithWebIdentityResult>
</AssumeRoleWithWebIdentityResult></AssumeRoleWithWebIdentityResponse>`

func webIdentityWrapper(t *testing.T, handler http.HandlerFunc) *AwsServiceWrapper {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return &AwsServiceWrapper{
		defaultTimeout: 5 * time.Second,
		stsClient: sts.New(sts.Options{
			Region:       "us-east-1",
			BaseEndpoint: aws.String(srv.URL),
			Credentials:  credentials.NewStaticCredentialsProvider("AKIAFAKE", "secret", "tok"),
		}),
		getCallerIdentityFn: hubIdentity,
	}
}

func hubIdentity(context.Context) (*sts.GetCallerIdentityOutput, error) {
	return &sts.GetCallerIdentityOutput{Account: aws.String("111111111111"), Arn: aws.String("arn:aws:iam::111111111111:user/warden")}, nil
}

func xmlHandler(body string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/xml")
		_, _ = w.Write([]byte(body))
	}
}

const testRoleARN = "arn:aws:iam::111111111111:role/Target"

func TestAssumeRoleWithWebIdentityUnsigned(t *testing.T) {
	w := webIdentityWrapper(t, func(rw http.ResponseWriter, r *http.Request) {
		assert.Empty(t, r.Header.Get("Authorization"))
		assert.Empty(t, r.Header.Get("X-Amz-Security-Token"))
		xmlHandler(webIdentityOK)(rw, r)
	})
	c := &AwsConsumer{AWS: w}
	creds, err := c.AssumeRoleWithWebIdentity(context.Background(), testRoleARN, "sess", "tok", nil, 3600)
	require.NoError(t, err)
	assert.Equal(t, "AKIAEXAMPLE", *creds.AccessKeyId)
}

func TestAssumeRoleWithWebIdentityPassesDurationPolicyName(t *testing.T) {
	var got map[string]string
	w := webIdentityWrapper(t, func(rw http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())
		got = map[string]string{}
		for k := range r.PostForm {
			got[k] = r.PostForm.Get(k)
		}
		xmlHandler(webIdentityOK)(rw, r)
	})
	c := &AwsConsumer{AWS: w}
	_, err := c.AssumeRoleWithWebIdentity(context.Background(), testRoleARN, "sess", "jwt-token", aws.String(`{"p":1}`), 7200)
	require.NoError(t, err)
	assert.Equal(t, "7200", got["DurationSeconds"])
	assert.Equal(t, `{"p":1}`, got["Policy"])
	assert.Equal(t, "sess", got["RoleSessionName"])
	assert.Equal(t, "jwt-token", got["WebIdentityToken"])
	assert.Equal(t, testRoleARN, got["RoleArn"])
}

func TestAssumeRoleWithWebIdentityOmitsEmptyPolicy(t *testing.T) {
	tests := []struct {
		name   string
		policy *string
	}{
		{"nil", nil},
		{"empty", aws.String("")},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var hasPolicy bool
			w := webIdentityWrapper(t, func(rw http.ResponseWriter, r *http.Request) {
				require.NoError(t, r.ParseForm())
				_, hasPolicy = r.PostForm["Policy"]
				xmlHandler(webIdentityOK)(rw, r)
			})
			c := &AwsConsumer{AWS: w}
			_, err := c.AssumeRoleWithWebIdentity(context.Background(), testRoleARN, "sess", "tok", tc.policy, 3600)
			require.NoError(t, err)
			assert.False(t, hasPolicy)
		})
	}
}

func wiErr(code, msg string) error {
	return &smithy.GenericAPIError{Code: code, Message: msg}
}

func TestClassifyWebIdentityError(t *testing.T) {
	markers := []error{ErrWebIdentityDenied, ErrWebIdentityUnavailable, ErrWebIdentityDurationExceedsRoleMax, ErrWebIdentityPackedPolicyTooLarge}
	tests := []struct {
		name string
		err  error
		want error
	}{
		{"AccessDenied", wiErr("AccessDenied", "Not authorized to perform sts:AssumeRoleWithWebIdentity"), ErrWebIdentityDenied},
		{"AccessDeniedException", wiErr("AccessDeniedException", "Not authorized"), ErrWebIdentityDenied},
		{"IDPRejectedClaim", wiErr("IDPRejectedClaim", "Incorrect token audience"), ErrWebIdentityDenied},
		{"ExpiredToken", wiErr("ExpiredTokenException", "Token expired"), ErrWebIdentityUnavailable},
		{"verification key retrieve", wiErr("InvalidIdentityToken", "Couldn't retrieve verification key from your identity provider, please reference AssumeRoleWithWebIdentity documentation for requirements"), ErrWebIdentityUnavailable},
		{"Could not fetch OpenID configuration", wiErr("InvalidIdentityToken", "Could not fetch OpenID configuration"), ErrWebIdentityUnavailable},
		{"Unable to retrieve JWKS", wiErr("InvalidIdentityToken", "Unable to retrieve JWKS"), ErrWebIdentityUnavailable},
		{"no verification key found", wiErr("InvalidIdentityToken", "no verification key found"), ErrWebIdentityUnavailable},
		{"No OIDC provider", wiErr("InvalidIdentityToken", "No OpenIDConnect provider found in your account for https://x"), ErrWebIdentityDenied},
		{"IDPCommunicationError", wiErr("IDPCommunicationError", "Error communicating with IDP"), ErrWebIdentityUnavailable},
		{"duration exceeds role max", wiErr("ValidationError", "1 validation error detected: Value '43200' at 'durationSeconds' failed to satisfy constraint: Member must have value less than or equal to 3600. DurationSeconds exceeds the MaxSessionDuration set for this role."), ErrWebIdentityDurationExceedsRoleMax},
		{"ValidationError without MaxSessionDuration", wiErr("ValidationError", "Value at 'durationSeconds' failed: DurationSeconds is invalid"), nil},
		{"PackedPolicyTooLarge", wiErr("PackedPolicyTooLarge", "Packed policy too large"), ErrWebIdentityPackedPolicyTooLarge},
		{"Throttling", wiErr("ThrottlingException", "Rate exceeded"), nil},
		{"non-API", errors.New("boom"), nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := classifyWebIdentityError(tc.err)
			require.Error(t, got)
			for _, m := range markers {
				if m == tc.want {
					assert.ErrorIs(t, got, m)
				} else {
					assert.NotErrorIs(t, got, m)
				}
			}
			assert.ErrorIs(t, got, tc.err)
		})
	}
}

func TestSTSClientNoRequestBodyLogging(t *testing.T) {
	w := NewAwsServiceWrapper()
	assert.Zero(t, w.stsClient.Options().ClientLogMode&aws.LogRequestWithBody)
}

func TestAssumeRoleWithWebIdentityRequiresArgs(t *testing.T) {
	tests := []struct{ name, role, sess, token string }{
		{"empty role", "", "s", "t"},
		{"empty session", testRoleARN, "", "t"},
		{"empty token", testRoleARN, "s", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			w := webIdentityWrapper(t, func(rw http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				xmlHandler(webIdentityOK)(rw, r)
			})
			c := &AwsConsumer{AWS: w}
			_, err := c.AssumeRoleWithWebIdentity(context.Background(), tc.role, tc.sess, tc.token, nil, 3600)
			require.Error(t, err)
			assert.Zero(t, calls.Load())
		})
	}
}

func TestAssumeRoleWithWebIdentityAccountCheck(t *testing.T) {
	const memberRole = "arn:aws:iam::222222222222:role/Target"
	tests := []struct {
		name    string
		role    string
		cfg     *gtvcfg.Config
		allowed bool
	}{
		{"cross_account unset", memberRole, &gtvcfg.Config{}, false},
		{"cross_account disabled", memberRole, &gtvcfg.Config{CrossAccount: &gtvcfg.CrossAccount{AllowedAccounts: []string{"222222222222"}}}, false},
		{"account not listed", memberRole, &gtvcfg.Config{CrossAccount: &gtvcfg.CrossAccount{Enabled: true, AllowedAccounts: []string{"333333333333"}}}, false},
		{"account listed", memberRole, &gtvcfg.Config{CrossAccount: &gtvcfg.CrossAccount{Enabled: true, AllowedAccounts: []string{"222222222222"}}}, true},
		{"empty allow-list permits any account", memberRole, &gtvcfg.Config{CrossAccount: &gtvcfg.CrossAccount{Enabled: true}}, true},
		{"hub account with cross_account unset", testRoleARN, &gtvcfg.Config{}, true},
		{"hub account not listed", testRoleARN, &gtvcfg.Config{CrossAccount: &gtvcfg.CrossAccount{Enabled: true, AllowedAccounts: []string{"222222222222"}}}, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			w := webIdentityWrapper(t, func(rw http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				xmlHandler(webIdentityOK)(rw, r)
			})
			c := &AwsConsumer{AWS: w, Config: tc.cfg}
			creds, err := c.AssumeRoleWithWebIdentity(context.Background(), tc.role, "s", "t", nil, 3600)
			if tc.allowed {
				require.NoError(t, err)
				assert.NotNil(t, creds)
				assert.EqualValues(t, 1, calls.Load())
				return
			}
			require.ErrorIs(t, err, ErrAccountNotAllowed)
			assert.Zero(t, calls.Load())
		})
	}
}

func TestAssumeRoleWithWebIdentityNilCredentials(t *testing.T) {
	w := webIdentityWrapper(t, xmlHandler(webIdentityNoCreds))
	c := &AwsConsumer{AWS: w}
	_, err := c.AssumeRoleWithWebIdentity(context.Background(), testRoleARN, "s", "t", nil, 3600)
	require.Error(t, err)
}

func TestProductionSTSClientIsUnsigned(t *testing.T) {
	var sawRequest atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		sawRequest.Store(true)
		assert.Empty(t, r.Header.Get("Authorization"))
		assert.Empty(t, r.Header.Get("X-Amz-Security-Token"))
		xmlHandler(webIdentityOK)(rw, r)
	}))
	t.Cleanup(srv.Close)
	t.Setenv("AWS_ENDPOINT_URL_STS", srv.URL)
	t.Setenv("AWS_REGION", "us-east-1")
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIAFAKE")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	t.Setenv("AWS_SESSION_TOKEN", "tok")

	prevWrapper := wrapper
	initOnce, wrapper = sync.Once{}, nil
	t.Cleanup(func() { initOnce, wrapper = sync.Once{}, prevWrapper })

	tests := []struct {
		name  string
		build func() *AwsServiceWrapper
	}{
		{"NewAwsServiceWrapper", NewAwsServiceWrapper},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sawRequest.Store(false)
			w := tc.build()
			w.getCallerIdentityFn = hubIdentity
			c := &AwsConsumer{AWS: w}
			_, err := c.AssumeRoleWithWebIdentity(context.Background(), testRoleARN, "sess", "tok", nil, 3600)
			require.NoError(t, err)
			assert.True(t, sawRequest.Load())
		})
	}
}
