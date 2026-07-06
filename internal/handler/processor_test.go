package handler_test

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
	"github.com/boogy/aws-oidc-warden/internal/config"
	"github.com/boogy/aws-oidc-warden/internal/handler"
	"github.com/boogy/aws-oidc-warden/internal/types"
	"github.com/boogy/aws-oidc-warden/internal/validator"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testIssuer = "https://token.actions.githubusercontent.com"

// fixedExtractor returns a fixed set of claims without touching any token.
type fixedExtractor struct{ claims *types.Claims }

func (f *fixedExtractor) Extract(_ context.Context, _ validator.ExtractionInput) (*types.Claims, error) {
	return f.claims, nil
}

// staticProvider builds a config.Provider that maps "org/repo" → "arn:aws:iam::123456789012:role/MyRole".
func staticProvider(t *testing.T) *config.Provider {
	t.Helper()
	cfg := &config.Config{
		Issuers: []config.IssuerConfig{{
			Issuer:    testIssuer,
			Provider:  "github",
			Audiences: []string{"sts.amazonaws.com"},
		}},
		RoleSessionName: "test",
		Cache:           &config.Cache{TTL: 0},
		RoleMappings: []config.RoleMapping{{
			Subject: "org/repo",
			Roles:   []string{"arn:aws:iam::123456789012:role/MyRole"},
		}},
	}
	require.NoError(t, cfg.Validate())
	return config.NewStaticProvider(cfg)
}

// mockConsumer returns a fakeConsumer that successfully assumes any role.
func mockConsumer(t *testing.T) *fakeConsumer {
	t.Helper()
	exp := time.Now().Add(time.Hour)
	return &fakeConsumer{
		assumeOut: &ststypes.Credentials{
			AccessKeyId:     aws.String("AKID"),
			SecretAccessKey: aws.String("SECRET"),
			SessionToken:    aws.String("TOKEN"),
			Expiration:      &exp,
		},
		allowAccount: true,
	}
}

func TestProcessRequest_DelegatedMode(t *testing.T) {
	// extractor returns fixed claims without touching a token (delegated/apigw mode)
	ex := &fixedExtractor{claims: &types.Claims{
		RegisteredClaims: jwt.RegisteredClaims{Issuer: testIssuer, Subject: "org/repo"},
		Repository:       "org/repo",
		Ref:              "refs/heads/main",
		Actor:            "octocat",
	}}
	proc := handler.NewRequestProcessor(staticProvider(t), mockConsumer(t), ex, nil, "test")
	creds, err := proc.ProcessRequest(
		context.Background(),
		&handler.RequestData{Role: "arn:aws:iam::123456789012:role/MyRole"},
		validator.ExtractionInput{AuthorizerClaims: map[string]string{"repository": "org/repo"}},
		"req-123",
		slog.Default(),
	)
	require.NoError(t, err)
	assert.NotNil(t, creds)
}
