package handler_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsiam "github.com/aws/aws-sdk-go-v2/service/iam"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
	"github.com/boogy/aws-oidc-warden/pkg/config"
	"github.com/boogy/aws-oidc-warden/pkg/handler"
	"github.com/boogy/aws-oidc-warden/pkg/types"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type tagModeValidator struct{ claims *types.GithubClaims }

func (v *tagModeValidator) Validate(string) (*types.GithubClaims, error)   { return v.claims, nil }
func (v *tagModeValidator) ParseToken(string) (*types.GithubClaims, error) { return v.claims, nil }
func (v *tagModeValidator) FetchJWKS(string) (*types.JWKS, error)          { return nil, nil }
func (v *tagModeValidator) GenKeyFunc(*types.JWKS) jwt.Keyfunc             { return nil }

type fakeConsumer struct {
	tags         map[string]string
	tagsErr      error
	assumed      string
	gotClaims    *types.GithubClaims // claims passed to AssumeRole → drive session tags (ABAC)
	assumeOut    *ststypes.Credentials
	allowAccount bool
}

func (f *fakeConsumer) ReadS3Configuration() error { return nil }
func (f *fakeConsumer) GetS3Object(string, string) (io.ReadCloser, error) {
	return nil, errors.New("not used")
}
func (f *fakeConsumer) GetRole(string) (*awsiam.GetRoleOutput, error) { return nil, nil }
func (f *fakeConsumer) GetRoleTags(string) (map[string]string, error) { return f.tags, f.tagsErr }
func (f *fakeConsumer) IsTargetAccountAllowed(string) (bool, error)   { return f.allowAccount, nil }
func (f *fakeConsumer) AssumeRole(roleARN, _ string, _ *string, _ *int32, claims *types.GithubClaims) (*ststypes.Credentials, error) {
	f.assumed = roleARN
	f.gotClaims = claims
	return f.assumeOut, nil
}

func baseTagCfg(t *testing.T) *config.Config {
	cfg := &config.Config{
		Issuer:          "https://token.actions.githubusercontent.com",
		Audiences:       []string{"sts.amazonaws.com"},
		RoleSessionName: "test",
		Cache:           &config.Cache{TTL: 0},
		TagAuth:         &config.TagAuth{Enabled: true, TagPrefix: "aow/"},
	}
	require.NoError(t, cfg.Validate())
	return cfg
}

func TestProcessRequest_TagAuthAllows(t *testing.T) {
	cfg := baseTagCfg(t)
	claims := &types.GithubClaims{Repository: "acme/api", RepositoryOwner: "acme", Ref: "refs/heads/main"}
	exp := time.Now()
	fc := &fakeConsumer{
		tags:         map[string]string{"aow/repo": "acme/api"},
		assumeOut:    &ststypes.Credentials{AccessKeyId: aws.String("AK"), SecretAccessKey: aws.String("SK"), SessionToken: aws.String("ST"), Expiration: &exp},
		allowAccount: true,
	}
	proc := handler.NewRequestProcessor(config.NewStaticProvider(cfg), fc, &tagModeValidator{claims})
	creds, err := proc.ProcessRequest(context.Background(),
		&handler.RequestData{Token: "t", Role: "arn:aws:iam::111111111111:role/app"}, "rid", slog.Default())
	require.NoError(t, err)
	assert.Equal(t, "AK", *creds.AccessKeyId)
	assert.Equal(t, "arn:aws:iam::111111111111:role/app", fc.assumed)
	// Claims must reach AssumeRole so session tags (repo/ref/...) are attached for ABAC.
	require.NotNil(t, fc.gotClaims)
	assert.Equal(t, "acme/api", fc.gotClaims.Repository)
}

func TestProcessRequest_TagAuthDenies(t *testing.T) {
	cfg := baseTagCfg(t)
	claims := &types.GithubClaims{Repository: "acme/api", RepositoryOwner: "acme", Ref: "refs/heads/main"}
	fc := &fakeConsumer{tags: map[string]string{"aow/repo": "acme/other"}, allowAccount: true}
	proc := handler.NewRequestProcessor(config.NewStaticProvider(cfg), fc, &tagModeValidator{claims})
	_, err := proc.ProcessRequest(context.Background(),
		&handler.RequestData{Token: "t", Role: "arn:aws:iam::111111111111:role/app"}, "rid", slog.Default())
	require.Error(t, err)
	assert.True(t, errors.Is(err, handler.ErrRoleNotPermitted))
}

func TestProcessRequest_AccountNotAllowed(t *testing.T) {
	cfg := baseTagCfg(t)
	claims := &types.GithubClaims{Repository: "acme/api", RepositoryOwner: "acme", Ref: "refs/heads/main"}
	fc := &fakeConsumer{tags: map[string]string{"aow/repo": "acme/api"}, allowAccount: false}
	proc := handler.NewRequestProcessor(config.NewStaticProvider(cfg), fc, &tagModeValidator{claims})
	_, err := proc.ProcessRequest(context.Background(),
		&handler.RequestData{Token: "t", Role: "arn:aws:iam::999999999999:role/app"}, "rid", slog.Default())
	require.Error(t, err)
	assert.True(t, errors.Is(err, handler.ErrAccountNotAllowed))
}
