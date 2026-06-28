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
	"github.com/boogy/aws-oidc-warden/internal/config"
	"github.com/boogy/aws-oidc-warden/internal/handler"
	"github.com/boogy/aws-oidc-warden/internal/types"
	"github.com/boogy/aws-oidc-warden/internal/validator"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type tagModeExtractor struct{ claims *types.GithubClaims }

func (e *tagModeExtractor) Extract(_ context.Context, _ validator.ExtractionInput) (*types.GithubClaims, error) {
	return e.claims, nil
}

type fakeConsumer struct {
	tags            map[string]string
	tagsErr         error
	assumed         string
	gotClaims       *types.GithubClaims // claims passed to AssumeRole → drive session tags (ABAC)
	assumeOut       *ststypes.Credentials
	allowAccount    bool
	allowAccountErr error
}

func (f *fakeConsumer) ReadS3Configuration() error { return nil }
func (f *fakeConsumer) GetS3Object(string, string) (io.ReadCloser, error) {
	return nil, errors.New("not used")
}
func (f *fakeConsumer) GetRole(string) (*awsiam.GetRoleOutput, error) { return nil, nil }
func (f *fakeConsumer) GetRoleTags(string) (map[string]string, error) { return f.tags, f.tagsErr }
func (f *fakeConsumer) IsTargetAccountAllowed(string) (bool, error) {
	return f.allowAccount, f.allowAccountErr
}
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
	proc := handler.NewRequestProcessor(config.NewStaticProvider(cfg), fc, &tagModeExtractor{claims})
	creds, err := proc.ProcessRequest(context.Background(),
		&handler.RequestData{Token: "t", Role: "arn:aws:iam::111111111111:role/app"},
		validator.ExtractionInput{Token: "t"},
		"rid", slog.Default())
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
	proc := handler.NewRequestProcessor(config.NewStaticProvider(cfg), fc, &tagModeExtractor{claims})
	_, err := proc.ProcessRequest(context.Background(),
		&handler.RequestData{Token: "t", Role: "arn:aws:iam::111111111111:role/app"},
		validator.ExtractionInput{Token: "t"},
		"rid", slog.Default())
	require.Error(t, err)
	assert.True(t, errors.Is(err, handler.ErrRoleNotPermitted))
}

// TestProcessRequest_TagAuthOverridesFailedMapping documents (and locks in) the
// additive precedence foot-gun: tag-auth is an OR-ed fallback, so a role that an
// explicit mapping deliberately constrains (here branch=main) is still assumable
// from a different branch when its aow/* tags match and carry no aow/branch tag.
// Operators must not rely on a mapping constraint alone to *deny* such a role.
func TestProcessRequest_TagAuthOverridesFailedMapping(t *testing.T) {
	cfg := &config.Config{
		Issuer:          "https://token.actions.githubusercontent.com",
		Audiences:       []string{"sts.amazonaws.com"},
		RoleSessionName: "test",
		Cache:           &config.Cache{TTL: 0},
		TagAuth:         &config.TagAuth{Enabled: true, TagPrefix: "aow/"},
		RepoRoleMappings: []config.RepoRoleMapping{{
			Repo:        "acme/api",
			Roles:       []string{"arn:aws:iam::111111111111:role/app"},
			Constraints: &config.Constraint{Branch: "main"}, // requires ref == main
		}},
	}
	require.NoError(t, cfg.Validate())

	// Claims are for a feature branch → the explicit mapping's branch constraint
	// fails, so the explicit path denies.
	claims := &types.GithubClaims{Repository: "acme/api", RepositoryOwner: "acme", Ref: "refs/heads/feature"}
	exp := time.Now()
	fc := &fakeConsumer{
		tags:         map[string]string{"aow/repo": "acme/api"}, // no aow/branch → branch unchecked
		assumeOut:    &ststypes.Credentials{AccessKeyId: aws.String("AK"), SecretAccessKey: aws.String("SK"), SessionToken: aws.String("ST"), Expiration: &exp},
		allowAccount: true,
	}
	proc := handler.NewRequestProcessor(config.NewStaticProvider(cfg), fc, &tagModeExtractor{claims})
	creds, err := proc.ProcessRequest(context.Background(),
		&handler.RequestData{Token: "t", Role: "arn:aws:iam::111111111111:role/app"},
		validator.ExtractionInput{Token: "t"},
		"rid", slog.Default())
	require.NoError(t, err, "tag-auth should authorize despite the failed mapping constraint")
	assert.Equal(t, "AK", *creds.AccessKeyId)
}

func TestProcessRequest_AccountNotAllowed(t *testing.T) {
	cfg := baseTagCfg(t)
	claims := &types.GithubClaims{Repository: "acme/api", RepositoryOwner: "acme", Ref: "refs/heads/main"}
	// allowAccount defaults to false → target account is denied.
	fc := &fakeConsumer{tags: map[string]string{"aow/repo": "acme/api"}}
	proc := handler.NewRequestProcessor(config.NewStaticProvider(cfg), fc, &tagModeExtractor{claims})
	_, err := proc.ProcessRequest(context.Background(),
		&handler.RequestData{Token: "t", Role: "arn:aws:iam::999999999999:role/app"},
		validator.ExtractionInput{Token: "t"},
		"rid", slog.Default())
	require.Error(t, err)
	assert.True(t, errors.Is(err, handler.ErrAccountNotAllowed))
}

func TestProcessRequest_AccountCheckError(t *testing.T) {
	cfg := baseTagCfg(t)
	claims := &types.GithubClaims{Repository: "acme/api", RepositoryOwner: "acme", Ref: "refs/heads/main"}
	// Infra error must take precedence over the allow/deny bool and map to a 5xx
	// (ErrAssumeRoleFailed), never a 403 (ErrAccountNotAllowed).
	fc := &fakeConsumer{tags: map[string]string{"aow/repo": "acme/api"}, allowAccount: true, allowAccountErr: errors.New("infra fail")}
	proc := handler.NewRequestProcessor(config.NewStaticProvider(cfg), fc, &tagModeExtractor{claims})
	_, err := proc.ProcessRequest(context.Background(),
		&handler.RequestData{Token: "t", Role: "arn:aws:iam::999999999999:role/app"},
		validator.ExtractionInput{Token: "t"},
		"rid", slog.Default())
	require.Error(t, err)
	assert.True(t, errors.Is(err, handler.ErrAssumeRoleFailed))
	assert.False(t, errors.Is(err, handler.ErrAccountNotAllowed))
}
