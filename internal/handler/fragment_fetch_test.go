package handler

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/aws/smithy-go"
	"github.com/boogy/aws-oidc-warden/internal/aws"
	"github.com/boogy/aws-oidc-warden/internal/config"
	"github.com/boogy/aws-oidc-warden/internal/logevent"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	fetchOwner    = "123456789012"
	fetchMappings = "role_mappings:\n  - subject: org/repo\n    roles: [\"arn:aws:iam::123456789012:role/R\"]\n"
	fetchIssuer   = "https://token.actions.githubusercontent.com"
)

type ifChangedCall struct{ bucket, key, prevETag, owner string }

type s3Fake struct {
	aws.AwsConsumerInterface
	body       string
	etag       string
	err        error
	wantOwner  string
	ifChanged  []ifChangedCall
	getObjects int
}

func (f *s3Fake) GetS3ObjectIfChanged(_ context.Context, bucket, key, prevETag, owner string) ([]byte, string, error) {
	f.ifChanged = append(f.ifChanged, ifChangedCall{bucket, key, prevETag, owner})
	if f.wantOwner != "" && owner != f.wantOwner {
		return nil, "", &smithy.GenericAPIError{Code: "AccessDenied", Message: "bucket owner mismatch"}
	}
	if f.err != nil {
		return nil, "", f.err
	}
	if prevETag != "" && prevETag == f.etag {
		return nil, prevETag, nil
	}
	return []byte(f.body), f.etag, nil
}

func (f *s3Fake) GetS3Object(context.Context, string, string) (io.ReadCloser, error) {
	f.getObjects++
	return io.NopCloser(strings.NewReader(f.body)), nil
}

func digestOf(s string) string {
	sum := sha256.Sum256([]byte(s))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func fetchBaseConfig(t *testing.T, mutate func(*config.Config)) *config.Config {
	t.Helper()
	cfg := &config.Config{
		Issuers: []config.IssuerConfig{{
			Issuer:    fetchIssuer,
			Provider:  "github",
			Audiences: []string{"sts.amazonaws.com"},
		}},
		RoleSessionName: "test",
		Cache:           &config.Cache{TTL: 0},
	}
	mutate(cfg)
	require.NoError(t, cfg.Validate())
	return cfg
}

func captureLogs(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(logevent.NewHandler(slog.NewJSONHandler(&buf, nil))))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return &buf
}

func TestParseS3URI(t *testing.T) {
	tests := []struct {
		uri     string
		bucket  string
		key     string
		wantErr bool
	}{
		{uri: "s3://b/k.yaml", bucket: "b", key: "k.yaml"},
		{uri: "s3://b/a//b.yaml", bucket: "b", key: "a//b.yaml"},
		{uri: "s3://b", wantErr: true},
		{uri: "s3://b/", wantErr: true},
		{uri: "s3://b:80/k", wantErr: true},
		{uri: "s3://u@b/k", wantErr: true},
		{uri: "https://b/k", wantErr: true},
		{uri: "s3://b/k?x=1", wantErr: true},
		{uri: "s3://b/k#f", wantErr: true},
		{uri: "", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.uri, func(t *testing.T) {
			bucket, key, err := parseS3URI(tt.uri)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.bucket, bucket)
			assert.Equal(t, tt.key, key)
		})
	}
}

func TestFragmentFetchDigestETag(t *testing.T) {
	tests := []struct {
		name   string
		s3ETag string
	}{
		{"s3_etag_present", `"abc"`},
		{"s3_etag_empty", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &s3Fake{body: fetchMappings, etag: tt.s3ETag}
			fetch := s3FragmentFetcher(f, fetchOwner)

			data, digest, err := fetch(context.Background(), "s3://b/k.yaml", "")
			require.NoError(t, err)
			assert.Equal(t, fetchMappings, string(data))
			assert.Equal(t, digestOf(fetchMappings), digest)
			assert.Empty(t, f.ifChanged[0].prevETag)

			data, digest2, err := fetch(context.Background(), "s3://b/k.yaml", digest)
			require.NoError(t, err)
			assert.Equal(t, digest, digest2)
			assert.Equal(t, tt.s3ETag, f.ifChanged[1].prevETag)
			if tt.s3ETag != "" {
				assert.Nil(t, data, "304 must return no body")
			} else {
				assert.Equal(t, digest, digest2, "identical body must yield the same digest")
			}
		})
	}
}

func TestFragmentFetchPassesOwner(t *testing.T) {
	f := &s3Fake{body: fetchMappings, etag: `"e"`}
	_, _, err := s3FragmentFetcher(f, fetchOwner)(context.Background(), "s3://bkt/dir/k.yaml", "")
	require.NoError(t, err)
	assert.Equal(t, ifChangedCall{"bkt", "dir/k.yaml", "", fetchOwner}, f.ifChanged[0])
}

func TestFragmentFetchErrorPropagates(t *testing.T) {
	boom := errors.New("boom")
	_, _, err := s3FragmentFetcher(&s3Fake{err: boom}, fetchOwner)(context.Background(), "s3://b/k.yaml", "")
	require.ErrorIs(t, err, boom)

	_, _, err = s3FragmentFetcher(&s3Fake{}, fetchOwner)(context.Background(), "https://b/k.yaml", "")
	require.Error(t, err)
}

func TestBuildConfigProviderOwnerMismatchFailsClosed(t *testing.T) {
	f := &s3Fake{body: fetchMappings, etag: `"e"`, wantOwner: fetchOwner}
	cfg := fetchBaseConfig(t, func(c *config.Config) {
		c.MappingsFile, c.S3ConfigBucketOwner = "s3://b/m.yaml", "999999999999"
	})
	_, err := BuildConfigProvider(cfg, f)
	require.Error(t, err)
}

func TestBuildConfigProviderMappingsFile(t *testing.T) {
	buf := captureLogs(t)
	f := &s3Fake{body: fetchMappings, etag: `"e"`, wantOwner: fetchOwner}
	cfg := fetchBaseConfig(t, func(c *config.Config) {
		c.MappingsFile, c.S3ConfigBucketOwner, c.ConfigReloadInterval = "s3://b/m.yaml", fetchOwner, time.Minute
	})

	p, err := BuildConfigProvider(cfg, f)
	require.NoError(t, err)
	require.NoError(t, p.Refresh(context.Background()), "provider must not be static")
	ok, roles := p.Get().AuthorizeRoles(fetchIssuer, "org/repo", nil)
	assert.True(t, ok)
	assert.Contains(t, roles, "arn:aws:iam::123456789012:role/R")
	assert.Contains(t, buf.String(), `"mappingsFile"`)

	f.err = errors.New("s3 down")
	_, err = BuildConfigProvider(cfg, f)
	require.Error(t, err)
}

func TestBuildConfigProviderStaticWhenNoRemote(t *testing.T) {
	cfg := fetchBaseConfig(t, func(*config.Config) {})
	p, err := BuildConfigProvider(cfg, &s3Fake{})
	require.NoError(t, err)
	require.Error(t, p.Refresh(context.Background()))
	assert.Same(t, cfg, p.Get())
}

func TestBuildConfigProviderOverlayPinsOwner(t *testing.T) {
	f := &s3Fake{body: "log_level: info\n", etag: `"e"`}
	cfg := fetchBaseConfig(t, func(c *config.Config) {
		c.S3ConfigBucket, c.S3ConfigPath, c.S3ConfigBucketOwner = "cfgbkt", "dir/cfg.yaml", fetchOwner
	})
	_, err := BuildConfigProvider(cfg, f)
	require.NoError(t, err)
	require.NotEmpty(t, f.ifChanged)
	assert.Equal(t, ifChangedCall{"cfgbkt", "dir/cfg.yaml", "", fetchOwner}, f.ifChanged[0])
	assert.Zero(t, f.getObjects)
}

func TestBuildConfigProviderOverlayWithoutOwnerWarnsAndLoads(t *testing.T) {
	buf := captureLogs(t)
	f := &s3Fake{body: "log_level: info\n"}
	cfg := fetchBaseConfig(t, func(c *config.Config) {
		c.S3ConfigBucket, c.S3ConfigPath = "cfgbkt", "cfg.yaml"
	})
	_, err := BuildConfigProvider(cfg, f)
	require.NoError(t, err)
	assert.Equal(t, 1, f.getObjects)
	assert.Empty(t, f.ifChanged)
	assert.Equal(t, 1, strings.Count(buf.String(), `"config.s3_owner_unpinned"`))
}
