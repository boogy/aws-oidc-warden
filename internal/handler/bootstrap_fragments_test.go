package handler

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/boogy/aws-oidc-warden/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fragmentTestBaseConfig returns a minimal valid config with one issuer and
// one base role mapping, listing fragmentPath under config_fragments.
func fragmentTestBaseConfig(t *testing.T, fragmentPath string) *config.Config {
	t.Helper()
	cfg := &config.Config{
		Issuers: []config.IssuerConfig{{
			Issuer:    "https://token.actions.githubusercontent.com",
			Provider:  "github",
			Audiences: []string{"sts.amazonaws.com"},
		}},
		RoleSessionName: "test-session",
		RoleMappings: []config.RoleMapping{{
			Subject: "org/base-repo",
			Roles:   []string{"arn:aws:iam::123456789012:role/BaseRole"},
		}},
	}
	if fragmentPath != "" {
		cfg.ConfigFragments = []string{fragmentPath}
	}
	require.NoError(t, cfg.Validate())
	return cfg
}

// TestBuildConfigProvider_LocalFragmentsWithoutS3Source is the regression test
// for fragments being silently dropped when no S3 config source is set: the
// provider buildConfigProvider returns must serve a config with the fragment's
// role_mappings merged in, not the bare base config.
func TestBuildConfigProvider_LocalFragmentsWithoutS3Source(t *testing.T) {
	fragPath := filepath.Join(t.TempDir(), "team-fragment.yaml")
	require.NoError(t, os.WriteFile(fragPath, []byte(`
role_mappings:
  - subject: org/frag-repo
    roles:
      - arn:aws:iam::123456789012:role/FragmentRole
`), 0o600))

	cfg := fragmentTestBaseConfig(t, fragPath)
	require.Empty(t, cfg.S3ConfigBucket, "test premise: no S3 config source")

	provider, err := buildConfigProvider(cfg, nil)
	require.NoError(t, err)

	served := provider.Get()

	matched, roles := served.AuthorizeRoles(
		"https://token.actions.githubusercontent.com", "org/frag-repo", nil)
	assert.True(t, matched, "fragment role_mapping must be merged and authorizable")
	assert.Contains(t, roles, "arn:aws:iam::123456789012:role/FragmentRole")

	matched, roles = served.AuthorizeRoles(
		"https://token.actions.githubusercontent.com", "org/base-repo", nil)
	assert.True(t, matched, "base role_mapping must survive the fragment merge")
	assert.Contains(t, roles, "arn:aws:iam::123456789012:role/BaseRole")
}

// TestBuildConfigProvider_NoFragmentsNoS3IsStatic pins the fast path: with
// neither an S3 source nor fragments, the provider serves the base config
// as-is.
func TestBuildConfigProvider_NoFragmentsNoS3IsStatic(t *testing.T) {
	cfg := fragmentTestBaseConfig(t, "")

	provider, err := buildConfigProvider(cfg, nil)
	require.NoError(t, err)
	assert.Same(t, cfg, provider.Get(), "no-fragment path must serve the base config unchanged")
}

// TestBuildConfigProvider_InvalidFragmentFailsFast: a broken fragment must
// fail bootstrap (fail closed), not silently serve the base config.
func TestBuildConfigProvider_InvalidFragmentFailsFast(t *testing.T) {
	fragPath := filepath.Join(t.TempDir(), "bad-fragment.yaml")
	require.NoError(t, os.WriteFile(fragPath, []byte(`
tag_auth:
  enabled: true
`), 0o600))

	cfg := fragmentTestBaseConfig(t, fragPath)
	_, err := buildConfigProvider(cfg, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not allowed in a config fragment")
}
