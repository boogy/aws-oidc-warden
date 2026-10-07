package main

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/boogy/aws-oidc-warden/internal/config"
)

const baseYAML = `issuers:
  - issuer: "https://token.actions.githubusercontent.com"
    provider: "github"
    audiences: ["sts.amazonaws.com"]
default_issuer: "https://token.actions.githubusercontent.com"
s3_config_bucket_owner: "111122223333"
config_fragments:
  - "s3://cfg/fragments/team-data.yaml"
`

const goodFragment = `role_mappings:
  - subject: "acme/data-pipeline"
    roles: ["arn:aws:iam::444455556666:role/data-deploy"]
`

func writeFile(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(p, []byte(body), 0o600))
	return p
}

func loadBase(t *testing.T, body string) *config.Config {
	t.Helper()
	viper.Reset()
	t.Cleanup(viper.Reset)
	dir := t.TempDir()
	writeFile(t, dir, "service.yaml", body)
	t.Setenv("CONFIG_PATH", dir)
	t.Setenv("CONFIG_NAME", "service")
	c := &config.Config{}
	require.NoError(t, c.LoadConfig())
	return c
}

func TestRunOverrideFragment(t *testing.T) {
	tests := []struct {
		name     string
		fragment string
		override func(frag string) overrides
		wantErr  string
	}{
		{
			name:     "valid fragment merges",
			fragment: goodFragment,
			override: func(f string) overrides { return overrides{"s3://cfg/fragments/team-data.yaml": f} },
		},
		{
			name:     "disallowed key rejected",
			fragment: goodFragment + "issuers: []\n",
			override: func(f string) overrides { return overrides{"s3://cfg/fragments/team-data.yaml": f} },
			wantErr:  "not allowed in a config fragment",
		},
		{
			name:     "override matching no source rejected",
			fragment: goodFragment,
			override: func(f string) overrides {
				return overrides{"s3://cfg/fragments/team-data.yaml": f, "s3://cfg/typo.yaml": f}
			},
			wantErr: "override matches no configured source: s3://cfg/typo.yaml",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := loadBase(t, baseYAML)
			frag := writeFile(t, t.TempDir(), "team-data.yaml", tt.fragment)
			cfg, err := run(c, tt.override(frag), true, nil)
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			require.Len(t, cfg.RoleMappings, 1)
			assert.Equal(t, "acme/data-pipeline", cfg.RoleMappings[0].Subject[0])
		})
	}
}

func TestRunOverrideKeepsChecksumPin(t *testing.T) {
	sum := sha256.Sum256([]byte(goodFragment))
	pin := "sha256:" + hex.EncodeToString(sum[:])
	tests := []struct {
		name    string
		body    string
		wantErr bool
	}{
		{name: "pinned content passes", body: goodFragment},
		{name: "edited content fails pin", body: strings.Replace(goodFragment, "data-pipeline", "other", 1), wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := loadBase(t, baseYAML+"config_fragment_checksums:\n  - uri: \"s3://cfg/fragments/team-data.yaml\"\n    checksum: \""+pin+"\"\n")
			frag := writeFile(t, t.TempDir(), "team-data.yaml", tt.body)
			_, err := run(c, overrides{"s3://cfg/fragments/team-data.yaml": frag}, true, nil)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestRunOverrideOverlay(t *testing.T) {
	c := loadBase(t, baseYAML+"s3_config_bucket: \"cfg\"\ns3_config_path: \"overlay.yaml\"\n")
	dir := t.TempDir()
	overlay := writeFile(t, dir, "overlay.yaml", "role_session_name: \"from-overlay\"\n")
	frag := writeFile(t, dir, "team-data.yaml", goodFragment)

	cfg, err := run(c, overrides{
		"s3://cfg/overlay.yaml":             overlay,
		"s3://cfg/fragments/team-data.yaml": frag,
	}, true, nil)
	require.NoError(t, err)
	assert.Equal(t, "from-overlay", cfg.RoleSessionName)
	assert.Len(t, cfg.RoleMappings, 1)
}

func TestOverridesSet(t *testing.T) {
	o := overrides{}
	require.NoError(t, o.Set("s3://b/k.yaml=./k.yaml"))
	assert.ErrorContains(t, o.Set("s3://b/k.yaml=./other.yaml"), "overridden twice")
	assert.ErrorContains(t, o.Set("no-equals"), "want URI=PATH")
	assert.ErrorContains(t, o.Set("=./k.yaml"), "want URI=PATH")
}

func TestRunOffline(t *testing.T) {
	tests := []struct {
		name    string
		base    string
		ov      func(dir string) overrides
		wantErr string
	}{
		{
			name:    "fragment without override",
			base:    baseYAML,
			ov:      func(string) overrides { return overrides{} },
			wantErr: "offline: no -override for remote source: s3://cfg/fragments/team-data.yaml",
		},
		{
			name: "overlay without override",
			base: baseYAML + "s3_config_bucket: \"cfg\"\ns3_config_path: \"overlay.yaml\"\n",
			ov: func(dir string) overrides {
				return overrides{"s3://cfg/fragments/team-data.yaml": writeFile(t, dir, "f.yaml", goodFragment)}
			},
			wantErr: "offline: no -override for remote source: s3://cfg/overlay.yaml",
		},
		{
			name: "mappings file with override",
			base: strings.Replace(baseYAML, "config_fragments:\n  - \"s3://cfg/fragments/team-data.yaml\"\n",
				"mappings_file: \"s3://cfg/mappings.yaml\"\n", 1),
			ov: func(dir string) overrides {
				return overrides{"s3://cfg/mappings.yaml": writeFile(t, dir, "mappings.yaml", goodFragment)}
			},
		},
		{
			name:    "mappings file without override",
			base:    strings.Replace(baseYAML, "config_fragments:\n  - \"s3://cfg/fragments/team-data.yaml\"\n", "mappings_file: \"s3://cfg/mappings.yaml\"\n", 1),
			ov:      func(string) overrides { return overrides{} },
			wantErr: "offline: no -override for remote source: s3://cfg/mappings.yaml",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := loadBase(t, tt.base)
			cfg, err := run(c, tt.ov(t.TempDir()), true, nil)
			if tt.wantErr != "" {
				require.EqualError(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Len(t, cfg.RoleMappings, 1)
		})
	}
}

func TestRunOverrideKeepsMappingsFilePin(t *testing.T) {
	sum := sha256.Sum256([]byte(goodFragment))
	pin := "sha256:" + hex.EncodeToString(sum[:])
	tests := []struct {
		name    string
		body    string
		wantErr bool
	}{
		{name: "pinned content passes", body: goodFragment},
		{name: "edited content fails pin", body: strings.Replace(goodFragment, "data-pipeline", "other", 1), wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := loadBase(t, baseYAML+"mappings_file: \"s3://cfg/mappings.yaml\"\nconfig_fragment_checksums:\n  - uri: \"s3://cfg/mappings.yaml\"\n    checksum: \""+pin+"\"\n")
			dir := t.TempDir()
			_, err := run(c, overrides{
				"s3://cfg/mappings.yaml":            writeFile(t, dir, "mappings.yaml", tt.body),
				"s3://cfg/fragments/team-data.yaml": writeFile(t, dir, "team-data.yaml", "role_sets: {}\n"),
			}, true, nil)
			if tt.wantErr {
				require.ErrorContains(t, err, "failed integrity check")
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestRunOverlayOverCapRejected(t *testing.T) {
	c := loadBase(t, baseYAML+"max_config_bytes: 64\ns3_config_bucket: \"cfg\"\ns3_config_path: \"overlay.yaml\"\n")
	overlay := writeFile(t, t.TempDir(), "overlay.yaml", "role_session_name: \""+strings.Repeat("a", 60)+"\"\n")
	_, err := run(c, overrides{"s3://cfg/overlay.yaml": overlay}, true, nil)
	require.ErrorContains(t, err, "overlay override")
}

func TestRunOverlayCannotSetBaseOnlyKeys(t *testing.T) {
	c := loadBase(t, baseYAML+"s3_config_bucket: \"cfg\"\ns3_config_path: \"overlay.yaml\"\n")
	dir := t.TempDir()
	overlay := writeFile(t, dir, "overlay.yaml", "s3_config_bucket_owner: \"444455556666\"\nsession_policy_bucket_owner: \"999988887777\"\nmax_config_bytes: 2048\n")
	cfg, err := run(c, overrides{
		"s3://cfg/overlay.yaml":             overlay,
		"s3://cfg/fragments/team-data.yaml": writeFile(t, dir, "team-data.yaml", goodFragment),
	}, true, nil)
	require.NoError(t, err)
	assert.Equal(t, "111122223333", cfg.S3ConfigBucketOwner)
	assert.Empty(t, cfg.SessionPolicyBucketOwner)
	assert.Equal(t, 1<<20, cfg.MaxConfigBytes)
}
