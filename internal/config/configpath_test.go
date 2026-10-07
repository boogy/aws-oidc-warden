package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUseConfigFile(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "svc.yaml")
	require.NoError(t, os.WriteFile(file, nil, 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "config.yaml"), nil, 0o600))
	emptyDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(emptyDir, "config.env"), nil, 0o600))
	twoDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(twoDir, "config.yaml"), nil, 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(twoDir, "config.json"), nil, 0o600))

	tests := []struct {
		name     string
		in       string
		wantPath string
		wantFile string
		wantErr  bool
	}{
		{"empty is a no-op", "", "", "", false},
		{"directory resolves its config file", dir, "", filepath.Join(dir, "config.yaml"), false},
		{"directory without a config file errors", emptyDir, "", "", true},
		{"directory with two config files errors", twoDir, "", "", true},
		{"file sets CONFIG_FILE", file, "", file, false},
		{"missing file errors", filepath.Join(dir, "typo.yml"), "", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("CONFIG_PATH", "")
			t.Setenv("CONFIG_FILE", "")
			err := UseConfigFile(tt.in)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			assert.Equal(t, tt.wantPath, os.Getenv("CONFIG_PATH"))
			assert.Equal(t, tt.wantFile, os.Getenv("CONFIG_FILE"))
		})
	}
}

func TestLoadConfigReadsExactConfigFile(t *testing.T) {
	viper.Reset()
	t.Cleanup(viper.Reset)
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "svc.json"), []byte(`{"role_session_name":"from-json"}`), 0o600))
	yml := filepath.Join(dir, "svc.yaml")
	require.NoError(t, os.WriteFile(yml, []byte(`issuers:
  - issuer: "https://token.actions.githubusercontent.com"
    provider: "github"
    audiences: ["sts.amazonaws.com"]
role_session_name: from-yaml
`), 0o600))
	t.Setenv("CONFIG_FILE", yml)

	c := &Config{}
	require.NoError(t, c.LoadConfig())
	assert.Equal(t, "from-yaml", c.RoleSessionName)
}

func TestLoadConfigRejectsUnsupportedConfigFile(t *testing.T) {
	viper.Reset()
	t.Cleanup(viper.Reset)
	p := filepath.Join(t.TempDir(), "svc.conf")
	require.NoError(t, os.WriteFile(p, []byte("role_session_name: x\n"), 0o600))
	t.Setenv("CONFIG_FILE", p)

	require.ErrorContains(t, (&Config{}).LoadConfig(), "unsupported extension")
}

func TestLoadConfigRejectsViperOnlyFormat(t *testing.T) {
	viper.Reset()
	t.Cleanup(viper.Reset)
	p := filepath.Join(t.TempDir(), "svc.ini")
	require.NoError(t, os.WriteFile(p, []byte("role_session_name = x\n"), 0o600))
	t.Setenv("CONFIG_FILE", p)

	require.ErrorContains(t, (&Config{}).LoadConfig(), "unsupported extension")
}
