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

func TestLoadConfigSearch(t *testing.T) {
	tests := []struct {
		name    string
		files   []string
		subdir  string
		wantErr string
	}{
		{name: "two formats", files: []string{"config.yaml", "config.json"}, wantErr: "ambiguous config"},
		{name: "viper-only format", files: []string{"config.hcl"}, wantErr: "unsupported extension"},
		{name: "viper-only sibling is ignored", files: []string{"config.yaml", "config.env"}},
		{name: "home-relative path is searched", files: []string{"config.yaml", "config.json"}, subdir: "$HOME/cfg", wantErr: "ambiguous config"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			viper.Reset()
			t.Cleanup(viper.Reset)
			prev := systemConfigDir
			systemConfigDir = t.TempDir()
			t.Cleanup(func() { systemConfigDir = prev })
			home := t.TempDir()
			t.Setenv("HOME", home)
			searchPath := t.TempDir()
			dir := searchPath
			if tt.subdir != "" {
				searchPath, dir = tt.subdir, filepath.Join(home, "cfg")
				require.NoError(t, os.Mkdir(dir, 0o700))
			}
			for _, f := range tt.files {
				require.NoError(t, os.WriteFile(filepath.Join(dir, f), []byte("issuers:\n  - issuer: https://token.actions.githubusercontent.com\n    provider: github\n    audiences: [sts.amazonaws.com]\nrole_session_name: from-file\n"), 0o600))
			}
			t.Setenv("CONFIG_FILE", "")
			t.Setenv("CONFIG_NAME", "config")
			t.Setenv("CONFIG_PATH", searchPath)

			c := &Config{}
			err := c.LoadConfig()
			if tt.wantErr == "" {
				require.NoError(t, err)
				assert.Equal(t, "from-file", c.RoleSessionName)
				require.NoError(t, UseConfigFile(dir))
				assert.Equal(t, filepath.Join(dir, "config.yaml"), os.Getenv("CONFIG_FILE"))
				return
			}
			require.ErrorContains(t, err, tt.wantErr)
			require.ErrorContains(t, UseConfigFile(dir), tt.wantErr)
		})
	}
}

func TestLoadConfigEmptySearchPathIsNotWorkingDir(t *testing.T) {
	viper.Reset()
	t.Cleanup(viper.Reset)
	dir := t.TempDir()
	t.Chdir(dir)
	for _, f := range []string{"config.yaml", "config.json"} {
		require.NoError(t, os.WriteFile(filepath.Join(dir, f), nil, 0o600))
	}
	t.Setenv("CONFIG_FILE", "")
	t.Setenv("CONFIG_NAME", "config")
	t.Setenv("CONFIG_PATH", "")

	require.NoError(t, (&Config{}).LoadConfig())
}
