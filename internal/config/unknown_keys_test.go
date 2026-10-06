package config

import (
	"bytes"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// captureUnknownKeyWarnings routes the default slog logger to a buffer for one test.
func captureUnknownKeyWarnings(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return &buf
}

const unknownKeyIssuers = `
role_session_name: aow
issuers:
  - issuer: "https://token.actions.githubusercontent.com"
    provider: github
    audiences: ["sts.amazonaws.com"]
`

func loadFile(t *testing.T, body string) error {
	t.Helper()
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(body), 0o600))
	t.Setenv("CONFIG_PATH", dir)
	t.Setenv("CONFIG_NAME", "config")
	viper.Reset()
	once = sync.Once{}
	t.Cleanup(viper.Reset)
	return (&Config{}).LoadConfig()
}

func TestUnknownNestedKeyIsRejected(t *testing.T) {
	const role = `["arn:aws:iam::111111111111:role/r"]`
	bodies := map[string]string{
		"mapping key typo": `
role_mappings:
  - subject: "acme/app"
    roles: ` + role + `
    condtions:
      ref: "refs/heads/main"
`,
		"tag_auth typo": `
tag_auth:
  enabeld: true
`,
		"role_groups defaults typo": `
role_groups:
  - subjects: ["acme/app"]
    defaults:
      roels: ` + role + `
`,
	}
	wantKey := map[string]string{
		"mapping key typo":          "role_mappings[0].condtions",
		"tag_auth typo":             "tag_auth.enabeld",
		"role_groups defaults typo": "role_groups[0].defaults.roels",
	}

	for name, body := range bodies {
		t.Run("base file/"+name, func(t *testing.T) {
			err := loadFile(t, unknownKeyIssuers+body)
			require.Error(t, err)
			assert.Contains(t, err.Error(), wantKey[name])
		})
		t.Run("overlay/"+name, func(t *testing.T) {
			cfg := wildcardCfg("acme/repo")
			err := cfg.MergeBytes([]byte(body), "yaml")
			require.Error(t, err)
			assert.Contains(t, err.Error(), wantKey[name])
		})
	}

	t.Run("fragment", func(t *testing.T) {
		_, err := parseFragment([]byte(`
role_mappings:
  - subject: "acme/app"
    roles: `+role+`
    condtions:
      ref: "refs/heads/main"
`), "yaml", "frag.yaml")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "role_mappings[0].condtions")
		assert.Contains(t, err.Error(), "frag.yaml")
	})

	t.Run("fragment through a refresh keeps the last good config", func(t *testing.T) {
		dir := t.TempDir()
		frag := a2Write(t, dir, "f.yaml", "role_mappings:\n  - subject: \"acme/app\"\n    roles: "+role+"\n    condtions: {ref: x}\n")
		base := a2Base(t)
		base.ConfigFragments = []string{frag}
		p := NewProvider(base, 0, "", nil)
		require.Error(t, p.Refresh(t.Context()))
		assert.Same(t, base, p.Get())
	})
}

func TestUnknownTopLevelKeyOnlyWarns(t *testing.T) {
	t.Run("base file with an anchor holder", func(t *testing.T) {
		buf := captureUnknownKeyWarnings(t)
		err := loadFile(t, `
x-anchors:
  roles: &roles ["arn:aws:iam::111111111111:role/r"]
`+unknownKeyIssuers+`
role_mappings:
  - subject: "acme/app"
    roles: *roles
`)
		require.NoError(t, err)
		assert.Contains(t, buf.String(), "unknown_config_key")
		assert.Contains(t, buf.String(), "x-anchors")
	})

	t.Run("overlay", func(t *testing.T) {
		buf := captureUnknownKeyWarnings(t)
		cfg := wildcardCfg("acme/repo")
		require.NoError(t, cfg.MergeBytes([]byte("x-anchors: {a: 1}\nlog_level: debug\n"), "yaml"))
		assert.Equal(t, "debug", cfg.LogLevel)
		assert.Contains(t, buf.String(), "unknown_config_key")
	})
}

// Defaults, bound env vars and stray AOW_ variables are not "unused" keys.
func TestEnvAndDefaultsAreNotUnknownKeys(t *testing.T) {
	buf := captureUnknownKeyWarnings(t)
	t.Setenv("AOW_ROLE_SESSION_NAME", "test-session")
	t.Setenv("AOW_LOG_LEVEL", "debug")
	t.Setenv("AOW_CACHE_TTL", "10m")
	t.Setenv("AOW_TAG_AUTH_ENABLED", "true")
	t.Setenv("AOW_NOT_A_REAL_KEY", "1")
	t.Setenv("AOW_CROSS_ACCOUNT_ENABLED", "false")

	err := loadFile(t, unknownKeyIssuers+"cache:\n  type: memory\n")
	require.NoError(t, err)
	assert.NotContains(t, buf.String(), "unknown_config_key")
}
