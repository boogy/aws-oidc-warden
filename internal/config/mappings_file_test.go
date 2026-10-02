package config

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const (
	mapOwner    = "123456789012"
	mapIssuer   = "https://token.actions.githubusercontent.com"
	mapRoleARN  = "arn:aws:iam::123456789012:role/R"
	mapAdminARN = "arn:aws:iam::123456789012:role/Admin"
	okMappings  = "role_mappings:\n  - subject: org/repo\n    roles: [\"arn:aws:iam::123456789012:role/R\"]\n"
)

func mappingsCfg(t *testing.T, mappings string) *Config {
	t.Helper()
	c := baseConfig(t)
	c.MappingsFile = filepath.Join(t.TempDir(), "mappings.yaml")
	require.NoError(t, os.WriteFile(c.MappingsFile, []byte(mappings), 0o600))
	return c
}

func s3MappingsCfg(t *testing.T, interval time.Duration) (*Config, *fakeFragmentStore) {
	t.Helper()
	c := baseConfig(t)
	c.MappingsFile, c.S3ConfigBucketOwner, c.ConfigReloadInterval = "s3://b/m.yaml", mapOwner, interval
	st := newFakeFragmentStore()
	st.set(c.MappingsFile, []byte(okMappings))
	return c, st
}

func dur(d time.Duration) *time.Duration { return &d }

func TestMappingsFileLoadsRoleMappings(t *testing.T) {
	tests := []struct {
		name string
		prov func(t *testing.T) *Provider
	}{
		{"local file", func(t *testing.T) *Provider {
			return NewProvider(mappingsCfg(t, okMappings), 0, "", nil)
		}},
		{"s3 file", func(t *testing.T) *Provider {
			c, st := s3MappingsCfg(t, time.Minute)
			return NewProvider(c, time.Minute, "", nil, WithFragmentFetcher(st.fetch))
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := tt.prov(t)
			require.NoError(t, p.Refresh(context.Background()))
			ok, _ := p.Get().AuthorizeRoles(mapIssuer, "org/repo", nil)
			require.True(t, ok)
		})
	}
}

func TestMappingsFileRejectsBaseOnlyKeys(t *testing.T) {
	tests := []struct{ name, content string }{
		{"issuers", "issuers:\n  - issuer: https://evil.example.com\n    provider: github\n    audiences: [x]\n"},
		{"idp allowed_roles", "idp:\n  allowed_roles: [\"" + mapAdminARN + "\"]\n"},
		{"idp max_session_duration", "idp:\n  max_session_duration: 4h\n"},
		{"idp allow_session_name", "idp:\n  allow_session_name: true\n"},
		{"mappings_file", "mappings_file: /etc/other.yaml\n"},
		{"mappings_max_stale", "mappings_max_stale: 1h\n"},
		{"s3_config_bucket_owner", "s3_config_bucket_owner: \"123456789012\"\n"},
		{"config_fragments", "config_fragments: [/etc/other.yaml]\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := NewProvider(mappingsCfg(t, tt.content), 0, "", nil)
			err := p.Refresh(context.Background())
			require.Error(t, err)
			require.Contains(t, err.Error(), "not allowed")
		})
	}
}

func TestMappingsFileAcceptsMappingIdPFields(t *testing.T) {
	content := "role_mappings:\n  - subject: org/repo\n    roles: [\"" + mapRoleARN + "\"]\n" +
		"    idp_token: true\n    idp_max_session_duration: 4h\n    allow_session_name: true\n"
	p := NewProvider(mappingsCfg(t, content), 0, "", nil)
	require.NoError(t, p.Refresh(context.Background()))
}

func TestMappingsFileKeepsLastGoodOnBadReload(t *testing.T) {
	c := mappingsCfg(t, okMappings)
	p := NewProvider(c, 0, "", nil)
	require.NoError(t, p.Refresh(context.Background()))

	require.NoError(t, os.WriteFile(c.MappingsFile, []byte("idp:\n  enabled: true\n"), 0o600))
	require.Error(t, p.Refresh(context.Background()))

	ok, _ := p.Get().AuthorizeRoles(mapIssuer, "org/repo", nil)
	require.True(t, ok)
}

func TestMappingsFileMissingFailsClosed(t *testing.T) {
	c := baseConfig(t)
	c.MappingsFile = filepath.Join(t.TempDir(), "absent.yaml")
	p := NewProvider(c, 0, "", nil)
	require.Error(t, p.Refresh(context.Background()))
}

func TestMappingsFileChecksumPin(t *testing.T) {
	tests := []struct {
		pin     func(content string) string
		label   string
		wantErr string
	}{
		{func(string) string { return "sha256:deadbeef" }, "wrong pin", "integrity"},
		{func(content string) string { return etagOf([]byte(content)) }, "correct pin", ""},
	}
	for _, tt := range tests {
		t.Run(tt.label, func(t *testing.T) {
			c := mappingsCfg(t, okMappings)
			c.ConfigFragmentChecksums = []FragmentChecksum{{URI: c.MappingsFile, Checksum: tt.pin(okMappings)}}
			err := NewProvider(c, 0, "", nil).Refresh(context.Background())
			if tt.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.ErrorContains(t, err, tt.wantErr)
		})
	}
}

func TestMappingsFileEnv(t *testing.T) {
	t.Setenv("AOW_MAPPINGS_FILE", "s3://b/k.yaml")
	t.Setenv("AOW_S3_CONFIG_BUCKET_OWNER", mapOwner)
	t.Setenv("AOW_MAPPINGS_MAX_STALE", "0")
	c := &Config{}
	reapplyEnvOverrides(c)
	require.Equal(t, "s3://b/k.yaml", c.MappingsFile)
	require.Equal(t, mapOwner, c.S3ConfigBucketOwner)
	require.NotNil(t, c.MappingsMaxStale)
	require.Zero(t, *c.MappingsMaxStale)
}

func TestValidateMappingsSplit(t *testing.T) {
	arn := []string{mapRoleARN}
	tests := []struct {
		name    string
		mutate  func(c *Config)
		wantErr string
	}{
		{"no mappings_file", func(c *Config) { c.RoleMappings = []RoleMapping{{Roles: arn}} }, ""},
		{"inline role_mappings", func(c *Config) {
			c.MappingsFile = "/m.yaml"
			c.RoleMappings = []RoleMapping{{Roles: arn}}
		}, "mappings_file is set"},
		{"inline role_groups", func(c *Config) {
			c.MappingsFile = "/m.yaml"
			c.RoleGroups = []RoleGroup{{Subjects: []string{"a/b"}}}
		}, "mappings_file is set"},
		{"unreferenced base role_sets", func(c *Config) {
			c.MappingsFile = "/m.yaml"
			c.RoleSets = map[string][]string{"other": arn}
		}, "role_sets"},
		{"role_sets referenced by idp.allowed_roles", func(c *Config) {
			c.MappingsFile = "/m.yaml"
			c.RoleSets = map[string][]string{"idp": arn}
			c.IdP = &IdPConfig{AllowedRoles: []string{"@IdP"}}
		}, ""},
		{"padded path", func(c *Config) { c.MappingsFile = " /m.yaml" }, "whitespace"},
		{"also in config_fragments", func(c *Config) {
			c.MappingsFile = "/m.yaml"
			c.ConfigFragments = []string{"/m.yaml"}
		}, "config_fragments"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Config{}
			tt.mutate(c)
			err := c.validateMappingsSplit()
			if tt.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.ErrorContains(t, err, tt.wantErr)
		})
	}
}

func TestMappingsFileExclusiveWithInlineMappings(t *testing.T) {
	c := mappingsCfg(t, okMappings)
	c.RoleMappings = []RoleMapping{{Subject: Patterns{"org/inline"}, Roles: []string{mapRoleARN}}}
	err := NewProvider(c, 0, "", nil).Refresh(context.Background())
	require.ErrorContains(t, err, "mappings_file is set")
}

func TestMappingsFileCannotWidenIdPAllowedRoles(t *testing.T) {
	c := mappingsCfg(t, okMappings)
	c.RoleSets = map[string][]string{"idp": {mapRoleARN}}
	c.IdP = validIdP()
	c.IdP.AllowedRoles = []string{"@idp"}
	require.NoError(t, c.Validate())

	p := NewProvider(c, 0, "", nil)
	require.NoError(t, p.Refresh(context.Background()))

	widened := "role_sets:\n  idp: [\"" + mapRoleARN + "\", \"" + mapAdminARN + "\"]\n"
	require.NoError(t, os.WriteFile(c.MappingsFile, []byte(widened), 0o600))
	err := p.Refresh(context.Background())
	require.ErrorContains(t, err, "referenced by idp.allowed_roles")
	require.False(t, p.Get().IdPRoleAllowed(mapAdminARN))
	require.True(t, p.Get().IdPRoleAllowed(mapRoleARN))
}

func TestMaxStale(t *testing.T) {
	const overlay = "config_reload_interval: 5m\n"
	tests := []struct {
		name     string
		local    bool
		interval time.Duration
		stale    *time.Duration
		overlay  bool
		want     time.Duration
		wantErr  string
	}{
		{name: "s3 unset interval 1m", interval: time.Minute, want: 3 * time.Minute},
		{name: "s3 explicit zero", interval: time.Minute, stale: dur(0), want: 0},
		{name: "s3 10m", interval: time.Minute, stale: dur(10 * time.Minute), want: 10 * time.Minute},
		{name: "s3 unset interval 0", want: 0},
		{name: "local unset", local: true, interval: time.Minute, want: 0},
		{name: "s3 unset overlay interval 5m", interval: time.Minute, overlay: true, want: 15 * time.Minute},
		{name: "local 10m", local: true, interval: time.Minute, stale: dur(10 * time.Minute), wantErr: "s3://"},
		{name: "s3 90s", interval: time.Minute, stale: dur(90 * time.Second), wantErr: "at least twice"},
		{name: "s3 10m interval 0", stale: dur(10 * time.Minute), wantErr: "config_reload_interval"},
		{name: "s3 negative", interval: time.Minute, stale: dur(-time.Second), wantErr: "negative"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, st := s3MappingsCfg(t, tt.interval)
			if tt.local {
				c = mappingsCfg(t, okMappings)
				c.ConfigReloadInterval = tt.interval
			}
			c.MappingsMaxStale = tt.stale
			err := c.Validate()
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)

			p := NewProvider(c, tt.interval, "yaml", nil, WithFragmentFetcher(st.fetch))
			if tt.overlay {
				p = NewProvider(c, tt.interval, "yaml", func(context.Context) ([]byte, error) { return []byte(overlay), nil },
					WithFragmentFetcher(st.fetch))
				require.NoError(t, p.Refresh(context.Background()))
			}
			require.Equal(t, tt.want, p.Get().effectiveMappingsMaxStale())
			if tt.stale != nil && *tt.stale == 0 {
				require.NoError(t, p.Refresh(context.Background()))
				p.now = func() time.Time { return time.Now().Add(100 * time.Hour) }
				_, _, stale := p.Stale()
				require.False(t, stale)
			}
		})
	}
}

func TestMaxStaleStale(t *testing.T) {
	c, st := s3MappingsCfg(t, time.Minute)
	c.MappingsMaxStale = dur(10 * time.Minute)
	require.NoError(t, c.Validate())

	now := time.Now()
	p := NewProvider(c, time.Minute, "", nil, WithFragmentFetcher(st.fetch))
	p.now = func() time.Time { return now }

	age, limit, stale := p.Stale()
	require.Equal(t, time.Duration(0), age)
	require.Equal(t, 10*time.Minute, limit)
	require.True(t, stale)

	require.NoError(t, p.Refresh(context.Background()))
	_, _, stale = p.Stale()
	require.False(t, stale)

	st.delete(c.MappingsFile)
	now = now.Add(11 * time.Minute)
	require.Error(t, p.Refresh(context.Background()))

	age, limit, stale = p.Stale()
	require.Equal(t, 11*time.Minute, age)
	require.Equal(t, 10*time.Minute, limit)
	require.True(t, stale)
}

func TestMaxStaleStaticProviderNeverStale(t *testing.T) {
	_, _, stale := NewStaticProvider(&Config{MappingsMaxStale: dur(10 * time.Minute)}).Stale()
	require.False(t, stale)
}

func TestS3BucketOwnerRequired(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(c *Config)
		wantErr string
	}{
		{"s3 mappings_file without owner", func(c *Config) { c.MappingsFile = "s3://b/k" }, "s3_config_bucket_owner"},
		{"s3 fragment without owner", func(c *Config) { c.ConfigFragments = []string{"s3://b/k"} }, "s3_config_bucket_owner"},
		{"overlay without owner", func(c *Config) { c.S3ConfigBucket, c.S3ConfigPath = "b", "k.yaml" }, ""},
		{"overlay with short owner", func(c *Config) {
			c.S3ConfigBucket, c.S3ConfigPath, c.S3ConfigBucketOwner = "b", "k.yaml", "12345"
		}, "12 digits"},
		{"mappings_file with short owner", func(c *Config) {
			c.MappingsFile, c.S3ConfigBucketOwner = "s3://b/k", "12345"
		}, "12 digits"},
		{"local only without owner", func(c *Config) { c.MappingsFile = "/m.yaml" }, ""},
		{"s3 with valid owner", func(c *Config) { c.MappingsFile, c.S3ConfigBucketOwner = "s3://b/k", mapOwner }, ""},
		{"uppercase scheme mappings_file", func(c *Config) { c.MappingsFile = "S3://b/k" }, "lowercase s3://"},
		{"mixed-case scheme fragment", func(c *Config) { c.ConfigFragments = []string{"s3://b/a", "S3://b/k"} }, "config_fragments[1]"},
		{"non-s3 remote fragment", func(c *Config) { c.ConfigFragments = []string{"https://b/k"} }, "lowercase s3://"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := baseConfig(t)
			c.S3ConfigBucketOwner = ""
			tt.mutate(c)
			err := c.Validate()
			if tt.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.ErrorContains(t, err, tt.wantErr)
		})
	}
}
