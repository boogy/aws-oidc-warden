package config

import (
	"strings"
	"testing"
	"time"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

const idpTestIss = "https://token.actions.githubusercontent.com"

func idpMappingCfg(m RoleMapping) *Config {
	return &Config{
		Issuers:         []IssuerConfig{{Issuer: idpTestIss, Provider: "github", Audiences: []string{"sts.amazonaws.com"}}},
		RoleSessionName: "idp-test",
		Cache:           &Cache{},
		RoleMappings:    []RoleMapping{m},
	}
}

func idpCeilingCfg(m RoleMapping, ceiling time.Duration) *Config {
	cfg := idpMappingCfg(m)
	cfg.IdP = validIdP()
	cfg.IdP.MaxSessionDuration = ceiling
	return cfg
}

func TestIDPTokenDecision(t *testing.T) {
	const role = "arn:aws:iam::123456789012:role/R"
	for _, tc := range []struct {
		name string
		flag bool
	}{{"opted in", true}, {"not opted in", false}} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := idpMappingCfg(RoleMapping{Subject: Patterns{"org/repo"}, Roles: []string{role}, IDPToken: tc.flag})
			require.NoError(t, cfg.Validate())
			d := cfg.Authorize(idpTestIss, "org/repo", role, map[string]any{})
			require.Equal(t, tc.flag, d.IDPTokenAllowed())
		})
	}
	require.False(t, Decision{}.IDPTokenAllowed())
}

func TestIDPTokenWithSessionPolicyAllowed(t *testing.T) {
	cfg := idpMappingCfg(RoleMapping{Subject: Patterns{"org/repo"}, Roles: []string{"arn:aws:iam::123456789012:role/R"}, IDPToken: true, SessionPolicy: `{"Version":"2012-10-17","Statement":[]}`, RoleSessionName: "fixed"})
	require.NoError(t, cfg.Validate())
}

func TestIDPTokenInheritedFromRoleGroup(t *testing.T) {
	cfg := idpMappingCfg(RoleMapping{Subject: Patterns{"x/y"}, Roles: []string{"arn:aws:iam::123456789012:role/Other"}})
	cfg.RoleGroups = []RoleGroup{{
		Subjects: []string{"org/repo"},
		Defaults: RoleGroupDefaults{Roles: []string{"arn:aws:iam::123456789012:role/R"}, IDPToken: true},
	}}
	require.NoError(t, cfg.Validate())
	d := cfg.Authorize(idpTestIss, "org/repo", "arn:aws:iam::123456789012:role/R", map[string]any{})
	require.True(t, d.IDPTokenAllowed())
}

func TestAllowSessionNameRequiresIDPToken(t *testing.T) {
	const role = "arn:aws:iam::123456789012:role/R"
	allowed := func(m RoleMapping, base bool) bool {
		cfg := idpMappingCfg(m)
		cfg.IdP = validIdP()
		cfg.IdP.AllowSessionName = base
		require.NoError(t, cfg.Validate())
		return cfg.Authorize(idpTestIss, "org/repo", role, map[string]any{}).AllowSessionName()
	}

	cfg := idpMappingCfg(RoleMapping{Subject: Patterns{"org/repo"}, Roles: []string{role}, AllowSessionName: true})
	require.ErrorContains(t, cfg.Validate(), "allow_session_name requires idp_token")

	cfg = idpMappingCfg(RoleMapping{Subject: Patterns{"x/y"}, Roles: []string{role}})
	cfg.RoleGroups = []RoleGroup{{Subjects: []string{"org/repo"}, Defaults: RoleGroupDefaults{Roles: []string{role}, AllowSessionName: true}}}
	require.ErrorContains(t, cfg.Validate(), "allow_session_name requires idp_token")

	on := RoleMapping{Subject: Patterns{"org/repo"}, Roles: []string{role}, IDPToken: true, AllowSessionName: true}
	off := RoleMapping{Subject: Patterns{"org/repo"}, Roles: []string{role}, IDPToken: true}
	require.True(t, allowed(on, true))
	require.False(t, allowed(on, false), "base gate off")
	require.False(t, allowed(off, true), "mapping not opted in")
	require.False(t, Decision{}.AllowSessionName())

	cfg = idpMappingCfg(RoleMapping{Subject: Patterns{"x/y"}, Roles: []string{role}})
	cfg.RoleGroups = []RoleGroup{{Subjects: []string{"org/repo"}, Defaults: RoleGroupDefaults{Roles: []string{role}, IDPToken: true, AllowSessionName: true}}}
	cfg.IdP = validIdP()
	cfg.IdP.AllowSessionName = true
	require.NoError(t, cfg.Validate())
	require.True(t, cfg.Authorize(idpTestIss, "org/repo", role, map[string]any{}).AllowSessionName(), "group default is copied at expansion")
}

func TestIdPRoleAllowed(t *testing.T) {
	const allowed, other = "arn:aws:iam::123456789012:role/R", "arn:aws:iam::123456789012:role/Other"
	cfg := idpMappingCfg(RoleMapping{Subject: Patterns{"org/repo"}, Roles: []string{allowed, other}, IDPToken: true})
	cfg.IdP = validIdP()
	require.NoError(t, cfg.Validate())
	require.True(t, cfg.IdPRoleAllowed(other), "empty allowed_roles means no restriction")

	cfg.RoleSets = map[string][]string{"idp": {allowed}}
	cfg.IdP.AllowedRoles = []string{"@idp"}
	require.NoError(t, cfg.Validate())
	require.NoError(t, cfg.Validate(), "Validate is repeatable")
	require.True(t, cfg.IdPRoleAllowed(allowed))
	require.False(t, cfg.IdPRoleAllowed(other))
	require.Len(t, cfg.idpAllowedRoles, 1)

	cfg.IdP.AllowedRoles = []string{"@missing"}
	require.ErrorContains(t, cfg.Validate(), "idp.allowed_roles")
}

func TestIdPAllowedRolesRejectedInFragment(t *testing.T) {
	_, err := parseFragment([]byte("idp:\n  allowed_roles: [\"arn:aws:iam::1:role/X\"]\n"), "yaml", "frag")
	require.ErrorContains(t, err, "not allowed in a config fragment")
}

func TestIdPMaxSessionDurationValidate(t *testing.T) {
	const role = "arn:aws:iam::123456789012:role/R"
	tests := []struct {
		name    string
		idpTok  bool
		mapping time.Duration
		wantErr string
	}{
		{"unset", true, 0, ""},
		{"mapping 1h", true, time.Hour, ""},
		{"mapping 12h", true, 12 * time.Hour, ""},
		{"mapping 14m", true, 14 * time.Minute, "idp_max_session_duration"},
		{"mapping 15m", true, 15 * time.Minute, ""},
		{"mapping 13h", true, 13 * time.Hour, "idp_max_session_duration"},
		{"mapping sub-second", true, time.Hour + 500*time.Millisecond, "whole number of seconds"},
		{"mapping negative", true, -time.Hour, "idp_max_session_duration"},
		{"mapping without idp_token", false, 4 * time.Hour, "idp_max_session_duration requires idp_token"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := idpMappingCfg(RoleMapping{Subject: Patterns{"org/repo"}, Roles: []string{role}, IDPToken: tt.idpTok, IdPMaxSessionDuration: tt.mapping})
			cfg.IdP = validIdP()
			err := cfg.Validate()
			if tt.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.ErrorContains(t, err, tt.wantErr)
		})
	}

	t.Run("group default ok", func(t *testing.T) {
		cfg := idpMappingCfg(RoleMapping{Subject: Patterns{"x/y"}, Roles: []string{role}})
		cfg.RoleGroups = []RoleGroup{{Subjects: []string{"org/repo"}, Defaults: RoleGroupDefaults{Roles: []string{role}, IDPToken: true, IdPMaxSessionDuration: 4 * time.Hour}}}
		require.NoError(t, cfg.Validate())
	})
	t.Run("group default without idp_token", func(t *testing.T) {
		cfg := idpMappingCfg(RoleMapping{Subject: Patterns{"x/y"}, Roles: []string{role}})
		cfg.RoleGroups = []RoleGroup{{Subjects: []string{"org/repo"}, Defaults: RoleGroupDefaults{Roles: []string{role}, IdPMaxSessionDuration: 4 * time.Hour}}}
		require.ErrorContains(t, cfg.Validate(), "idp_max_session_duration requires idp_token")
	})
}

func TestRoleGroupExpansionCopiesIdPMaxSessionDuration(t *testing.T) {
	const grouped, own = "arn:aws:iam::123456789012:role/Grouped", "arn:aws:iam::123456789012:role/Own"
	cfg := idpMappingCfg(RoleMapping{Subject: Patterns{"org/own"}, Roles: []string{own}, IDPToken: true, IdPMaxSessionDuration: 2 * time.Hour})
	cfg.RoleGroups = []RoleGroup{{Subjects: []string{"org/grouped"}, Defaults: RoleGroupDefaults{Roles: []string{grouped}, IDPToken: true, IdPMaxSessionDuration: 4 * time.Hour}}}
	cfg.IdP = validIdP()
	cfg.IdP.MaxSessionDuration = 12 * time.Hour
	require.NoError(t, cfg.Validate())
	require.Equal(t, 4*time.Hour, cfg.Authorize(idpTestIss, "org/grouped", grouped, map[string]any{}).IdPMaxSessionDuration())
	require.Equal(t, 2*time.Hour, cfg.Authorize(idpTestIss, "org/own", own, map[string]any{}).IdPMaxSessionDuration(), "an explicit mapping keeps its own cap next to a group default")
}

func TestIdPSessionCap(t *testing.T) {
	const (
		role     = "arn:aws:iam::123456789012:role/R"
		grouped  = "arn:aws:iam::123456789012:role/Grouped"
		override = "arn:aws:iam::123456789012:role/Override"
	)
	tests := []struct {
		name    string
		mapping time.Duration
		group   time.Duration
		ceiling time.Duration
		role    string
		want    time.Duration
	}{
		{"no mapping cap, default ceiling", 0, 0, 0, role, time.Hour},
		{"mapping 4h, base 1h", 4 * time.Hour, 0, time.Hour, role, time.Hour},
		{"mapping 4h, base 12h", 4 * time.Hour, 0, 12 * time.Hour, role, 4 * time.Hour},
		{"mapping 30m, base 1h", 30 * time.Minute, 0, time.Hour, role, 30 * time.Minute},
		{"group default 6h, base 12h", 0, 6 * time.Hour, 12 * time.Hour, grouped, 6 * time.Hour},
		{"explicit mapping precedes group default", 2 * time.Hour, 6 * time.Hour, 12 * time.Hour, override, 2 * time.Hour},
		{"no mapping matched", 0, 0, time.Hour, "arn:aws:iam::123456789012:role/Nope", 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := idpCeilingCfg(RoleMapping{Subject: Patterns{"org/repo"}, Roles: []string{role}, IDPToken: true, IdPMaxSessionDuration: tt.mapping}, tt.ceiling)
			cfg.RoleMappings = append(cfg.RoleMappings,
				RoleMapping{Subject: Patterns{"org/repo"}, Roles: []string{override}, IDPToken: true, IdPMaxSessionDuration: tt.mapping})
			cfg.RoleGroups = []RoleGroup{{Subjects: []string{"org/repo"}, Defaults: RoleGroupDefaults{Roles: []string{grouped, override}, IDPToken: true, IdPMaxSessionDuration: tt.group}}}
			require.NoError(t, cfg.Validate())
			require.Equal(t, tt.want, cfg.Authorize(idpTestIss, "org/repo", tt.role, map[string]any{}).IdPMaxSessionDuration())
		})
	}
	require.Zero(t, Decision{}.IdPMaxSessionDuration())
}

func TestDecisionIdPMaxSessionDurationUsesAuthorizingMapping(t *testing.T) {
	const role = "arn:aws:iam::123456789012:role/R"
	cfg := idpCeilingCfg(RoleMapping{Subject: Patterns{"org/repo"}, Roles: []string{role}, IDPToken: true, IdPMaxSessionDuration: 2 * time.Hour}, 12*time.Hour)
	cfg.RoleMappings = append(cfg.RoleMappings, RoleMapping{Subject: Patterns{"org/repo"}, Roles: []string{role}, IDPToken: true, IdPMaxSessionDuration: 8 * time.Hour})
	require.NoError(t, cfg.Validate())
	d := cfg.Authorize(idpTestIss, "org/repo", role, map[string]any{})
	require.Equal(t, 2*time.Hour, d.IdPMaxSessionDuration(), "lowest-order mapping wins, so a tight mapping shadows a looser one")
	require.Zero(t, Decision{}.IdPMaxSessionDuration())
}

func TestIdPCeilingSettingsValidate(t *testing.T) {
	const role = "arn:aws:iam::123456789012:role/R"
	tests := []struct {
		name    string
		set     time.Duration
		want    time.Duration
		wantErr string
	}{
		{"zero defaults to 1h", 0, time.Hour, ""},
		{"14m", 14 * time.Minute, 0, "idp.max_session_duration"},
		{"13h", 13 * time.Hour, 0, "idp.max_session_duration"},
		{"negative", -time.Hour, 0, "idp.max_session_duration"},
		{"sub-second", time.Hour + 500*time.Millisecond, 0, "whole number of seconds"},
		{"12h", 12 * time.Hour, 12 * time.Hour, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := idpCeilingCfg(RoleMapping{Subject: Patterns{"org/repo"}, Roles: []string{role}}, tt.set)
			err := cfg.Validate()
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.want, cfg.IdP.MaxSessionDuration)
		})
	}
}

func TestIdPUncappedWarns(t *testing.T) {
	const role = "arn:aws:iam::123456789012:role/R"
	cfg := idpCeilingCfg(RoleMapping{Subject: Patterns{"org/repo"}, Roles: []string{role}, IDPToken: true}, 12*time.Hour)
	logs := captureWarnings(t, func() { require.NoError(t, cfg.Validate()) })
	require.Equal(t, 1, strings.Count(logs, "config.idp_uncapped"))

	cfg = idpCeilingCfg(RoleMapping{Subject: Patterns{"org/repo"}, Roles: []string{role}, IDPToken: true}, time.Hour)
	logs = captureWarnings(t, func() { require.NoError(t, cfg.Validate()) })
	require.Zero(t, strings.Count(logs, "config.idp_uncapped"))
}

func TestIdPUncappedWarningOnlyWhenEnabled(t *testing.T) {
	const role = "arn:aws:iam::123456789012:role/R"
	cfg := idpCeilingCfg(RoleMapping{Subject: Patterns{"org/repo"}, Roles: []string{role}, IDPToken: true}, 12*time.Hour)
	cfg.IdP.Enabled = false
	logs := captureWarnings(t, func() { require.NoError(t, cfg.Validate()) })
	require.Zero(t, strings.Count(logs, "config.idp_uncapped"))
}

func TestIdPEnvSessionSettings(t *testing.T) {
	t.Run("set on existing block", func(t *testing.T) {
		viper.Reset()
		t.Setenv("AOW_IDP_MAX_SESSION_DURATION", "4h")
		t.Setenv("AOW_IDP_ALLOW_SESSION_NAME", "true")
		c := &Config{IdP: &IdPConfig{}}
		reapplyEnvOverrides(c)
		require.Equal(t, 4*time.Hour, c.IdP.MaxSessionDuration)
		require.True(t, c.IdP.AllowSessionName)
	})
	t.Run("no block stays nil", func(t *testing.T) {
		viper.Reset()
		t.Setenv("AOW_IDP_MAX_SESSION_DURATION", "4h")
		t.Setenv("AOW_IDP_ALLOW_SESSION_NAME", "true")
		c := &Config{}
		reapplyEnvOverrides(c)
		require.Nil(t, c.IdP)
	})
}

func TestIdPMappingFieldsSurviveClone(t *testing.T) {
	cfg := idpMappingCfg(RoleMapping{Subject: Patterns{"org/repo"}, Roles: []string{"arn:aws:iam::123456789012:role/R"}, IDPToken: true, IdPMaxSessionDuration: 2 * time.Hour, AllowSessionName: true})
	clone, err := cloneConfig(cfg)
	require.NoError(t, err)
	got := clone.RoleMappings[0]
	require.True(t, got.IDPToken)
	require.Equal(t, 2*time.Hour, got.IdPMaxSessionDuration)
	require.True(t, got.AllowSessionName)
}
