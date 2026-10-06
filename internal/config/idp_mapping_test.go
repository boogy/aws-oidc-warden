package config

import (
	"testing"
	"time"

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

func TestIDPTokenAllowedFollowsMapping(t *testing.T) {
	const role = "arn:aws:iam::123456789012:role/R"
	tests := []struct {
		name   string
		idpTok bool
		max    time.Duration
		want   bool
	}{
		{"neither", false, 0, false},
		{"idp_token", true, 0, true},
		{"ceiling 1h", false, time.Hour, false},
		{"ceiling 30m", false, 30 * time.Minute, false},
		{"ceiling over 1h", false, time.Hour + time.Second, true},
		{"ceiling 12h", false, 12 * time.Hour, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := idpMappingCfg(RoleMapping{Subject: Patterns{"org/repo"}, Roles: []string{role}, IDPToken: tt.idpTok, MaxSessionDuration: tt.max})
			cfg.IdP = validIdP()
			require.NoError(t, cfg.Validate())
			require.Equal(t, tt.want, cfg.Authorize(idpTestIss, "org/repo", role, map[string]any{}).IDPTokenAllowed())
		})
	}
}

func TestIdPBlockRejectedInFragment(t *testing.T) {
	_, err := parseFragment([]byte("idp:\n  enabled: true\n"), "yaml", "frag")
	require.ErrorContains(t, err, "not allowed in a config fragment")
}

func TestMaxSessionDurationValidate(t *testing.T) {
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
		{"mapping 14m", true, 14 * time.Minute, "max_session_duration"},
		{"mapping 15m", true, 15 * time.Minute, ""},
		{"mapping 13h", true, 13 * time.Hour, "max_session_duration"},
		{"mapping sub-second", true, time.Hour + 500*time.Millisecond, "whole number of seconds"},
		{"mapping negative", true, -time.Hour, "max_session_duration"},
		{"mapping without idp_token", false, 4 * time.Hour, ""},
		{"mapping 1h without idp_token", false, time.Hour, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := idpMappingCfg(RoleMapping{Subject: Patterns{"org/repo"}, Roles: []string{role}, IDPToken: tt.idpTok, MaxSessionDuration: tt.mapping})
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
		cfg.RoleGroups = []RoleGroup{{Subjects: []string{"org/repo"}, Defaults: RoleGroupDefaults{Roles: []string{role}, MaxSessionDuration: 4 * time.Hour}}}
		cfg.IdP = validIdP()
		require.NoError(t, cfg.Validate())
	})
	t.Run("over 1h without idp block", func(t *testing.T) {
		cfg := idpMappingCfg(RoleMapping{Subject: Patterns{"org/repo"}, Roles: []string{role}, MaxSessionDuration: 4 * time.Hour})
		require.ErrorContains(t, cfg.Validate(), "max_session_duration over 1h requires an idp block")
	})
	t.Run("1h without idp block", func(t *testing.T) {
		cfg := idpMappingCfg(RoleMapping{Subject: Patterns{"org/repo"}, Roles: []string{role}, MaxSessionDuration: time.Hour})
		require.NoError(t, cfg.Validate())
	})
}

func TestRoleGroupExpansionCopiesMaxSessionDuration(t *testing.T) {
	const grouped, own = "arn:aws:iam::123456789012:role/Grouped", "arn:aws:iam::123456789012:role/Own"
	cfg := idpMappingCfg(RoleMapping{Subject: Patterns{"org/own"}, Roles: []string{own}, IDPToken: true, MaxSessionDuration: 2 * time.Hour})
	cfg.RoleGroups = []RoleGroup{{Subjects: []string{"org/grouped"}, Defaults: RoleGroupDefaults{Roles: []string{grouped}, IDPToken: true, MaxSessionDuration: 4 * time.Hour}}}
	cfg.IdP = validIdP()
	require.NoError(t, cfg.Validate())
	require.Equal(t, 4*time.Hour, cfg.Authorize(idpTestIss, "org/grouped", grouped, map[string]any{}).MaxSessionDuration())
	require.Equal(t, 2*time.Hour, cfg.Authorize(idpTestIss, "org/own", own, map[string]any{}).MaxSessionDuration(), "an explicit mapping keeps its own cap next to a group default")
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
		role    string
		want    time.Duration
	}{
		{"unset defaults to 1h", 0, 0, role, time.Hour},
		{"mapping 4h", 4 * time.Hour, 0, role, 4 * time.Hour},
		{"mapping 12h", 12 * time.Hour, 0, role, 12 * time.Hour},
		{"mapping 30m", 30 * time.Minute, 0, role, 30 * time.Minute},
		{"group default 6h", 0, 6 * time.Hour, grouped, 6 * time.Hour},
		{"explicit mapping precedes group default", 2 * time.Hour, 6 * time.Hour, override, 2 * time.Hour},
		{"no mapping matched", 0, 0, "arn:aws:iam::123456789012:role/Nope", 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := idpMappingCfg(RoleMapping{Subject: Patterns{"org/repo"}, Roles: []string{role}, IDPToken: true, MaxSessionDuration: tt.mapping})
			cfg.IdP = validIdP()
			cfg.RoleMappings = append(cfg.RoleMappings,
				RoleMapping{Subject: Patterns{"org/repo"}, Roles: []string{override}, IDPToken: true, MaxSessionDuration: tt.mapping})
			cfg.RoleGroups = []RoleGroup{{Subjects: []string{"org/repo"}, Defaults: RoleGroupDefaults{Roles: []string{grouped, override}, IDPToken: true, MaxSessionDuration: tt.group}}}
			require.NoError(t, cfg.Validate())
			require.Equal(t, tt.want, cfg.Authorize(idpTestIss, "org/repo", tt.role, map[string]any{}).MaxSessionDuration())
		})
	}
	require.Zero(t, Decision{}.MaxSessionDuration())
}

func TestDecisionMaxSessionDurationUsesAuthorizingMapping(t *testing.T) {
	const role = "arn:aws:iam::123456789012:role/R"
	cfg := idpMappingCfg(RoleMapping{Subject: Patterns{"org/repo"}, Roles: []string{role}, IDPToken: true, MaxSessionDuration: 2 * time.Hour})
	cfg.IdP = validIdP()
	cfg.RoleMappings = append(cfg.RoleMappings, RoleMapping{Subject: Patterns{"org/repo"}, Roles: []string{role}, IDPToken: true, MaxSessionDuration: 8 * time.Hour})
	require.NoError(t, cfg.Validate())
	d := cfg.Authorize(idpTestIss, "org/repo", role, map[string]any{})
	require.Equal(t, 2*time.Hour, d.MaxSessionDuration(), "lowest-order mapping wins, so a tight mapping shadows a looser one")
	require.Zero(t, Decision{}.MaxSessionDuration())
}

func TestIdPMappingFieldsSurviveClone(t *testing.T) {
	cfg := idpMappingCfg(RoleMapping{Subject: Patterns{"org/repo"}, Roles: []string{"arn:aws:iam::123456789012:role/R"}, IDPToken: true, MaxSessionDuration: 2 * time.Hour})
	clone, err := cloneConfig(cfg)
	require.NoError(t, err)
	got := clone.RoleMappings[0]
	require.True(t, got.IDPToken)
	require.Equal(t, 2*time.Hour, got.MaxSessionDuration)
}
