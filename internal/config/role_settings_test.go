package config

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/go-viper/mapstructure/v2"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	rsPlan  = "arn:aws:iam::111122223333:role/Plan"
	rsApply = "arn:aws:iam::111122223333:role/Apply"
	rsAudit = "arn:aws:iam::111122223333:role/Audit"
)

const rsHeader = `
issuers:
  - issuer: "` + vIss + `"
    provider: "generic"
    audiences: ["aud"]
    claim_mappings:
      subject: "sub"
default_issuer: "` + vIss + `"
role_session_name: "test"
role_sets:
  pair:
    - "` + rsPlan + `"
    - "` + rsApply + `"
  dup:
    - "` + rsPlan + `"
    - "` + rsApply + `"
    - "` + rsPlan + `"
`

func rsLoad(t *testing.T, mappings string, withIdP bool) (*Config, error) {
	t.Helper()
	if !withIdP {
		return rsLoadIdP(t, mappings, nil)
	}
	return rsLoadIdP(t, mappings, validIdP())
}

func rsLoadIdP(t *testing.T, mappings string, idp *IdPConfig) (*Config, error) {
	t.Helper()
	v := viper.New()
	v.SetConfigType("yaml")
	require.NoError(t, v.ReadConfig(strings.NewReader(rsHeader+mappings)))
	var c Config
	var md mapstructure.Metadata
	if err := v.Unmarshal(&c, decoderOptions(&md)...); err != nil {
		return nil, err
	}
	if err := rejectUnusedKeys(v, md.Unused, "test"); err != nil {
		return nil, err
	}
	c.IdP = idp
	return &c, c.Validate()
}

func rsMapping(entry string) string {
	return "role_mappings:\n  - subject: \"acme/app\"\n" + entry
}

func TestRoleConditionsReplaceEntryConditions(t *testing.T) {
	const doc = `    conditions:
      ref: "refs/heads/main"
    roles:
      - "` + rsAudit + `"
      - role: "` + rsPlan + `"
        conditions:
          event_name: ["pull_request", "push"]
      - role: "` + rsApply + `"
        conditions:
          all_of:
            - event_name: "push"
            - any_of:
                - ref: "refs/heads/main"
                - environment: "production"
            - none_of:
                - actor: "mallory"
`
	cfg, err := rsLoad(t, rsMapping(doc), false)
	require.NoError(t, err)

	pr := map[string]any{"event_name": "pull_request", "ref": "refs/pull/1/merge"}
	push := map[string]any{"event_name": "push", "ref": "refs/heads/main"}
	pushEnv := map[string]any{"event_name": "push", "ref": "refs/heads/dev", "environment": "production"}
	mallory := map[string]any{"event_name": "push", "ref": "refs/heads/main", "actor": "mallory"}

	tests := []struct {
		name   string
		claims map[string]any
		want   []string
	}{
		{"pr gets plan only", pr, []string{rsPlan}},
		{"main push gets everything", push, []string{rsAudit, rsPlan, rsApply}},
		{"env alone satisfies nested any_of", pushEnv, []string{rsPlan, rsApply}},
		{"none_of denies apply", mallory, []string{rsAudit, rsPlan}},
		{"nothing matches", map[string]any{"event_name": "schedule"}, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, got := cfg.AuthorizeRoles(vIss, "acme/app", tc.claims)
			assert.ElementsMatch(t, tc.want, got)
		})
	}
}

func TestRoleKeyGroupsReplaceIndependently(t *testing.T) {
	const doc = `    session_policy: '{"Version":"2012-10-17","Statement":[]}'
    allow_session_name: true
    max_session_duration: 30m
    session_duration: 20m
    session_tags:
      who: "actor"
    roles:
      - "` + rsAudit + `"
      - role: "` + rsPlan + `"
        session_policy_file: "policies/plan.json"
        role_session_name: "plan"
        session_duration: 25m
      - role: "` + rsApply + `"
        allow_session_name: false
        max_session_duration: 45m
        session_tags:
          env: "environment"
`
	cfg, err := rsLoad(t, rsMapping(doc), false)
	require.NoError(t, err)
	claims := map[string]any{}
	const inline = `{"Version":"2012-10-17","Statement":[]}`

	tests := []struct {
		name         string
		role         string
		wantInline   string
		wantFile     string
		wantName     string
		wantAllow    bool
		wantDuration time.Duration
		wantDefault  time.Duration
		wantTags     map[string]string
	}{
		{"inherits all", rsAudit, inline, "", "", true, 30 * time.Minute, 20 * time.Minute, map[string]string{"who": "actor"}},
		{"policy pair replaced, name pair replaced, session_duration only on role, limit inherited", rsPlan, "", "policies/plan.json", "plan", false, 30 * time.Minute, 25 * time.Minute, map[string]string{"who": "actor"}},
		{"explicit false and tags replace; limit only on role, default inherited", rsApply, inline, "", "", false, 45 * time.Minute, 20 * time.Minute, map[string]string{"env": "environment"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d := cfg.Authorize(vIss, "acme/app", tc.role, claims)
			require.True(t, d.Matched)
			in, file := d.SessionPolicy()
			assert.Equal(t, tc.wantInline, valueOf(in))
			assert.Equal(t, tc.wantFile, valueOf(file))
			assert.Equal(t, tc.wantName, d.RoleSessionName())
			assert.Equal(t, tc.wantAllow, d.SessionNameAllowed())
			assert.Equal(t, tc.wantDuration, d.MaxSessionDuration())
			assert.Equal(t, tc.wantDefault, d.SessionDuration())
			assert.Equal(t, tc.wantTags, cfg.EffectiveSessionTags(vIss, d))
		})
	}
}

func TestRoleOverridesSurviveClone(t *testing.T) {
	const doc = `    allow_session_name: true
    idp_token: true
    max_session_duration: 2h
    session_duration: 90m
    roles:
      - "` + rsAudit + `"
      - role: "` + rsApply + `"
        allow_session_name: false
        idp_token: false
        max_session_duration: 30m
        session_duration: 20m
        conditions:
          ref: "refs/heads/main"
`
	cfg, err := rsLoad(t, rsMapping(doc), true)
	require.NoError(t, err)
	clone, err := cloneConfig(cfg)
	require.NoError(t, err)
	require.NoError(t, clone.Validate())

	got := clone.RoleMappings[0].Roles[1]
	require.NotNil(t, got.AllowSessionName)
	require.NotNil(t, got.IDPToken)
	assert.False(t, *got.AllowSessionName)
	assert.False(t, *got.IDPToken)

	main := map[string]any{"ref": "refs/heads/main"}
	for name, c := range map[string]*Config{"source": cfg, "clone": clone} {
		t.Run(name, func(t *testing.T) {
			d := c.Authorize(vIss, "acme/app", rsApply, main)
			assert.False(t, d.SessionNameAllowed())
			assert.False(t, d.IDPTokenAllowed())
			assert.Equal(t, 30*time.Minute, d.MaxSessionDuration())
			assert.Equal(t, 20*time.Minute, d.SessionDuration())
			assert.NotContains(t, c.Authorize(vIss, "acme/app", rsApply, map[string]any{"ref": "refs/heads/dev"}).Roles, rsApply)
		})
	}
}

func TestEmptySessionTagsOverrideSurvivesClone(t *testing.T) {
	cfg := &Config{
		Issuers:         []IssuerConfig{{Issuer: vIss, Provider: "generic", Audiences: []string{"aud"}}},
		RoleSessionName: "t",
		RoleMappings: []RoleMapping{{
			Subject: Patterns{"a/b"}, SessionTags: map[string]string{"x": "actor"},
			Roles: []RoleEntry{{Role: rsAudit}, {Role: rsApply, SessionTags: map[string]string{}}},
		}},
	}
	clone, err := cloneConfig(cfg)
	require.NoError(t, err)
	assert.NotNil(t, clone.RoleMappings[0].Roles[1].SessionTags)
	assert.Nil(t, clone.RoleMappings[0].Roles[0].SessionTags)
}

func TestRoleConditionsClonedBeforeCompile(t *testing.T) {
	const doc = `    roles:
      - role: "` + rsApply + `"
        conditions:
          ref: "refs/heads/main"
`
	cfg, err := rsLoad(t, rsMapping(doc), false)
	require.NoError(t, err)
	assert.Nil(t, cfg.RoleMappings[0].Roles[0].Conditions.compiled)
	require.NotNil(t, cfg.effective[0].Conditions.compiled)
}

func TestRoleSettingLoadErrors(t *testing.T) {
	tests := []struct {
		name    string
		entry   string
		idp     bool
		wantErr string
	}{
		{"role object without role names its index", `    roles:
      - "` + rsAudit + `"
      - session_policy_file: "p.json"
`, false, "roles[1]: roles: an entry is empty"},
		{"empty conditions key", `    roles:
      - role: "` + rsApply + `"
        conditions:
`, false, "present but empty"},
		{"empty conditions map", `    roles:
      - role: "` + rsApply + `"
        conditions: {}
`, false, "conditions"},
		{"empty session_policy", `    roles:
      - role: "` + rsApply + `"
        session_policy: ""
`, false, "session_policy must not be empty"},
		{"empty session_policy_file", `    roles:
      - role: "` + rsApply + `"
        session_policy_file: ""
`, false, "session_policy_file must not be empty"},
		{"empty session_tags", `    roles:
      - role: "` + rsApply + `"
        session_tags: {}
`, false, "session_tags must not be empty"},
		{"zero duration", `    roles:
      - role: "` + rsApply + `"
        max_session_duration: 0
`, false, "max_session_duration must not be 0"},
		{"null key", `    roles:
      - role: "` + rsApply + `"
        session_policy:
`, false, "present but empty"},
		{"duplicate override role", `    roles:
      - "` + rsApply + `"
      - role: "` + rsApply + `"
        max_session_duration: 30m
`, false, "more than once"},
		{"override role inside overlapping set", `    roles:
      - "@pair"
      - role: "` + rsApply + `"
        max_session_duration: 30m
`, false, "more than once"},
		{"duplicate override role differing in case", `    roles:
      - "arn:aws:iam::111122223333:role/apply"
      - role: "` + rsApply + `"
        max_session_duration: 30m
`, false, "more than once"},
		{"override error names the role", `    roles:
      - "` + rsAudit + `"
      - role: "` + rsApply + `"
        role_session_name: "a/b"
`, false, "role " + rsApply + ": role_session_name"},
		{"set override error names the set", `    roles:
      - role: "@pair"
        role_session_name: "a/b"
`, false, "role @pair: role_session_name"},
		{"entry-level error on a single role names no role", `    role_session_name: "a/b"
    roles:
      - "` + rsApply + `"
`, false, "(acme/app): role_session_name"},
		{"entry conditions no role inherits", `    conditions:
      ref: "refs/heads/main"
    roles:
      - role: "` + rsApply + `"
        conditions:
          ref: "refs/heads/dev"
`, false, "no role inherits"},
		{"entry policy no role inherits", `    session_policy: '{"Version":"2012-10-17","Statement":[]}'
    roles:
      - role: "` + rsApply + `"
        session_policy: '{"Version":"2012-10-17","Statement":[]}'
`, false, "no role inherits"},
		{"entry name no role inherits", `    role_session_name: "ent"
    roles:
      - role: "` + rsApply + `"
        role_session_name: "own"
`, false, "no role inherits"},
		{"entry duration no role inherits", `    max_session_duration: 30m
    roles:
      - role: "` + rsApply + `"
        max_session_duration: 15m
`, false, "no role inherits"},
		{"entry idp_token no role inherits", `    idp_token: true
    roles:
      - role: "` + rsApply + `"
        idp_token: false
`, true, "no role inherits"},
		{"entry tags no role inherits", `    session_tags:
      a: "actor"
    roles:
      - role: "` + rsApply + `"
        session_tags:
          b: "actor"
`, false, "no role inherits"},
		{"idp_token false over 1h", `    max_session_duration: 2h
    idp_token: true
    roles:
      - "` + rsAudit + `"
      - role: "` + rsApply + `"
        idp_token: false
`, true, "idp_token: false"},
		{"policy and file after overlay", `    session_policy: '{"Version":"2012-10-17","Statement":[]}'
    roles:
      - "` + rsAudit + `"
      - role: "` + rsApply + `"
        session_policy: '{"Version":"2012-10-17","Statement":[]}'
        session_policy_file: "p.json"
`, false, "session_policy"},
		{"bad session name on role", `    roles:
      - role: "` + rsApply + `"
        role_session_name: "bad name!"
`, false, "role_session_name"},
		{"allow_session_name with entry name", `    roles:
      - role: "` + rsApply + `"
        allow_session_name: true
        role_session_name: "fixed"
`, false, "allow_session_name"},
		{"zero session_duration", `    roles:
      - role: "` + rsApply + `"
        session_duration: 0
`, false, "session_duration must not be 0"},
		{"session_duration over default limit", `    session_duration: 2h
    roles:
      - "` + rsApply + `"
`, true, "session_duration 2h0m0s exceeds max_session_duration 1h0m0s (default)"},
		{"session_duration error names the role", `    roles:
      - "` + rsAudit + `"
      - role: "` + rsApply + `"
        session_duration: 2h
`, true, "role " + rsApply + ": session_duration 2h0m0s exceeds"},
		{"role session_duration over inherited limit", `    max_session_duration: 2h
    roles:
      - role: "` + rsApply + `"
        session_duration: 3h
`, true, "exceeds max_session_duration"},
		{"role limit drops below inherited session_duration", `    max_session_duration: 3h
    session_duration: 2h
    roles:
      - "` + rsAudit + `"
      - role: "` + rsApply + `"
        max_session_duration: 1h
`, true, "exceeds max_session_duration"},
		{"session_duration out of bounds", `    roles:
      - role: "` + rsApply + `"
        session_duration: 1m
`, false, "session_duration"},
		{"entry session_duration no role inherits", `    max_session_duration: 30m
    session_duration: 20m
    roles:
      - role: "` + rsApply + `"
        session_duration: 25m
`, false, "no role inherits"},
		{"duration out of bounds", `    roles:
      - role: "` + rsApply + `"
        max_session_duration: 1m
`, false, "max_session_duration"},
		{"subject on role", `    roles:
      - role: "` + rsApply + `"
        subject: "other/repo"
`, false, "unknown key"},
		{"issuer on role", `    roles:
      - role: "` + rsApply + `"
        issuer: "` + vIss + `"
`, false, "unknown key"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := rsLoad(t, rsMapping(tc.entry), tc.idp)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErr)
		})
	}
}

func TestRoleEntryHookReportsFirstEmptyKeyInOrder(t *testing.T) {
	data := map[string]any{"role": "x", "session_policy": nil, "idp_token": nil, "conditions": nil, "max_session_duration": nil}
	for range 50 {
		_, err := roleEntryHookFunc()(reflect.TypeOf(data), roleEntryType, data)
		require.EqualError(t, err, `role setting "conditions" is present but empty`)
	}
}

func TestScalarRolesSplitOnComma(t *testing.T) {
	cfg, err := rsLoad(t, rsMapping(`    roles: "`+rsAudit+`,`+rsApply+`"
`), false)
	require.NoError(t, err)
	for _, role := range []string{rsAudit, rsApply} {
		assert.Contains(t, cfg.Authorize(vIss, "acme/app", role, nil).Roles, role)
	}
}

func TestRoleSetBlockAppliesToEveryMember(t *testing.T) {
	for _, set := range []string{"@pair", "@dup"} {
		doc := `    roles:
      - role: "` + set + `"
        conditions:
          ref: "refs/heads/main"
        max_session_duration: 30m
`
		cfg, err := rsLoad(t, rsMapping(doc), false)
		require.NoError(t, err, set)
		for _, role := range []string{rsPlan, rsApply} {
			t.Run(set+"/"+role, func(t *testing.T) {
				d := cfg.Authorize(vIss, "acme/app", role, map[string]any{"ref": "refs/heads/main"})
				require.True(t, d.Matched)
				assert.Equal(t, 30*time.Minute, d.MaxSessionDuration())
				assert.NotContains(t, cfg.Authorize(vIss, "acme/app", role, map[string]any{"ref": "refs/heads/dev"}).Roles, role)
			})
		}
	}
}

func TestRoleEntryWarnings(t *testing.T) {
	tests := []struct {
		name     string
		entry    string
		tagAuth  bool
		wantCode string
		wantRole string
		wantBy   string
	}{
		{"unconditional beside conditioned", `    roles:
      - "` + rsAudit + `"
      - role: "` + rsApply + `"
        conditions:
          ref: "refs/heads/main"
`, false, "unconditional_role_beside_conditioned", rsAudit, ""},
		{"unconditional role with other overrides beside conditioned", `    roles:
      - role: "` + rsAudit + `"
        role_session_name: "audit"
      - role: "` + rsApply + `"
        conditions:
          ref: "refs/heads/main"
`, false, "unconditional_role_beside_conditioned", rsAudit, ""},
		{"entry conditions cover plain role", `    conditions:
      event_name: "push"
    roles:
      - "` + rsAudit + `"
      - role: "` + rsApply + `"
        conditions:
          ref: "refs/heads/main"
`, false, "", "", ""},
		{"no role conditions at all", `    roles:
      - "` + rsAudit + `"
      - role: "` + rsApply + `"
        max_session_duration: 30m
`, false, "", "", ""},
		{"tag auth bypasses role conditions", `    roles:
      - role: "` + rsApply + `"
        conditions:
          ref: "refs/heads/main"
`, true, "tag_auth_bypasses_mapping_scoping", rsApply, "role_conditions"},
		{"tag auth bypasses duration limit", `    roles:
      - role: "` + rsApply + `"
        max_session_duration: 15m
`, true, "tag_auth_bypasses_mapping_scoping", rsApply, "max_session_duration"},
		{"tag auth duration at 1h is no bypass", `    roles:
      - role: "` + rsApply + `"
        max_session_duration: 1h
`, true, "", "", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			logs := captureWarnings(t, func() {
				v := viper.New()
				v.SetConfigType("yaml")
				doc := rsHeader + rsMapping(tc.entry)
				if tc.tagAuth {
					doc += "tag_auth:\n  enabled: true\n  allowed_accounts: [\"111122223333\"]\n"
				}
				require.NoError(t, v.ReadConfig(strings.NewReader(doc)))
				var c Config
				require.NoError(t, v.Unmarshal(&c, decoderOptions(nil)...))
				require.NoError(t, c.Validate())
			})
			codes := []string{"unconditional_role_beside_conditioned", "tag_auth_bypasses_mapping_scoping"}
			for _, code := range codes {
				assert.Equal(t, code == tc.wantCode, hasWarningCode(t, logs, code), code)
			}
			if tc.wantCode == "" {
				return
			}
			var found bool
			for _, w := range parseWarnLines(t, logs) {
				if w.Warning == tc.wantCode {
					found = true
					assert.Equal(t, tc.wantRole, w.Role)
					assert.Equal(t, tc.wantBy, w.ScopedBy)
				}
			}
			assert.True(t, found)
		})
	}
}

func TestIdPOnlyRejectsExplicitIdPTokenFalse(t *testing.T) {
	const falseRole = `    roles:
      - "` + rsAudit + `"
      - role: "` + rsApply + `"
        idp_token: false
`
	const trueRole = `    roles:
      - role: "` + rsApply + `"
        idp_token: true
`
	const plainRole = `    roles: ["` + rsAudit + `"]
`
	tests := []struct {
		name     string
		entry    string
		only     bool
		disabled bool
		wantErr  string
	}{
		{"idp_token false with only", falseRole, true, false, "idp.only"},
		{"idp_token false without only", falseRole, false, false, ""},
		{"idp_token true with only", trueRole, true, false, ""},
		{"only with idp disabled", plainRole, true, true, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			idp := validIdP()
			idp.Only, idp.Enabled = tc.only, !tc.disabled
			_, err := rsLoadIdP(t, rsMapping(tc.entry), idp)
			if tc.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.ErrorContains(t, err, tc.wantErr)
		})
	}
}

func TestSessionDurationValidate(t *testing.T) {
	tests := []struct {
		name         string
		session, max time.Duration
		wantErr      string
	}{
		{"unset", 0, 0, ""},
		{"equals default limit", time.Hour, 0, ""},
		{"below limit", 30 * time.Minute, 4 * time.Hour, ""},
		{"equals limit", 4 * time.Hour, 4 * time.Hour, ""},
		{"under 15m", 14 * time.Minute, 4 * time.Hour, "session_duration"},
		{"over 12h", 13 * time.Hour, 12 * time.Hour, "session_duration"},
		{"sub-second", 30*time.Minute + time.Millisecond, time.Hour, "whole number of seconds"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := idpMappingCfg(RoleMapping{Subject: Patterns{"org/repo"}, Roles: roleEntries(rsApply), SessionDuration: tt.session, MaxSessionDuration: tt.max})
			cfg.IdP = validIdP()
			err := cfg.Validate()
			if tt.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.ErrorContains(t, err, tt.wantErr)
		})
	}
}

func TestRoleGroupWarnsOncePerRoleNotPerSubject(t *testing.T) {
	var c *Config
	logs := captureWarnings(t, func() {
		var err error
		c, err = rsLoad(t, `role_groups:
  - subjects: ["repo:o/a:ref:refs/heads/main", "repo:o/b:ref:refs/heads/main", "repo:o/c:ref:refs/heads/main"]
    defaults:
      roles:
        - "`+rsAudit+`"
        - role: "`+rsApply+`"
          conditions:
            ref: "refs/heads/main"
`, false)
		require.NoError(t, err)
	})
	assert.Equal(t, 1, strings.Count(logs, "unconditional_role_beside_conditioned"))
	assert.Len(t, c.effective, 6)
}

func TestInheritedConditionTypoWarnsOncePerSubject(t *testing.T) {
	const ghIss = "https://token.actions.githubusercontent.com"
	for _, tc := range []struct {
		name, claim, roles string
		want               int
	}{
		{"known-claim tags do not split the warning", "evnet_name", `
      - "` + rsAudit + `"
      - role: "` + rsApply + `"
        role_session_name: "apply"
        session_tags: {repo: "repository"}
      - role: "` + rsPlan + `"
        session_tags: {owner: "repository_owner"}
`, 1},
		{"tag naming the claim silences only its own role", "team_slug", `
      - role: "` + rsApply + `"
        session_tags: {team: "team_slug"}
      - role: "` + rsPlan + `"
        role_session_name: "plan"
`, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			doc := `
issuers:
  - issuer: "` + ghIss + `"
    provider: "github"
    audiences: ["sts.amazonaws.com"]
default_issuer: "` + ghIss + `"
role_session_name: "test"
role_mappings:
  - subject: "repo:o/r:ref:refs/heads/main"
    conditions:
      claims:
        ` + tc.claim + `: "push"
    roles:` + tc.roles
			logs := captureWarnings(t, func() {
				v := viper.New()
				v.SetConfigType("yaml")
				require.NoError(t, v.ReadConfig(strings.NewReader(doc)))
				var c Config
				require.NoError(t, v.Unmarshal(&c, decoderOptions(nil)...))
				require.NoError(t, c.Validate())
			})
			assert.Equal(t, tc.want, strings.Count(logs, "condition_unknown_claim"))
		})
	}
}
