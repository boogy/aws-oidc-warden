package config

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

// decodeConditions parses one role_mappings entry's `conditions:` block through
// the real viper/mapstructure path (decoder options included), which is the
// only way to exercise the string-or-list decode.
func decodeConditions(t *testing.T, conditionsYAML string) *Condition {
	t.Helper()
	doc := `
role_mappings:
  - subject: "acme/app"
    roles: ["arn:aws:iam::111111111111:role/app"]
    conditions:
` + conditionsYAML

	v := viper.New()
	v.SetConfigType("yaml")
	require.NoError(t, v.ReadConfig(strings.NewReader(doc)))

	var c Config
	require.NoError(t, v.Unmarshal(&c, decoderOptions()...))
	require.Len(t, c.RoleMappings, 1)
	return c.RoleMappings[0].Conditions
}

// TestPatternsDecodeStringOrList proves one claim key accepts either shape, for
// a named field and for a generic (remain-map) claim alike.
func TestPatternsDecodeStringOrList(t *testing.T) {
	cond := decodeConditions(t, `
      ref: "refs/heads/main"
      actor: ["release-bot", "release-manager"]
      project_path: "mygroup/myproject"
      groups:
        - platform-team
        - sre
`)
	require.Equal(t, Patterns{"refs/heads/main"}, cond.Ref)
	require.Equal(t, Patterns{"release-bot", "release-manager"}, cond.Claims["actor"])
	require.Equal(t, Patterns{"mygroup/myproject"}, cond.Claims["project_path"])
	require.Equal(t, Patterns{"platform-team", "sre"}, cond.Claims["groups"])
}

// TestPatternsDecodeKeepsCommasInRegexes pins that a bounded-repetition regex
// survives decoding intact. A string bound for a slice is one comma-splitting
// hook away from being torn in half — silently changing what the gate matches —
// so this is asserted rather than reasoned about.
func TestPatternsDecodeKeepsCommasInRegexes(t *testing.T) {
	cond := decodeConditions(t, `
      ref: 'refs/tags/v[0-9]{1,3}'
      custom_claim: 'a{2,4}b'
`)
	require.Equal(t, Patterns{`refs/tags/v[0-9]{1,3}`}, cond.Ref)
	require.Equal(t, Patterns{`a{2,4}b`}, cond.Claims["custom_claim"])
}

// TestPatternsUnmarshalJSON covers the other decode path: the provider's
// hot-reload snapshot clone round-trips the config through encoding/json.
func TestPatternsUnmarshalJSON(t *testing.T) {
	var one Patterns
	require.NoError(t, json.Unmarshal([]byte(`"main"`), &one))
	require.Equal(t, Patterns{"main"}, one)

	var many Patterns
	require.NoError(t, json.Unmarshal([]byte(`["main","dev"]`), &many))
	require.Equal(t, Patterns{"main", "dev"}, many)

	var bad Patterns
	require.Error(t, json.Unmarshal([]byte(`{"a":1}`), &bad))

	// Round trip: what Marshal writes must decode back to the same value.
	data, err := json.Marshal(Patterns{"main", "dev"})
	require.NoError(t, err)
	var back Patterns
	require.NoError(t, json.Unmarshal(data, &back))
	require.Equal(t, Patterns{"main", "dev"}, back)
}

// TestClaimPatternsAreOredWithinAClaim pins the core semantics of the list
// form: OR within one claim's patterns, AND across claims.
func TestClaimPatternsAreOredWithinAClaim(t *testing.T) {
	cfg := condCfg(t, &Condition{
		Claims: map[string]Patterns{
			"actor":      {"release-bot", "release-manager"},
			"event_name": {"push"},
		},
	})

	cases := []struct {
		name   string
		claims map[string]any
		want   bool
	}{
		{"first pattern matches", map[string]any{"actor": "release-bot", "event_name": "push"}, true},
		{"second pattern matches", map[string]any{"actor": "release-manager", "event_name": "push"}, true},
		{"no pattern matches", map[string]any{"actor": "mallory", "event_name": "push"}, false},
		{"other claim fails", map[string]any{"actor": "release-bot", "event_name": "pull_request"}, false},
		{"array claim matches one pattern", map[string]any{"actor": []any{"x", "release-manager"}, "event_name": "push"}, true},
		{"absent claim denies", map[string]any{"event_name": "push"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := authorizes(cfg, tc.claims); got != tc.want {
				t.Fatalf("authorized = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestNonGitHubClaimsGateAuthorization proves the same syntax gates a
// non-GitHub issuer's claims — the point of naming condition keys after the
// claim rather than after a GitHub-shaped field.
func TestNonGitHubClaimsGateAuthorization(t *testing.T) {
	cfg := condCfg(t, &Condition{
		Claims: map[string]Patterns{
			"project_path": {"mygroup/myproject"},
			"groups":       {"platform-team", "sre"},
		},
	})

	require.True(t, authorizes(cfg, map[string]any{
		"project_path": "mygroup/myproject",
		"groups":       []any{"contractors", "sre"},
	}))
	require.False(t, authorizes(cfg, map[string]any{
		"project_path": "othergroup/myproject",
		"groups":       []any{"sre"},
	}))
	require.False(t, authorizes(cfg, map[string]any{
		"project_path": "mygroup/myproject",
		"groups":       []any{"contractors"},
	}))
}

// TestValidate_RejectsEmptyPatternLists proves a key that lists no pattern is a
// hard error rather than a silently-absent gate. `ref: []` reads as a
// predicate; treating it as "unset" would drop the gate without a word.
func TestValidate_RejectsEmptyPatternLists(t *testing.T) {
	cases := map[string]*Condition{
		"named field":                        {Ref: Patterns{}},
		"generic claim":                      {Claims: map[string]Patterns{"project_path": {}}},
		"nested group":                       {AnyOf: []*Condition{{EventName: Patterns{}}}},
		"empty pattern":                      {Ref: Patterns{""}},
		"one empty pattern among valid ones": {Ref: Patterns{"refs/heads/main", ""}},
		"bare wildcard in a list":            {Ref: Patterns{"refs/heads/main", ".*"}},
	}
	for name, cond := range cases {
		t.Run(name, func(t *testing.T) {
			require.Error(t, validateCond(cond))
		})
	}
}

// TestValidate_WarnsOnDeprecatedConditionKeys pins the deprecation contract:
// the old keys keep working (the config still validates and still authorizes),
// but Validate() names the mapping, the key, and its replacement.
func TestValidate_WarnsOnDeprecatedConditionKeys(t *testing.T) {
	cond := &Condition{
		Branch:       Patterns{"main"},
		Environment:  Patterns{"github-hosted"},
		ActorMatches: Patterns{"release-bot"},
		AnyOf:        []*Condition{{Branch: Patterns{"dev"}}},
	}

	logs := captureWarnings(t, func() {
		require.NoError(t, validateCond(cond))
	})

	for _, want := range []string{
		"conditions.branch", "conditions.environment", "conditions.actor_matches",
		"conditions.any_of[0].branch", // groups are walked too
		`"use":"ref"`, `"use":"runner_environment"`, `"use":"actor"`,
		"acme/app", // the mapping is named
	} {
		require.Contains(t, logs, want)
	}

	// Still gating exactly as before the deprecation.
	cfg := condCfg(t, &Condition{Branch: Patterns{"main"}, Environment: Patterns{"github-hosted"}, ActorMatches: Patterns{"release-bot"}})
	require.True(t, authorizes(cfg, map[string]any{"ref": "main", "runner_environment": "github-hosted", "actor": "release-bot"}))
	require.False(t, authorizes(cfg, map[string]any{"ref": "dev", "runner_environment": "github-hosted", "actor": "release-bot"}))
}

// TestValidate_WarnsOnUnknownGitHubClaim catches the typo that would otherwise
// fail silently: a misspelled claim never matches, so the mapping simply stops
// authorizing with no explanation.
func TestValidate_WarnsOnUnknownGitHubClaim(t *testing.T) {
	const ghIss = "https://token.actions.githubusercontent.com"
	build := func(cond *Condition, issuer IssuerConfig) *Config {
		return &Config{
			Issuers:         []IssuerConfig{issuer},
			DefaultIssuer:   issuer.Issuer,
			RoleSessionName: "test",
			RoleMappings: []RoleMapping{{
				Subject:    "acme/app",
				Roles:      []string{"arn:aws:iam::111111111111:role/app"},
				Conditions: cond,
			}},
		}
	}
	github := IssuerConfig{Issuer: ghIss, Provider: "github", Audiences: []string{"sts.amazonaws.com"}}

	t.Run("unknown claim warns", func(t *testing.T) {
		cfg := build(&Condition{Claims: map[string]Patterns{
			"repository_owner": {"acme"}, // known
			"event-name":       {"push"}, // typo: dash, not underscore
			"any_of_typo":      {"push"}, // not a claim at all
		}}, github)
		logs := captureWarnings(t, func() { require.NoError(t, cfg.Validate()) })
		require.Contains(t, logs, "conditions.event-name")
		require.Contains(t, logs, "conditions.any_of_typo")
		require.NotContains(t, logs, "conditions.repository_owner")
	})

	t.Run("nested groups are walked", func(t *testing.T) {
		cfg := build(&Condition{AnyOf: []*Condition{
			{Claims: map[string]Patterns{"reposiory": {"acme/app"}}},
			{EventName: Patterns{"push"}},
		}}, github)
		logs := captureWarnings(t, func() { require.NoError(t, cfg.Validate()) })
		require.Contains(t, logs, "conditions.any_of[0].reposiory")
	})

	t.Run("a claim the issuer declares is not a typo", func(t *testing.T) {
		declared := github
		declared.SessionTags = map[string]string{"Team": "custom_team_claim"}
		declared.RequiredClaims = []string{"custom_required_claim"}
		cfg := build(&Condition{Claims: map[string]Patterns{
			"custom_team_claim":     {"platform"},
			"custom_required_claim": {"yes"},
		}}, declared)
		logs := captureWarnings(t, func() { require.NoError(t, cfg.Validate()) })
		require.NotContains(t, logs, "check the spelling")
	})

	t.Run("generic issuers are never warned about", func(t *testing.T) {
		generic := IssuerConfig{
			Issuer:        vIss,
			Provider:      "generic",
			Audiences:     []string{"aud"},
			ClaimMappings: map[string]string{"subject": "sub"},
		}
		cfg := build(&Condition{Claims: map[string]Patterns{"project_path": {"grp/prj"}, "groups": {"sre"}}}, generic)
		logs := captureWarnings(t, func() { require.NoError(t, cfg.Validate()) })
		require.NotContains(t, logs, "check the spelling")
	})
}

// TestGitHubClaimNamesCoverTheValidatorsVocabulary guards against the warning's
// known set drifting away from what the github provider actually unmarshals:
// every claim types.Claims models must be spelled the same here, or a valid
// condition would be reported as a typo.
func TestGitHubClaimNamesCoverTheValidatorsVocabulary(t *testing.T) {
	for _, claim := range []string{
		"actor", "actor_id", "base_ref", "event_name", "head_ref", "job_workflow_ref",
		"job_workflow_sha", "ref", "ref_protected", "ref_type", "repository",
		"repository_id", "repository_owner", "repository_owner_id",
		"repository_visibility", "run_attempt", "run_id", "run_number",
		"runner_environment", "sha", "sub", "workflow", "workflow_ref", "workflow_sha",
		"iss", "aud", "exp", "environment", "enterprise",
	} {
		require.True(t, githubClaimNames[claim], "claim %q must be part of the known GitHub vocabulary", claim)
	}
	require.False(t, githubClaimNames["raw"], "Raw is a Go field, not a claim")
}
