package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

// The condition engine: claim matching, the all_of/any_of/none_of groups and
// their nesting limits, pattern decoding (scalar or list, YAML and JSON), the
// explicit `claims:` map, and everything Validate() rejects — an empty group,
// a key written with no pattern, a gate that gates nothing.

// condCfg builds a validated single-mapping config gated by c. vcfg and vIss
// come from authz_adversarial_test.go.
func condCfg(t *testing.T, c *Condition) *Config {
	t.Helper()
	return vcfg(t, []RoleMapping{{
		Subject:    Patterns{"acme/app"},
		Roles:      []string{"arn:aws:iam::111111111111:role/app"},
		Conditions: c,
	}})
}

// authorizes reports whether the mapping built by condCfg grants its role.
func authorizes(cfg *Config, claims map[string]any) bool {
	ok, roles := cfg.AuthorizeRoles(vIss, "acme/app", claims)
	return ok && len(roles) > 0
}

// TestClaimMatches_ArrayClaims pins the leaf-matching contract: a string claim
// matches on the anchored pattern, an array claim matches when ANY string
// element does, and every other shape denies.
func TestClaimMatches_ArrayClaims(t *testing.T) {
	cfg := condCfg(t, &Condition{Claims: map[string]Patterns{"groups": {"team-a"}}})

	cases := []struct {
		name   string
		claims map[string]any
		want   bool
	}{
		{"string claim matches", map[string]any{"groups": "team-a"}, true},
		{"string claim does not match", map[string]any{"groups": "team-b"}, false},
		{"array with matching element", map[string]any{"groups": []any{"team-b", "team-a"}}, true},
		{"array with only the matching element", map[string]any{"groups": []any{"team-a"}}, true},
		{"array with no matching element", map[string]any{"groups": []any{"team-b", "team-c"}}, false},
		{"empty array denies", map[string]any{"groups": []any{}}, false},
		{"non-string elements are ignored", map[string]any{"groups": []any{1, true, nil}}, false},
		{"anchoring still applies inside the array", map[string]any{"groups": []any{"xteam-ax"}}, false},
		{"number claim denies", map[string]any{"groups": float64(1)}, false},
		{"bool claim denies", map[string]any{"groups": true}, false},
		{"object claim denies", map[string]any{"groups": map[string]any{"a": "team-a"}}, false},
		{"absent claim denies", map[string]any{}, false},
		{"null claim denies", map[string]any{"groups": nil}, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := authorizes(cfg, tc.claims); got != tc.want {
				t.Fatalf("authorized = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestClaimMatches_ActorUsesTheSameMatcher proves `actor` routes
// through the same leaf matcher, so an array-valued actor claim behaves like
// every other array claim rather than through a second, divergent code path.
func TestClaimMatches_ActorUsesTheSameMatcher(t *testing.T) {
	cfg := condCfg(t, &Condition{Actor: Patterns{"release-bot", "alice"}})

	cases := []struct {
		name   string
		claims map[string]any
		want   bool
	}{
		{"string actor in the list", map[string]any{"actor": "alice"}, true},
		{"string actor not in the list", map[string]any{"actor": "mallory"}, false},
		{"array actor with a listed element", map[string]any{"actor": []any{"mallory", "alice"}}, true},
		{"array actor with no listed element", map[string]any{"actor": []any{"mallory"}}, false},
		{"absent actor denies", map[string]any{}, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := authorizes(cfg, tc.claims); got != tc.want {
				t.Fatalf("authorized = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestAnyOf pins OR semantics: the group is satisfied when at least one member
// condition is satisfied in full.
func TestAnyOf(t *testing.T) {
	cfg := condCfg(t, &Condition{
		AnyOf: []*Condition{
			{EventName: Patterns{"push"}, Ref: Patterns{"refs/heads/main"}},
			{EventName: Patterns{"workflow_dispatch"}},
		},
	})

	cases := []struct {
		name   string
		claims map[string]any
		want   bool
	}{
		{"first member fully matches", map[string]any{"event_name": "push", "ref": "refs/heads/main"}, true},
		{"first member only partly matches", map[string]any{"event_name": "push", "ref": "refs/heads/dev"}, false},
		{"second member matches", map[string]any{"event_name": "workflow_dispatch"}, true},
		{"no member matches", map[string]any{"event_name": "pull_request"}, false},
		{"no claims at all", map[string]any{}, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := authorizes(cfg, tc.claims); got != tc.want {
				t.Fatalf("authorized = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestAllOf pins AND semantics for an explicit group (the same rule the top
// level applies implicitly).
func TestAllOf(t *testing.T) {
	cfg := condCfg(t, &Condition{
		AllOf: []*Condition{
			{RefType: Patterns{"tag"}},
			{Ref: Patterns{`refs/tags/v[0-9]+\.[0-9]+\.[0-9]+`}},
		},
	})

	cases := []struct {
		name   string
		claims map[string]any
		want   bool
	}{
		{"both members match", map[string]any{"ref_type": "tag", "ref": "refs/tags/v1.2.3"}, true},
		{"one member fails", map[string]any{"ref_type": "branch", "ref": "refs/tags/v1.2.3"}, false},
		{"other member fails", map[string]any{"ref_type": "tag", "ref": "refs/tags/nightly"}, false},
		{"claim absent fails", map[string]any{"ref_type": "tag"}, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := authorizes(cfg, tc.claims); got != tc.want {
				t.Fatalf("authorized = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestNoneOf pins negation semantics, including the decided contract that an
// ABSENT claim satisfies a none_of: the inner predicate cannot match, so its
// negation holds. none_of is exactly NOT(any_of).
func TestNoneOf(t *testing.T) {
	cfg := condCfg(t, &Condition{
		NoneOf: []*Condition{
			{RunnerEnvironment: Patterns{"sandbox"}},
			{EventName: Patterns{"pull_request"}},
		},
	})

	cases := []struct {
		name   string
		claims map[string]any
		want   bool
	}{
		{"neither member matches", map[string]any{"runner_environment": "production", "event_name": "push"}, true},
		{"first member matches", map[string]any{"runner_environment": "sandbox", "event_name": "push"}, false},
		{"second member matches", map[string]any{"runner_environment": "production", "event_name": "pull_request"}, false},
		{"both members match", map[string]any{"runner_environment": "sandbox", "event_name": "pull_request"}, false},
		{"claims absent entirely satisfies none_of", map[string]any{}, true},
		{"array claim with a matching element still trips none_of", map[string]any{"runner_environment": []any{"production", "sandbox"}}, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := authorizes(cfg, tc.claims); got != tc.want {
				t.Fatalf("authorized = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestTopLevelStaysImplicitAnd proves the new groups compose with the existing
// flat fields on the same node: leaves AND actor AND all_of AND any_of
// AND none_of must all hold. This is what makes every pre-existing config keep
// its exact meaning.
func TestTopLevelStaysImplicitAnd(t *testing.T) {
	cfg := condCfg(t, &Condition{
		RefType: Patterns{"tag"}, // flat leaf, AND'd with everything below
		AnyOf: []*Condition{
			{Ref: Patterns{`refs/tags/v[0-9]+\.[0-9]+\.[0-9]+`}},
			{Ref: Patterns{`refs/tags/hotfix-.+`}},
		},
		NoneOf: []*Condition{
			{RunnerEnvironment: Patterns{"sandbox"}},
		},
	})

	cases := []struct {
		name   string
		claims map[string]any
		want   bool
	}{
		{"leaf + any_of + none_of all hold", map[string]any{"ref_type": "tag", "ref": "refs/tags/v1.2.3", "runner_environment": "production"}, true},
		{"hotfix alternative holds", map[string]any{"ref_type": "tag", "ref": "refs/tags/hotfix-9", "runner_environment": "production"}, true},
		{"flat leaf fails", map[string]any{"ref_type": "branch", "ref": "refs/tags/v1.2.3", "runner_environment": "production"}, false},
		{"any_of fails", map[string]any{"ref_type": "tag", "ref": "refs/tags/nightly", "runner_environment": "production"}, false},
		{"none_of trips", map[string]any{"ref_type": "tag", "ref": "refs/tags/v1.2.3", "runner_environment": "sandbox"}, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := authorizes(cfg, tc.claims); got != tc.want {
				t.Fatalf("authorized = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestNestedGroups proves groups nest and that the composition is functionally
// complete: this is "(push from main) OR (a release workflow dispatch by the
// release bot), and never from the sandbox runner".
func TestNestedGroups(t *testing.T) {
	cfg := condCfg(t, &Condition{
		AnyOf: []*Condition{
			{AllOf: []*Condition{
				{EventName: Patterns{"push"}},
				{Ref: Patterns{"refs/heads/main"}},
			}},
			{AllOf: []*Condition{
				{EventName: Patterns{"workflow_dispatch"}},
				{Actor: Patterns{"release-bot", "alice"}},
				{NoneOf: []*Condition{{Ref: Patterns{"refs/heads/wip-.+"}}}},
			}},
		},
		NoneOf: []*Condition{{RunnerEnvironment: Patterns{"sandbox"}}},
	})

	cases := []struct {
		name   string
		claims map[string]any
		want   bool
	}{
		{"push from main", map[string]any{"event_name": "push", "ref": "refs/heads/main"}, true},
		{"push from a feature branch", map[string]any{"event_name": "push", "ref": "refs/heads/feature"}, false},
		{"dispatch by the bot", map[string]any{"event_name": "workflow_dispatch", "actor": "release-bot", "ref": "refs/heads/main"}, true},
		{"dispatch by a stranger", map[string]any{"event_name": "workflow_dispatch", "actor": "mallory", "ref": "refs/heads/main"}, false},
		{"dispatch by the bot from a wip branch", map[string]any{"event_name": "workflow_dispatch", "actor": "release-bot", "ref": "refs/heads/wip-x"}, false},
		{"push from main on the sandbox runner", map[string]any{"event_name": "push", "ref": "refs/heads/main", "runner_environment": "sandbox"}, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := authorizes(cfg, tc.claims); got != tc.want {
				t.Fatalf("authorized = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestGroupsGateSessionPolicyAndSessionName proves the boolean gate applies to
// every predicate-driven lookup, not only AuthorizeRoles — FindSessionPolicy
// and FindRoleSessionName share findAuthorizingMapping, so a mapping whose
// group is unsatisfied must contribute neither its policy nor its name.
func TestGroupsGateSessionPolicyAndSessionName(t *testing.T) {
	const role = "arn:aws:iam::111111111111:role/app"
	cfg := vcfg(t, []RoleMapping{{
		Subject:         Patterns{"acme/app"},
		Roles:           []string{role},
		SessionPolicy:   `{"Version":"2012-10-17","Statement":[]}`,
		RoleSessionName: "acme-app",
		Conditions: &Condition{AnyOf: []*Condition{
			{EventName: Patterns{"push"}},
			{EventName: Patterns{"workflow_dispatch"}},
		}},
	}})

	good := map[string]any{"event_name": "push"}
	bad := map[string]any{"event_name": "pull_request"}

	if policy, _ := cfg.FindSessionPolicy(vIss, "acme/app", role, good); policy == nil {
		t.Fatal("satisfied any_of should yield the mapping's session policy")
	}
	if policy, file := cfg.FindSessionPolicy(vIss, "acme/app", role, bad); policy != nil || file != nil {
		t.Fatal("unsatisfied any_of must yield no session policy")
	}
	if name := cfg.FindRoleSessionName(vIss, "acme/app", role, good); name != "acme-app" {
		t.Fatalf("role session name = %q, want %q", name, "acme-app")
	}
	if name := cfg.FindRoleSessionName(vIss, "acme/app", role, bad); name != "" {
		t.Fatalf("unsatisfied any_of must yield no session name override, got %q", name)
	}
}

// validateCond runs Validate() over a single mapping gated by c and returns the
// error, so a test can assert on rejection rather than fataling.
func validateCond(c *Condition) error {
	cfg := &Config{
		Issuers: []IssuerConfig{{
			Issuer:        vIss,
			Provider:      "generic",
			Audiences:     []string{"aud"},
			ClaimMappings: map[string]string{"subject": "sub"},
		}},
		DefaultIssuer:   vIss,
		RoleSessionName: "test",
		RoleMappings: []RoleMapping{{
			Subject:    Patterns{"acme/app"},
			Roles:      []string{"arn:aws:iam::111111111111:role/app"},
			Conditions: c,
		}},
	}
	return cfg.Validate()
}

// TestValidate_RejectsDefeatedGroups pins the structural guards. Each rejected
// shape is one that COMPILES fine but reduces its group to a constant, which is
// exactly the class of accident an authorization gate must not accept.
func TestValidate_RejectsDefeatedGroups(t *testing.T) {
	cases := []struct {
		name string
		cond *Condition
		want bool // want an error
	}{
		{"empty any_of list", &Condition{AnyOf: []*Condition{}}, true},
		{"empty all_of list", &Condition{AllOf: []*Condition{}}, true},
		{"empty none_of list", &Condition{NoneOf: []*Condition{}}, true},
		{"empty member in any_of", &Condition{AnyOf: []*Condition{{EventName: Patterns{"push"}}, {}}}, true},
		{"nil member in any_of", &Condition{AnyOf: []*Condition{nil}}, true},
		{"member whose only pattern is empty", &Condition{AnyOf: []*Condition{{EventName: Patterns{""}}}}, true},
		{"member whose only generic claim pattern is empty", &Condition{AnyOf: []*Condition{{Claims: map[string]Patterns{"x": {""}}}}}, true},
		{"bare wildcard leaf nested two levels deep", &Condition{AnyOf: []*Condition{{AllOf: []*Condition{{EventName: Patterns{".*"}}}}}}, true},
		{"bare wildcard in a nested actor", &Condition{NoneOf: []*Condition{{Actor: Patterns{".+"}}}}, true},
		{"invalid regex nested", &Condition{AnyOf: []*Condition{{Ref: Patterns{"refs/heads/("}}}}, true},
		{"valid nested group", &Condition{AnyOf: []*Condition{{EventName: Patterns{"push"}}, {EventName: Patterns{"workflow_dispatch"}}}}, false},
		{"empty top-level condition is rejected", &Condition{}, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateCond(tc.cond)
			if tc.want && err == nil {
				t.Fatal("expected Validate() to reject this shape, got nil")
			}
			if !tc.want && err != nil {
				t.Fatalf("expected Validate() to accept this shape, got: %v", err)
			}
		})
	}
}

// TestValidate_ErrorNamesTheOffendingNode proves a rejected config points at
// the exact entry, so an operator does not have to bisect a nested block.
func TestValidate_ErrorNamesTheOffendingNode(t *testing.T) {
	err := validateCond(&Condition{
		AnyOf: []*Condition{
			{EventName: Patterns{"push"}},
			{AllOf: []*Condition{{EventName: Patterns{"push"}}, {Ref: Patterns{".*"}}}},
		},
	})
	if err == nil {
		t.Fatal("expected a bare-wildcard rejection")
	}
	if !strings.Contains(err.Error(), "conditions.any_of[1].all_of[1]") {
		t.Fatalf("error should name the offending node, got: %v", err)
	}
}

const nestedConditionYAML = `
role_mappings:
  - subject: "acme/app"
    roles: ["arn:aws:iam::111111111111:role/app"]
    conditions:
      ref_type: "tag"
      sha: "[0-9a-f]{40}"
      any_of:
        - event_name: "push"
          ref: "refs/heads/main"
        - all_of:
            - event_name: "workflow_dispatch"
            - actor: ["release-bot"]
      none_of:
        - runner_environment: "sandbox"
`

// TestNestedConditionsDecodeFromYAML proves mapstructure routes the three
// group keys to their fields while the remain-map still collects generic claim
// predicates ("sha") at the same level — the decode both features depend on.
func TestNestedConditionsDecodeFromYAML(t *testing.T) {
	v := viper.New()
	v.SetConfigType("yaml")
	require.NoError(t, v.ReadConfig(strings.NewReader(nestedConditionYAML)))

	var c Config
	require.NoError(t, v.Unmarshal(&c, decoderOptions()...))
	require.Len(t, c.RoleMappings, 1)

	cond := c.RoleMappings[0].Conditions
	require.NotNil(t, cond)
	require.Equal(t, Patterns{"tag"}, cond.RefType)
	require.Equal(t, Patterns{"[0-9a-f]{40}"}, cond.Claims["sha"], "generic claim predicates must still land in the remain-map")
	require.NotContains(t, cond.Claims, "any_of", "group keys must not be swallowed by the remain-map")
	require.NotContains(t, cond.Claims, "none_of", "group keys must not be swallowed by the remain-map")
	require.Len(t, cond.AnyOf, 2)
	require.Equal(t, Patterns{"push"}, cond.AnyOf[0].EventName)
	require.Len(t, cond.AnyOf[1].AllOf, 2)
	require.Equal(t, Patterns{"release-bot"}, cond.AnyOf[1].AllOf[1].Actor)
	require.Len(t, cond.NoneOf, 1)
	require.Equal(t, Patterns{"sandbox"}, cond.NoneOf[0].RunnerEnvironment)
}

// TestNestedConditionsSurviveJSONClone proves the hot-reload path preserves the
// tree. Provider.refreshLocked deep-copies Config through cloneConfig's JSON
// round trip and re-Validates, so the recursive []*Condition structure and the
// Claims remain-map must both survive marshal/unmarshal for a nested gate to
// keep gating after a reload.
//
// Note what would and would NOT break this: encoding/json falls back to the
// field NAME for an exported field with no tag, so omitting `json:"any_of"` is
// a style bug, not a dropped gate. What drops a gate is `json:"-"` (as on the
// unexported compiled cache, deliberately) or an unexported
// field. This test pins the round trip end-to-end rather than the tags.
func TestNestedConditionsSurviveJSONClone(t *testing.T) {
	const role = "arn:aws:iam::111111111111:role/app"
	orig := &Config{
		Issuers: []IssuerConfig{{
			Issuer:        vIss,
			Provider:      "generic",
			Audiences:     []string{"aud"},
			ClaimMappings: map[string]string{"subject": "sub"},
		}},
		DefaultIssuer:   vIss,
		RoleSessionName: "test",
		RoleMappings: []RoleMapping{{
			Subject: Patterns{"acme/app"},
			Roles:   []string{role},
			Conditions: &Condition{
				AnyOf:          []*Condition{{EventName: Patterns{"push"}}, {EventName: Patterns{"workflow_dispatch"}}},
				NoneOf:         []*Condition{{RunnerEnvironment: Patterns{"sandbox"}}},
				Claims:         map[string]Patterns{"sha": {"[0-9a-f]{40}"}},
				ExplicitClaims: map[string]Patterns{"environment": {"production"}},
			},
		}},
	}
	require.NoError(t, orig.Validate())

	clone, err := cloneConfig(orig)
	require.NoError(t, err)
	require.NoError(t, clone.Validate())

	allow := map[string]any{"event_name": "push", "sha": "0123456789abcdef0123456789abcdef01234567", "environment": "production"}
	deny := map[string]any{"event_name": "push", "sha": "0123456789abcdef0123456789abcdef01234567", "environment": "production", "runner_environment": "sandbox"}
	denyNoSha := map[string]any{"event_name": "push", "environment": "production"}
	denyNoEnv := map[string]any{"event_name": "push", "sha": "0123456789abcdef0123456789abcdef01234567"}

	for name, cfg := range map[string]*Config{"original": orig, "clone": clone} {
		t.Run(name, func(t *testing.T) {
			ok, _ := cfg.AuthorizeRoles(vIss, "acme/app", allow)
			require.True(t, ok, "satisfied condition must authorize")
			ok, _ = cfg.AuthorizeRoles(vIss, "acme/app", deny)
			require.False(t, ok, "none_of must still deny after the round trip")
			ok, _ = cfg.AuthorizeRoles(vIss, "acme/app", denyNoSha)
			require.False(t, ok, "the generic-claim leaf must still deny after the round trip")
			ok, _ = cfg.AuthorizeRoles(vIss, "acme/app", denyNoEnv)
			require.False(t, ok, "the claims: leaf must still deny after the round trip")
		})
	}
}

// nestCondition builds a chain of all_of groups depth levels deep, with a real
// leaf predicate at the innermost node. nestCondition(1) is a bare leaf.
func nestCondition(depth int) *Condition {
	c := &Condition{EventName: Patterns{"push"}}
	for i := 1; i < depth; i++ {
		c = &Condition{AllOf: []*Condition{c}}
	}
	return c
}

// TestValidate_RejectsExcessiveNesting pins the depth cap. Deep boolean nesting
// is unreadable in a security config long before it is slow, and an unbounded
// depth makes evaluation cost a property of a config file rather than of the
// code.
func TestValidate_RejectsExcessiveNesting(t *testing.T) {
	cases := []struct {
		name  string
		depth int
		want  bool // want an error
	}{
		{"single leaf", 1, false},
		{"at the cap", maxConditionDepth, false},
		{"one past the cap", maxConditionDepth + 1, true},
		{"far past the cap", maxConditionDepth + 10, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateCond(nestCondition(tc.depth))
			if tc.want {
				require.Error(t, err)
				require.Contains(t, err.Error(), "nesting")
				return
			}
			require.NoError(t, err)
		})
	}
}

// TestValidate_RejectsTooManyNodes pins the node budget: depth alone does not
// bound the work, since one any_of can hold arbitrarily many members.
func TestValidate_RejectsTooManyNodes(t *testing.T) {
	build := func(members int) *Condition {
		nodes := make([]*Condition, members)
		for i := range nodes {
			nodes[i] = &Condition{EventName: Patterns{"push"}}
		}
		return &Condition{AnyOf: nodes}
	}

	// The top-level node counts too, so maxConditionNodes-1 members is exactly
	// at the cap and one more is over it.
	require.NoError(t, validateCond(build(maxConditionNodes-1)), "a tree exactly at the cap must be accepted")

	err := validateCond(build(maxConditionNodes))
	require.Error(t, err, "a tree one node past the cap must be rejected")
	require.Contains(t, err.Error(), "condition nodes")
}

// TestNestedConditionIndexParity proves the owner-bucketed index stays
// equivalent to a full linear scan once conditions carry boolean groups.
// Bucketing is a performance detail whose correctness rests on candidatesFor
// never hiding a mapping that would have matched; conditions do not affect
// bucketing, and this test is what keeps that true as the condition engine
// grows.
func TestNestedConditionIndexParity(t *testing.T) {
	mappings := []RoleMapping{
		{ // exact-literal subject bucket
			Subject: Patterns{"acme/app"},
			Roles:   []string{"arn:aws:iam::111111111111:role/app"},
			Conditions: &Condition{AnyOf: []*Condition{
				{EventName: Patterns{"push"}, Ref: Patterns{"refs/heads/main"}},
				{EventName: Patterns{"workflow_dispatch"}},
			}},
		},
		{ // byOwner bucket
			Subject: Patterns{`acme/service-.+`},
			Roles:   []string{"arn:aws:iam::111111111111:role/service"},
			Conditions: &Condition{
				RefType: Patterns{"tag"},
				NoneOf:  []*Condition{{RunnerEnvironment: Patterns{"sandbox"}}},
			},
		},
		{ // "any" bucket (top-level alternation has no literal prefix)
			Subject: Patterns{`acme/app|other/app`},
			Roles:   []string{"arn:aws:iam::111111111111:role/either"},
			Conditions: &Condition{AllOf: []*Condition{
				{EventName: Patterns{"push"}},
				{AnyOf: []*Condition{{Ref: Patterns{"refs/heads/main"}}, {Ref: Patterns{"refs/heads/release"}}}},
			}},
		},
	}
	cfg := vcfg(t, mappings)

	subjects := []string{"acme/app", "acme/service-a", "other/app", "acme/nope"}
	claimSets := []map[string]any{
		{},
		{"event_name": "push", "ref": "refs/heads/main"},
		{"event_name": "push", "ref": "refs/heads/release"},
		{"event_name": "push", "ref": "refs/heads/wip"},
		{"event_name": "workflow_dispatch"},
		{"ref_type": "tag"},
		{"ref_type": "tag", "runner_environment": "sandbox"},
		{"ref_type": "tag", "runner_environment": []any{"production", "sandbox"}},
	}

	for _, subject := range subjects {
		for i, claims := range claimSets {
			gotOK, gotRoles := cfg.AuthorizeRoles(vIss, subject, claims)
			wantOK, wantRoles := linearAuthorizeRoles(cfg, vIss, subject, claims)
			if gotOK != wantOK {
				t.Fatalf("subject %q claims[%d]: indexed matched=%v, linear matched=%v", subject, i, gotOK, wantOK)
			}
			slices.Sort(gotRoles)
			slices.Sort(wantRoles)
			if !slices.Equal(gotRoles, wantRoles) {
				t.Fatalf("subject %q claims[%d]: indexed roles=%v, linear roles=%v", subject, i, gotRoles, wantRoles)
			}
		}
	}
}

// ---------- claims, patterns, and decoding ----------

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
	require.Equal(t, Patterns{"release-bot", "release-manager"}, cond.Actor)
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

// TestEnvironmentAndRunnerEnvironmentAreDistinctClaims pins the 3.0 break:
// `environment` checks the deployment environment a job declares, and
// `runner_environment` checks the runner type. Before 3.0 the `environment`
// key checked runner_environment, which left the deployment-environment claim
// unreachable and the key's name misleading.
func TestEnvironmentAndRunnerEnvironmentAreDistinctClaims(t *testing.T) {
	cfg := condCfg(t, &Condition{
		Environment:       Patterns{"production"},
		RunnerEnvironment: Patterns{"github-hosted"},
	})

	require.True(t, authorizes(cfg, map[string]any{
		"environment": "production", "runner_environment": "github-hosted",
	}))
	// Each key reads its own claim: neither value satisfies the other's gate.
	require.False(t, authorizes(cfg, map[string]any{
		"environment": "github-hosted", "runner_environment": "production",
	}))
	require.False(t, authorizes(cfg, map[string]any{"runner_environment": "github-hosted"}))
	require.False(t, authorizes(cfg, map[string]any{"environment": "production"}))
}

// TestExplicitClaimsMapReachesReservedNames proves the `claims:` escape hatch:
// its keys are always raw claim names, so a claim named like a key this schema
// reserves is still gateable.
func TestExplicitClaimsMapReachesReservedNames(t *testing.T) {
	cond := decodeConditions(t, `
      claims:
        all_of: "literal-claim"
        claims: "meta"
        environment: ["production", "staging"]
`)
	require.Equal(t, Patterns{"literal-claim"}, cond.ExplicitClaims["all_of"])
	require.Equal(t, Patterns{"meta"}, cond.ExplicitClaims["claims"])
	require.Equal(t, Patterns{"production", "staging"}, cond.ExplicitClaims["environment"])
	require.Nil(t, cond.AllOf, "a claim named all_of under claims: is not a boolean group")

	cfg := condCfg(t, &Condition{ExplicitClaims: map[string]Patterns{
		"all_of":      {"literal-claim"},
		"environment": {"production", "staging"},
	}})
	require.True(t, authorizes(cfg, map[string]any{"all_of": "literal-claim", "environment": "staging"}))
	require.False(t, authorizes(cfg, map[string]any{"all_of": "literal-claim", "environment": "dev"}))
	require.False(t, authorizes(cfg, map[string]any{"environment": "staging"}))
}

// TestExplicitClaimsAreAndedWithTopLevelKeys proves the escape hatch is not a
// separate evaluation mode: an entry under `claims:` is one more AND'd
// predicate on the same node, identical to writing it at the top level.
func TestExplicitClaimsAreAndedWithTopLevelKeys(t *testing.T) {
	cfg := condCfg(t, &Condition{
		Ref:            Patterns{"refs/heads/main"},
		ExplicitClaims: map[string]Patterns{"event_name": {"push"}},
	})
	require.True(t, authorizes(cfg, map[string]any{"ref": "refs/heads/main", "event_name": "push"}))
	require.False(t, authorizes(cfg, map[string]any{"ref": "refs/heads/main", "event_name": "pull_request"}))
	require.False(t, authorizes(cfg, map[string]any{"ref": "refs/heads/dev", "event_name": "push"}))
}

// TestValidate_RejectsEmptyExplicitClaimPatterns keeps the escape hatch under
// the same load-time rules as every other key: a listed claim must gate
// something, and the error names it by its `claims.` path.
func TestValidate_RejectsEmptyExplicitClaimPatterns(t *testing.T) {
	err := validateCond(&Condition{ExplicitClaims: map[string]Patterns{"environment": {}}})
	require.Error(t, err)
	require.Contains(t, err.Error(), `"claims.environment"`)

	err = validateCond(&Condition{ExplicitClaims: map[string]Patterns{"environment": {".*"}}})
	require.Error(t, err)
	require.Contains(t, err.Error(), `"claims.environment"`)
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
				Subject:    Patterns{"acme/app"},
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

	// A typo under none_of is the one that fails OPEN: the member can never
	// match, so it can never veto, and the mapping authorizes exactly what the
	// operator wrote it to refuse. It gets its own wording for that reason.
	t.Run("a typo under none_of says the veto is lost", func(t *testing.T) {
		cfg := build(&Condition{
			EventName: Patterns{"push"},
			NoneOf: []*Condition{
				{Claims: map[string]Patterns{"runner_env": {"self-hosted"}}}, // typo for runner_environment
			},
		}, github)
		logs := captureWarnings(t, func() { require.NoError(t, cfg.Validate()) })
		require.Contains(t, logs, "conditions.none_of[0].runner_env")
		require.Contains(t, logs, "can never veto")
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

// TestEmptyConditionKeyIsRejected pins that a condition key naming no claim is
// a load error rather than a leaf that can never match. YAML makes this easy to
// write by accident (`"": pattern`, or a dangling key), and a leaf keyed on the
// empty string is indistinguishable at request time from a gate the operator
// believes is enforcing something.
func TestEmptyConditionKeyIsRejected(t *testing.T) {
	for name, conditions := range map[string]string{
		"top level": `      "": "release-bot"`,
		"claims":    "      claims:\n        \"\": \"release-bot\"",
	} {
		t.Run(name, func(t *testing.T) {
			err := compileCondition(decodeConditions(t, conditions+"\n"), nil)
			require.Error(t, err)
			require.Contains(t, err.Error(), "must name a claim")
		})
	}
}

// TestConditionCompileErrorsAreDeterministic pins that a config with more than
// one bad claim entry reports the SAME entry on every load. Both claim maps are
// walked in sorted key order for exactly this reason: Go map iteration is
// randomized, so without the sort an operator fixing one error would be handed
// a different one at random on the next restart.
func TestConditionCompileErrorsAreDeterministic(t *testing.T) {
	const conditions = `
      aaa_claim: "*invalid("
      zzz_claim: "*also_invalid("
`
	for i := 0; i < 50; i++ {
		err := compileCondition(decodeConditions(t, conditions), nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "aaa_claim", "the lexically first bad key must always be the one reported")
	}
}

// TestValidate_RejectsKeysWrittenWithNoPattern pins the shape that used to
// authorize unconditionally: a condition key typed with nothing after it.
//
// YAML gives such a key a null value, and mapstructure skips a field whose
// input is nil, so `environment:` decoded to exactly what omitting the key
// decoded to — a mapping whose file says it is gated and whose compiled form
// gates nothing. Every variant below is now a load-time error: a named field,
// a generic (remain-map) claim, a `claims:` entry, and a whole block that
// compiles to no predicate.
func TestValidate_RejectsKeysWrittenWithNoPattern(t *testing.T) {
	for name, conditions := range map[string]string{
		"named field":                    "      environment:\n",
		"generic claim":                  "      repository:\n",
		"claims entry":                   "      claims:\n        any_of:\n",
		"named field beside a valid one": "      environment:\n      event_name: \"push\"\n",
		"generic claim inside a group":   "      any_of:\n        - repository:\n",
		"none_of member with no pattern": "      none_of:\n        - actor:\n",
	} {
		t.Run(name, func(t *testing.T) {
			require.Error(t, compileCondition(decodeConditions(t, conditions), nil))
		})
	}

	t.Run("empty block", func(t *testing.T) {
		require.ErrorContains(t, compileCondition(decodeConditions(t, "      {}\n"), nil), "declares no predicate")
	})

	// `conditions:` itself written with nothing under it. The field is a
	// *Condition, so a nil value leaves it nil — indistinguishable from a
	// mapping that declares no conditions — unless nilConditionHookFunc turns
	// it into an empty node first. Terraform renders exactly this key for an
	// all-null `conditions` object, so it is not only a typo.
	t.Run("conditions key with nothing under it", func(t *testing.T) {
		cond := decodeConditions(t, "")
		require.NotNil(t, cond, "a valueless `conditions:` must not decode as an absent gate")
		require.ErrorContains(t, compileCondition(cond, nil), "declares no predicate")
	})

	// A claim map built in code, not decoded: the decode hook never ran, so
	// this is what the compiler must catch on its own. Each case pairs the
	// valueless key with a working one, so the block is not empty and only the
	// per-key check can reject it.
	t.Run("nil entry in a hand-built claim map", func(t *testing.T) {
		require.ErrorContains(t, compileCondition(&Condition{
			Ref:    Patterns{"refs/heads/main"},
			Claims: map[string]Patterns{"repository": nil},
		}, nil), "has no value")
		require.ErrorContains(t, compileCondition(&Condition{
			Ref:            Patterns{"refs/heads/main"},
			ExplicitClaims: map[string]Patterns{"any_of": nil},
		}, nil), "has no value")
	})
}

// ---------- named-field constraints ----------

// TestWorkflowRefConstraint_Anchored verifies the workflow_ref condition regex
// is auto-anchored like every other regex condition, so a pattern matches the
// full claim and not a substring.
func TestWorkflowRefConstraint_Anchored(t *testing.T) {
	const claim = "org/repo/.github/workflows/predeploy.yml@refs/heads/main"
	const iss = "https://token.actions.githubusercontent.com"

	cases := []struct {
		name        string
		workflowRef string
		want        bool
	}{
		{"substring no longer matches", "deploy", false},
		{"bare filename does not match full ref", "deploy.yml", false},
		{"exact full claim matches", `org/repo/\.github/workflows/predeploy\.yml@refs/heads/main`, true},
		{"anchored alternation over full claim", `.*/predeploy\.yml@.*`, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &Config{
				Issuers:         singleIssuer(iss, "sts.amazonaws.com"),
				RoleSessionName: "test",
				RoleMappings: []RoleMapping{{
					Subject:    Patterns{"org/repo"},
					Roles:      []string{"arn:aws:iam::111111111111:role/app"},
					Conditions: &Condition{WorkflowRef: Patterns{tc.workflowRef}},
				}},
			}
			require.NoError(t, cfg.Validate())

			claims := map[string]any{"workflow_ref": claim}
			matched, roles := cfg.AuthorizeRoles(iss, "org/repo", claims)
			if tc.want {
				require.True(t, matched, "expected workflow_ref %q to match", tc.workflowRef)
				require.Contains(t, roles, "arn:aws:iam::111111111111:role/app")
			} else {
				require.False(t, matched, "expected workflow_ref %q NOT to match (substring)", tc.workflowRef)
			}
		})
	}
}

// A condition key is written in the case the issuer actually mints. Viper
// lowercases every key it reads from a config file, so by the time the key
// reaches the compiler it is `iscontractor` while the token carries
// `isContractor`. If the leaf then resolves to "no value", the predicate is
// silently dead: harmless-looking under a plain AND (it denies), and an
// authorization BYPASS under none_of, where a veto that can never fire lets
// through exactly what the config was written to refuse.
//
// GitHub never surfaced this — every GitHub Actions claim is already
// lowercase. Any other issuer (Auth0, Entra, Keycloak, a custom IdP) routinely
// mints camelCase claims.
func TestConditionKeyResolvesClaimCaseInsensitively(t *testing.T) {
	tests := []struct {
		name   string
		cond   *Condition
		claims map[string]any
		want   bool
	}{
		{
			name:   "none_of veto fires against a camelCase claim",
			cond:   &Condition{NoneOf: []*Condition{{Claims: map[string]Patterns{"iscontractor": {"true"}}}}},
			claims: map[string]any{"isContractor": "true"},
			want:   false,
		},
		{
			name:   "none_of still passes when the camelCase claim does not match",
			cond:   &Condition{NoneOf: []*Condition{{Claims: map[string]Patterns{"iscontractor": {"true"}}}}},
			claims: map[string]any{"isContractor": "false"},
			want:   true,
		},
		{
			name:   "plain leaf matches a camelCase claim",
			cond:   &Condition{Claims: map[string]Patterns{"costcenter": {"cc-1234"}}},
			claims: map[string]any{"costCenter": "cc-1234"},
			want:   true,
		},
		{
			name:   "plain leaf still denies a camelCase claim that does not match",
			cond:   &Condition{Claims: map[string]Patterns{"costcenter": {"cc-1234"}}},
			claims: map[string]any{"costCenter": "cc-9999"},
			want:   false,
		},
		{
			// An exact hit does NOT settle it. The key reaching the matcher is
			// already lower-cased, so "role" may be what the operator wrote or
			// may be what "ROLE" was folded into — two claims are candidates
			// for one key and neither can be shown to be the intended one.
			// Preferring the exact one authorizes on a claim the config may
			// never have named; the same shape under none_of disarms the veto.
			name:   "an exact-case claim alongside a case variant is ambiguous and denies",
			cond:   &Condition{Claims: map[string]Patterns{"role": {"admin"}}},
			claims: map[string]any{"role": "admin", "ROLE": "nobody"},
			want:   false,
		},
		{
			name:   "a lone exact-case claim resolves normally",
			cond:   &Condition{Claims: map[string]Patterns{"role": {"admin"}}},
			claims: map[string]any{"role": "admin"},
			want:   true,
		},
		{
			name:   "two case variants and no exact match is ambiguous and denies",
			cond:   &Condition{Claims: map[string]Patterns{"role": {"admin"}}},
			claims: map[string]any{"Role": "admin", "ROLE": "admin"},
			want:   false,
		},
		{
			name:   "an array-valued camelCase claim matches on any element",
			cond:   &Condition{Claims: map[string]Patterns{"groupmembership": {"platform"}}},
			claims: map[string]any{"groupMembership": []any{"eng", "platform"}},
			want:   true,
		},
		{
			name:   "an absent claim is still absent",
			cond:   &Condition{Claims: map[string]Patterns{"iscontractor": {"true"}}},
			claims: map[string]any{"sub": "acme/app"},
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := compileCondition(tt.cond, nil); err != nil {
				t.Fatalf("compile: %v", err)
			}
			if got := satisfiesConditions(tt.cond, tt.claims); got != tt.want {
				t.Errorf("satisfiesConditions = %v, want %v", got, tt.want)
			}
		})
	}
}

// The unit table above simulates the post-viper state directly. This one walks
// the whole chain — YAML file, viper's key lowercasing, Validate(), and
// AuthorizeRoles — so the regression is pinned where an operator would hit it:
// a `none_of` veto written against a camelCase claim, which before the
// claimResolver fix loaded and validated cleanly and then authorized the exact
// request it was written to refuse.
func TestNoneOfVetoOnCamelCaseClaimDeniesEndToEnd(t *testing.T) {
	const iss = "https://auth0.example.com"
	dir := t.TempDir()
	yaml := `
issuers:
  - issuer: "` + iss + `"
    provider: generic
    audiences: ["sts.amazonaws.com"]
    claim_mappings:
      subject: "sub"
role_mappings:
  - subject: "acme/platform"
    issuer: "` + iss + `"
    roles: ["arn:aws:iam::123456789012:role/prod-deploy"]
    conditions:
      none_of:
        - claims:
            isContractor: "true"
`
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CONFIG_PATH", dir)

	// Reset viper and load into a fresh Config, for the reasons ambigCfg
	// documents below: viper's AddConfigPath ACCUMULATES across calls, so
	// without a reset this test can read an earlier test's temp-dir config,
	// and NewConfig is sync.Once-cached, so it would hand back a Config another
	// test already populated and this YAML would merge into it rather than
	// replace it. Either one makes this veto guard silently stop guarding.
	viper.Reset()
	c := &Config{}
	if err := c.LoadConfig(); err != nil {
		t.Fatalf("load: %v", err)
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}

	contractor := map[string]any{"sub": "acme/platform", "isContractor": "true"}
	if matched, roles := c.AuthorizeRoles(iss, "acme/platform", contractor); matched {
		t.Errorf("contractor authorized for %v despite the none_of veto", roles)
	}

	employee := map[string]any{"sub": "acme/platform", "isContractor": "false"}
	matched, roles := c.AuthorizeRoles(iss, "acme/platform", employee)
	if !matched || len(roles) != 1 {
		t.Errorf("employee should still be authorized; matched=%v roles=%v", matched, roles)
	}
}

// ambigCfg loads a config through the real YAML/Viper path — not a Go literal —
// because the defect these tests guard only exists once the loader has folded
// the condition key's case away. A config built in Go keeps its key case and
// never reaches the folded lookup at all.
func ambigCfg(t *testing.T, conditions string) (*Config, string) {
	t.Helper()
	const iss = "https://auth0.example.com"
	dir := t.TempDir()
	yaml := `
issuers:
  - issuer: "` + iss + `"
    provider: generic
    audiences: ["sts.amazonaws.com"]
    claim_mappings:
      subject: "sub"
role_mappings:
  - subject: "acme/platform"
    issuer: "` + iss + `"
    roles: ["arn:aws:iam::123456789012:role/prod-deploy"]
    conditions:
` + conditions
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CONFIG_PATH", dir)
	// LoadConfig reads through viper's package-level singleton, which keeps
	// state between calls in one test binary. Reset so each case loads only
	// its own YAML. Load into a fresh Config rather than NewConfig(): that one
	// is sync.Once-cached, and unmarshalling a second YAML over the cached
	// struct merges the two conditions instead of replacing them.
	viper.Reset()
	c := &Config{}
	if err := c.LoadConfig(); err != nil {
		t.Fatalf("load: %v", err)
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	return c, iss
}

const noneOfContractor = `      none_of:
        - claims:
            isContractor: "true"
`

// TestAmbiguousClaimCannotDisarmANoneOfVeto is the regression guard for the
// bypass: a `none_of` veto must not be silently disarmed by the presence of a
// second casing of the claim it vetoes.
//
// Denying only the leaf is polarity-dependent — under none_of, a leaf that
// cannot match is a veto that cannot fire — so the caller the config was
// written to refuse was authorized instead. The decoy case is the sharpest:
// the second casing carries a value that does not even match the pattern, so
// nothing about the caller's actual contractor status changed.
func TestAmbiguousClaimCannotDisarmANoneOfVeto(t *testing.T) {
	c, iss := ambigCfg(t, noneOfContractor)

	tests := []struct {
		name   string
		claims map[string]any
	}{
		{"single casing: veto fires as written", map[string]any{
			"sub": "acme/platform", "isContractor": "true"}},
		{"second casing of the same claim", map[string]any{
			"sub": "acme/platform", "isContractor": "true", "IsContractor": "true"}},
		{"decoy casing whose value does not match", map[string]any{
			"sub": "acme/platform", "isContractor": "true", "ISCONTRACTOR": "x"}},
		{"three casings", map[string]any{
			"sub": "acme/platform", "isContractor": "true",
			"IsContractor": "true", "ISCONTRACTOR": "true"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matched, roles := c.AuthorizeRoles(iss, "acme/platform", tt.claims)
			if matched {
				t.Fatalf("VETO DISARMED: contractor authorized for %v", roles)
			}
		})
	}
}

// An ambiguous claim must deny under a plain AND too. This direction already
// denied before the fix (the leaf could not match), so the test pins that the
// fix did not change it — the deny is now for the stronger reason. Note it is
// NOT evidence that the `ambiguous` flag works: deleting the flag entirely
// leaves this test passing, because a collision still resolves to nil and a
// leaf with no value fails an AND on its own. The flag is pinned by the none_of
// tests above, where a nil-resolving leaf would instead pass.
func TestAmbiguousClaimDeniesUnderPlainAnd(t *testing.T) {
	c, iss := ambigCfg(t, `      claims:
        isContractor: "false"
`)
	claims := map[string]any{
		"sub": "acme/platform", "isContractor": "false", "IsContractor": "false",
	}
	if matched, roles := c.AuthorizeRoles(iss, "acme/platform", claims); matched {
		t.Fatalf("ambiguous claim authorized under AND: %v", roles)
	}
}

// Ambiguity nested inside a none_of inside an any_of must still deny: the check
// is on the resolver, so it is independent of how many groups enclose the leaf.
func TestAmbiguousClaimDeniesWhenNestedUnderNegation(t *testing.T) {
	c, iss := ambigCfg(t, `      any_of:
        - none_of:
            - claims:
                isContractor: "true"
`)
	claims := map[string]any{
		"sub": "acme/platform", "isContractor": "true", "IsContractor": "true",
	}
	if matched, roles := c.AuthorizeRoles(iss, "acme/platform", claims); matched {
		t.Fatalf("VETO DISARMED through nesting: authorized for %v", roles)
	}
}

// The fix must not deny requests that were previously allowed for good reason.
// A non-contractor with a single claim casing still gets the role, and so does
// one whose token carries an unrelated mixed-case claim the config never names
// — ambiguity is only ever recorded for a claim a condition actually looks up.
func TestAmbiguousFixDoesNotDenyLegitimateCallers(t *testing.T) {
	c, iss := ambigCfg(t, noneOfContractor)

	tests := []struct {
		name   string
		claims map[string]any
	}{
		{"employee, single casing", map[string]any{
			"sub": "acme/platform", "isContractor": "false"}},
		{"employee, claim absent entirely", map[string]any{
			"sub": "acme/platform"}},
		{"unrelated claim collides but is never looked up", map[string]any{
			"sub": "acme/platform", "isContractor": "false",
			"costCenter": "a", "CostCenter": "b"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matched, roles := c.AuthorizeRoles(iss, "acme/platform", tt.claims)
			if !matched || len(roles) != 1 {
				t.Fatalf("legitimate caller denied: matched=%v roles=%v", matched, roles)
			}
		})
	}
}

// An exact-case hit does NOT settle a collision. This test previously asserted
// the opposite — that a lower-case claim matching the key exactly wins outright
// and a stray casing can never make it ambiguous. That premise was wrong, and it
// was the same bypass as TestAmbiguousClaimCannotDisarmANoneOfVeto reached
// through the other branch: viper has already lower-cased the key, so
// `iscontractor` is equally consistent with an operator who wrote
// `isContractor`, and preferring the exact claim decides on one the config may
// never have named. Under none_of it disarms the veto outright.
func TestExactHitDoesNotResolveACollision(t *testing.T) {
	c, iss := ambigCfg(t, `      claims:
        iscontractor: "false"
`)
	claims := map[string]any{
		"sub": "acme/platform", "iscontractor": "false",
		"IsContractor": "true", "ISCONTRACTOR": "true",
	}
	if matched, roles := c.AuthorizeRoles(iss, "acme/platform", claims); matched {
		t.Fatalf("collision resolved by exact hit instead of denying: %v", roles)
	}
}

// The veto must not be disarmed by a LOWER-CASE twin of the vetoed claim
// either. This is the direction the exact-first lookup used to authorize: the
// decoy is the claim whose name matches the folded key exactly, so it won the
// lookup and supplied a value that did not trip the veto.
func TestLowerCaseTwinCannotDisarmANoneOfVeto(t *testing.T) {
	c, iss := ambigCfg(t, noneOfContractor)

	tests := []struct {
		name   string
		claims map[string]any
	}{
		{"lower-case twin carrying a passing value", map[string]any{
			"sub": "acme/platform", "isContractor": "true", "iscontractor": "false"}},
		{"lower-case twin carrying nonsense", map[string]any{
			"sub": "acme/platform", "isContractor": "true", "iscontractor": "zzz"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if matched, roles := c.AuthorizeRoles(iss, "acme/platform", tt.claims); matched {
				t.Fatalf("VETO DISARMED by lower-case twin: authorized for %v", roles)
			}
		})
	}
}

// The all-lower-case path — every GitHub Actions deployment, since GitHub mints
// no upper-case claim name — must be untouched: no collision is possible, so the
// folded index is never even built and lookups answer from the raw claims.
func TestAllLowerCaseClaimsTakeTheUnfoldedPath(t *testing.T) {
	c, iss := ambigCfg(t, `      claims:
        iscontractor: "false"
`)
	claims := map[string]any{"sub": "acme/platform", "iscontractor": "false"}
	matched, roles := c.AuthorizeRoles(iss, "acme/platform", claims)
	if !matched || len(roles) != 1 {
		t.Fatalf("all-lower-case claims denied: matched=%v roles=%v", matched, roles)
	}

	res := newClaimResolver(claims)
	if v := res.lookup("iscontractor"); v != "false" {
		t.Fatalf("lookup returned %v", v)
	}
	if res.folded != nil {
		t.Fatal("folded index was built for all-lower-case claims; the fast path should skip it")
	}
	if res.ambiguous {
		t.Fatal("all-lower-case claims marked ambiguous")
	}
}

// TestLeftoverV2KeyUnderNoneOfAuthorizes pins the one shape in which a v2
// config that was never migrated fails OPEN rather than closed, because the
// migration guide, the changelog, and example-config.yaml all now promise
// exactly this and nothing else asserted it.
//
// `branch:` was removed in 3.0.0, so it is read as a claim of that literal
// name. GitHub does not issue one, the member can never match, and a member
// that can never match under `none_of` is a veto that can never fire — so the
// group passes and the mapping authorizes precisely the push the operator
// wrote it to refuse. Deny-listing a branch is the natural `none_of` use case,
// which is what makes this worth pinning rather than a curiosity.
//
// The renamed half is what keeps this test honest: swap `branch:` for `ref:`
// and the same push must be refused. Without it the test would pass against a
// build where `none_of` did nothing at all.
func TestLeftoverV2KeyUnderNoneOfAuthorizes(t *testing.T) {
	const ghIss = "https://token.actions.githubusercontent.com"

	load := func(t *testing.T, key string) *Config {
		t.Helper()
		dir := t.TempDir()
		yaml := `
issuers:
  - issuer: "` + ghIss + `"
    provider: github
    audiences: ["sts.amazonaws.com"]
role_session_name: "test"
role_mappings:
  - subject: "acme/app"
    issuer: "` + ghIss + `"
    roles: ["arn:aws:iam::123456789012:role/Deploy"]
    conditions:
      none_of:
        - ` + key + `: "refs/heads/release/.*"
`
		require.NoError(t, os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(yaml), 0o600))
		t.Setenv("CONFIG_PATH", dir)
		viper.Reset()
		c := &Config{}
		require.NoError(t, c.LoadConfig())
		require.NoError(t, c.Validate(), "a leftover v2 key must still LOAD; that is the whole hazard")
		return c
	}

	// The exact push the deny-list was written to block.
	claims := map[string]any{
		"repository": "acme/app",
		"ref":        "refs/heads/release/1.0",
	}

	t.Run("leftover branch: authorizes the push it meant to refuse", func(t *testing.T) {
		matched, roles := load(t, "branch").AuthorizeRoles(ghIss, "acme/app", claims)
		require.True(t, matched,
			"documented fail-open: an unmatchable none_of member is a veto that never fires")
		require.Equal(t, []string{"arn:aws:iam::123456789012:role/Deploy"}, roles)
	})

	t.Run("renamed ref: refuses it", func(t *testing.T) {
		matched, roles := load(t, "ref").AuthorizeRoles(ghIss, "acme/app", claims)
		require.False(t, matched, "after the rename the veto fires; got roles %v", roles)
	})
}

// jsonClaims decodes a claim set the way the pipeline does, so a JSON number
// arrives as float64 and a JSON bool as bool. Hand-built maps would let this
// test pass against shapes a real token can never carry.
func jsonClaims(t *testing.T, raw string) map[string]any {
	t.Helper()
	var m map[string]any
	require.NoError(t, json.Unmarshal([]byte(raw), &m))
	return m
}

// TestNoneOfReadsNonStringClaimValues pins the polarity fix for claim shapes
// valueMatches declines.
//
// valueMatches answers false for a bool, a number, an object, and a non-string
// array element. In positive polarity false denies, which is conservative and
// correct. Under none_of it is the opposite: a member that cannot match is a
// veto that cannot fire, so the group passes and the mapping authorizes exactly
// the caller the deny-list names. GitHub Actions mints only string claims, so
// this is invisible there; an issuer that mints `email_verified` as a bool or a
// risk score as a number hits it on the most natural deny-list there is.
//
// The fix reads the value rather than giving up on its Go type, which is what
// makes the two halves below the point of this test: `email_verified: false`
// must be vetoed by `none_of: [{email_verified: "false"}]`, and
// `email_verified: true` must NOT be — none_of refuses this claim at THIS
// value, not every token that happens to carry the claim.
//
// Absence stays exact negation and is deliberately untouched: an absent claim
// gives the veto nothing to fire on.
func TestNoneOfReadsNonStringClaimValues(t *testing.T) {
	t.Run("bool claim", func(t *testing.T) {
		cfg := condCfg(t, &Condition{NoneOf: []*Condition{
			{Claims: map[string]Patterns{"email_verified": {"false"}}},
		}})

		cases := []struct {
			name string
			raw  string
			want bool
		}{
			// The fix: the veto can no longer be disarmed by the claim being a
			// JSON bool rather than the string the pattern was written against.
			{"bool false is the refused value, so the veto fires", `{"email_verified":false}`, false},
			// The other half, and the one that keeps the fix honest: the value
			// is readable and is NOT the refused one, so nothing is vetoed.
			{"bool true is not the refused value", `{"email_verified":true}`, true},
			// Unchanged behaviour: a string claim already decided on its value.
			{"string false vetoes", `{"email_verified":"false"}`, false},
			{"string true does not veto", `{"email_verified":"true"}`, true},
			{"absent claim leaves the veto nothing to fire on", `{}`, true},
			{"null claim is absence, not a value", `{"email_verified":null}`, true},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				if got := authorizes(cfg, jsonClaims(t, tc.raw)); got != tc.want {
					t.Fatalf("authorized = %v, want %v", got, tc.want)
				}
			})
		}
	})

	t.Run("number claim", func(t *testing.T) {
		cfg := condCfg(t, &Condition{NoneOf: []*Condition{
			{Claims: map[string]Patterns{"risk_score": {"9"}}},
		}})

		cases := []struct {
			name string
			raw  string
			want bool
		}{
			{"the refused score vetoes", `{"risk_score":9}`, false},
			{"another score does not", `{"risk_score":1}`, true},
			// Claim text comes from utils.FormatClaimValue, the formatter audit
			// records and session tags use, so an integral JSON number reads as
			// "9" and never as Go's default "9e+00"-style float rendering.
			{"an integral number is not rendered in scientific notation", `{"risk_score":9.0}`, false},
			{"a fractional score keeps its fraction and does not match", `{"risk_score":9.5}`, true},
			{"string 9 vetoes", `{"risk_score":"9"}`, false},
			{"string 1 does not veto", `{"risk_score":"1"}`, true},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				if got := authorizes(cfg, jsonClaims(t, tc.raw)); got != tc.want {
					t.Fatalf("authorized = %v, want %v", got, tc.want)
				}
			})
		}
	})

	t.Run("array claim", func(t *testing.T) {
		cfg := condCfg(t, &Condition{NoneOf: []*Condition{
			{Claims: map[string]Patterns{"groups": {"admins"}}},
		}})

		cases := []struct {
			name string
			raw  string
			want bool
		}{
			{"matching element vetoes", `{"groups":["admins"]}`, false},
			{"no matching element does not veto", `{"groups":["devs"]}`, true},
			{"empty array carries no values, so nothing vetoes", `{"groups":[]}`, true},
			// A non-string element is read like any other scalar rather than
			// disarming the veto, so it decides on its own value too.
			{"a numeric element the pattern does not name is still readable", `{"groups":["devs",42]}`, true},
			// An element with no readable text at all is the case that fires.
			{"an object element cannot be read, so the veto fires", `{"groups":["devs",{"x":1}]}`, false},
			{"object claim cannot be read, so the veto fires", `{"groups":{"a":"admins"}}`, false},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				if got := authorizes(cfg, jsonClaims(t, tc.raw)); got != tc.want {
					t.Fatalf("authorized = %v, want %v", got, tc.want)
				}
			})
		}
	})

	// A numeric element IS readable, so it vetoes when it is the value named.
	t.Run("a numeric element vetoes on its own value", func(t *testing.T) {
		cfg := condCfg(t, &Condition{NoneOf: []*Condition{
			{Claims: map[string]Patterns{"group_ids": {"42"}}},
		}})
		if authorizes(cfg, jsonClaims(t, `{"group_ids":[7,42]}`)) {
			t.Fatal("the refused group id must veto")
		}
		if !authorizes(cfg, jsonClaims(t, `{"group_ids":[7,8]}`)) {
			t.Fatal("group ids that are not refused must not veto")
		}
	})

	// Positive polarity reads the same value the same way. A predicate must not
	// mean one thing under a none_of and another outside it: before this, a
	// positive `email_verified: "true"` denied every caller on an issuer that
	// mints the claim as a JSON bool, while the none_of spelling read it
	// correctly. The JSON type a value arrived as is not a thing an operator
	// writing a gate should have to know.
	t.Run("positive polarity decides on the value too", func(t *testing.T) {
		cfg := condCfg(t, &Condition{Claims: map[string]Patterns{
			"email_verified": {"true"},
			"risk_score":     {"1"},
		}})

		// Every mix of JSON types for the SAME values authorizes identically.
		for _, raw := range []string{
			`{"email_verified":true,"risk_score":1}`,
			`{"email_verified":"true","risk_score":1}`,
			`{"email_verified":true,"risk_score":"1"}`,
			`{"email_verified":"true","risk_score":"1"}`,
		} {
			if !authorizes(cfg, jsonClaims(t, raw)) {
				t.Fatalf("claims %s must authorize: the values match whatever type they arrived as", raw)
			}
		}

		// Reading the value is not the same as ignoring it. A value that does
		// not match still denies, which is the whole point of the gate.
		for _, raw := range []string{
			`{"email_verified":false,"risk_score":1}`,
			`{"email_verified":true,"risk_score":9}`,
			`{"email_verified":true}`,
			`{"email_verified":null,"risk_score":1}`,
			`{"email_verified":{"nested":true},"risk_score":1}`,
		} {
			if authorizes(cfg, jsonClaims(t, raw)) {
				t.Fatalf("claims %s must deny", raw)
			}
		}
	})

	// The two spellings of one predicate must be exact complements for every
	// value the gate can read. This is the property the old type-dispatch broke:
	// it made `x: v` and `none_of: [{x: v}]` both deny for a non-string claim,
	// so neither branch of a decision an operator thought was total was taken.
	t.Run("positive and none_of are exact complements", func(t *testing.T) {
		positive := condCfg(t, &Condition{Claims: map[string]Patterns{"email_verified": {"true"}}})
		negative := condCfg(t, &Condition{NoneOf: []*Condition{
			{Claims: map[string]Patterns{"email_verified": {"true"}}},
		}})

		for _, raw := range []string{
			`{"email_verified":true}`,
			`{"email_verified":false}`,
			`{"email_verified":"true"}`,
			`{"email_verified":"false"}`,
			`{"email_verified":1}`,
		} {
			claims := jsonClaims(t, raw)
			if authorizes(positive, claims) == authorizes(negative, claims) {
				t.Fatalf("claims %s: a predicate and its none_of must not agree; both said %v",
					raw, authorizes(positive, claims))
			}
		}
	})

	// The deny is local to the branch that could not decide, not sticky for the
	// whole evaluation — unlike the `ambiguous` flag, which must be sticky
	// because a collision means the gate cannot trust ANY reading of the claim.
	// Here another any_of branch has decided on its own evidence.
	t.Run("an unreadable none_of does not poison a sibling any_of branch", func(t *testing.T) {
		cfg := condCfg(t, &Condition{AnyOf: []*Condition{
			{Claims: map[string]Patterns{"repository": {"acme/app"}}},
			{NoneOf: []*Condition{{Claims: map[string]Patterns{"attrs": {"admin"}}}}},
		}})

		if !authorizes(cfg, jsonClaims(t, `{"repository":"acme/app","attrs":{"role":"admin"}}`)) {
			t.Fatal("the matching any_of branch must still authorize")
		}
		if authorizes(cfg, jsonClaims(t, `{"repository":"other/app","attrs":{"role":"admin"}}`)) {
			t.Fatal("with no branch able to decide, the mapping must deny")
		}
	})

	// Polarity toggles per none_of rather than latching, so a none_of nested in
	// a none_of is positive again — the double negation the operator wrote.
	t.Run("nesting toggles polarity rather than latching it", func(t *testing.T) {
		leaf := func() *Condition {
			return &Condition{Claims: map[string]Patterns{"email_verified": {"false"}}}
		}
		claims := jsonClaims(t, `{"email_verified":false}`)

		// NOT(NOT(match)) == match. The claim reads as the named value, so the
		// leaf matches and the whole expression authorizes. This identity is
		// exactly what the old type-dispatch broke: a bool never matched in
		// positive polarity, so double negation denied a claim that plainly
		// held, and NOT(NOT(x)) == x failed for every non-string value.
		doubleNeg := condCfg(t, &Condition{NoneOf: []*Condition{{NoneOf: []*Condition{leaf()}}}})
		if !authorizes(doubleNeg, claims) {
			t.Fatal("double negation is positive polarity: the value matches, so it must authorize")
		}

		// NOT(NOT(NOT(match))) == NOT(match): negative again, the value reads
		// as the refused one, so the veto fires.
		tripleNeg := condCfg(t, &Condition{NoneOf: []*Condition{{NoneOf: []*Condition{{NoneOf: []*Condition{leaf()}}}}}})
		if authorizes(tripleNeg, claims) {
			t.Fatal("triple negation is negative polarity and must deny")
		}
	})
}
