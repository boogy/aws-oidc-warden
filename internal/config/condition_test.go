package config

// The condition engine: claim matching, the all_of/any_of/none_of groups and
// their nesting limits, pattern decoding (scalar or list, YAML and JSON), the
// explicit `claims:` map, and everything Validate() rejects — an empty group,
// a key written with no pattern, a gate that gates nothing.

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

// condCfg builds a validated single-mapping config gated by c. vcfg and vIss
// come from authz_adversarial_test.go.
func condCfg(t *testing.T, c *Condition) *Config {
	t.Helper()
	return vcfg(t, []RoleMapping{{
		Subject:    "acme/app",
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
		Subject:         "acme/app",
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
			Subject:    "acme/app",
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
			Subject: "acme/app",
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
			Subject: "acme/app",
			Roles:   []string{"arn:aws:iam::111111111111:role/app"},
			Conditions: &Condition{AnyOf: []*Condition{
				{EventName: Patterns{"push"}, Ref: Patterns{"refs/heads/main"}},
				{EventName: Patterns{"workflow_dispatch"}},
			}},
		},
		{ // byOwner bucket
			Subject: `acme/service-.+`,
			Roles:   []string{"arn:aws:iam::111111111111:role/service"},
			Conditions: &Condition{
				RefType: Patterns{"tag"},
				NoneOf:  []*Condition{{RunnerEnvironment: Patterns{"sandbox"}}},
			},
		},
		{ // "any" bucket (top-level alternation has no literal prefix)
			Subject: `acme/app|other/app`,
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
			err := compileCondition(decodeConditions(t, conditions+"\n"))
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
		err := compileCondition(decodeConditions(t, conditions))
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
			require.Error(t, compileCondition(decodeConditions(t, conditions)))
		})
	}

	t.Run("empty block", func(t *testing.T) {
		require.ErrorContains(t, compileCondition(decodeConditions(t, "      {}\n")), "declares no predicate")
	})

	// `conditions:` itself written with nothing under it. The field is a
	// *Condition, so a nil value leaves it nil — indistinguishable from a
	// mapping that declares no conditions — unless nilConditionHookFunc turns
	// it into an empty node first. Terraform renders exactly this key for an
	// all-null `conditions` object, so it is not only a typo.
	t.Run("conditions key with nothing under it", func(t *testing.T) {
		cond := decodeConditions(t, "")
		require.NotNil(t, cond, "a valueless `conditions:` must not decode as an absent gate")
		require.ErrorContains(t, compileCondition(cond), "declares no predicate")
	})

	// A claim map built in code, not decoded: the decode hook never ran, so
	// this is what the compiler must catch on its own. Each case pairs the
	// valueless key with a working one, so the block is not empty and only the
	// per-key check can reject it.
	t.Run("nil entry in a hand-built claim map", func(t *testing.T) {
		require.ErrorContains(t, compileCondition(&Condition{
			Ref:    Patterns{"refs/heads/main"},
			Claims: map[string]Patterns{"repository": nil},
		}), "has no value")
		require.ErrorContains(t, compileCondition(&Condition{
			Ref:            Patterns{"refs/heads/main"},
			ExplicitClaims: map[string]Patterns{"any_of": nil},
		}), "has no value")
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
					Subject:    "org/repo",
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
