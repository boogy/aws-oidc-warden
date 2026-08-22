package config

import (
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

// TestClaimMatches_ActorMatchesUsesTheSameMatcher proves actor_matches routes
// through the same leaf matcher, so an array-valued actor claim behaves like
// every other array claim rather than through a second, divergent code path.
func TestClaimMatches_ActorMatchesUsesTheSameMatcher(t *testing.T) {
	cfg := condCfg(t, &Condition{ActorMatches: Patterns{"release-bot", "alice"}})

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
			{Environment: Patterns{"sandbox"}},
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
// flat fields on the same node: leaves AND actor_matches AND all_of AND any_of
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
			{Environment: Patterns{"sandbox"}},
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
				{ActorMatches: Patterns{"release-bot", "alice"}},
				{NoneOf: []*Condition{{Ref: Patterns{"refs/heads/wip-.+"}}}},
			}},
		},
		NoneOf: []*Condition{{Environment: Patterns{"sandbox"}}},
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
		{"bare wildcard in a nested actor_matches", &Condition{NoneOf: []*Condition{{ActorMatches: Patterns{".+"}}}}, true},
		{"invalid regex nested", &Condition{AnyOf: []*Condition{{Ref: Patterns{"refs/heads/("}}}}, true},
		{"valid nested group", &Condition{AnyOf: []*Condition{{EventName: Patterns{"push"}}, {EventName: Patterns{"workflow_dispatch"}}}}, false},
		{"empty top-level condition stays legal", &Condition{}, false},
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
            - actor_matches: ["release-bot"]
      none_of:
        - environment: "sandbox"
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
	require.Equal(t, Patterns{"release-bot"}, cond.AnyOf[1].AllOf[1].ActorMatches)
	require.Len(t, cond.NoneOf, 1)
	require.Equal(t, Patterns{"sandbox"}, cond.NoneOf[0].Environment)
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
				AnyOf:  []*Condition{{EventName: Patterns{"push"}}, {EventName: Patterns{"workflow_dispatch"}}},
				NoneOf: []*Condition{{Environment: Patterns{"sandbox"}}},
				Claims: map[string]Patterns{"sha": {"[0-9a-f]{40}"}},
			},
		}},
	}
	require.NoError(t, orig.Validate())

	clone, err := cloneConfig(orig)
	require.NoError(t, err)
	require.NoError(t, clone.Validate())

	allow := map[string]any{"event_name": "push", "sha": "0123456789abcdef0123456789abcdef01234567"}
	deny := map[string]any{"event_name": "push", "sha": "0123456789abcdef0123456789abcdef01234567", "runner_environment": "sandbox"}
	denyNoSha := map[string]any{"event_name": "push"}

	for name, cfg := range map[string]*Config{"original": orig, "clone": clone} {
		t.Run(name, func(t *testing.T) {
			ok, _ := cfg.AuthorizeRoles(vIss, "acme/app", allow)
			require.True(t, ok, "satisfied condition must authorize")
			ok, _ = cfg.AuthorizeRoles(vIss, "acme/app", deny)
			require.False(t, ok, "none_of must still deny after the round trip")
			ok, _ = cfg.AuthorizeRoles(vIss, "acme/app", denyNoSha)
			require.False(t, ok, "the Extra leaf must still deny after the round trip")
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
				NoneOf:  []*Condition{{Environment: Patterns{"sandbox"}}},
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
			wantOK, wantRoles := linearAuthorize(cfg, vIss, subject, claims)
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
