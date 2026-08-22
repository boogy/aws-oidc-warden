package config

import "testing"

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
	cfg := condCfg(t, &Condition{Extra: map[string]string{"groups": "team-a"}})

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
	cfg := condCfg(t, &Condition{ActorMatches: []string{"release-bot", "alice"}})

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
