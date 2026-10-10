package config

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A literal pattern compares with ==; anything else keeps its regexp.
func TestAnchorLiteralFastPath(t *testing.T) {
	tests := []struct {
		pattern     string
		wantLiteral bool
		matches     []string
		rejects     []string
	}{
		{"refs/heads/main", true, []string{"refs/heads/main"}, []string{"refs/heads/main\n", "xrefs/heads/main", "refs/heads/mainx", ""}},
		{`my\.repo`, true, []string{"my.repo"}, []string{"myxrepo"}},
		{`\Qa+b\E`, true, []string{"a+b"}, []string{"aab"}},
		{"(?i)main", false, []string{"MAIN", "main"}, []string{"mainx"}},
		{"main|dev", false, []string{"main", "dev"}, []string{"maindev"}},
		{"v[0-9]+", false, []string{"v12"}, []string{"v"}},
		{"\xef\xbf\xbd", false, []string{"\xef\xbf\xbd", "\xff"}, []string{"x"}},
	}
	for _, tc := range tests {
		t.Run(tc.pattern, func(t *testing.T) {
			m, err := regexCache{}.anchor(tc.pattern)
			require.NoError(t, err)
			assert.Equal(t, tc.wantLiteral, m.re == nil)
			for _, s := range tc.matches {
				assert.True(t, m.match(s), s)
			}
			for _, s := range tc.rejects {
				assert.False(t, m.match(s), s)
			}
		})
	}
}

// Literal leaves must behave identically under negation and none_of.
func TestLiteralConditionsUnderNegation(t *testing.T) {
	cfg := condCfg(t, &Condition{
		Ref:    Patterns{"refs/heads/main"},
		NoneOf: []*Condition{{Actor: Patterns{"mallory", `bot\[ci\]`}}},
	})
	tests := []struct {
		name   string
		claims map[string]any
		want   bool
	}{
		{"allowed", map[string]any{"ref": "refs/heads/main", "actor": "alice"}, true},
		{"vetoed literal", map[string]any{"ref": "refs/heads/main", "actor": "mallory"}, false},
		{"vetoed escaped literal", map[string]any{"ref": "refs/heads/main", "actor": "bot[ci]"}, false},
		{"veto is exact, not a prefix", map[string]any{"ref": "refs/heads/main", "actor": "mallory2"}, true},
		{"absent actor", map[string]any{"ref": "refs/heads/main"}, true},
		{"trailing newline is not the literal", map[string]any{"ref": "refs/heads/main\n"}, false},
		{"array element vetoes", map[string]any{"ref": "refs/heads/main", "actor": []any{"alice", "mallory"}}, false},
		{"wrong ref", map[string]any{"ref": "refs/heads/dev", "actor": "alice"}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, authorizes(cfg, tc.claims))
		})
	}
}

// One resolver serves every candidate of a request; an ambiguous claim denies
// only the mapping that reads it.
func TestAuthorizeAmbiguityIsPerMapping(t *testing.T) {
	const roleA = "arn:aws:iam::111111111111:role/a"
	const roleB = "arn:aws:iam::111111111111:role/b"
	claims := map[string]any{"isContractor": "true", "iscontractor": "false", "ref": "main"}

	mapping := func(subject, role string, c *Condition) RoleMapping {
		return RoleMapping{Subject: Patterns{subject}, Roles: []string{role}, Conditions: c}
	}
	ambiguous := &Condition{Claims: map[string]Patterns{"iscontractor": {"false"}}}
	clean := &Condition{Ref: Patterns{"main"}}

	for name, ms := range map[string][]RoleMapping{
		"ambiguous first": {mapping("acme/app", roleA, ambiguous), mapping("acme/app", roleB, clean)},
		"ambiguous last":  {mapping("acme/app", roleB, clean), mapping("acme/app", roleA, ambiguous)},
		"across buckets":  {mapping("acme/.*", roleA, ambiguous), mapping("acme/app", roleB, clean)},
	} {
		t.Run(name, func(t *testing.T) {
			cfg := vcfg(t, ms)
			ok, roles := cfg.AuthorizeRoles(vIss, "acme/app", claims)
			require.True(t, ok)
			assert.Equal(t, []string{roleB}, roles)
		})
	}

	// Every candidate agrees with the standalone evaluator.
	cfg := vcfg(t, []RoleMapping{
		mapping("acme/app", roleA, ambiguous),
		mapping("acme/app", roleB, &Condition{NoneOf: []*Condition{ambiguous}}),
	})
	ok, _ := cfg.AuthorizeRoles(vIss, "acme/app", claims)
	assert.False(t, ok, "ambiguity under none_of must still deny")
	for _, m := range cfg.effective {
		assert.False(t, satisfiesConditions(m.Conditions, claims))
	}
}

func TestAuthorizeKeepsOrderAcrossBuckets(t *testing.T) {
	roles := func(i int) []string { return []string{fmt.Sprintf("arn:aws:iam::111111111111:role/r%d", i)} }
	cfg := vcfg(t, []RoleMapping{
		{Subject: Patterns{"acme/.*"}, Roles: roles(0), SessionPolicy: "p0"},
		{Subject: Patterns{"acme/app"}, Roles: roles(0), SessionPolicy: "p1"},
		{Subject: Patterns{`ac.*/app`}, Roles: roles(0), SessionPolicy: "p2"},
	})
	d := cfg.Authorize(vIss, "acme/app", roles(0)[0], map[string]any{})
	require.True(t, d.Matched)
	require.Len(t, d.Roles, 3)
	p, _ := d.SessionPolicy()
	require.NotNil(t, p)
	assert.Equal(t, "p0", *p, "lowest declaration order wins regardless of bucket")
}
