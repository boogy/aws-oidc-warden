package config

import (
	"regexp"
	"testing"
)

// TestClassifySubject_QuantifiedFirstSlash is the regression test for the index
// mis-bucketing bug: a subject pattern whose first '/' is quantified (optional
// or repeatable) also matches slash-less subjects, so it must not be bucketed
// under a literal owner — candidatesFor keys on ownerOf(subject) and would miss
// those matches, diverging from a linear scan (and mis-scoping session policy).
func TestClassifySubject_QuantifiedFirstSlash(t *testing.T) {
	compile := func(p string) *RoleMapping {
		m := &RoleMapping{Subject: p}
		re, err := regexp.Compile("^(?:" + p + ")$") // same anchoring Validate() applies
		if err != nil {
			t.Fatalf("compile %q: %v", p, err)
		}
		m.compiledPattern = re
		return m
	}

	// (pattern, must-not-be-owner-bucketed)
	anyShapes := []string{
		"myorg/?prod-.*", // optional slash: matches "myorgprod-x"
		"y/*a",           // repeatable slash: matches "ya"
		"/?x",            // optional leading slash: matches "x"
		"a/b|c/d",        // alternation: matches "c/d" (owner c)
	}
	for _, p := range anyShapes {
		m := compile(p)
		owner, class := classifySubject(m.Subject, m.compiledPattern)
		if class == subjectOwner {
			t.Errorf("pattern %q bucketed as owner=%q (subjectOwner); must be subjectAny", p, owner)
		}
	}

	// Genuine owner-scoped shapes must still be bucketed by owner (perf path).
	for _, tc := range []struct{ pattern, owner string }{
		{"myorg/.*", "myorg"},
		{"myorg/repo-.*", "myorg"},
		{"a/b|a/c", "a"}, // common-prefix alternation is legitimately owner-scoped
	} {
		m := compile(tc.pattern)
		owner, class := classifySubject(m.Subject, m.compiledPattern)
		if class != subjectOwner || owner != tc.owner {
			t.Errorf("pattern %q: got (owner=%q, class=%d), want (owner=%q, subjectOwner)", tc.pattern, owner, class, tc.owner)
		}
	}
}

// TestClassifySubject_EndToEndAuthzParity proves the fix at the API level: a
// quantified-first-slash mapping is found by AuthorizeRoles/FindSessionPolicy
// for a slash-less subject, matching what a compiled-pattern match asserts.
func TestClassifySubject_EndToEndAuthzParity(t *testing.T) {
	const iss = "https://token.actions.githubusercontent.com"
	const role = "arn:aws:iam::111111111111:role/opt"
	policy := `{"scoped":true}`

	c := &Config{
		Issuers:         []IssuerConfig{{Issuer: iss, Provider: "github", Audiences: []string{"sts.amazonaws.com"}}},
		DefaultIssuer:   iss,
		RoleSessionName: "s",
		RoleMappings: []RoleMapping{
			{Subject: "myorg/?opt-.*", Roles: []string{role}, SessionPolicy: policy},
		},
	}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}

	// "myorgopt-x" (no slash) matches the pattern via the optional-slash branch.
	subject := "myorgopt-x"
	ok, roles := c.AuthorizeRoles(iss, subject, map[string]any{})
	if !ok || len(roles) != 1 || roles[0] != role {
		t.Fatalf("AuthorizeRoles(%q): the index dropped a match a linear scan finds; got ok=%v roles=%v", subject, ok, roles)
	}
	p, _ := c.FindSessionPolicy(iss, subject, role, map[string]any{})
	if p == nil || *p != policy {
		t.Fatalf("FindSessionPolicy(%q): expected %q, got %v", subject, policy, p)
	}
}
