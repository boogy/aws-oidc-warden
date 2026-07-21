package config

import "testing"

// TestFindSessionPolicy_ScopedToGrantingRole is the regression test for the
// session-policy scoping bug: FindSessionPolicy used to resolve by (issuer,
// subject) only and return the lowest-order mapping matching the subject,
// regardless of which mapping granted the requested role. A broad, policy-less
// mapping declared before a narrow mapping that scopes a privileged role
// therefore caused that role to be assumed with NO session policy.
//
// The fix makes the lookup role- and condition-aware: the policy must come from
// a mapping that matches the subject, satisfies its conditions, AND grants the
// requested role.
func TestFindSessionPolicy_ScopedToGrantingRole(t *testing.T) {
	const iss = "https://token.actions.githubusercontent.com"
	restrictive := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::only-this-bucket/*"}]}`
	const readonly = "arn:aws:iam::111111111111:role/ci-readonly"
	const deploy = "arn:aws:iam::111111111111:role/deploy"

	c := &Config{
		Issuers:         []IssuerConfig{{Issuer: iss, Provider: "github", Audiences: []string{"sts.amazonaws.com"}}},
		DefaultIssuer:   iss,
		RoleSessionName: "s",
		RoleMappings: []RoleMapping{
			{Subject: "myorg/.*", Roles: []string{readonly}},                                  // order 0: broad, no policy
			{Subject: "myorg/.*-deploy", Roles: []string{deploy}, SessionPolicy: restrictive}, // order 1: scoped
		},
	}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}

	// "myorg/foo-deploy" matches BOTH mappings (attacker controls repo name).
	subject := "myorg/foo-deploy"

	// The privileged deploy role must be scoped by the restrictive policy on the
	// mapping that granted it — not the absent policy of the broad order-0 mapping.
	policy, file := c.FindSessionPolicy(iss, subject, deploy, map[string]any{})
	if file != nil {
		t.Fatalf("unexpected policy file ref %q", *file)
	}
	if policy == nil {
		t.Fatal("deploy role assumed WITHOUT its restrictive session policy (regression)")
	}
	if *policy != restrictive {
		t.Fatalf("wrong policy for deploy role:\n got %q\nwant %q", *policy, restrictive)
	}

	// The read-only role is granted only by the policy-less broad mapping, so it
	// correctly has no session policy.
	if p, f := c.FindSessionPolicy(iss, subject, readonly, map[string]any{}); p != nil || f != nil {
		t.Fatalf("readonly role should have no policy, got policy=%v file=%v", p, f)
	}

	// A role no mapping grants yields no policy (e.g. tag-auth-authorized roles).
	if p, f := c.FindSessionPolicy(iss, subject, "arn:aws:iam::111111111111:role/unlisted", map[string]any{}); p != nil || f != nil {
		t.Fatalf("ungranted role should have no policy, got policy=%v file=%v", p, f)
	}
}

// TestFindSessionPolicy_ConditionsGateThePolicy proves the policy of a mapping
// whose conditions are NOT satisfied does not apply, even if it grants the role
// and matches the subject — the request was not authorized by that mapping.
func TestFindSessionPolicy_ConditionsGateThePolicy(t *testing.T) {
	const iss = "https://token.actions.githubusercontent.com"
	const role = "arn:aws:iam::111111111111:role/app"
	mainOnly := `{"scope":"main"}`

	c := &Config{
		Issuers:         []IssuerConfig{{Issuer: iss, Provider: "github", Audiences: []string{"sts.amazonaws.com"}}},
		DefaultIssuer:   iss,
		RoleSessionName: "s",
		RoleMappings: []RoleMapping{
			// order 0: grants role but only on refs/heads/main, with a policy.
			{Subject: "acme/app", Roles: []string{role}, SessionPolicy: mainOnly,
				Conditions: &Condition{Ref: "refs/heads/main"}},
			// order 1: grants role on any branch, no policy.
			{Subject: "acme/app", Roles: []string{role}},
		},
	}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}

	// On main, the conditioned mapping (order 0) authorizes → its policy applies.
	if p, _ := c.FindSessionPolicy(iss, "acme/app", role, map[string]any{"ref": "refs/heads/main"}); p == nil || *p != mainOnly {
		t.Fatalf("on main: expected %q, got %v", mainOnly, p)
	}
	// On another branch, order 0 fails conditions; only order 1 authorizes → no policy.
	if p, f := c.FindSessionPolicy(iss, "acme/app", role, map[string]any{"ref": "refs/heads/dev"}); p != nil || f != nil {
		t.Fatalf("off main: expected no policy, got policy=%v file=%v", p, f)
	}
}
