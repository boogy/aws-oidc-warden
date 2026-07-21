package config

// Adversarial verification of the authorization core: index/linear-scan
// equivalence, subject anchoring, issuer binding, session-policy scoping,
// condition semantics, the role gate, and tag-based authorization.

import (
	"fmt"
	"math/rand"
	"regexp"
	"slices"
	"testing"
)

const vIss = "https://iss.example/a"
const vIss2 = "https://iss.example/b"

func vcfg(t *testing.T, mappings []RoleMapping) *Config {
	t.Helper()
	c := &Config{
		Issuers: []IssuerConfig{
			{Issuer: vIss, Provider: "generic", Audiences: []string{"aud"}, ClaimMappings: map[string]string{"subject": "sub"}},
			{Issuer: vIss2, Provider: "generic", Audiences: []string{"aud"}, ClaimMappings: map[string]string{"subject": "sub"}},
		},
		DefaultIssuer:   vIss,
		RoleSessionName: "test",
		RoleMappings:    mappings,
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	return c
}

// ---------- reference implementations (no index) ----------

func linearAuthorize(c *Config, issuer, subject string, claims map[string]any) (bool, []string) {
	matched := false
	roles := []string{}
	for _, m := range c.effective {
		if m.Issuer != issuer {
			continue
		}
		if m.compiledPattern == nil || !m.compiledPattern.MatchString(subject) {
			continue
		}
		if !satisfiesConditions(m.Conditions, claims) {
			continue
		}
		matched = true
		roles = append(roles, m.Roles...)
	}
	return matched, roles
}

func linearPolicy(c *Config, issuer, subject, role string, claims map[string]any) (string, string) {
	var best *RoleMapping
	for _, m := range c.effective {
		if m.Issuer != issuer {
			continue
		}
		if m.compiledPattern == nil || !m.compiledPattern.MatchString(subject) {
			continue
		}
		if !satisfiesConditions(m.Conditions, claims) {
			continue
		}
		if !slices.Contains(m.Roles, role) {
			continue
		}
		if best == nil || m.order < best.order {
			best = m
		}
	}
	if best == nil {
		return "", ""
	}
	return best.SessionPolicy, best.SessionPolicyFile
}

func deref(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

// ---------- P1: index/linear differential fuzz ----------

// TestIndexDifferentialFuzz proves the owner-bucketed index is
// observationally identical to a full linear scan for both AuthorizeRoles and
// FindSessionPolicy. A false negative here is fail-OPEN: a policy-bearing
// mapping dropped from the scan while a broader policy-less mapping still
// authorizes the role yields an UNSCOPED role assumption.
func TestIndexDifferentialFuzz(t *testing.T) {
	patterns := []string{
		"myorg/repo",
		"myorg/.*",
		"myorg/?repo",       // quantified first slash: also matches "myorgrepo"
		"myorg/*repo",       // quantified slash again
		"myorg/(a|b)",       //nolint
		"a/b|c/d",           // top-level alternation
		"(?i)MyOrg/repo",    // case-insensitive: literal prefix must not mislead
		"(?i)myorg/.*",      //
		"[a-z]+/[a-z]+",     //
		"[^/]+/[^/]+",       // permissive, but not a bare wildcard (now rejected)
		"^myorg/repo",       // redundant nested anchor
		"myorg/repo$",       //
		"(?s)myorg/.*",      // dot-matches-newline
		"myorg\\/repo",      // escaped slash
		"my.rg/repo",        // metachar before the slash
		"myorg/repo-[0-9]+", //
		"other/repo",
		"myorg",            // no slash at all
		"(?:myorg|other)/", //
		"myorg/repo/sub",   // three segments
		"MYORG/repo",
	}
	subjects := []string{
		"myorg/repo", "myorgrepo", "myorg/a", "myorg/b", "myorg/repo-12",
		"other/repo", "myorg", "MYORG/repo", "MyOrg/repo", "myorg/repo/sub",
		"myorg/", "/myorg", "my0rg/repo", "myorg/repo\nevil/repo", "",
		"a/b", "c/d", "myorg/repo ",
	}

	rng := rand.New(rand.NewSource(1))
	for iter := 0; iter < 400; iter++ {
		n := 1 + rng.Intn(6)
		ms := make([]RoleMapping, 0, n)
		for i := 0; i < n; i++ {
			p := patterns[rng.Intn(len(patterns))]
			m := RoleMapping{
				Subject: p,
				Roles:   []string{fmt.Sprintf("arn:aws:iam::111111111111:role/r%d", rng.Intn(3))},
			}
			if rng.Intn(2) == 0 {
				m.SessionPolicy = fmt.Sprintf("policy-%d", i)
			}
			if rng.Intn(4) == 0 {
				m.Issuer = vIss2
			}
			ms = append(ms, m)
		}
		c := vcfg(t, ms)

		for _, iss := range []string{vIss, vIss2} {
			for _, s := range subjects {
				gotM, gotR := c.AuthorizeRoles(iss, s, map[string]any{})
				wantM, wantR := linearAuthorize(c, iss, s, map[string]any{})
				slices.Sort(gotR)
				slices.Sort(wantR)
				if gotM != wantM || !slices.Equal(gotR, wantR) {
					t.Fatalf("AuthorizeRoles mismatch iter=%d iss=%s subject=%q\n patterns=%v\n index=(%v,%v) linear=(%v,%v)",
						iter, iss, s, patternsOf(ms), gotM, gotR, wantM, wantR)
				}
				for r := 0; r < 3; r++ {
					role := fmt.Sprintf("arn:aws:iam::111111111111:role/r%d", r)
					gp, gf := c.FindSessionPolicy(iss, s, role, map[string]any{})
					wp, wf := linearPolicy(c, iss, s, role, map[string]any{})
					if deref(gp) != wp || deref(gf) != wf {
						t.Fatalf("FindSessionPolicy mismatch iter=%d iss=%s subject=%q role=%s\n patterns=%v\n index=(%q,%q) linear=(%q,%q)",
							iter, iss, s, role, patternsOf(ms), deref(gp), deref(gf), wp, wf)
					}
				}
			}
		}
	}
}

func patternsOf(ms []RoleMapping) []string {
	out := make([]string, len(ms))
	for i, m := range ms {
		out[i] = m.Subject
	}
	return out
}

// TestLiteralPrefixSoundness is the direct property classifySubject
// depends on: whatever bucket a pattern lands in, every subject it can match
// must hash to that same bucket.
func TestLiteralPrefixSoundness(t *testing.T) {
	pats := []string{
		"(?i)MyOrg/repo", "(?i)myorg/repo", "myorg/?repo", "myorg/*repo",
		"a/b|c/d", "myorg/.*", "[a-z]+/x", "(?s)myorg/.*", "my.rg/repo",
		"myorg\\/repo", "^myorg/repo", "(?U)myorg/.*", "(?m)myorg/repo",
	}
	corpus := []string{
		"myorg/repo", "MyOrg/repo", "MYORG/REPO", "myorgrepo", "myorg/x",
		"a/b", "c/d", "myrg/repo", "abc/x", "myorg/repo\n", "\nmyorg/repo",
	}
	for _, p := range pats {
		re := regexp.MustCompile("^(?:" + p + ")$")
		owner, class := classifySubject(p, re)
		if class != subjectOwner {
			continue
		}
		for _, s := range corpus {
			if re.MatchString(s) && ownerOf(s) != owner {
				t.Errorf("UNSOUND bucket: pattern %q filed under owner %q but matches subject %q (owner %q)",
					p, owner, s, ownerOf(s))
			}
		}
	}
}

// ---------- P2: anchoring ----------

func TestSubjectAnchoringNoNewlineBypass(t *testing.T) {
	c := vcfg(t, []RoleMapping{{
		Subject: "myorg/allowed",
		Roles:   []string{"arn:aws:iam::111111111111:role/r"},
	}})
	for _, s := range []string{
		"myorg/allowed\n",
		"\nmyorg/allowed",
		"myorg/allowed\nevil/repo",
		"evil/repo\nmyorg/allowed",
		"myorg/allowed ",
		" myorg/allowed",
		"xmyorg/allowedx",
	} {
		if ok, roles := c.AuthorizeRoles(vIss, s, map[string]any{}); ok {
			t.Errorf("ANCHOR BYPASS: subject %q authorized roles %v", s, roles)
		}
	}
	if ok, _ := c.AuthorizeRoles(vIss, "myorg/allowed", map[string]any{}); !ok {
		t.Fatal("exact subject should authorize")
	}
}

// ---------- P3: issuer binding ----------

func TestIssuerBinding(t *testing.T) {
	c := vcfg(t, []RoleMapping{
		{Issuer: vIss, Subject: "myorg/repo", Roles: []string{"arn:aws:iam::111111111111:role/a"}, SessionPolicy: "pa"},
		{Issuer: vIss2, Subject: "myorg/repo", Roles: []string{"arn:aws:iam::111111111111:role/b"}, SessionPolicy: "pb"},
	})
	_, roles := c.AuthorizeRoles(vIss, "myorg/repo", map[string]any{})
	if slices.Contains(roles, "arn:aws:iam::111111111111:role/b") {
		t.Error("CROSS-ISSUER LEAK: issuer A grant returned issuer B's role")
	}
	if ok, _ := c.AuthorizeRoles("https://unconfigured/", "myorg/repo", map[string]any{}); ok {
		t.Error("unconfigured issuer authorized")
	}
	p, _ := c.FindSessionPolicy(vIss, "myorg/repo", "arn:aws:iam::111111111111:role/b", map[string]any{})
	if p != nil {
		t.Errorf("CROSS-ISSUER POLICY LEAK: got %q", *p)
	}
}

// ---------- P4: session policy scoping ----------

func TestSessionPolicyTravelsWithGrant(t *testing.T) {
	priv := "arn:aws:iam::111111111111:role/privileged"
	broad := "arn:aws:iam::111111111111:role/broad"
	c := vcfg(t, []RoleMapping{
		// Declared FIRST, broad, policy-less, does NOT grant priv.
		{Subject: "myorg/.*", Roles: []string{broad}},
		// Declared second, narrow, scoped, grants priv.
		{Subject: "myorg/repo", Roles: []string{priv}, SessionPolicy: `{"scoped":true}`},
	})
	p, _ := c.FindSessionPolicy(vIss, "myorg/repo", priv, map[string]any{})
	if p == nil || *p != `{"scoped":true}` {
		t.Fatalf("UNSCOPED PRIVILEGED ROLE: expected scoping policy, got %v", p)
	}
	if p2, _ := c.FindSessionPolicy(vIss, "myorg/repo", broad, map[string]any{}); p2 != nil {
		t.Errorf("policy leaked onto broad role: %q", *p2)
	}
	// A role nobody grants must yield no policy.
	if p3, f3 := c.FindSessionPolicy(vIss, "myorg/repo", "arn:aws:iam::111111111111:role/ghost", map[string]any{}); p3 != nil || f3 != nil {
		t.Error("policy returned for an ungranted role")
	}
}

func TestSessionPolicyConditionGated(t *testing.T) {
	role := "arn:aws:iam::111111111111:role/deploy"
	c := vcfg(t, []RoleMapping{
		{Subject: "myorg/repo", Roles: []string{role}, SessionPolicy: "prod", Conditions: &Condition{Ref: "refs/heads/main"}},
		{Subject: "myorg/repo", Roles: []string{role}, SessionPolicy: "dev"},
	})
	if p, _ := c.FindSessionPolicy(vIss, "myorg/repo", role, map[string]any{"ref": "refs/heads/main"}); p == nil || *p != "prod" {
		t.Errorf("expected prod policy on main, got %v", p)
	}
	if p, _ := c.FindSessionPolicy(vIss, "myorg/repo", role, map[string]any{"ref": "refs/heads/feature"}); p == nil || *p != "dev" {
		t.Errorf("expected dev policy off main, got %v", p)
	}
}

// TestOrderWinsAmongMappingsGrantingTheSameRole pins the documented,
// accepted order-sensitivity: when SEVERAL mappings grant the same role,
// lowest `order` (first-declared) wins — even when the winner carries no
// session_policy and a later, narrower mapping does. That is a config
// footgun, not a lookup bug: both mappings genuinely grant the role, and
// first-match-wins mirrors AuthorizeRoles' union semantics (see CHANGELOG
// 2.1.0 → Upgrade notes).
//
// This asserts the behavior rather than logging it, so that changing the
// selection rule to prefer the most-specific or policy-bearing mapping is a
// deliberate decision with a failing test, not a silent drift.
func TestOrderWinsAmongMappingsGrantingTheSameRole(t *testing.T) {
	priv := "arn:aws:iam::111111111111:role/privileged"
	c := vcfg(t, []RoleMapping{
		{Subject: "myorg/.*", Roles: []string{priv}},
		{Subject: "myorg/repo", Roles: []string{priv}, SessionPolicy: `{"scoped":true}`},
	})
	p, f := c.FindSessionPolicy(vIss, "myorg/repo", priv, map[string]any{})
	if p != nil || f != nil {
		t.Fatalf("selection rule changed: the broad first-declared mapping no longer wins "+
			"(policy=%v file=%v). If intentional, update this test and CHANGELOG 2.1.0 upgrade notes.",
			p, f)
	}

	// Reversing the declaration order is the documented remedy.
	c2 := vcfg(t, []RoleMapping{
		{Subject: "myorg/repo", Roles: []string{priv}, SessionPolicy: `{"scoped":true}`},
		{Subject: "myorg/.*", Roles: []string{priv}},
	})
	if p2, _ := c2.FindSessionPolicy(vIss, "myorg/repo", priv, map[string]any{}); p2 == nil || *p2 != `{"scoped":true}` {
		t.Fatalf("declaring the scoped mapping first should win, got %v", p2)
	}
}

// ---------- P5: conditions ----------

func TestConditionSemantics(t *testing.T) {
	role := "arn:aws:iam::111111111111:role/r"
	c := vcfg(t, []RoleMapping{{
		Subject:    "myorg/repo",
		Roles:      []string{role},
		Conditions: &Condition{Ref: "refs/heads/main", EventName: "push"},
	}})
	ok := func(claims map[string]any) bool {
		m, _ := c.AuthorizeRoles(vIss, "myorg/repo", claims)
		return m
	}
	if !ok(map[string]any{"ref": "refs/heads/main", "event_name": "push"}) {
		t.Error("all conditions met should authorize")
	}
	// AND semantics: one satisfied, one not.
	if ok(map[string]any{"ref": "refs/heads/main", "event_name": "pull_request"}) {
		t.Error("AND VIOLATION: authorized with event_name unmet")
	}
	// Missing claim must deny, not skip.
	if ok(map[string]any{"ref": "refs/heads/main"}) {
		t.Error("FAIL-OPEN: missing event_name claim authorized")
	}
	if ok(map[string]any{}) {
		t.Error("FAIL-OPEN: empty claims authorized")
	}
	if ok(nil) {
		t.Error("FAIL-OPEN: nil claims authorized")
	}
	// Type confusion: non-string claim must deny.
	if ok(map[string]any{"ref": "refs/heads/main", "event_name": 42}) {
		t.Error("TYPE CONFUSION: numeric claim satisfied a string condition")
	}
	if ok(map[string]any{"ref": "refs/heads/main", "event_name": []any{"push"}}) {
		t.Error("TYPE CONFUSION: array claim satisfied a string condition")
	}
	if ok(map[string]any{"ref": "refs/heads/main", "event_name": nil}) {
		t.Error("TYPE CONFUSION: null claim satisfied a string condition")
	}
	// Condition values are anchored too.
	if ok(map[string]any{"ref": "refs/heads/main\nx", "event_name": "push"}) {
		t.Error("ANCHOR BYPASS in condition value")
	}
	if ok(map[string]any{"ref": "xrefs/heads/mainx", "event_name": "push"}) {
		t.Error("ANCHOR BYPASS in condition value (substring)")
	}
}

// TestTypoedConditionKeyFailsClosed proves an unrecognized condition
// key is NOT silently ignored: it lands in Extra and is checked against a
// claim that does not exist, denying the request.
func TestTypoedConditionKeyFailsClosed(t *testing.T) {
	c := vcfg(t, []RoleMapping{{
		Subject:    "myorg/repo",
		Roles:      []string{"arn:aws:iam::111111111111:role/r"},
		Conditions: &Condition{Extra: map[string]string{"event-name": "push"}}, // typo: dash not underscore
	}})
	if m, _ := c.AuthorizeRoles(vIss, "myorg/repo", map[string]any{"event_name": "push"}); m {
		t.Error("FAIL-OPEN: a typo'd condition key was silently ignored")
	}
}

func TestActorMatchesIsOrAndAnded(t *testing.T) {
	c := vcfg(t, []RoleMapping{{
		Subject:    "myorg/repo",
		Roles:      []string{"arn:aws:iam::111111111111:role/r"},
		Conditions: &Condition{ActorMatches: []string{"alice", "bob"}, EventName: "push"},
	}})
	ok := func(claims map[string]any) bool {
		m, _ := c.AuthorizeRoles(vIss, "myorg/repo", claims)
		return m
	}
	if !ok(map[string]any{"actor": "bob", "event_name": "push"}) {
		t.Error("OR within actor_matches broken")
	}
	if ok(map[string]any{"actor": "mallory", "event_name": "push"}) {
		t.Error("unlisted actor authorized")
	}
	if ok(map[string]any{"event_name": "push"}) {
		t.Error("FAIL-OPEN: missing actor claim authorized")
	}
	if ok(map[string]any{"actor": "bob"}) {
		t.Error("AND VIOLATION: actor match bypassed the event_name condition")
	}
}

func TestPermissiveConditionPatternsRejected(t *testing.T) {
	for _, p := range []string{".*", ".+", ""} {
		c := &Config{
			Issuers:         []IssuerConfig{{Issuer: vIss, Provider: "generic", Audiences: []string{"a"}, ClaimMappings: map[string]string{"subject": "sub"}}},
			RoleSessionName: "t",
			RoleMappings: []RoleMapping{{
				Subject: "myorg/repo", Roles: []string{"arn:aws:iam::111111111111:role/r"},
				Conditions: &Condition{Ref: p},
			}},
		}
		err := c.Validate()
		if p == "" {
			continue // empty means "no condition on this field", by design
		}
		if err == nil {
			t.Errorf("permissive condition pattern %q accepted by Validate()", p)
		}
	}
}

// ---------- P6: role set / role gate ----------

func TestRequestedRoleMustMatchExactly(t *testing.T) {
	role := "arn:aws:iam::111111111111:role/Deploy"
	c := vcfg(t, []RoleMapping{{Subject: "myorg/repo", Roles: []string{role}}})
	_, roles := c.AuthorizeRoles(vIss, "myorg/repo", map[string]any{})
	for _, variant := range []string{
		"arn:aws:iam::111111111111:role/deploy",
		"arn:aws:iam::111111111111:role/Deploy ",
		"arn:aws:iam::111111111111:role/Deploy/",
		"arn:aws:iam::111111111111:role/DeployAdmin",
		"arn:aws:iam::999999999999:role/Deploy",
		"ARN:AWS:IAM::111111111111:ROLE/Deploy",
	} {
		if slices.Contains(roles, variant) {
			t.Errorf("ROLE GATE BYPASS: variant %q accepted", variant)
		}
	}
	if !slices.Contains(roles, role) {
		t.Fatal("exact role not granted")
	}
}

func TestRoleSetResolvedFromConfigNotToken(t *testing.T) {
	c := &Config{
		Issuers:         []IssuerConfig{{Issuer: vIss, Provider: "generic", Audiences: []string{"a"}, ClaimMappings: map[string]string{"subject": "sub"}}},
		RoleSessionName: "t",
		RoleSets:        map[string][]string{"deploy": {"arn:aws:iam::111111111111:role/A", "arn:aws:iam::111111111111:role/B"}},
		RoleMappings:    []RoleMapping{{Subject: "myorg/repo", Roles: []string{"@deploy"}}},
	}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	_, roles := c.AuthorizeRoles(vIss, "myorg/repo", map[string]any{})
	if !slices.Contains(roles, "arn:aws:iam::111111111111:role/A") || len(roles) != 2 {
		t.Fatalf("role set expansion wrong: %v", roles)
	}
	if slices.Contains(roles, "@deploy") {
		t.Error("unresolved alias leaked into granted roles")
	}
	// Undefined set must fail closed at Validate.
	c2 := &Config{
		Issuers:         []IssuerConfig{{Issuer: vIss, Provider: "generic", Audiences: []string{"a"}, ClaimMappings: map[string]string{"subject": "sub"}}},
		RoleSessionName: "t",
		RoleMappings:    []RoleMapping{{Subject: "myorg/repo", Roles: []string{"@nope"}}},
	}
	if err := c2.Validate(); err == nil {
		t.Error("undefined role set accepted")
	}
}

// ---------- P7: tag-auth ----------

func TestTagAuthGates(t *testing.T) {
	base := func(multi bool) *TagAuth {
		return &TagAuth{Enabled: true, TagPrefix: "aow/", multiIssuer: multi}
	}
	claims := map[string]any{"repository": "myorg/repo", "repository_owner": "myorg", "ref": "refs/heads/main", "actor": "alice"}

	// No identity tag at all -> deny even if every other dimension matches.
	if base(false).Authorize(map[string]string{"aow/ref": "refs/heads/main"}, claims, vIss, "myorg/repo") {
		t.Error("FAIL-OPEN: tag-auth authorized with no identity tag")
	}
	// Identity tag present but non-matching.
	if base(false).Authorize(map[string]string{"aow/subject": "other/repo"}, claims, vIss, "myorg/repo") {
		t.Error("non-matching subject tag authorized")
	}
	// Empty identity tag value.
	if base(false).Authorize(map[string]string{"aow/subject": ""}, claims, vIss, "myorg/repo") {
		t.Error("empty subject tag authorized")
	}
	// Happy path.
	if !base(false).Authorize(map[string]string{"aow/subject": "myorg/repo"}, claims, vIss, "myorg/repo") {
		t.Error("matching subject tag should authorize")
	}
	// Multi-issuer: missing issuer tag fails closed.
	if base(true).Authorize(map[string]string{"aow/subject": "myorg/repo"}, claims, vIss, "myorg/repo") {
		t.Error("MULTI-ISSUER LEAK: authorized without an issuer tag")
	}
	// Multi-issuer: wrong issuer tag fails closed.
	if base(true).Authorize(map[string]string{"aow/subject": "myorg/repo", "aow/issuer": vIss2}, claims, vIss, "myorg/repo") {
		t.Error("wrong issuer tag authorized")
	}
	if !base(true).Authorize(map[string]string{"aow/subject": "myorg/repo", "aow/issuer": vIss}, claims, vIss, "myorg/repo") {
		t.Error("correct issuer tag should authorize")
	}
	// Extra dimension is AND'd.
	if base(false).Authorize(map[string]string{"aow/subject": "myorg/repo", "aow/ref": "refs/heads/prod"}, claims, vIss, "myorg/repo") {
		t.Error("AND VIOLATION: mismatched ref tag authorized")
	}
	// Tag matching is exact, never regex.
	for _, v := range []string{"myorg/.*", ".*", "myorg/rep*", "myorg/repo*"} {
		if base(false).Authorize(map[string]string{"aow/subject": v}, claims, vIss, "myorg/repo") {
			t.Errorf("REGEX IN TAG: value %q matched", v)
		}
	}
	// Disabled tag-auth never authorizes.
	if (&TagAuth{Enabled: false, TagPrefix: "aow/"}).Authorize(map[string]string{"aow/subject": "myorg/repo"}, claims, vIss, "myorg/repo") {
		t.Error("disabled tag-auth authorized")
	}
	// nil receiver.
	var nilTA *TagAuth
	if nilTA.Authorize(map[string]string{"aow/subject": "myorg/repo"}, claims, vIss, "myorg/repo") {
		t.Error("nil tag-auth authorized")
	}
	// Bare repo token without default_org must not match.
	if base(false).Authorize(map[string]string{"aow/repo": "repo"}, claims, vIss, "myorg/repo") {
		t.Error("bare repo token matched without default_org")
	}
	withOrg := &TagAuth{Enabled: true, TagPrefix: "aow/", DefaultOrg: "myorg"}
	if !withOrg.Authorize(map[string]string{"aow/repo": "repo"}, claims, vIss, "myorg/repo") {
		t.Error("bare repo token should match with default_org")
	}
	// default_org must not let a foreign org through.
	foreign := map[string]any{"repository": "evil/repo", "repository_owner": "evil"}
	if withOrg.Authorize(map[string]string{"aow/repo": "repo"}, foreign, vIss, "evil/repo") {
		t.Error("DEFAULT_ORG BYPASS: foreign org matched a bare repo token")
	}
}

// TestTagAuthPrefixConfusion checks that tags outside the prefix are
// ignored and cannot be used to forge an identity.
func TestTagAuthPrefixConfusion(t *testing.T) {
	ta := &TagAuth{Enabled: true, TagPrefix: "aow/"}
	claims := map[string]any{"repository": "myorg/repo"}
	for _, k := range []string{"subject", "AOW/subject", "aow-subject", "xaow/subject", "aow//subject"} {
		if ta.Authorize(map[string]string{k: "myorg/repo"}, claims, vIss, "myorg/repo") {
			t.Errorf("PREFIX CONFUSION: tag key %q was honored", k)
		}
	}
}
