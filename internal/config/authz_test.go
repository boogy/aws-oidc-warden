package config

// Adversarial verification of the authorization core: index/linear-scan
// equivalence, subject anchoring and the bare-wildcard gate, issuer binding,
// session-policy scoping, condition semantics, and the role gate.

import (
	"fmt"
	"math/rand"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const vIss = "https://iss.example/a"
const vIss2 = "https://iss.example/b"

// ---------- helpers ----------

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

// wildcardCfg builds a minimal single-issuer config whose sole role_mapping
// uses the given subject pattern.
func wildcardCfg(subject string) *Config {
	return &Config{
		Issuers: []IssuerConfig{{
			Issuer: "https://token.actions.githubusercontent.com", Provider: "github",
			Audiences: []string{"sts.amazonaws.com"},
		}},
		RoleSessionName: "aow",
		RoleMappings: []RoleMapping{{
			Subject: Patterns{subject},
			Roles:   []string{"arn:aws:iam::111111111111:role/Deploy"},
		}},
	}
}

// TestValidate_RejectsBareWildcardSubject pins the identity gate: a subject
// pattern that matches everything would grant its roles to every repository
// able to obtain a token from the bound issuer.

// linearAuthorizeRoles is a brute-force reference implementation of
// AuthorizeRoles: it scans every effective mapping directly, bypassing the
// owner-bucketed index (index.go) entirely. TestIndexParity asserts the
// index path is byte-identical to this for a large, mixed sample — the
// index↔linear-scan parity proof.
func linearAuthorizeRoles(c *Config, issuer, subject string, claims map[string]any) (bool, []string) {
	matched := false
	var roles []string
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

// linearFindSessionPolicy is the brute-force reference for FindSessionPolicy:
// same match+conditions+grants-role filter and first-match-wins (lowest
// m.order) semantics, but via a full scan of c.effective instead of the index.

// linearFindSessionPolicy is the brute-force reference for FindSessionPolicy:
// same match+conditions+grants-role filter and first-match-wins (lowest
// m.order) semantics, but via a full scan of c.effective instead of the index.
func linearFindSessionPolicy(c *Config, issuer, subject, role string, claims map[string]any) (*string, *string) {
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
		return nil, nil
	}
	if best.SessionPolicyFile != "" {
		return nil, &best.SessionPolicyFile
	}
	if best.SessionPolicy != "" {
		return &best.SessionPolicy, nil
	}
	return nil, nil
}

// TestIndexParity is a differential/property test: it builds a large config
// with thousands of mappings across many owners, spanning every subject
// class the index buckets (exact literals, owner/.* patterns, fully-generic
// patterns, and alternation/multi-owner patterns such as "a/b|c/d"), then
// asserts that AuthorizeRoles/FindSessionPolicy (index path) return
// byte-identical results to a brute-force linear scan for a large sample of
// query subjects. This must fail if classifySubject ever misclassifies an
// alternation pattern as owner-scoped (the D-1 bug: "a/b|c/d" bucketed under
// owner "a" would be missed for a query subject of "c/d").

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

func patternsOf(ms []RoleMapping) []string {
	out := make([]string, len(ms))
	for i, m := range ms {
		out[i] = strings.Join(m.Subject, ",")
	}
	return out
}

// TestLiteralPrefixSoundness is the direct property classifySubject
// depends on: whatever bucket a pattern lands in, every subject it can match
// must hash to that same bucket.

// ---------- index / linear-scan equivalence ----------

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
				Subject: Patterns{p},
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
				wantM, wantR := linearAuthorizeRoles(c, iss, s, map[string]any{})
				slices.Sort(gotR)
				slices.Sort(wantR)
				if gotM != wantM || !slices.Equal(gotR, wantR) {
					t.Fatalf("AuthorizeRoles mismatch iter=%d iss=%s subject=%q\n patterns=%v\n index=(%v,%v) linear=(%v,%v)",
						iter, iss, s, patternsOf(ms), gotM, gotR, wantM, wantR)
				}
				for r := 0; r < 3; r++ {
					role := fmt.Sprintf("arn:aws:iam::111111111111:role/r%d", r)
					gp, gf := c.FindSessionPolicy(iss, s, role, map[string]any{})
					wp, wf := linearFindSessionPolicy(c, iss, s, role, map[string]any{})
					if deref(gp) != deref(wp) || deref(gf) != deref(wf) {
						t.Fatalf("FindSessionPolicy mismatch iter=%d iss=%s subject=%q role=%s\n patterns=%v\n index=(%q,%q) linear=(%q,%q)",
							iter, iss, s, role, patternsOf(ms), deref(gp), deref(gf), deref(wp), deref(wf))
					}
				}
			}
		}
	}
}

// TestIndexParity is a differential/property test: it builds a large config
// with thousands of mappings across many owners, spanning every subject
// class the index buckets (exact literals, owner/.* patterns, fully-generic
// patterns, and alternation/multi-owner patterns such as "a/b|c/d"), then
// asserts that AuthorizeRoles/FindSessionPolicy (index path) return
// byte-identical results to a brute-force linear scan for a large sample of
// query subjects. This must fail if classifySubject ever misclassifies an
// alternation pattern as owner-scoped (the D-1 bug: "a/b|c/d" bucketed under
// owner "a" would be missed for a query subject of "c/d").
func TestIndexParity(t *testing.T) {
	const numOwners = 350
	issuers := []string{
		"https://issuer0.example.com",
		"https://issuer1.example.com",
	}

	var issuerConfigs []IssuerConfig
	for _, iss := range issuers {
		issuerConfigs = append(issuerConfigs, IssuerConfig{Issuer: iss, Provider: "github", Audiences: []string{"aud"}})
	}

	owners := make([]string, numOwners)
	for i := range owners {
		owners[i] = fmt.Sprintf("owner%d", i)
	}

	var mappings []RoleMapping
	roleN := 0
	addMapping := func(issuer, subject string) {
		mappings = append(mappings, RoleMapping{
			Issuer:  issuer,
			Subject: Patterns{subject},
			Roles:   []string{fmt.Sprintf("arn:aws:iam::123456789012:role/role-%d", roleN)},
			// Distinct per-mapping policy so the role-aware FindSessionPolicy
			// parity check is non-vacuous: overlapping mappings (an exact
			// subject and its owner/.* pattern) grant different roles and must
			// each resolve to their own mapping's policy.
			SessionPolicy: fmt.Sprintf(`{"Version":"2012-10-17","policyID":%d}`, roleN),
		})
		roleN++
	}

	for _, iss := range issuers {
		for i, o := range owners {
			// Exact literal mappings (subjectExact bucket).
			addMapping(iss, o+"/repo0")
			addMapping(iss, o+"/repo1")
			// Owner-prefixed regex (subjectOwner bucket).
			addMapping(iss, o+"/.*")
			// Alternation spanning two owners (must NOT be bucketed as
			// owner-scoped — this is exactly the D-1 shape). Only every 7th
			// owner pairs with its neighbor, to keep the count bounded.
			if i%7 == 0 && i+1 < numOwners {
				addMapping(iss, fmt.Sprintf("%s/special|%s/special", o, owners[i+1]))
			}
			// Quantified first slash: the '/' is optional/repeatable, so these
			// also match slash-less subjects (e.g. "owner0opt-x") whose owner
			// segment differs from the literal prefix. classifySubject must NOT
			// bucket them as owner-scoped or candidatesFor would miss those
			// matches. Only every 5th owner, to bound the count.
			if i%5 == 0 {
				addMapping(iss, fmt.Sprintf("%s/?opt-.*", o))
				addMapping(iss, fmt.Sprintf("%s/*star-.*", o))
			}
		}
		// Fully-generic patterns (subjectAny bucket).
		addMapping(iss, ".*/shared-repo")
		addMapping(iss, "(owner1|owner2)/anything")
	}

	cfg := &Config{
		Issuers:         issuerConfigs,
		RoleSessionName: "test",
		RoleMappings:    mappings,
	}
	require.NoError(t, cfg.Validate())
	require.Greater(t, len(cfg.effective), 2000, "want a large mixed config (thousands of mappings)")

	// Large, mixed sample of query subjects: exact hits, owner-prefix hits,
	// misses, and — critically — the "far" branch of each alternation
	// pattern (e.g. ownerB/special when the pattern is
	// "ownerA/special|ownerB/special"), since that's the subject whose owner
	// segment ("ownerB") never appears left of the pattern's first '/'.
	var subjects []string
	for i, o := range owners {
		subjects = append(subjects, o+"/repo0", o+"/repo1", o+"/repo-not-listed", o+"/special")
		if i%7 == 0 && i+1 < numOwners {
			subjects = append(subjects, owners[i+1]+"/special")
		}
		// Slash-less subjects the quantified-first-slash mappings match via the
		// zero-slash branch: ownerOf is the whole string ("owner0opt-x"), which
		// differs from the pattern's literal prefix ("owner0"). These are the
		// subjects that exposed the classifySubject mis-bucketing.
		if i%5 == 0 {
			subjects = append(subjects, o+"opt-x", o+"star-y", o+"/opt-x", o+"/star-y")
		}
	}
	subjects = append(subjects, "unrelated/thing", "owner1/anything", "owner2/anything", "x/shared-repo")

	rng := rand.New(rand.NewSource(42))
	for i := 0; i < 300; i++ {
		subjects = append(subjects, fmt.Sprintf("owner%d/repo%d", rng.Intn(numOwners*2), rng.Intn(20)))
	}

	for _, iss := range issuers {
		for _, subj := range subjects {
			wantMatched, wantRoles := linearAuthorizeRoles(cfg, iss, subj, nil)
			gotMatched, gotRoles := cfg.AuthorizeRoles(iss, subj, nil)
			assert.Equalf(t, wantMatched, gotMatched, "AuthorizeRoles matched mismatch for issuer=%s subject=%s", iss, subj)
			assert.ElementsMatchf(t, wantRoles, gotRoles, "AuthorizeRoles roles mismatch for issuer=%s subject=%s", iss, subj)

			// Role-aware policy parity: for each authorized role (plus a role
			// that no mapping grants) the index path must resolve the same
			// scoping policy as the linear scan.
			rolesToCheck := append([]string{"arn:aws:iam::123456789012:role/role-absent"}, gotRoles...)
			for _, role := range rolesToCheck {
				wantPolicy, wantFile := linearFindSessionPolicy(cfg, iss, subj, role, nil)
				gotPolicy, gotFile := cfg.FindSessionPolicy(iss, subj, role, nil)
				assert.Equalf(t, wantPolicy, gotPolicy, "FindSessionPolicy policy mismatch for issuer=%s subject=%s role=%s", iss, subj, role)
				assert.Equalf(t, wantFile, gotFile, "FindSessionPolicy file mismatch for issuer=%s subject=%s role=%s", iss, subj, role)
			}
		}
	}
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

// TestClassifySubject_QuantifiedFirstSlash is the regression test for the index
// mis-bucketing bug: a subject pattern whose first '/' is quantified (optional
// or repeatable) also matches slash-less subjects, so it must not be bucketed
// under a literal owner — candidatesFor keys on ownerOf(subject) and would miss
// those matches, diverging from a linear scan (and mis-scoping session policy).
func TestClassifySubject_QuantifiedFirstSlash(t *testing.T) {
	compile := func(p string) *RoleMapping {
		m := &RoleMapping{Subject: Patterns{p}, resolvedSubject: p}
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
		owner, class := classifySubject(m.resolvedSubject, m.compiledPattern)
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
		owner, class := classifySubject(m.resolvedSubject, m.compiledPattern)
		if class != subjectOwner || owner != tc.owner {
			t.Errorf("pattern %q: got (owner=%q, class=%d), want (owner=%q, subjectOwner)", tc.pattern, owner, class, tc.owner)
		}
	}
}

// TestClassifySubject_EndToEndAuthzParity proves the fix at the API level: a
// quantified-first-slash mapping is found by AuthorizeRoles/FindSessionPolicy
// for a slash-less subject, matching what a compiled-pattern match asserts.

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
		RoleSessionName: "test",
		RoleMappings: []RoleMapping{
			{Subject: Patterns{"myorg/?opt-.*"}, Roles: []string{role}, SessionPolicy: policy},
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

// ---------- subject matching ----------

func TestSubjectAnchoringNoNewlineBypass(t *testing.T) {
	c := vcfg(t, []RoleMapping{{
		Subject: Patterns{"myorg/allowed"},
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

// TestValidate_RejectsBareWildcardSubject pins the identity gate: a subject
// pattern that matches everything would grant its roles to every repository
// able to obtain a token from the bound issuer.
func TestValidate_RejectsBareWildcardSubject(t *testing.T) {
	for _, subject := range []string{".*", ".+"} {
		err := wildcardCfg(subject).Validate()
		if err == nil {
			t.Fatalf("subject %q was accepted; it matches every subject for the issuer", subject)
		}
		if !strings.Contains(err.Error(), "too permissive") {
			t.Errorf("subject %q: unexpected error %v", subject, err)
		}
	}
}

// TestValidate_RejectsBareWildcardSubjectInRoleGroup covers the other path
// into appendEffective — role_groups expand to role_mappings, and must not
// dodge the check.

// TestValidate_RejectsBareWildcardSubjectInRoleGroup covers the other path
// into appendEffective — role_groups expand to role_mappings, and must not
// dodge the check.
func TestValidate_RejectsBareWildcardSubjectInRoleGroup(t *testing.T) {
	c := &Config{
		Issuers: []IssuerConfig{{
			Issuer: "https://token.actions.githubusercontent.com", Provider: "github",
			Audiences: []string{"sts.amazonaws.com"},
		}},
		RoleSessionName: "aow",
		RoleGroups: []RoleGroup{{
			Subjects: []string{"myorg/repo", ".*"},
			Defaults: RoleGroupDefaults{Roles: []string{"arn:aws:iam::111111111111:role/Deploy"}},
		}},
	}
	if err := c.Validate(); err == nil {
		t.Fatal("a bare wildcard in role_groups.subjects was accepted")
	}
}

// TestValidate_AcceptsSpecificSubjectPatterns guards against over-rejection:
// legitimate wildcard-bearing patterns must keep working. `example-config.yaml`
// ships `org/service-.*`, so this is a real compatibility constraint.

// TestValidate_AcceptsSpecificSubjectPatterns guards against over-rejection:
// legitimate wildcard-bearing patterns must keep working. `example-config.yaml`
// ships `org/service-.*`, so this is a real compatibility constraint.
func TestValidate_AcceptsSpecificSubjectPatterns(t *testing.T) {
	for _, subject := range []string{
		"myorg/repo",
		"org/service-.*",
		"myorg/.*",
		"myorg/(api|web)",
		"repo:myorg/.*:ref:refs/heads/main",
		".*/shared-lib", // permissive in the owner segment, still not a bare wildcard
	} {
		if err := wildcardCfg(subject).Validate(); err != nil {
			t.Errorf("subject %q should be valid: %v", subject, err)
		}
	}
}

// TestValidate_WildcardRejectionIsLiteralOnly documents the limit of the check
// honestly: it catches the shapes operators actually type, not every regex
// that happens to match everything. If this ever starts failing, the check got
// smarter and the doc comment on bareWildcards needs updating.

// TestValidate_WildcardRejectionIsLiteralOnly documents the limit of the check
// honestly: it catches the shapes operators actually type, not every regex
// that happens to match everything. If this ever starts failing, the check got
// smarter and the doc comment on bareWildcards needs updating.
func TestValidate_WildcardRejectionIsLiteralOnly(t *testing.T) {
	if err := wildcardCfg("(.*)").Validate(); err != nil {
		t.Skipf("equivalent-wildcard detection has improved: %v", err)
	}
	c := wildcardCfg("(.*)")
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	if ok, _ := c.AuthorizeRoles("https://token.actions.githubusercontent.com", "anyone/anything", map[string]any{}); !ok {
		t.Fatal("expected `(.*)` to still match everything")
	}
}

// ---------- issuer binding ----------

func TestIssuerBinding(t *testing.T) {
	c := vcfg(t, []RoleMapping{
		{Issuer: vIss, Subject: Patterns{"myorg/repo"}, Roles: []string{"arn:aws:iam::111111111111:role/a"}, SessionPolicy: "pa"},
		{Issuer: vIss2, Subject: Patterns{"myorg/repo"}, Roles: []string{"arn:aws:iam::111111111111:role/b"}, SessionPolicy: "pb"},
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

// ---------- session-policy scoping ----------

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
		RoleSessionName: "test",
		RoleMappings: []RoleMapping{
			{Subject: Patterns{"myorg/.*"}, Roles: []string{readonly}},                                  // order 0: broad, no policy
			{Subject: Patterns{"myorg/.*-deploy"}, Roles: []string{deploy}, SessionPolicy: restrictive}, // order 1: scoped
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
		return // unreachable: t.Fatal exits the goroutine. Keeps staticcheck SA5011 quiet.
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
		RoleSessionName: "test",
		RoleMappings: []RoleMapping{
			// order 0: grants role but only on refs/heads/main, with a policy.
			{Subject: Patterns{"acme/app"}, Roles: []string{role}, SessionPolicy: mainOnly,
				Conditions: &Condition{Ref: Patterns{"refs/heads/main"}}},
			// order 1: grants role on any branch, no policy.
			{Subject: Patterns{"acme/app"}, Roles: []string{role}},
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

	// Same shape, but the fallback mapping carries its own policy: the request
	// must be scoped by the mapping that actually authorized it, not by the
	// first one that merely matches the subject and grants the role.
	devOnly := `{"scope":"dev"}`
	c2 := &Config{
		Issuers:         []IssuerConfig{{Issuer: iss, Provider: "github", Audiences: []string{"sts.amazonaws.com"}}},
		DefaultIssuer:   iss,
		RoleSessionName: "test",
		RoleMappings: []RoleMapping{
			{Subject: Patterns{"acme/app"}, Roles: []string{role}, SessionPolicy: mainOnly,
				Conditions: &Condition{Ref: Patterns{"refs/heads/main"}}},
			{Subject: Patterns{"acme/app"}, Roles: []string{role}, SessionPolicy: devOnly},
		},
	}
	if err := c2.Validate(); err != nil {
		t.Fatal(err)
	}
	if p, _ := c2.FindSessionPolicy(iss, "acme/app", role, map[string]any{"ref": "refs/heads/main"}); p == nil || *p != mainOnly {
		t.Fatalf("on main: expected %q, got %v", mainOnly, p)
	}
	if p, _ := c2.FindSessionPolicy(iss, "acme/app", role, map[string]any{"ref": "refs/heads/dev"}); p == nil || *p != devOnly {
		t.Fatalf("off main: expected %q, got %v", devOnly, p)
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
		{Subject: Patterns{"myorg/.*"}, Roles: []string{priv}},
		{Subject: Patterns{"myorg/repo"}, Roles: []string{priv}, SessionPolicy: `{"scoped":true}`},
	})
	p, f := c.FindSessionPolicy(vIss, "myorg/repo", priv, map[string]any{})
	if p != nil || f != nil {
		t.Fatalf("selection rule changed: the broad first-declared mapping no longer wins "+
			"(policy=%v file=%v). If intentional, update this test and CHANGELOG 2.1.0 upgrade notes.",
			p, f)
	}

	// Reversing the declaration order is the documented remedy.
	c2 := vcfg(t, []RoleMapping{
		{Subject: Patterns{"myorg/repo"}, Roles: []string{priv}, SessionPolicy: `{"scoped":true}`},
		{Subject: Patterns{"myorg/.*"}, Roles: []string{priv}},
	})
	if p2, _ := c2.FindSessionPolicy(vIss, "myorg/repo", priv, map[string]any{}); p2 == nil || *p2 != `{"scoped":true}` {
		t.Fatalf("declaring the scoped mapping first should win, got %v", p2)
	}
}

// ---------- P5: conditions ----------

// ---------- conditions ----------

func TestConditionSemantics(t *testing.T) {
	role := "arn:aws:iam::111111111111:role/r"
	c := vcfg(t, []RoleMapping{{
		Subject:    Patterns{"myorg/repo"},
		Roles:      []string{role},
		Conditions: &Condition{Ref: Patterns{"refs/heads/main"}, EventName: Patterns{"push"}},
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
	if ok(map[string]any{"ref": "refs/heads/main", "event_name": []any{"pull_request"}}) {
		t.Error("TYPE CONFUSION: array claim with no matching element satisfied a condition")
	}
	if ok(map[string]any{"ref": "refs/heads/main", "event_name": []any{42, true}}) {
		t.Error("TYPE CONFUSION: array claim of non-strings satisfied a condition")
	}
	// Array claims match on ANY string element (GitLab/Okta group lists).
	if !ok(map[string]any{"ref": "refs/heads/main", "event_name": []any{"pull_request", "push"}}) {
		t.Error("array claim with a matching element should authorize")
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
// key is NOT silently ignored: it is read as a claim name and checked against
// a claim that does not exist, denying the request.

// TestTypoedConditionKeyFailsClosed proves an unrecognized condition
// key is NOT silently ignored: it is read as a claim name and checked against
// a claim that does not exist, denying the request.
func TestTypoedConditionKeyFailsClosed(t *testing.T) {
	c := vcfg(t, []RoleMapping{{
		Subject:    Patterns{"myorg/repo"},
		Roles:      []string{"arn:aws:iam::111111111111:role/r"},
		Conditions: &Condition{Claims: map[string]Patterns{"event-name": {"push"}}}, // typo: dash not underscore
	}})
	if m, _ := c.AuthorizeRoles(vIss, "myorg/repo", map[string]any{"event_name": "push"}); m {
		t.Error("FAIL-OPEN: a typo'd condition key was silently ignored")
	}
}

func TestActorIsOrAndAnded(t *testing.T) {
	c := vcfg(t, []RoleMapping{{
		Subject:    Patterns{"myorg/repo"},
		Roles:      []string{"arn:aws:iam::111111111111:role/r"},
		Conditions: &Condition{Actor: Patterns{"alice", "bob"}, EventName: Patterns{"push"}},
	}})
	ok := func(claims map[string]any) bool {
		m, _ := c.AuthorizeRoles(vIss, "myorg/repo", claims)
		return m
	}
	if !ok(map[string]any{"actor": "bob", "event_name": "push"}) {
		t.Error("OR within actor patterns broken")
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
			RoleSessionName: "test",
			RoleMappings: []RoleMapping{{
				Subject: Patterns{"myorg/repo"}, Roles: []string{"arn:aws:iam::111111111111:role/r"},
				Conditions: &Condition{Ref: Patterns{p}},
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

// ---------- role gate ----------

func TestRequestedRoleMustMatchExactly(t *testing.T) {
	role := "arn:aws:iam::111111111111:role/Deploy"
	c := vcfg(t, []RoleMapping{{Subject: Patterns{"myorg/repo"}, Roles: []string{role}}})
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
		RoleSessionName: "test",
		RoleSets:        map[string][]string{"deploy": {"arn:aws:iam::111111111111:role/A", "arn:aws:iam::111111111111:role/B"}},
		RoleMappings:    []RoleMapping{{Subject: Patterns{"myorg/repo"}, Roles: []string{"@deploy"}}},
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
		RoleSessionName: "test",
		RoleMappings:    []RoleMapping{{Subject: Patterns{"myorg/repo"}, Roles: []string{"@nope"}}},
	}
	if err := c2.Validate(); err == nil {
		t.Error("undefined role set accepted")
	}
}

// ---------- P7: tag-auth ----------

// BenchmarkAuthorizeRoles measures one whole authorization decision — owner
// bucket lookup, subject regex, and a nested condition tree — against a config
// far larger than a realistic deployment. It exists to keep the condition
// engine's cost in perspective: the decision is dwarfed by the STS AssumeRole
// round trip that follows it, so micro-optimizing the gate (a literal fast path
// for non-regex patterns, say) buys nothing and adds a second matching path to
// the security-critical code. Measure here before proposing one.
func BenchmarkAuthorizeRoles(b *testing.B) {
	const issuer = "https://token.actions.githubusercontent.com"

	var sb strings.Builder
	sb.WriteString(`
role_session_name: "aow"
issuers:
  - issuer: "` + issuer + `"
    provider: "github"
    audiences: ["sts.amazonaws.com"]
    claim_mappings: {subject: "sub"}
default_issuer: "` + issuer + `"
role_mappings:
`)
	for i := 0; i < 500; i++ {
		fmt.Fprintf(&sb, `  - subject: "org%d/repo%d:.*"
    roles: ["arn:aws:iam::123456789012:role/r%d"]
    conditions:
      ref: "refs/heads/main"
      event_name: ["push", "workflow_dispatch"]
      runner_environment: "github-hosted"
      any_of:
        - actor: "release-bot"
        - repository: "org%d/.*"
`, i, i, i, i)
	}

	cfg := &Config{}
	require.NoError(b, cfg.MergeBytes([]byte(sb.String()), "yaml"))

	subject := "org250/repo250:ref:refs/heads/main"
	claims := map[string]any{
		"sub":                subject,
		"repository":         "org250/repo250",
		"ref":                "refs/heads/main",
		"event_name":         "push",
		"runner_environment": "github-hosted",
		"actor":              "someone",
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ok, roles := cfg.AuthorizeRoles(issuer, subject, claims)
		if !ok || len(roles) != 1 {
			b.Fatalf("expected exactly one role, got ok=%v roles=%v", ok, roles)
		}
	}
}
