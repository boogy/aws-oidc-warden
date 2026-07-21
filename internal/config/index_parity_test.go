package config

import (
	"fmt"
	"math/rand"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
			Subject: subject,
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
