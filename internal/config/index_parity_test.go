package config

import (
	"fmt"
	"math/rand"
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
// same first-match-wins (lowest m.order) semantics, but via a full scan of
// c.effective instead of the index.
func linearFindSessionPolicy(c *Config, issuer, subject string) (*string, *string) {
	var best *RoleMapping
	for _, m := range c.effective {
		if m.Issuer != issuer {
			continue
		}
		if m.compiledPattern == nil || !m.compiledPattern.MatchString(subject) {
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

			wantPolicy, wantFile := linearFindSessionPolicy(cfg, iss, subj)
			gotPolicy, gotFile := cfg.FindSessionPolicy(iss, subj)
			assert.Equalf(t, wantPolicy, gotPolicy, "FindSessionPolicy policy mismatch for issuer=%s subject=%s", iss, subj)
			assert.Equalf(t, wantFile, gotFile, "FindSessionPolicy file mismatch for issuer=%s subject=%s", iss, subj)
		}
	}
}
