package config

import (
	"encoding/json"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func FuzzIsUniversalIsSound(f *testing.F) {
	for _, p := range []string{".*", ".+", "(?s).*", `[\s\S]*`, "(.*)", "^.*$", "a|.*", "a*", "[^\n]*", `\C*`, "(?i).*x", "x?.*", ".*|"} {
		f.Add(p, "abc")
	}
	f.Fuzz(func(t *testing.T, pattern, s string) {
		tree, err := parsePattern(pattern)
		if err != nil || !isUniversal(tree) {
			return
		}
		re, err := regexp.Compile("^(?:" + pattern + ")$")
		if err != nil {
			return
		}
		for _, in := range []string{s, s + strings.Repeat("x", len(pattern)), "repo:org/r:ref:refs/heads/main"} {
			if len(in) >= len(pattern) && !strings.Contains(in, "\n") && !re.MatchString(in) {
				t.Fatalf("isUniversal(%q) but it rejects %q", pattern, in)
			}
		}
	})
}

func FuzzAuthorizeRolesMatchesLinearScan(f *testing.F) {
	for _, seed := range [][2]string{
		{"owner0/.*", "owner0/repo"},
		{"owner0/special|owner1/special", "owner1/special"},
		{"owner0/?opt-.*", "owner0opt-x"},
		{"owner0/*star-.*", "owner0star-y"},
		{"(owner1|owner2)/anything", "owner2/anything"},
		{".*/shared-repo", "x/shared-repo"},
		{"o(?i)WNER0/x", "owner0/X"},
	} {
		f.Add(seed[0], seed[1])
	}
	const iss = "https://issuer0.example.com"
	f.Fuzz(func(t *testing.T, pattern, subject string) {
		cfg := &Config{
			Issuers:         []IssuerConfig{{Issuer: iss, Provider: "github", Audiences: []string{"aud"}}},
			RoleSessionName: "test",
			RoleMappings: []RoleMapping{
				{Issuer: iss, Subject: Patterns{pattern}, Roles: roleEntries("arn:aws:iam::123456789012:role/fuzz")},
				{Issuer: iss, Subject: Patterns{"owner0/repo"}, Roles: roleEntries("arn:aws:iam::123456789012:role/exact")},
				{Issuer: iss, Subject: Patterns{"owner1/.*"}, Roles: roleEntries("arn:aws:iam::123456789012:role/owner")},
				{Issuer: iss, Subject: Patterns{pattern}, Roles: []RoleEntry{
					{Role: "arn:aws:iam::123456789012:role/plain"},
					{Role: "arn:aws:iam::123456789012:role/gated", Conditions: &Condition{Ref: Patterns{"refs/heads/main"}}},
				}},
			},
		}
		if cfg.Validate() != nil {
			return
		}
		subjectMatches := subjectOracle(&RoleMapping{resolvedSubject: pattern}).MatchString(subject)
		for _, claims := range []map[string]any{nil, {"ref": "refs/heads/main"}, {"ref": "refs/heads/dev"}} {
			wantMatched, wantRoles := linearAuthorizeRoles(cfg, iss, subject, claims)
			gotMatched, gotRoles := cfg.AuthorizeRoles(iss, subject, claims)
			assert.Equal(t, wantMatched, gotMatched, "pattern=%q subject=%q claims=%v", pattern, subject, claims)
			assert.ElementsMatch(t, wantRoles, gotRoles, "pattern=%q subject=%q claims=%v", pattern, subject, claims)
			wantGated := subjectMatches && claims["ref"] == "refs/heads/main"
			assert.Equal(t, wantGated, slices.Contains(gotRoles, "arn:aws:iam::123456789012:role/gated"), "pattern=%q subject=%q claims=%v", pattern, subject, claims)
		}
	})
}

func FuzzParseFragmentOnlyAllowedKeys(f *testing.F) {
	for _, seed := range []string{
		`{"role_mappings":[{"subject":"org/repo","roles":["arn:aws:iam::123456789012:role/r"]}]}`,
		`{"role_sets":{"a":["arn:aws:iam::123456789012:role/r"]},"default_issuer":"https://x"}`,
		`{"Issuers":[{"issuer":"https://evil"}]}`,
		`{"TAG_AUTH":{"enabled":true}}`,
		`{"role_sets":{},"idp":{"enabled":true}}`,
		`{"role_mappings":[{"subject":"org/repo","roles":["arn:aws:iam::123456789012:role/r",{"role":"arn:aws:iam::123456789012:role/s","conditions":{"ref":"refs/heads/main"},"idp_token":false}]}]}`,
		`{"role_mappings":[{"subject":"org/repo","roles":[{"role":"arn:aws:iam::123456789012:role/s","session_tags":{},"max_session_duration":null}]}]}`,
		`{"role_mappings":[{"subject":"org/repo","roles":[{"role":"arn:aws:iam::123456789012:role/s","subject":"x"}]}]}`,
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if _, err := parseFragment(data, "json", "fuzz"); err != nil {
			return
		}
		var top map[string]any
		if json.Unmarshal(data, &top) != nil {
			return
		}
		for k, v := range top {
			if obj, ok := v.(map[string]any); ok && len(obj) == 0 {
				continue // viper drops empty objects; nothing is contributed
			}
			if !fragmentAllowedKeys[strings.ToLower(k)] {
				t.Fatalf("fragment accepted base-only key %q", k)
			}
		}
	})
}
