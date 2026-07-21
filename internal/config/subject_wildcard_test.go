package config

import (
	"strings"
	"testing"
)

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
			Subject: subject,
			Roles:   []string{"arn:aws:iam::111111111111:role/Deploy"},
		}},
	}
}

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
