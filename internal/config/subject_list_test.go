package config

// A role_mappings entry may declare several subjects sharing one set of roles,
// conditions and policies. Validate() fans the list out into one effective
// mapping per element, so these tests pin two things: the fan-out is equivalent
// to writing the entries separately, and every per-element guard still fires.

import (
	"strings"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const slRole = "arn:aws:iam::111111111111:role/app"

// loadYAML decodes a whole config document the way LoadConfig does, so the
// mapstructure hooks (scalar-or-list, DecodeNil) are exercised rather than
// bypassed by a Go struct literal.
func loadYAML(t *testing.T, doc string) *Config {
	t.Helper()
	v := viper.New()
	v.SetConfigType("yaml")
	require.NoError(t, v.ReadConfig(strings.NewReader(doc)))

	var c Config
	require.NoError(t, v.Unmarshal(&c, decoderOptions()...))
	return &c
}

func slYAML(subjectBlock string) string {
	return `
issuers:
  - issuer: "` + vIss + `"
    provider: "generic"
    audiences: ["aud"]
    claim_mappings:
      subject: "sub"
default_issuer: "` + vIss + `"
role_session_name: "test"
role_mappings:
  - subject: ` + subjectBlock + `
    roles: ["` + slRole + `"]
`
}

// ---------- decode ----------

func TestSubjectDecodesScalarOrList(t *testing.T) {
	scalar := loadYAML(t, slYAML(`"acme/app"`))
	require.Equal(t, Patterns{"acme/app"}, scalar.RoleMappings[0].Subject)

	list := loadYAML(t, slYAML("\n      - \"acme/app\"\n      - \"acme/api\""))
	require.Equal(t, Patterns{"acme/app", "acme/api"}, list.RoleMappings[0].Subject)

	flow := loadYAML(t, slYAML(`["acme/app", "acme/api"]`))
	require.Equal(t, Patterns{"acme/app", "acme/api"}, flow.RoleMappings[0].Subject)
}

// A subject is a regex, so a bounded repetition must survive decoding whole.
// Patterns is a defined type, so StringToSliceHookFunc (which requires exactly
// reflect.SliceOf(string)) declines it — assert that rather than trust it.
func TestSubjectListKeepsCommasInRegexes(t *testing.T) {
	cfg := loadYAML(t, slYAML("\n      - 'acme/app-v[0-9]{1,3}'\n      - 'acme/api-a{2,4}b'"))
	require.Equal(t, Patterns{`acme/app-v[0-9]{1,3}`, `acme/api-a{2,4}b`}, cfg.RoleMappings[0].Subject)

	require.NoError(t, cfg.Validate())
	ok, _ := cfg.AuthorizeRoles(vIss, "acme/app-v12", nil)
	assert.True(t, ok, "a comma-bearing subject regex must match after decode")
}

// ---------- fan-out semantics ----------

func TestSubjectListExpandsToOneMappingPerSubject(t *testing.T) {
	cfg := vcfg(t, []RoleMapping{{
		Subject:    Patterns{"acme/app", "acme/api"},
		Roles:      []string{slRole},
		Conditions: &Condition{Ref: Patterns{"refs/heads/main"}},
	}})

	require.Len(t, cfg.effective, 2, "one effective mapping per declared subject")

	claims := map[string]any{"ref": "refs/heads/main"}
	for _, subject := range []string{"acme/app", "acme/api"} {
		ok, roles := cfg.AuthorizeRoles(vIss, subject, claims)
		assert.True(t, ok, "%s must be authorized", subject)
		assert.Equal(t, []string{slRole}, roles, "%s gets the entry's roles", subject)
	}

	ok, _ := cfg.AuthorizeRoles(vIss, "acme/other", claims)
	assert.False(t, ok, "a subject not in the list must not be authorized")

	// The shared conditions gate every element, not just the first.
	for _, subject := range []string{"acme/app", "acme/api"} {
		ok, _ := cfg.AuthorizeRoles(vIss, subject, map[string]any{"ref": "refs/heads/dev"})
		assert.False(t, ok, "%s must still be gated by the shared conditions", subject)
	}
}

// The two spellings must decode to the same authorization behavior, so a
// config rewritten from a scalar to a one-element list is a no-op.
func TestSubjectScalarAndListAreEquivalent(t *testing.T) {
	scalar := loadYAML(t, slYAML(`"acme/app"`))
	require.NoError(t, scalar.Validate())
	list := loadYAML(t, slYAML("\n      - \"acme/app\""))
	require.NoError(t, list.Validate())

	require.Equal(t, scalar.RoleMappings[0].Subject, list.RoleMappings[0].Subject)

	for _, subject := range []string{"acme/app", "acme/other"} {
		sOK, sRoles := scalar.AuthorizeRoles(vIss, subject, nil)
		lOK, lRoles := list.AuthorizeRoles(vIss, subject, nil)
		assert.Equal(t, sOK, lOK, "subject %q", subject)
		assert.Equal(t, sRoles, lRoles, "subject %q", subject)
	}
}

// Splitting one entry into N mappings must not disturb first-declared-wins:
// orders are contiguous and a later entry can never outrank an earlier one.
func TestSubjectListPreservesDeclarationOrder(t *testing.T) {
	cfg := vcfg(t, []RoleMapping{
		{Subject: Patterns{"acme/a", "acme/b", "acme/c"}, Roles: []string{slRole}, SessionPolicy: "first"},
		{Subject: Patterns{"acme/b"}, Roles: []string{slRole}, SessionPolicy: "second"},
	})

	require.Len(t, cfg.effective, 4)
	for i, m := range cfg.effective {
		assert.Equal(t, i, m.order, "orders must be contiguous in declaration order")
	}

	pol, _ := cfg.FindSessionPolicy(vIss, "acme/b", slRole, nil)
	require.NotNil(t, pol)
	assert.Equal(t, "first", *pol, "the earlier entry's element must outrank the later entry")
}

// Each element is bucketed independently (exact vs byOwner vs any), so the
// index must stay observationally identical to a full linear scan.
func TestSubjectListIsIndexedPerElement(t *testing.T) {
	cfg := vcfg(t, []RoleMapping{{
		Subject: Patterns{"acme/api", "acme/svc-.*", "a/b|c/d"},
		Roles:   []string{slRole},
	}})

	for _, subject := range []string{"acme/api", "acme/svc-1", "a/b", "c/d", "acme/nope", "other/x"} {
		gotOK, gotRoles := cfg.AuthorizeRoles(vIss, subject, nil)
		wantOK, wantRoles := linearAuthorizeRoles(cfg, vIss, subject, nil)
		assert.Equal(t, wantOK, gotOK, "index/linear disagree on %q", subject)
		assert.ElementsMatchf(t, wantRoles, gotRoles, "index/linear roles mismatch for %q", subject)
	}
}

// Validate() takes the mapping by value, so m.Subject aliases the declared
// config's backing array — a fragment shares that array across snapshots.
// Repeated validation must neither mutate nor re-expand it.
func TestSubjectListDoesNotMutateDeclaredConfig(t *testing.T) {
	declared := Patterns{"acme/b", "acme/a"}
	cfg := vcfg(t, []RoleMapping{{Subject: declared, Roles: []string{slRole}}})

	before := len(cfg.effective)
	require.NoError(t, cfg.Validate())

	assert.Equal(t, before, len(cfg.effective), "re-validation must be idempotent")
	assert.Equal(t, Patterns{"acme/b", "acme/a"}, cfg.RoleMappings[0].Subject,
		"declared order must survive validation unsorted and undeduped")
	assert.Equal(t, Patterns{"acme/b", "acme/a"}, declared, "the caller's slice must be untouched")
}

// ---------- per-element guards ----------

func TestSubjectListRejectsEmptyAndWildcardElements(t *testing.T) {
	// Guards must fire in a NON-first position: a loop that only validates
	// element 0 passes every case below with the bad element second.
	for _, tc := range []struct {
		name    string
		subject Patterns
	}{
		{"absent", nil},
		{"empty list", Patterns{}},
		{"only an empty string", Patterns{""}},
		{"empty string second", Patterns{"acme/app", ""}},
		{"bare .* second", Patterns{"acme/app", ".*"}},
		{"bare .+ second", Patterns{"acme/app", ".+"}},
		{"invalid regex second", Patterns{"acme/app", "acme/["}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &Config{
				Issuers:         singleIssuer(vIss, "aud"),
				DefaultIssuer:   vIss,
				RoleSessionName: "test",
				RoleMappings:    []RoleMapping{{Subject: tc.subject, Roles: []string{slRole}}},
			}
			require.Error(t, cfg.Validate())
		})
	}
}

func TestSubjectListRejectsDuplicateElements(t *testing.T) {
	dup := &Config{
		Issuers:         singleIssuer(vIss, "aud"),
		DefaultIssuer:   vIss,
		RoleSessionName: "test",
		RoleMappings:    []RoleMapping{{Subject: Patterns{"acme/app", "acme/app"}, Roles: []string{slRole}}},
	}
	err := dup.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "duplicate subject")

	// Boundary: the same subject in two DIFFERENT entries is legal — that is
	// how distinct roles, conditions or policies are layered onto one subject.
	cross := &Config{
		Issuers:         singleIssuer(vIss, "aud"),
		DefaultIssuer:   vIss,
		RoleSessionName: "test",
		RoleMappings: []RoleMapping{
			{Subject: Patterns{"acme/app"}, Roles: []string{slRole}},
			{Subject: Patterns{"acme/app"}, Roles: []string{"arn:aws:iam::111111111111:role/other"}},
		},
	}
	require.NoError(t, cross.Validate())
}

// ---------- session policy / session name apply to the whole list ----------

func TestSubjectListSharesInlineSessionPolicy(t *testing.T) {
	const policy = `{"Version":"2012-10-17","Statement":[]}`
	cfg := vcfg(t, []RoleMapping{{
		Subject:       Patterns{"acme/app", "acme/api"},
		Roles:         []string{slRole},
		SessionPolicy: policy,
	}})

	for _, subject := range []string{"acme/app", "acme/api"} {
		pol, file := cfg.FindSessionPolicy(vIss, subject, slRole, nil)
		require.NotNil(t, pol, "inline policy must apply to %s", subject)
		assert.Equal(t, policy, *pol)
		assert.Nil(t, file)
	}
}

// The S3 key is a literal, so every subject in the entry resolves to the same
// object: one entry cannot carry a per-subject policy file.
func TestSubjectListSharesSessionPolicyFile(t *testing.T) {
	cfg := vcfg(t, []RoleMapping{{
		Subject:           Patterns{"acme/app", "acme/api"},
		Roles:             []string{slRole},
		SessionPolicyFile: "policies/shared.json",
	}})

	for _, subject := range []string{"acme/app", "acme/api"} {
		pol, file := cfg.FindSessionPolicy(vIss, subject, slRole, nil)
		require.NotNil(t, file, "policy file must apply to %s", subject)
		assert.Equal(t, "policies/shared.json", *file)
		assert.Nil(t, pol)
	}
}

func TestSubjectListSharesRoleSessionName(t *testing.T) {
	cfg := vcfg(t, []RoleMapping{{
		Subject:         Patterns{"acme/app", "acme/api"},
		Roles:           []string{slRole},
		RoleSessionName: "acme-team",
	}})

	for _, subject := range []string{"acme/app", "acme/api"} {
		assert.Equal(t, "acme-team", cfg.FindRoleSessionName(vIss, subject, slRole, nil), "subject %q", subject)
	}
}

// Fanning out must not loosen FindSessionPolicy's role and condition scoping:
// the policy still comes only from a mapping that granted the requested role
// and whose conditions the claims satisfy.
func TestSubjectListPolicyIsRoleAndConditionScoped(t *testing.T) {
	const other = "arn:aws:iam::111111111111:role/other"
	cfg := vcfg(t, []RoleMapping{{
		Subject:       Patterns{"acme/app", "acme/api"},
		Roles:         []string{slRole},
		SessionPolicy: "scoped",
		Conditions:    &Condition{Ref: Patterns{"refs/heads/main"}},
	}})

	main := map[string]any{"ref": "refs/heads/main"}
	pol, _ := cfg.FindSessionPolicy(vIss, "acme/api", slRole, main)
	require.NotNil(t, pol)

	pol, file := cfg.FindSessionPolicy(vIss, "acme/api", other, main)
	assert.Nil(t, pol, "a role this entry never granted gets no policy")
	assert.Nil(t, file)

	pol, file = cfg.FindSessionPolicy(vIss, "acme/api", slRole, map[string]any{"ref": "refs/heads/dev"})
	assert.Nil(t, pol, "unsatisfied conditions must yield no policy")
	assert.Nil(t, file)
}

// The hot-reload snapshot clone round-trips through encoding/json, where the
// mapstructure hook does not run — Patterns.UnmarshalJSON carries the field.
func TestSubjectListSurvivesJSONClone(t *testing.T) {
	orig := vcfg(t, []RoleMapping{{
		Subject:       Patterns{"acme/app", "acme/api"},
		Roles:         []string{slRole},
		SessionPolicy: "cloned",
	}})

	clone, err := cloneConfig(orig)
	require.NoError(t, err)
	require.NoError(t, clone.Validate())

	require.Equal(t, Patterns{"acme/app", "acme/api"}, clone.RoleMappings[0].Subject)
	require.Len(t, clone.effective, 2)
	for _, subject := range []string{"acme/app", "acme/api"} {
		ok, roles := clone.AuthorizeRoles(vIss, subject, nil)
		assert.True(t, ok, "%s must still authorize after a clone", subject)
		assert.Equal(t, []string{slRole}, roles)
		pol, _ := clone.FindSessionPolicy(vIss, subject, slRole, nil)
		require.NotNil(t, pol, "policy must survive the clone for %s", subject)
		assert.Equal(t, "cloned", *pol)
	}
}
