package config

// The issuer-agnostic `<prefix>claim.<name>` tag-auth dimension.
//
// Every other suffix Authorize understands (repo, ref, actor, workflow-ref, …)
// names a GitHub Actions claim, so before this dimension existed a non-GitHub
// issuer could constrain a tag-authorized role on `subject` and nothing else.
// These tests pin that a claim.* tag reaches an arbitrary verified claim, that
// it can only narrow access, and that every non-matching shape denies.

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTagAuth_GenericClaimDimension(t *testing.T) {
	ta := &TagAuth{Enabled: true, TagPrefix: "aow/"}
	const iss = "https://gitlab.example.com"
	const sub = "project_path:acme/api:ref_type:branch:ref:main"

	claims := map[string]any{
		"project_path":   "acme/api",
		"namespace_path": "acme",
		"ref":            "main",
		"isContractor":   "true",
		"groups":         []any{"platform", "sre"},
		"groups_typed":   []string{"platform", "sre"},
		"seats":          42, // non-string scalar
	}

	cases := []struct {
		name string
		tags map[string]string
		want bool
	}{
		{
			name: "claim tag matches a mapped-subject issuer's own claim",
			tags: map[string]string{"aow/subject": sub, "aow/claim.project_path": "acme/api"},
			want: true,
		},
		{
			name: "claim tag that does not match denies even though subject matches",
			tags: map[string]string{"aow/subject": sub, "aow/claim.project_path": "acme/other"},
			want: false,
		},
		{
			name: "space-separated claim tag value means OR",
			tags: map[string]string{"aow/subject": sub, "aow/claim.namespace_path": "widgets acme"},
			want: true,
		},
		{
			name: "every claim tag must match (AND)",
			tags: map[string]string{
				"aow/subject":              sub,
				"aow/claim.project_path":   "acme/api",
				"aow/claim.namespace_path": "widgets",
			},
			want: false,
		},
		{
			name: "claim name is matched case-sensitively, as written on the tag",
			tags: map[string]string{"aow/subject": sub, "aow/claim.isContractor": "true"},
			want: true,
		},
		{
			name: "a differently-cased claim name names no claim and denies",
			tags: map[string]string{"aow/subject": sub, "aow/claim.iscontractor": "true"},
			want: false,
		},
		{
			name: "list claim matches when any element does",
			tags: map[string]string{"aow/subject": sub, "aow/claim.groups": "sre"},
			want: true,
		},
		{
			name: "[]string list claim matches when any element does",
			tags: map[string]string{"aow/subject": sub, "aow/claim.groups_typed": "platform"},
			want: true,
		},
		{
			name: "list claim with no matching element denies",
			tags: map[string]string{"aow/subject": sub, "aow/claim.groups": "admins"},
			want: false,
		},
		{
			name: "non-string scalar claim never matches",
			tags: map[string]string{"aow/subject": sub, "aow/claim.seats": "42"},
			want: false,
		},
		{
			name: "absent claim denies",
			tags: map[string]string{"aow/subject": sub, "aow/claim.nope": "anything"},
			want: false,
		},
		{
			name: "bare claim. tag names no claim and denies",
			tags: map[string]string{"aow/subject": sub, "aow/claim.": "acme/api"},
			want: false,
		},
		{
			name: "claim tag alone is not an identity tag: it cannot grant access",
			tags: map[string]string{"aow/claim.project_path": "acme/api"},
			want: false,
		},
		{
			name: "a claim tag under a different prefix is not read",
			tags: map[string]string{"aow/subject": sub, "other/claim.project_path": "acme/other"},
			want: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, ta.Authorize(tc.tags, claims, iss, sub))
		})
	}
}

// The dimension must not weaken the gates that run before it: a claim.* tag
// that matches cannot rescue a role whose issuer or identity tag is wrong.
func TestTagAuth_GenericClaimDimensionCannotBypassEarlierGates(t *testing.T) {
	claims := map[string]any{"project_path": "acme/api"}
	const sub = "project_path:acme/api"

	t.Run("wrong issuer still denies", func(t *testing.T) {
		ta := &TagAuth{Enabled: true, TagPrefix: "aow/", multiIssuer: true}
		tags := map[string]string{
			"aow/issuer":             "https://other.example.com",
			"aow/subject":            sub,
			"aow/claim.project_path": "acme/api",
		}
		assert.False(t, ta.Authorize(tags, claims, "https://gitlab.example.com", sub))
	})

	t.Run("wrong subject still denies", func(t *testing.T) {
		ta := &TagAuth{Enabled: true, TagPrefix: "aow/"}
		tags := map[string]string{
			"aow/subject":            "project_path:acme/other",
			"aow/claim.project_path": "acme/api",
		}
		assert.False(t, ta.Authorize(tags, claims, "https://gitlab.example.com", sub))
	})

	t.Run("missing identity tag still denies", func(t *testing.T) {
		ta := &TagAuth{Enabled: true, TagPrefix: "aow/", multiIssuer: true}
		tags := map[string]string{
			"aow/issuer":             "https://gitlab.example.com",
			"aow/claim.project_path": "acme/api",
		}
		assert.False(t, ta.Authorize(tags, claims, "https://gitlab.example.com", sub))
	})
}
