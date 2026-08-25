package config_test

import (
	"os"
	"testing"

	"github.com/boogy/aws-oidc-warden/internal/config"
	"github.com/stretchr/testify/require"
)

// exampleConfigPath is the file shipped at the repo root and pointed at by the
// README, `make run`, and every deployment guide.
const exampleConfigPath = "../../example-config.yaml"

// TestExampleConfigLoadsAndValidates guards the one config an operator is most
// likely to copy. Nothing else in the suite reads it, so a key renamed in the
// engine could leave the shipped example rejecting at boot — or, worse,
// loading with a different meaning — and every test would still pass.
func TestExampleConfigLoadsAndValidates(t *testing.T) {
	data, err := os.ReadFile(exampleConfigPath)
	require.NoError(t, err)

	cfg := &config.Config{}
	require.NoError(t, cfg.MergeBytes(data, "yaml"), "example-config.yaml must load and validate")

	require.NotEmpty(t, cfg.Issuers)
	require.NotEmpty(t, cfg.RoleMappings)

	// Spot-check the mappings whose conditions carry the v3 semantics, through
	// the real authorization path. Each pair is the same subject with and
	// without the claim the example gates on, so a mapping that silently
	// stopped gating (or started denying) shows up here.
	const gh = "https://token.actions.githubusercontent.com"
	cases := []struct {
		name    string
		subject string
		claims  map[string]any
		want    bool
	}{
		{
			name:    "deployment environment gates prod",
			subject: "org/prod-repo",
			claims: map[string]any{
				"ref": "refs/tags/v1.2.3", "ref_type": "tag",
				"environment": "production", "runner_environment": "github-hosted",
				"actor": "release-bot", "sha": "0123456789abcdef0123456789abcdef01234567",
			},
			want: true,
		},
		{
			name:    "runner type is not the deployment environment",
			subject: "org/prod-repo",
			claims: map[string]any{
				"ref": "refs/tags/v1.2.3", "ref_type": "tag",
				"environment": "github-hosted", "runner_environment": "github-hosted",
				"actor": "release-bot", "sha": "0123456789abcdef0123456789abcdef01234567",
			},
			want: false,
		},
		{
			name:    "pull-request gate needs every claim",
			subject: "org/pr-checks",
			claims: map[string]any{
				"event_name": "pull_request", "base_ref": "main",
				"repository_visibility": "public", "ref_protected": "true",
			},
			want: true,
		},
		{
			name:    "pull-request gate denies an unprotected ref",
			subject: "org/pr-checks",
			claims: map[string]any{
				"event_name": "pull_request", "base_ref": "main",
				"repository_visibility": "public", "ref_protected": "false",
			},
			want: false,
		},
		{
			name:    "none_of members veto independently",
			subject: "org/guarded-repo",
			claims:  map[string]any{"ref": "refs/heads/main"},
			want:    true,
		},
		{
			name:    "a self-hosted runner alone is vetoed",
			subject: "org/guarded-repo",
			claims:  map[string]any{"ref": "refs/heads/main", "runner_environment": "self-hosted"},
			want:    false,
		},
		{
			name:    "a dispatched run alone is vetoed",
			subject: "org/guarded-repo",
			claims:  map[string]any{"ref": "refs/heads/main", "event_name": "workflow_dispatch"},
			want:    false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ok, roles := cfg.AuthorizeRoles(gh, tc.subject, tc.claims)
			require.Equal(t, tc.want, ok)
			if tc.want {
				require.NotEmpty(t, roles)
			}
		})
	}
}

// TestExampleConfigGenericIssuer exercises the GitLab (`provider: generic`)
// half of the shipped example through the same authorization path.
//
// TestExampleConfigLoadsAndValidates only drives the GitHub issuer, so every
// generic-issuer line in the example — the claim-native condition keys that
// name GitLab's own claims, the list-valued `groups` claim, and the issuer
// binding that keeps the two issuers' subject namespaces apart — was shipped
// unexercised. That is the half of the config a non-GitHub operator copies.
func TestExampleConfigGenericIssuer(t *testing.T) {
	data, err := os.ReadFile(exampleConfigPath)
	require.NoError(t, err)

	cfg := &config.Config{}
	require.NoError(t, cfg.MergeBytes(data, "yaml"))

	const (
		gitlab = "https://gitlab.com"
		gh     = "https://token.actions.githubusercontent.com"
		subj   = "mygroup/myproject"
	)

	// The canonical subject for this issuer comes from claim_mappings.subject,
	// so the example must map it — a generic issuer without it is a Validate()
	// error, and the mapping below could never be reached.
	var gitlabSpec *config.IssuerConfig
	for i := range cfg.Issuers {
		if cfg.Issuers[i].Issuer == gitlab {
			gitlabSpec = &cfg.Issuers[i]
		}
	}
	require.NotNil(t, gitlabSpec, "the example must keep a generic issuer")
	require.Equal(t, "generic", gitlabSpec.Provider)
	require.NotEmpty(t, gitlabSpec.ClaimMappings["subject"])

	base := func() map[string]any {
		return map[string]any{
			"ref":          "main",
			"project_path": subj,
			"groups":       []any{"platform-team", "docs"},
		}
	}

	cases := []struct {
		name    string
		issuer  string
		subject string
		mutate  func(map[string]any)
		want    bool
	}{
		{name: "every claim-native condition satisfied", issuer: gitlab, subject: subj, want: true},
		{
			name: "list claim matches on any element", issuer: gitlab, subject: subj,
			mutate: func(c map[string]any) { c["groups"] = []any{"unrelated", "sre"} },
			want:   true,
		},
		{
			name: "no group matches", issuer: gitlab, subject: subj,
			mutate: func(c map[string]any) { c["groups"] = []any{"contractors"} },
			want:   false,
		},
		{
			name: "the groups claim is absent", issuer: gitlab, subject: subj,
			mutate: func(c map[string]any) { delete(c, "groups") },
			want:   false,
		},
		{
			name: "a GitLab-named claim still gates", issuer: gitlab, subject: subj,
			mutate: func(c map[string]any) { c["project_path"] = "other/project" },
			want:   false,
		},
		{
			name: "the ref condition still gates", issuer: gitlab, subject: subj,
			mutate: func(c map[string]any) { c["ref"] = "feature/x" },
			want:   false,
		},
		// Issuer binding: the same subject string presented by the other
		// configured issuer must not reach this mapping.
		{name: "same subject, wrong issuer", issuer: gh, subject: subj, want: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			claims := base()
			if tc.mutate != nil {
				tc.mutate(claims)
			}
			ok, roles := cfg.AuthorizeRoles(tc.issuer, tc.subject, claims)
			require.Equal(t, tc.want, ok)
			if tc.want {
				require.NotEmpty(t, roles)
			}
		})
	}
}
