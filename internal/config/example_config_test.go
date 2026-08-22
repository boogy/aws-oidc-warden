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
