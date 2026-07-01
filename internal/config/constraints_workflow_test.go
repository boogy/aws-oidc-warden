package config

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestWorkflowRefConstraint_Anchored verifies the workflow_ref constraint regex
// is auto-anchored like every other regex constraint, so a pattern matches the
// full claim and not a substring.
func TestWorkflowRefConstraint_Anchored(t *testing.T) {
	const claim = "org/repo/.github/workflows/predeploy.yml@refs/heads/main"

	cases := []struct {
		name        string
		workflowRef string
		want        bool
	}{
		{"substring no longer matches", "deploy", false},
		{"bare filename does not match full ref", "deploy.yml", false},
		{"exact full claim matches", `org/repo/\.github/workflows/predeploy\.yml@refs/heads/main`, true},
		{"anchored alternation over full claim", `.*/predeploy\.yml@.*`, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &Config{
				Issuers:         singleIssuer("https://token.actions.githubusercontent.com", "sts.amazonaws.com"),
				RoleSessionName: "test",
				RepoRoleMappings: []RepoRoleMapping{{
					Repo:        "org/repo",
					Roles:       []string{"arn:aws:iam::111111111111:role/app"},
					Constraints: &Constraint{WorkflowRef: tc.workflowRef},
				}},
			}
			require.NoError(t, cfg.Validate())

			claims := map[string]any{"workflow_ref": claim}
			matched, roles := cfg.MatchRolesToRepoWithConstraints("org/repo", claims)
			if tc.want {
				require.True(t, matched, "expected workflow_ref %q to match", tc.workflowRef)
				require.Contains(t, roles, "arn:aws:iam::111111111111:role/app")
			} else {
				require.False(t, matched, "expected workflow_ref %q NOT to match (substring)", tc.workflowRef)
			}
		})
	}
}
