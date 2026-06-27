package config_test

import (
	"testing"

	"github.com/boogy/aws-oidc-warden/pkg/config"
	"github.com/stretchr/testify/assert"
)

func TestTagAuth_Authorize(t *testing.T) {
	ta := &config.TagAuth{Enabled: true, TagPrefix: "aow/"}
	claims := map[string]any{
		"repository":         "acme/api",
		"repository_owner":   "acme",
		"ref":                "refs/heads/main",
		"ref_type":           "branch",
		"event_name":         "push",
		"actor":              "deploy-bot",
		"runner_environment": "github-hosted",
		"workflow_ref":       "acme/api/.github/workflows/deploy.yml@refs/heads/main",
	}
	cases := []struct {
		name string
		tags map[string]string
		want bool
	}{
		{"exact repo", map[string]string{"aow/repo": "acme/api"}, true},
		{"repo space-list", map[string]string{"aow/repo": "acme/web acme/api"}, true},
		{"owner match", map[string]string{"aow/repo-owner": "acme"}, true},
		{"no identity tag -> deny", map[string]string{"aow/branch": "refs/heads/main"}, false},
		{"wrong repo -> deny", map[string]string{"aow/repo": "acme/web"}, false},
		{"repo + branch short name", map[string]string{"aow/repo": "acme/api", "aow/branch": "main"}, true},
		{"repo + branch full ref", map[string]string{"aow/repo": "acme/api", "aow/branch": "refs/heads/main"}, true},
		{"repo + wrong branch -> deny", map[string]string{"aow/repo": "acme/api", "aow/branch": "dev"}, false},
		{"all dims pass", map[string]string{"aow/repo": "acme/api", "aow/ref-type": "branch", "aow/event-name": "push", "aow/actor": "deploy-bot"}, true},
		{"one dim fails -> deny", map[string]string{"aow/repo": "acme/api", "aow/event-name": "pull_request"}, false},
		{"repo AND exact ref", map[string]string{"aow/repo": "acme/api", "aow/ref": "refs/heads/main"}, true},
		{"repo AND wrong ref -> deny", map[string]string{"aow/repo": "acme/api", "aow/ref": "refs/heads/dev"}, false},
		{"workflow-ref match", map[string]string{"aow/repo": "acme/api", "aow/workflow-ref": "acme/api/.github/workflows/deploy.yml@refs/heads/main"}, true},
		{"workflow-ref mismatch -> deny", map[string]string{"aow/repo": "acme/api", "aow/workflow-ref": "acme/api/.github/workflows/other.yml@refs/heads/main"}, false},
		{"non-aow tags ignored", map[string]string{"aow/repo": "acme/api", "Team": "platform"}, true},
		{"empty tags -> deny", map[string]string{}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.want, ta.Authorize(c.tags, claims))
		})
	}
}

func TestTagAuth_Authorize_Disabled(t *testing.T) {
	ta := &config.TagAuth{Enabled: false, TagPrefix: "aow/"}
	assert.False(t, ta.Authorize(map[string]string{"aow/repo": "acme/api"}, map[string]any{"repository": "acme/api"}))
}
