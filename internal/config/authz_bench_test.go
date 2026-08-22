package config

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// BenchmarkAuthorizeRoles measures one whole authorization decision — owner
// bucket lookup, subject regex, and a nested condition tree — against a config
// far larger than a realistic deployment. It exists to keep the condition
// engine's cost in perspective: the decision is dwarfed by the STS AssumeRole
// round trip that follows it, so micro-optimizing the gate (a literal fast path
// for non-regex patterns, say) buys nothing and adds a second matching path to
// the security-critical code. Measure here before proposing one.
func BenchmarkAuthorizeRoles(b *testing.B) {
	const issuer = "https://token.actions.githubusercontent.com"

	var sb strings.Builder
	sb.WriteString(`
role_session_name: "aow"
issuers:
  - issuer: "` + issuer + `"
    provider: "github"
    audiences: ["sts.amazonaws.com"]
    claim_mappings: {subject: "sub"}
default_issuer: "` + issuer + `"
role_mappings:
`)
	for i := 0; i < 500; i++ {
		fmt.Fprintf(&sb, `  - subject: "org%d/repo%d:.*"
    roles: ["arn:aws:iam::123456789012:role/r%d"]
    conditions:
      ref: "refs/heads/main"
      event_name: ["push", "workflow_dispatch"]
      runner_environment: "github-hosted"
      any_of:
        - actor: "release-bot"
        - repository: "org%d/.*"
`, i, i, i, i)
	}

	cfg := &Config{}
	require.NoError(b, cfg.MergeBytes([]byte(sb.String()), "yaml"))

	subject := "org250/repo250:ref:refs/heads/main"
	claims := map[string]any{
		"sub":                subject,
		"repository":         "org250/repo250",
		"ref":                "refs/heads/main",
		"event_name":         "push",
		"runner_environment": "github-hosted",
		"actor":              "someone",
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ok, roles := cfg.AuthorizeRoles(issuer, subject, claims)
		if !ok || len(roles) != 1 {
			b.Fatalf("expected exactly one role, got ok=%v roles=%v", ok, roles)
		}
	}
}
