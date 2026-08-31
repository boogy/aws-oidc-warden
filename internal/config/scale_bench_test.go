package config

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

const bIss = "https://token.actions.githubusercontent.com"

// buildCfg builds a config of nLiteral literal "acme/repoN" mappings plus
// nWild "acme/team-N-.*" wildcard mappings, all under ONE owner — the shape a
// single-org enterprise actually produces. Conditions mirror example-config.yaml.
func buildCfg(b *testing.B, nLiteral, nWild int) *Config {
	var sb strings.Builder
	sb.WriteString(`
role_session_name: "aow"
issuers:
  - issuer: "` + bIss + `"
    provider: "github"
    audiences: ["sts.amazonaws.com"]
    claim_mappings: {subject: "sub"}
default_issuer: "` + bIss + `"
role_mappings:
`)
	cond := `    session_policy: "{}"
    conditions:
      ref: "refs/heads/main"
      event_name: ["push", "workflow_dispatch"]
      runner_environment: "github-hosted"
      any_of:
        - actor: "release-bot"
        - repository: "acme/.*"
`
	for i := 0; i < nLiteral; i++ {
		fmt.Fprintf(&sb, "  - subject: \"acme/repo%d\"\n    roles: [\"arn:aws:iam::123456789012:role/r%d\"]\n%s", i, i, cond)
	}
	for i := 0; i < nWild; i++ {
		fmt.Fprintf(&sb, "  - subject: \"acme/team%d-.*\"\n    roles: [\"arn:aws:iam::123456789012:role/w%d\"]\n%s", i, i, cond)
	}
	cfg := &Config{}
	require.NoError(b, cfg.MergeBytes([]byte(sb.String()), "yaml"))
	return cfg
}

func claimsFor(subject string) map[string]any {
	return map[string]any{
		"sub": subject, "repository": subject,
		"ref": "refs/heads/main", "event_name": "push",
		"runner_environment": "github-hosted", "actor": "someone",
	}
}

// Full per-request decision, exactly what processor.go calls.
func decide(b *testing.B, cfg *Config, subject, role string, claims map[string]any) {
	d := cfg.Authorize(bIss, subject, role, claims)
	if !d.Matched {
		b.Fatal("no match")
	}
	d.SessionPolicy()
	d.RoleSessionName()
}

// All-literal: the dominant real shape. Should be O(1) via the exact bucket.
func BenchmarkDecideLiteral(b *testing.B) {
	for _, n := range []int{100, 1000, 5000, 10000} {
		b.Run(fmt.Sprintf("repos=%d", n), func(b *testing.B) {
			cfg := buildCfg(b, n, 0)
			subject := fmt.Sprintf("acme/repo%d", n/2)
			role := fmt.Sprintf("arn:aws:iam::123456789012:role/r%d", n/2)
			claims := claimsFor(subject)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				decide(b, cfg, subject, role, claims)
			}
		})
	}
}

// Realistic mix: mostly literal, some wildcard teams, all one owner.
func BenchmarkDecideMixed(b *testing.B) {
	for _, w := range []int{10, 100, 500} {
		b.Run(fmt.Sprintf("literal=2000,wild=%d", w), func(b *testing.B) {
			cfg := buildCfg(b, 2000, w)
			subject := "acme/repo1000"
			role := "arn:aws:iam::123456789012:role/r1000"
			claims := claimsFor(subject)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				decide(b, cfg, subject, role, claims)
			}
		})
	}
}

// Cold start / remote-refresh cost: parse + Validate a large config.
func BenchmarkValidateLarge(b *testing.B) {
	for _, n := range []int{1000, 5000, 10000} {
		b.Run(fmt.Sprintf("repos=%d", n), func(b *testing.B) {
			cfg := buildCfg(b, n, 0)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if err := cfg.Validate(); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// Parallel decide: many concurrent requests against ONE config snapshot.
// Guards the shared-*regexp.Regexp memo against matcher-pool contention.
func BenchmarkDecideParallel(b *testing.B) {
	cfg := buildCfg(b, 2000, 100)
	subject := "acme/repo1000"
	role := "arn:aws:iam::123456789012:role/r1000"
	claims := claimsFor(subject)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			d := cfg.Authorize(bIss, subject, role, claims)
			if !d.Matched {
				b.Fatal("no match")
			}
			d.SessionPolicy()
			d.RoleSessionName()
		}
	})
}
