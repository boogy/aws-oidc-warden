package handler_test

import (
	"context"
	"log/slog"
	"testing"

	"github.com/boogy/aws-oidc-warden/internal/config"
	"github.com/boogy/aws-oidc-warden/internal/handler"
	"github.com/boogy/aws-oidc-warden/internal/types"
	"github.com/boogy/aws-oidc-warden/internal/validator"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// githubRawClaims is a representative verified GitHub Actions claim set,
// including claims deliberately left out of the curated audit list.
func githubRawClaims() map[string]any {
	return map[string]any{
		"repository":            "org/repo",
		"repository_owner":      "org",
		"repository_visibility": "private",
		"ref":                   "refs/heads/main",
		"ref_type":              "branch",
		"event_name":            "push",
		"actor":                 "octocat",
		"workflow_ref":          "org/repo/.github/workflows/deploy.yml@refs/heads/main",
		"job_workflow_ref":      "org/repo/.github/workflows/deploy.yml@refs/heads/main",
		"sha":                   "abc123",
		"run_id":                "1234567890",
		"run_attempt":           "1",
		"runner_environment":    "github-hosted",
		// Excluded from the curated set — asserted absent below.
		"actor_id":      "583231",
		"repository_id": "42",
		"run_number":    "7",
		"workflow_sha":  "def456",
		"base_ref":      "",
		"head_ref":      "",
	}
}

func githubClaims(subject string) *types.Claims {
	return &types.Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:   testIssuer,
			Subject:  subject,
			Audience: jwt.ClaimStrings{"sts.amazonaws.com"},
		},
		Sub:        "raw-sub-value",
		Repository: "org/repo",
		Ref:        "refs/heads/main",
		Actor:      "octocat",
		Raw:        githubRawClaims(),
	}
}

func recClaims(t *testing.T, rec map[string]any) map[string]any {
	t.Helper()
	if rec["claims"] == nil {
		return nil
	}
	claims, ok := rec["claims"].(map[string]any)
	require.True(t, ok, "claims must be a JSON object, got %T", rec["claims"])
	return claims
}

// TestAuditClaims_GitHubCuratedSet pins which GitHub claims reach the audit
// record: the curated "who did this" set, and not the low-signal IDs.
func TestAuditClaims_GitHubCuratedSet(t *testing.T) {
	cfg := auditTestCfg(t, false, true)
	sink := &fakeAuditSink{}
	proc := handler.NewRequestProcessor(config.NewStaticProvider(cfg), mockConsumer(t), &fixedExtractor{claims: githubClaims("org/repo")}, sink, "test-frontend")

	_, err := proc.ProcessRequest(context.Background(),
		&handler.RequestData{Role: "arn:aws:iam::123456789012:role/MyRole"},
		validator.ExtractionInput{Token: "t"},
		"req-claims", slog.Default())
	require.NoError(t, err)

	claims := recClaims(t, sink.last(t))
	require.NotNil(t, claims, "audit record must carry claims when log_claim_values=true")

	// The claims the operator actually asked the audit trail to answer.
	assert.Equal(t, "org/repo", claims["repository"])
	assert.Equal(t, "org", claims["repository_owner"])
	assert.Equal(t, "refs/heads/main", claims["ref"])
	assert.Equal(t, "push", claims["event_name"])
	assert.Equal(t, "octocat", claims["actor"])
	assert.Equal(t, "github-hosted", claims["runner_environment"])
	assert.Equal(t, "1234567890", claims["run_id"])

	// Deliberately excluded to keep per-request S3 records small.
	for _, excluded := range []string{"actor_id", "repository_id", "run_number", "workflow_sha", "base_ref", "head_ref"} {
		assert.NotContains(t, claims, excluded, "%q should not be in the curated audit claim set", excluded)
	}
}

// TestAuditClaims_SuppressedWhenLogClaimValuesOff guards the gate: claims are
// claim VALUES, so log_claim_values=false must keep them out of both the
// durable record and the log stream.
func TestAuditClaims_SuppressedWhenLogClaimValuesOff(t *testing.T) {
	cfg := auditTestCfg(t, false, false)
	sink := &fakeAuditSink{}
	proc := handler.NewRequestProcessor(config.NewStaticProvider(cfg), mockConsumer(t), &fixedExtractor{claims: githubClaims("org/repo")}, sink, "test-frontend")

	_, err := proc.ProcessRequest(context.Background(),
		&handler.RequestData{Role: "arn:aws:iam::123456789012:role/MyRole"},
		validator.ExtractionInput{Token: "t"},
		"req-claims-off", slog.Default())
	require.NoError(t, err)

	assert.Nil(t, recClaims(t, sink.last(t)), "claims must be absent when log_claim_values=false")
}

// TestAuditClaims_OnDenyRecord pins that a denied attempt still records who
// made it — the case where the identity matters most.
func TestAuditClaims_OnDenyRecord(t *testing.T) {
	cfg := auditTestCfg(t, false, true)
	sink := &fakeAuditSink{}
	// Subject matches no mapping → deny at the authorize stage, after claims
	// were extracted.
	proc := handler.NewRequestProcessor(config.NewStaticProvider(cfg), mockConsumer(t), &fixedExtractor{claims: githubClaims("org/other-repo")}, sink, "test-frontend")

	_, err := proc.ProcessRequest(context.Background(),
		&handler.RequestData{Role: "arn:aws:iam::123456789012:role/MyRole"},
		validator.ExtractionInput{Token: "t"},
		"req-claims-deny", slog.Default())
	require.Error(t, err)

	rec := sink.last(t)
	require.Equal(t, "deny", rec["decision"])
	claims := recClaims(t, rec)
	require.NotNil(t, claims, "deny records must carry the identifying claims too")
	assert.Equal(t, "org/repo", claims["repository"])
	assert.Equal(t, "octocat", claims["actor"])
}

// TestAuditClaims_GenericIssuerUsesClaimMappings pins the non-GitHub path: a
// generic issuer has no fixed claim vocabulary, so the audit record reports
// the claims its own claim_mappings reference — and nothing else.
func TestAuditClaims_GenericIssuerUsesClaimMappings(t *testing.T) {
	const gitlabIssuer = "https://gitlab.example.com"
	cfg := &config.Config{
		Issuers: []config.IssuerConfig{{
			Issuer:    gitlabIssuer,
			Provider:  "generic",
			Audiences: []string{"sts.amazonaws.com"},
			ClaimMappings: map[string]string{
				"subject":    "project_path",
				"ref":        "ref",
				"pipeline":   "pipeline_id",
				"user_login": "user_login",
			},
		}},
		RoleSessionName: "test",
		Cache:           &config.Cache{TTL: 0},
		RoleMappings: []config.RoleMapping{{
			Subject: "group/project",
			Issuer:  gitlabIssuer,
			Roles:   []string{"arn:aws:iam::123456789012:role/MyRole"},
		}},
		LogClaimValues: true,
	}
	require.NoError(t, cfg.Validate())

	claims := &types.Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:   gitlabIssuer,
			Subject:  "group/project",
			Audience: jwt.ClaimStrings{"sts.amazonaws.com"},
		},
		Sub: "project_path:group/project:ref:main",
		Raw: map[string]any{
			"project_path": "group/project",
			"ref":          "main",
			"pipeline_id":  4242, // non-string: formatted like a session tag value
			"user_login":   "alice",
			"namespace_id": "99", // not mapped → must not be reported
		},
	}

	sink := &fakeAuditSink{}
	proc := handler.NewRequestProcessor(config.NewStaticProvider(cfg), mockConsumer(t), &fixedExtractor{claims: claims}, sink, "test-frontend")

	_, err := proc.ProcessRequest(context.Background(),
		&handler.RequestData{Role: "arn:aws:iam::123456789012:role/MyRole"},
		validator.ExtractionInput{Token: "t"},
		"req-claims-generic", slog.Default())
	require.NoError(t, err)

	got := recClaims(t, sink.last(t))
	require.NotNil(t, got)
	assert.Equal(t, map[string]any{
		"project_path": "group/project",
		"ref":          "main",
		"pipeline_id":  "4242",
		"user_login":   "alice",
	}, got, "only the issuer's mapped claims, formatted as strings")

	// GitHub's curated names must not leak into a generic issuer's record.
	assert.NotContains(t, got, "repository")
}
