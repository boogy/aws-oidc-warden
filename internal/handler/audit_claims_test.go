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
// including low-signal claims (actor_id, repository_id, run_number,
// workflow_sha) a curated list used to drop but a full dump now carries, plus
// empty base_ref/head_ref (PR-only claims, empty on a push event) to pin that
// empty claims are still skipped regardless of dump semantics.
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
		// Dropped by the old curated list, carried by the full dump.
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

// TestAuditClaims_GitHubDumpsEverythingWithAliases pins the full-dump
// semantics: every verified GitHub claim reaches the record, with the
// requested renames applied (repository -> repo, repository_id -> repo_id).
func TestAuditClaims_GitHubDumpsEverythingWithAliases(t *testing.T) {
	cfg := auditTestCfg(t, false, true)
	sink := &fakeAuditSink{}
	proc := handler.NewRequestProcessor(config.NewStaticProvider(cfg), mockConsumer(t),
		&fixedExtractor{claims: githubClaims("org/repo")}, sink, "test-frontend")

	_, err := proc.ProcessRequest(context.Background(),
		&handler.RequestData{Role: "arn:aws:iam::123456789012:role/MyRole"},
		validator.ExtractionInput{Token: "t"}, "req-claims", slog.Default())
	require.NoError(t, err)

	claims := recClaims(t, sink.last(t))
	require.NotNil(t, claims)

	// Renamed per the logging requirement.
	assert.Equal(t, "org/repo", claims["repo"])
	assert.Equal(t, "42", claims["repo_id"])
	assert.NotContains(t, claims, "repository", "repository must be emitted as repo")
	assert.NotContains(t, claims, "repository_id", "repository_id must be emitted as repo_id")

	// Explicitly required by the logging spec.
	for _, k := range []string{"actor", "ref", "workflow_ref", "job_workflow_ref", "sha"} {
		assert.NotEmpty(t, claims[k], "required claim %q must be logged", k)
	}

	// Previously dropped by the curated list — now present.
	assert.Equal(t, "583231", claims["actor_id"])
	assert.Equal(t, "7", claims["run_number"])
	assert.Equal(t, "def456", claims["workflow_sha"])

	// Empty claims are still skipped: they carry no information and cost bytes
	// in a per-request S3 object.
	assert.NotContains(t, claims, "base_ref")
}

// TestAuditClaims_NumericClaimsAreNotScientificNotation pins that a numeric
// claim reaches the audit record as a plain integer.
//
// This only became reachable with the full dump: claims are decoded into
// map[string]any, so every JSON number is a float64, and fmt's default float
// verb renders a 10-digit epoch second as "1.7555904e+09". An `exp` an auditor
// cannot read as a timestamp is a defect in the compliance artifact, so the
// value goes through utils.FormatClaimValue — the same helper BuildSessionTags
// uses, so the documented "a claim here and the same claim as a session tag can
// never disagree" guarantee still holds.
func TestAuditClaims_NumericClaimsAreNotScientificNotation(t *testing.T) {
	claims := githubClaims("org/repo")
	claims.Raw["exp"] = float64(1755590400) // as encoding/json decodes it
	claims.Raw["repository_id"] = float64(42)
	claims.Raw["run_number"] = float64(7)

	cfg := auditTestCfg(t, false, true)
	sink := &fakeAuditSink{}
	proc := handler.NewRequestProcessor(config.NewStaticProvider(cfg), mockConsumer(t),
		&fixedExtractor{claims: claims}, sink, "test-frontend")

	_, err := proc.ProcessRequest(context.Background(),
		&handler.RequestData{Role: "arn:aws:iam::123456789012:role/MyRole"},
		validator.ExtractionInput{Token: "t"}, "req-numeric", slog.Default())
	require.NoError(t, err)

	rec := recClaims(t, sink.last(t))
	require.NotNil(t, rec)
	assert.Equal(t, "1755590400", rec["exp"], "an epoch second must not be scientific notation")
	assert.Equal(t, "42", rec["repo_id"])
	assert.Equal(t, "7", rec["run_number"])
}

// TestAuditClaims_AliasSkippedWhenTargetClaimExists pins that the
// repository->repo rename does not overwrite a claim the token already carries
// under the alias target. Both landing on one key would drop a verified claim
// from the audit record, and which one survived would depend on Go's
// randomized map iteration order — a lossy, non-reproducible record.
func TestAuditClaims_AliasSkippedWhenTargetClaimExists(t *testing.T) {
	claims := githubClaims("org/repo")
	claims.Raw["repo"] = "already-taken"

	cfg := auditTestCfg(t, false, true)
	sink := &fakeAuditSink{}
	proc := handler.NewRequestProcessor(config.NewStaticProvider(cfg), mockConsumer(t),
		&fixedExtractor{claims: claims}, sink, "test-frontend")

	_, err := proc.ProcessRequest(context.Background(),
		&handler.RequestData{Role: "arn:aws:iam::123456789012:role/MyRole"},
		validator.ExtractionInput{Token: "t"}, "req-alias-clash", slog.Default())
	require.NoError(t, err)

	rec := recClaims(t, sink.last(t))
	require.NotNil(t, rec)
	assert.Equal(t, "already-taken", rec["repo"], "the token's own repo claim must win")
	assert.Equal(t, "org/repo", rec["repository"], "repository must keep its raw name rather than vanish")
}

// TestAuditRecord_IdentityFields pins the request-identity fields on the
// record itself: iss/sub/aud were already there, and the frontend join key
// plus the resolved client IP are added.
func TestAuditRecord_IdentityFields(t *testing.T) {
	cfg := auditTestCfg(t, false, true)
	sink := &fakeAuditSink{}
	proc := handler.NewRequestProcessor(config.NewStaticProvider(cfg), mockConsumer(t),
		&fixedExtractor{claims: githubClaims("org/repo")}, sink, "test-frontend")

	ctx := context.WithValue(context.Background(), handler.SourceIPContextKey, "203.0.113.7")
	ctx = context.WithValue(ctx, handler.FrontendRequestIDContextKey, "CPyipjveDoEEPIA=")

	_, err := proc.ProcessRequest(ctx,
		&handler.RequestData{Role: "arn:aws:iam::123456789012:role/MyRole"},
		validator.ExtractionInput{Token: "t"}, "req-identity", slog.Default())
	require.NoError(t, err)

	rec := sink.last(t)
	assert.Equal(t, testIssuer, rec["issuer"])
	assert.Equal(t, "raw-sub-value", rec["jwtSub"])
	assert.Equal(t, []any{"sts.amazonaws.com"}, rec["audience"])
	assert.Equal(t, "203.0.113.7", rec["sourceIp"])
	assert.Equal(t, "CPyipjveDoEEPIA=", rec["frontendRequestId"])
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
	assert.Equal(t, "org/repo", claims["repo"])
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
