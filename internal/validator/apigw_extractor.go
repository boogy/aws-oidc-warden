package validator

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/boogy/aws-oidc-warden/internal/types"
	"github.com/golang-jwt/jwt/v5"
)

// APIGWExtractor reads pre-validated claims from the API Gateway HTTP API v2
// JWT Authorizer context (event.requestContext.authorizer.jwt.claims).
// It does NOT verify signatures — that responsibility belongs to API Gateway.
// If AuthorizerClaims is nil or empty, it rejects the request to prevent
// direct Lambda invocations that bypass the authorizer.
// Defense-in-depth: re-validates issuer, audience, and expiry even though
// API Gateway checks these at authorizer time, guarding against misconfiguration
// and clock skew between authorization and Lambda invocation.
type APIGWExtractor struct {
	expectedIssuer    string
	expectedAudiences []string
}

// NewAPIGWExtractor creates an APIGWExtractor that re-validates issuer and audience
// against the configured values as a defense-in-depth check.
func NewAPIGWExtractor(issuer string, audiences []string) *APIGWExtractor {
	return &APIGWExtractor{expectedIssuer: issuer, expectedAudiences: audiences}
}

// Extract maps the API Gateway authorizer claims to GithubClaims, re-validating
// issuer, audience, and expiry for defense in depth.
func (a *APIGWExtractor) Extract(_ context.Context, input ExtractionInput) (*types.GithubClaims, error) {
	if len(input.AuthorizerClaims) == 0 {
		return nil, fmt.Errorf("no authorizer claims present: request may have bypassed API Gateway JWT Authorizer")
	}
	return a.mapAPIGWClaims(input.AuthorizerClaims)
}

func (a *APIGWExtractor) mapAPIGWClaims(raw map[string]string) (*types.GithubClaims, error) {
	repo := raw["repository"]
	if repo == "" {
		return nil, fmt.Errorf("missing required claim: repository")
	}

	// Re-validate issuer — guards against a reused or misconfigured JWT Authorizer.
	iss := raw["iss"]
	if iss != a.expectedIssuer {
		return nil, fmt.Errorf("iss mismatch: got %q, want %q", iss, a.expectedIssuer)
	}

	// Re-validate audience — at least one must match the configured set.
	aud := raw["aud"]
	matched := false
	for _, want := range a.expectedAudiences {
		if aud == want {
			matched = true
			break
		}
	}
	if !matched {
		return nil, fmt.Errorf("aud mismatch: token audience %q not in allowed set %v", aud, a.expectedAudiences)
	}

	// Re-validate expiry — API Gateway checks exp at auth time; Lambda cold starts
	// can add enough delay that a short-lived token expires before processing.
	expUnix, err := strconv.ParseInt(raw["exp"], 10, 64)
	if err != nil || expUnix == 0 {
		return nil, fmt.Errorf("missing or unparseable exp claim in authorizer context")
	}
	if time.Now().Unix() > expUnix {
		return nil, fmt.Errorf("token has expired (exp=%d)", expUnix)
	}

	c := &types.GithubClaims{
		Sub:                  raw["sub"],
		Actor:                raw["actor"],
		ActorID:              raw["actor_id"],
		BaseRef:              raw["base_ref"],
		EventName:            raw["event_name"],
		HeadRef:              raw["head_ref"],
		JobWorkflowRef:       raw["job_workflow_ref"],
		JobWorkflowSha:       raw["job_workflow_sha"],
		Ref:                  raw["ref"],
		RefProtected:         raw["ref_protected"],
		RefType:              raw["ref_type"],
		Repository:           repo,
		RepositoryID:         raw["repository_id"],
		RepositoryOwner:      raw["repository_owner"],
		RepositoryOwnerID:    raw["repository_owner_id"],
		RepositoryVisibility: raw["repository_visibility"],
		RunAttempt:           raw["run_attempt"],
		RunID:                raw["run_id"],
		RunNumber:            raw["run_number"],
		RunnerEnvironment:    raw["runner_environment"],
		Sha:                  raw["sha"],
		Workflow:             raw["workflow"],
		WorkflowRef:          raw["workflow_ref"],
		WorkflowSha:          raw["workflow_sha"],
	}

	c.Issuer = iss
	if aud != "" {
		c.Audience = jwt.ClaimStrings{aud}
	}
	c.ExpiresAt = jwt.NewNumericDate(time.Unix(expUnix, 0))
	if iat, err := strconv.ParseInt(raw["iat"], 10, 64); err == nil {
		// Reject a future iat, matching self-mode's jwt.WithIssuedAt() check.
		if time.Now().Unix() < iat {
			return nil, fmt.Errorf("token iat is in the future (%d)", iat)
		}
		c.IssuedAt = jwt.NewNumericDate(time.Unix(iat, 0))
	}

	return c, nil
}
