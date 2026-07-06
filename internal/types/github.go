package types

import "github.com/golang-jwt/jwt/v5"

// Claims is the canonical verified-claims structure produced by the validator
// for every provider. GitHub-specific fields are populated only when the
// token's issuer is configured with provider: "github" (native unmarshal);
// for any other provider only the embedded RegisteredClaims, Subject, and Raw
// are populated.
//
// Subject is the canonical authorization identity (repository, project path,
// etc.) and is the field authz/session-tag code must read. It is deliberately
// NOT populated by JSON unmarshal: the embedded jwt.RegisteredClaims.Subject
// field (json:"sub") is shadowed for JSON purposes by the depth-0 Sub field
// below, which retains the raw "sub" JWT claim. Claims.Subject is instead set
// exclusively by normalizeClaims (internal/validator) from the issuer's
// configured claim_mappings.subject — never directly from token JSON — so a
// token can never self-assert its own canonical identity. Do not read Subject
// on a value that hasn't gone through Validate()/normalizeClaims.
type Claims struct {
	jwt.RegisteredClaims
	Actor                string `json:"actor"`
	ActorID              string `json:"actor_id"`
	BaseRef              string `json:"base_ref"`
	EventName            string `json:"event_name"`
	HeadRef              string `json:"head_ref"`
	JobWorkflowRef       string `json:"job_workflow_ref"`
	JobWorkflowSha       string `json:"job_workflow_sha"`
	Ref                  string `json:"ref"`
	RefProtected         string `json:"ref_protected"`
	RefType              string `json:"ref_type"`
	Repository           string `json:"repository"`
	RepositoryID         string `json:"repository_id"`
	RepositoryOwner      string `json:"repository_owner"`
	RepositoryOwnerID    string `json:"repository_owner_id"`
	RepositoryVisibility string `json:"repository_visibility"`
	RunAttempt           string `json:"run_attempt"`
	RunID                string `json:"run_id"`
	RunNumber            string `json:"run_number"`
	RunnerEnvironment    string `json:"runner_environment"`
	Sha                  string `json:"sha"`
	Sub                  string `json:"sub"`
	Workflow             string `json:"workflow"`
	WorkflowRef          string `json:"workflow_ref"`
	WorkflowSha          string `json:"workflow_sha"`

	// Raw holds every verified claim from the token, keyed by raw claim name.
	// Used by generic (non-github) subject/condition/session-tag mapping and
	// by required_claims checks, since those reference provider-native claim
	// names that have no corresponding struct field. Excluded from JSON so it
	// never round-trips through the config-clone / audit-log JSON paths.
	Raw map[string]any `json:"-"`
}
