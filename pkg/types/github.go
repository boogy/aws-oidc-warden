package types

import "github.com/golang-jwt/jwt/v5"

type GithubClaims struct {
	// Iss                  string `json:"iss"`
	// Aud                  string `json:"aud"`
	// Exp                  int64  `json:"exp"`
	// Iat                  int64  `json:"iat"`
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
}
