package validator

import (
	"encoding/json"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"

	"github.com/boogy/aws-oidc-warden/internal/types"
)

// githubDocsExampleToken is the example payload from GitHub's "Understanding
// the OIDC token" docs: ids and counters are JSON strings.
const githubDocsExampleToken = `{
  "jti": "example-id",
  "sub": "repo:octo-org/octo-repo:environment:prod",
  "environment": "prod",
  "aud": "https://github.com/octo-org",
  "ref": "refs/heads/main",
  "sha": "example-sha",
  "repository": "octo-org/octo-repo",
  "repository_owner": "octo-org",
  "actor_id": "12",
  "repository_visibility": "private",
  "repository_id": "74",
  "repository_owner_id": "65",
  "run_id": "example-run-id",
  "run_number": "10",
  "run_attempt": "2",
  "runner_environment": "github-hosted",
  "actor": "octocat",
  "workflow": "example-workflow",
  "head_ref": "",
  "base_ref": "",
  "event_name": "workflow_dispatch",
  "ref_type": "branch",
  "job_workflow_ref": "octo-org/octo-automation/.github/workflows/oidc.yml@refs/heads/main",
  "iss": "https://token.actions.githubusercontent.com",
  "nbf": 1632492967,
  "exp": 1632493867,
  "iat": 1632493567
}`

func decodeClaims(t *testing.T, payload string) jwt.MapClaims {
	t.Helper()
	var raw jwt.MapClaims
	if err := json.Unmarshal([]byte(payload), &raw); err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestGithubPopulateDocsExample(t *testing.T) {
	c, err := normalizeClaims(decodeClaims(t, githubDocsExampleToken), "github", nil)
	if err != nil {
		t.Fatalf("normalizeClaims: %v", err)
	}
	want := types.Claims{
		Actor: "octocat", ActorID: "12", EventName: "workflow_dispatch",
		JobWorkflowRef: "octo-org/octo-automation/.github/workflows/oidc.yml@refs/heads/main",
		Ref:            "refs/heads/main", RefType: "branch", Repository: "octo-org/octo-repo",
		RepositoryID: "74", RepositoryOwner: "octo-org", RepositoryOwnerID: "65",
		RepositoryVisibility: "private", RunAttempt: "2", RunID: "example-run-id", RunNumber: "10",
		RunnerEnvironment: "github-hosted", Sha: "example-sha", Workflow: "example-workflow",
	}
	got := *c
	got.RegisteredClaims, got.Sub, got.Raw = jwt.RegisteredClaims{}, "", nil
	if !reflect.DeepEqual(got, want) {
		t.Errorf("populate mismatch:\n got %+v\nwant %+v", got, want)
	}
	if c.Subject != "octo-org/octo-repo" || c.Sub != "repo:octo-org/octo-repo:environment:prod" {
		t.Errorf("subject=%q sub=%q", c.Subject, c.Sub)
	}
}

func TestGithubPopulateAcceptsAnyJSONType(t *testing.T) {
	tests := []struct {
		name  string
		claim string
		value any
		get   func(*types.Claims) string
		want  string
	}{
		{"numeric run_id", "run_id", float64(1234567890), func(c *types.Claims) string { return c.RunID }, "1234567890"},
		{"numeric repository_id", "repository_id", float64(74), func(c *types.Claims) string { return c.RepositoryID }, "74"},
		{"bool ref_protected", "ref_protected", true, func(c *types.Claims) string { return c.RefProtected }, "true"},
		{"string ref_protected", "ref_protected", "false", func(c *types.Claims) string { return c.RefProtected }, "false"},
		{"null run_number", "run_number", nil, func(c *types.Claims) string { return c.RunNumber }, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw := decodeClaims(t, githubDocsExampleToken)
			raw[tt.claim] = tt.value
			c, err := normalizeClaims(raw, "github", nil)
			if err != nil {
				t.Fatalf("normalizeClaims: %v", err)
			}
			if got := tt.get(c); got != tt.want {
				t.Errorf("%s = %q, want %q", tt.claim, got, tt.want)
			}
		})
	}
}

func TestGithubClaimFieldsCoverClaimsStruct(t *testing.T) {
	var names []string
	for _, f := range githubClaimFields {
		names = append(names, f.name)
	}
	typ := reflect.TypeFor[types.Claims]()
	for i := range typ.NumField() {
		sf := typ.Field(i)
		tag, _, _ := strings.Cut(sf.Tag.Get("json"), ",")
		if sf.Anonymous || tag == "" || tag == "-" || tag == "sub" || sf.Type.Kind() != reflect.String {
			continue
		}
		if !slices.Contains(names, tag) {
			t.Errorf("types.Claims.%s (%q) is not in githubClaimFields", sf.Name, tag)
		}
	}
	var c types.Claims
	for _, f := range githubClaimFields {
		*f.field(&c) = f.name
	}
	b, _ := json.Marshal(c)
	var back map[string]any
	_ = json.Unmarshal(b, &back)
	for _, f := range githubClaimFields {
		if back[f.name] != f.name {
			t.Errorf("githubClaimFields %q writes the wrong field", f.name)
		}
	}
}
