package config

import (
	"strings"
	"testing"
)

// gitlabLikeConfig builds a two-issuer config where neither issuer is GitHub,
// so every assertion below exercises the provider-neutral path rather than the
// `provider: github` native-unmarshal shortcut.
func gitlabLikeConfig() *Config {
	return &Config{
		RoleSessionName: "aow-session",
		Issuers: []IssuerConfig{
			{
				Issuer:        "https://gitlab.com",
				Provider:      "generic",
				Audiences:     []string{"aow"},
				ClaimMappings: map[string]string{"subject": "project_path"},
				SessionTags: map[string]string{
					"project":   "project_path",
					"namespace": "namespace_path",
				},
			},
			{
				Issuer:        "https://token.example.buildkite.com",
				Provider:      "generic",
				Audiences:     []string{"aow"},
				ClaimMappings: map[string]string{"subject": "pipeline_slug"},
				SessionTags:   map[string]string{"pipeline": "pipeline_slug"},
			},
		},
	}
}

// TestIssuerSessionTags_PerIssuerIsolation pins the contract the session-tag
// lookup relies on: the spec returned is the one declared by the issuer that
// actually verified the token, and an issuer the config does not know gets
// nothing. Without this, a token from issuer A could be tagged with issuer B's
// spec and reach STS carrying claims A never asserted.
func TestIssuerSessionTags_PerIssuerIsolation(t *testing.T) {
	cfg := gitlabLikeConfig()

	gitlab := cfg.IssuerSessionTags("https://gitlab.com")
	if got, want := gitlab["project"], "project_path"; got != want {
		t.Fatalf("gitlab project tag = %q, want %q", got, want)
	}
	if _, leaked := gitlab["pipeline"]; leaked {
		t.Fatalf("gitlab spec leaked the buildkite tag key: %v", gitlab)
	}

	buildkite := cfg.IssuerSessionTags("https://token.example.buildkite.com")
	if got, want := buildkite["pipeline"], "pipeline_slug"; got != want {
		t.Fatalf("buildkite pipeline tag = %q, want %q", got, want)
	}
	if len(buildkite) != 1 {
		t.Fatalf("buildkite spec = %v, want exactly one entry", buildkite)
	}
}

// TestIssuerSessionTags_UnknownIssuerGetsNoSpec covers the fail-closed branch:
// an issuer string that is not configured must return nil, never the first
// issuer's spec as a fallback.
func TestIssuerSessionTags_UnknownIssuerGetsNoSpec(t *testing.T) {
	cfg := gitlabLikeConfig()
	if got := cfg.IssuerSessionTags("https://token.actions.githubusercontent.com"); got != nil {
		t.Fatalf("unknown issuer returned a spec: %v", got)
	}
}

// TestIssuerSessionTags_MatchIsExact mirrors the validator's exact-match issuer
// policy. A trailing slash or a case change is a different issuer everywhere
// else in the pipeline, so it must be a different issuer here too.
func TestIssuerSessionTags_MatchIsExact(t *testing.T) {
	cfg := gitlabLikeConfig()
	for _, near := range []string{
		"https://gitlab.com/",
		"https://GitLab.com",
		" https://gitlab.com",
	} {
		if got := cfg.IssuerSessionTags(near); got != nil {
			t.Errorf("near-miss issuer %q returned a spec: %v", near, got)
		}
	}
}

// TestIssuerSessionTags_NoSpecDeclared covers an issuer that declares no
// session_tags at all: the lookup returns an empty spec, which BuildSessionTags
// treats as "attach nothing".
func TestIssuerSessionTags_NoSpecDeclared(t *testing.T) {
	cfg := &Config{
		RoleSessionName: "aow-session",
		Issuers: []IssuerConfig{{
			Issuer:        "https://oidc.circleci.com/org/abc",
			Provider:      "generic",
			Audiences:     []string{"aow"},
			ClaimMappings: map[string]string{"subject": "oidc.circleci.com/project-id"},
		}},
	}
	if got := cfg.IssuerSessionTags("https://oidc.circleci.com/org/abc"); len(got) != 0 {
		t.Fatalf("issuer with no session_tags returned %v, want empty", got)
	}
}

// TestValidate_GenericIssuerMustDeclareSubjectMapping proves the provider-neutral
// guardrail: a non-github issuer has no native struct to derive a canonical
// subject from, so booting without claim_mappings.subject must be rejected
// rather than silently authorizing on an empty subject.
func TestValidate_GenericIssuerMustDeclareSubjectMapping(t *testing.T) {
	cfg := &Config{
		RoleSessionName: "aow-session",
		Issuers: []IssuerConfig{{
			Issuer:    "https://gitlab.com",
			Provider:  "generic",
			Audiences: []string{"aow"},
		}},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate accepted a generic issuer with no claim_mappings.subject")
	}
	if !strings.Contains(err.Error(), "claim_mappings.subject") {
		t.Fatalf("error does not name the missing key: %v", err)
	}
}

// TestValidate_ProviderDefaultsToGeneric pins the default: omitting `provider`
// selects the provider-neutral adapter, not GitHub. It also proves the default
// is written back through the pointer, since the same loop then enforces the
// generic-only claim_mappings.subject rule against it.
func TestValidate_ProviderDefaultsToGeneric(t *testing.T) {
	cfg := &Config{
		RoleSessionName: "aow-session",
		Issuers: []IssuerConfig{{
			Issuer:        "https://gitlab.com",
			Audiences:     []string{"aow"},
			ClaimMappings: map[string]string{"subject": "project_path"},
		}},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if got := cfg.Issuers[0].Provider; got != "generic" {
		t.Fatalf("provider defaulted to %q, want %q", got, "generic")
	}
}

// TestValidate_RejectsUnknownProvider keeps the adapter registry closed: an
// unregistered provider name must fail at boot, not at the first token, where
// normalizeClaims would reject every request instead.
func TestValidate_RejectsUnknownProvider(t *testing.T) {
	for _, provider := range []string{"gitlab", "GitHub", "Generic", "GITHUB"} {
		cfg := &Config{
			RoleSessionName: "aow-session",
			Issuers: []IssuerConfig{{
				Issuer:        "https://gitlab.com",
				Provider:      provider,
				Audiences:     []string{"aow"},
				ClaimMappings: map[string]string{"subject": "project_path"},
			}},
		}
		if err := cfg.Validate(); err == nil {
			t.Errorf("Validate accepted provider %q", provider)
		}
	}
}
