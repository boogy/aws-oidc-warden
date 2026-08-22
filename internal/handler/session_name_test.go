package handler_test

import (
	"context"
	"log/slog"
	"testing"

	"github.com/boogy/aws-oidc-warden/internal/config"
	"github.com/boogy/aws-oidc-warden/internal/handler"
	"github.com/boogy/aws-oidc-warden/internal/validator"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// sessionNameCfg builds a config whose two mappings differ only in their
// role_session_name override, so a test can prove the name follows the mapping
// that authorized the role rather than the first one that matched the subject.
func sessionNameCfg(t *testing.T, override string) *config.Config {
	t.Helper()
	cfg := &config.Config{
		Issuers: []config.IssuerConfig{{
			Issuer:    testIssuer,
			Provider:  "github",
			Audiences: []string{"sts.amazonaws.com"},
		}},
		RoleSessionName: "global-default",
		Cache:           &config.Cache{TTL: 0},
		RoleMappings: []config.RoleMapping{{
			Subject:         "org/repo",
			Roles:           []string{"arn:aws:iam::123456789012:role/MyRole"},
			RoleSessionName: override,
		}},
	}
	require.NoError(t, cfg.Validate())
	return cfg
}

func assumeWith(t *testing.T, cfg *config.Config, subject, role string) *fakeConsumer {
	t.Helper()
	consumer := mockConsumer(t)
	proc := handler.NewRequestProcessor(config.NewStaticProvider(cfg), consumer,
		&fixedExtractor{claims: allowClaims(subject)}, nil, "test")

	_, err := proc.ProcessRequest(context.Background(),
		&handler.RequestData{Role: role},
		validator.ExtractionInput{Token: "t"}, "req-session-name", slog.Default())
	require.NoError(t, err)
	return consumer
}

// TestAssumeRole_UsesPerMappingSessionName proves the per-mapping
// role_session_name reaches STS.
//
// Every handler-level mock bound AssumeRole's sessionName argument to `_`, so
// nothing in this package could tell the override apart from the global
// default — the whole point of the feature is CloudTrail attribution, and a
// wiring regression between FindRoleSessionName and the AssumeRole call would
// have been invisible.
func TestAssumeRole_UsesPerMappingSessionName(t *testing.T) {
	consumer := assumeWith(t, sessionNameCfg(t, "gha-org-repo"), "org/repo",
		"arn:aws:iam::123456789012:role/MyRole")

	assert.Equal(t, "gha-org-repo", consumer.gotSessionName,
		"the per-mapping role_session_name never reached AssumeRole")
}

// With no override the global role_session_name is used — the fallback must
// not regress into an empty session name, which STS rejects.
func TestAssumeRole_FallsBackToGlobalSessionName(t *testing.T) {
	consumer := assumeWith(t, sessionNameCfg(t, ""), "org/repo",
		"arn:aws:iam::123456789012:role/MyRole")

	assert.Equal(t, "global-default", consumer.gotSessionName)
}

// The name must come from the mapping that authorized THIS role, not from an
// earlier mapping that merely matched the subject. Same resolution rule as the
// session policy, and the same failure if it regresses: CloudTrail attributes
// a privileged assumption to the wrong session name.
func TestAssumeRole_SessionNameComesFromAuthorizingMapping(t *testing.T) {
	cfg := &config.Config{
		Issuers: []config.IssuerConfig{{
			Issuer:    testIssuer,
			Provider:  "github",
			Audiences: []string{"sts.amazonaws.com"},
		}},
		RoleSessionName: "global-default",
		Cache:           &config.Cache{TTL: 0},
		RoleMappings: []config.RoleMapping{
			{
				// Declared first and matches the subject, but does not grant
				// the requested role.
				Subject:         "org/repo",
				Roles:           []string{"arn:aws:iam::123456789012:role/OtherRole"},
				RoleSessionName: "wrong-name",
			},
			{
				Subject:         "org/repo",
				Roles:           []string{"arn:aws:iam::123456789012:role/MyRole"},
				RoleSessionName: "right-name",
			},
		},
	}
	require.NoError(t, cfg.Validate())

	consumer := assumeWith(t, cfg, "org/repo", "arn:aws:iam::123456789012:role/MyRole")
	assert.Equal(t, "right-name", consumer.gotSessionName,
		"session name came from a mapping that did not authorize the requested role")
}

// The audit record must report the name actually used, or CloudTrail and the
// audit trail disagree about who assumed the role.
func TestAuditRecord_ReportsSessionNameUsed(t *testing.T) {
	cfg := sessionNameCfg(t, "gha-org-repo")
	sink := &fakeAuditSink{}
	proc := handler.NewRequestProcessor(config.NewStaticProvider(cfg), mockConsumer(t),
		&fixedExtractor{claims: allowClaims("org/repo")}, sink, "test")

	_, err := proc.ProcessRequest(context.Background(),
		&handler.RequestData{Role: "arn:aws:iam::123456789012:role/MyRole"},
		validator.ExtractionInput{Token: "t"}, "req-session-name-audit", slog.Default())
	require.NoError(t, err)

	assert.Equal(t, "gha-org-repo", sink.last(t)["sessionName"])
}
