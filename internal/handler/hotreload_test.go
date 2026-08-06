package handler_test

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"

	"github.com/boogy/aws-oidc-warden/internal/config"
	"github.com/boogy/aws-oidc-warden/internal/handler"
	"github.com/boogy/aws-oidc-warden/internal/validator"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	hotReloadRoleA = "arn:aws:iam::123456789012:role/RoleA"
	hotReloadRoleB = "arn:aws:iam::123456789012:role/RoleB"
)

// TestHotReload_AuthorizationDecisionFollowsRemoteConfig proves the operator
// promise that role_mappings can be changed by rewriting the remote (S3)
// config object alone — no Lambda redeploy, no cold start — and that both
// directions take effect: a newly granted role becomes assumable and a
// withdrawn role stops being assumable on the very next request.
//
// The pipeline seam under test is ProcessRequest's leading
// provider.MaybeRefresh(ctx) + single-snapshot Get(): config-level reload is
// covered by config.TestProvider_RemovedKeyDisappearsOnReload, but nothing
// asserted that a reload actually changes the authorization OUTCOME through
// the handler. Without the MaybeRefresh call site, a running Lambda would
// serve the cold-start config forever while the operator believes a
// revocation has landed.
func TestHotReload_AuthorizationDecisionFollowsRemoteConfig(t *testing.T) {
	mappings := func(role string) string {
		return fmt.Sprintf(
			`{"role_mappings":[{"subject":"org/repo","issuer":%q,"roles":[%q]}]}`,
			testIssuer, role)
	}

	// payload stands in for the S3 config object's bytes; rewriting it models an
	// operator uploading a new object version.
	var payload atomic.Pointer[string]
	v1 := mappings(hotReloadRoleA)
	payload.Store(&v1)

	base := auditTestCfg(t, false, false)
	// A 1ns interval makes every request due for a refresh, so the test does not
	// depend on wall-clock timing to observe the reload.
	provider := config.NewProvider(base, time.Nanosecond, "json", func(context.Context) ([]byte, error) {
		return []byte(*payload.Load()), nil
	})
	require.NoError(t, provider.Refresh(context.Background()))

	proc := handler.NewRequestProcessor(provider, mockConsumer(t),
		&fixedExtractor{claims: allowClaims("org/repo")}, &fakeAuditSink{}, "test")

	assume := func(role string) error {
		_, err := proc.ProcessRequest(context.Background(),
			&handler.RequestData{Role: role},
			validator.ExtractionInput{Token: "t"}, "req-hot-reload", slog.Default())
		return err
	}

	// v1: RoleA granted, RoleB unknown.
	require.NoError(t, assume(hotReloadRoleA), "RoleA is granted by the initially fetched config")
	require.Error(t, assume(hotReloadRoleB), "RoleB is not granted by the initially fetched config")

	// Operator rewrites the object: RoleA withdrawn, RoleB granted.
	v2 := mappings(hotReloadRoleB)
	payload.Store(&v2)

	err := assume(hotReloadRoleA)
	require.Error(t, err, "withdrawing RoleA in the remote config must revoke it without a redeploy")
	assert.True(t, errors.Is(err, handler.ErrRoleNotPermitted), "want ErrRoleNotPermitted, got %v", err)
	assert.NoError(t, assume(hotReloadRoleB), "granting RoleB in the remote config must take effect without a redeploy")

	// A broken object must not open anything up or take the service down: the
	// last-good config keeps being served (reload fails safe).
	broken := `{"role_mappings":[{"subject":".*","issuer":"` + testIssuer + `","roles":["` + hotReloadRoleA + `"]}]}`
	payload.Store(&broken) // bare-wildcard subject: rejected by Validate()

	assert.Error(t, assume(hotReloadRoleA),
		"a config Validate() rejects must not be applied, so RoleA stays withdrawn")
	assert.NoError(t, assume(hotReloadRoleB),
		"the last-good config keeps being served after a rejected reload")
}
