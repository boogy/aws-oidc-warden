package validator_test

// Answers the one question the existing suite does not cover: can an attacker
// who exhausts the forced-refetch limiter PIN a stale/revoked key set after a
// real signing-key rotation, so that legitimate tokens signed with the new key
// are permanently rejected?
//
// Every test here asserts; none merely observes.

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"testing"
	"time"

	"github.com/boogy/aws-oidc-warden/internal/cache"
	"github.com/boogy/aws-oidc-warden/internal/config"
	"github.com/boogy/aws-oidc-warden/internal/types"
	"github.com/boogy/aws-oidc-warden/internal/validator"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// clockedValidator builds a TokenValidator whose refetch-limiter cooldown
// windows advance with the returned setter rather than with wall time.
func clockedValidator(cfg *config.Config, c cache.Cache) (*validator.TokenValidator, func(time.Duration)) {
	now := time.Now()
	v := validator.NewTokenValidator(
		config.NewStaticProvider(cfg), c,
		validator.WithTimeNow(func() time.Time { return now }),
	)
	return v, func(d time.Duration) { now = now.Add(d) }
}

// TestRefetch_LimiterFloodCannotPinStaleKeySetAfterRotation is the primary
// pinning test. An attacker floods one issuer with distinct bogus kids to
// exhaust the per-issuer refetch backstop, and only THEN does a legitimate
// token signed with the rotated-in key arrive. If the limiter could pin a
// stale key set, that legitimate token would be rejected.
func TestRefetch_LimiterFloodCannotPinStaleKeySetAfterRotation(t *testing.T) {
	oldKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	newKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	served := &types.JWKS{Keys: []types.JSONWebKey{jwkFromKey("k-old", &oldKey.PublicKey)}}
	srv := oidcServer(t, func() *types.JWKS { return served })

	cfg := githubIssuer(srv.URL, "aud")
	require.NoError(t, cfg.Validate())
	v, _ := clockedValidator(cfg, cache.NewMemoryCache())

	// Warm the cache with the pre-rotation key set.
	_, err = v.Validate(signToken(t, oldKey, "k-old", srv.URL, "aud"))
	require.NoError(t, err, "pre-rotation token must validate")

	// Real key rotation: the old key is REVOKED, only the new one is served.
	served = &types.JWKS{Keys: []types.JSONWebKey{jwkFromKey("k-new", &newKey.PublicKey)}}

	// Attacker exhausts the limiter with distinct never-before-seen kids.
	for i := 0; i < 50; i++ {
		_, aerr := v.Validate(signToken(t, oldKey, fmt.Sprintf("bogus-%d", i), srv.URL, "aud"))
		require.Error(t, aerr, "bogus kid %d must never validate", i)
	}

	// The legitimate rotated token now arrives.
	claims, err := v.Validate(signToken(t, newKey, "k-new", srv.URL, "aud"))
	require.NoError(t, err,
		"FINDING: attacker flood pinned a stale key set - legitimate post-rotation token rejected")
	assert.Equal(t, "owner/repo", claims.Subject)
}

// TestRefetch_LimiterDenialAfterRotationIsTransientNotPinned covers the
// worst-case ordering the previous test cannot reach: the attacker consumes
// the per-issuer refetch slot while upstream is STILL serving the old key set,
// and rotation lands immediately afterwards. The first legitimate token is
// genuinely denied (the slot is spent and the cache is stale) -- this test
// pins that denial as TRANSIENT, clearing on its own once the 2s per-issuer
// backstop elapses, rather than as a durable pin.
func TestRefetch_LimiterDenialAfterRotationIsTransientNotPinned(t *testing.T) {
	oldKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	newKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	served := &types.JWKS{Keys: []types.JSONWebKey{jwkFromKey("k-old", &oldKey.PublicKey)}}
	srv := oidcServer(t, func() *types.JWKS { return served })

	cfg := githubIssuer(srv.URL, "aud")
	require.NoError(t, cfg.Validate())
	v, advance := clockedValidator(cfg, cache.NewMemoryCache())

	_, err = v.Validate(signToken(t, oldKey, "k-old", srv.URL, "aud"))
	require.NoError(t, err)

	// Attacker burns the per-issuer slot BEFORE rotation, so the refetch it
	// triggers re-caches the still-old key set.
	_, err = v.Validate(signToken(t, oldKey, "bogus-preroll", srv.URL, "aud"))
	require.Error(t, err)

	// Rotation lands now, with the slot already spent and the cache stale.
	served = &types.JWKS{Keys: []types.JSONWebKey{jwkFromKey("k-new", &newKey.PublicKey)}}

	rotated := signToken(t, newKey, "k-new", srv.URL, "aud")

	// Within the 2s backstop the refetch is denied, so this fails closed.
	_, err = v.Validate(rotated)
	require.Error(t, err, "expected the spent per-issuer slot to deny this refetch")

	// Once the backstop elapses the very same token validates: the denial was
	// a bounded window, not a pin.
	advance(3 * time.Second)
	claims, err := v.Validate(signToken(t, newKey, "k-new", srv.URL, "aud"))
	require.NoError(t, err,
		"FINDING: denial persisted past the per-issuer backstop - stale key set is pinned")
	assert.Equal(t, "owner/repo", claims.Subject)
}

// TestRefetch_DeniedRefetchNeverAcceptsAgainstStaleKeySet pins the fail-closed
// direction explicitly: when the limiter denies a refetch, the token must be
// REJECTED, never accepted against the stale cached key set. A revoked key
// must not verify anything once it is gone from the served JWKS and the cache
// has caught up.
func TestRefetch_DeniedRefetchNeverAcceptsAgainstStaleKeySet(t *testing.T) {
	oldKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	newKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	served := &types.JWKS{Keys: []types.JSONWebKey{jwkFromKey("k-old", &oldKey.PublicKey)}}
	srv := oidcServer(t, func() *types.JWKS { return served })

	cfg := githubIssuer(srv.URL, "aud")
	require.NoError(t, cfg.Validate())
	v, advance := clockedValidator(cfg, cache.NewMemoryCache())

	_, err = v.Validate(signToken(t, oldKey, "k-old", srv.URL, "aud"))
	require.NoError(t, err)

	// Revoke the old key upstream and force the cache to catch up via a
	// legitimate new-kid refetch.
	served = &types.JWKS{Keys: []types.JSONWebKey{jwkFromKey("k-new", &newKey.PublicKey)}}
	advance(3 * time.Second)
	_, err = v.Validate(signToken(t, newKey, "k-new", srv.URL, "aud"))
	require.NoError(t, err)

	// A token signed by the REVOKED key must now fail, and must keep failing
	// however many times it is retried (no limiter state can resurrect it).
	revoked := signToken(t, oldKey, "k-old", srv.URL, "aud")
	for i := 0; i < 5; i++ {
		advance(90 * time.Second) // clear both cooldown windows each round
		_, rerr := v.Validate(revoked)
		require.Error(t, rerr, "revoked key must never validate (attempt %d)", i)
	}
}
