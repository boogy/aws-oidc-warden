package validator

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/boogy/aws-oidc-warden/internal/cache"
	"github.com/boogy/aws-oidc-warden/internal/config"
	"github.com/boogy/aws-oidc-warden/internal/types"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/sync/singleflight"
)

// defaultMaxTokenBytes is used only if a TokenValidator is built from a
// config.Config that never went through Validate() (e.g. a hand-built config
// in a test). Normal bootstrap always calls Validate(), which applies this
// same default (internal/config.defaultMaxTokenBytes).
const defaultMaxTokenBytes = 8192

var (
	// ErrKeyNotFound is returned by the key function when no JWKS key matches
	// the token's "kid". It is a sentinel so callers can detect a key miss
	// (e.g. after signing-key rotation) and force a cache-bypassing JWKS
	// refetch.
	ErrKeyNotFound = errors.New("key not found")
	// ErrUnknownIssuer is returned when a token's issuer has no entry in the
	// registry. No JWKS fetch is attempted for an unknown issuer.
	ErrUnknownIssuer = errors.New("unknown issuer")
	// ErrTokenTooLarge is returned when a token exceeds the configured
	// maximum size, before any parsing is attempted.
	ErrTokenTooLarge = errors.New("token exceeds maximum allowed size")
	// ErrInvalidAudience is returned when none of the token's audiences match
	// any of the issuer's configured audiences.
	ErrInvalidAudience = errors.New("token audience not accepted for this issuer")
	// ErrMissingRequiredClaim is returned when one of the issuer's
	// required_claims is absent or empty in the verified token.
	ErrMissingRequiredClaim = errors.New("required claim missing or empty")
	// ErrTokenLifetimeExceeded is returned when exp-iat exceeds the configured
	// MaxTokenLifetime.
	ErrTokenLifetimeExceeded = errors.New("token lifetime exceeds maximum allowed")
	// ErrTokenTooOld is returned when now-iat exceeds the configured MaxTokenAge.
	ErrTokenTooOld = errors.New("token age exceeds maximum allowed")
)

// TokenValidatorInterface is the contract for validating an OIDC token end to
// end: signature, issuer, audience, expiration, and required claims, then
// normalizing to a canonical subject + raw claims map.
type TokenValidatorInterface interface {
	// Validate verifies a token against the issuer it claims, using that
	// issuer's registered spec (audiences/claim mappings/required claims),
	// and returns the normalized claims. Always use Validate for end-to-end
	// token authentication.
	Validate(string) (*types.Claims, error)
	// FetchJWKS fetches the JWKS for the given issuer, using the cache when
	// available. Exposed for testing and warm-prefetch; Validate calls it
	// internally with the issuer's registered spec (which may carry a
	// jwks_uri override).
	FetchJWKS(issuer string) (*types.JWKS, error)
	GenKeyFunc(jwks *types.JWKS) jwt.Keyfunc
}

// issuerSpec is the immutable, per-issuer view of config.IssuerConfig used on
// the request path. Rebuilt (never mutated) whenever the backing config
// changes.
type issuerSpec struct {
	Issuer, Provider, JWKSURI string
	Audiences                 []string
	ClaimMappings             map[string]string
	RequiredClaims            []string
}

// snapshot is an immutable view of the current set of trusted issuers, keyed
// by exact issuer string (no normalization — matches config.Validate's
// duplicate-issuer check).
type snapshot struct {
	registry map[string]*issuerSpec
}

// buildSnapshot projects cfg.Issuers into an issuer-keyed registry.
func buildSnapshot(cfg *config.Config) *snapshot {
	registry := make(map[string]*issuerSpec, len(cfg.Issuers))
	for i := range cfg.Issuers {
		ic := &cfg.Issuers[i]
		registry[ic.Issuer] = newIssuerSpec(ic)
	}
	return &snapshot{registry: registry}
}

// newIssuerSpec projects one config.IssuerConfig into the immutable
// issuerSpec used on the request path. Shared by the self-mode registry
// (buildSnapshot) and the delegated (apigw/alb) extractor constructors, so
// every mode builds an identical spec from the same config fields.
func newIssuerSpec(ic *config.IssuerConfig) *issuerSpec {
	return &issuerSpec{
		Issuer:         ic.Issuer,
		Provider:       ic.Provider,
		JWKSURI:        ic.JWKSURI,
		Audiences:      ic.Audiences,
		ClaimMappings:  ic.ClaimMappings,
		RequiredClaims: ic.RequiredClaims,
	}
}

// TokenValidator routes an incoming token to its issuer's spec via an
// atomically-published registry snapshot, verifies it, and normalizes the
// result. Safe for concurrent use; a hot config reload swaps the snapshot
// without locking the read path.
type TokenValidator struct {
	snap     atomic.Pointer[snapshot]
	cache    cache.Cache
	provider *config.Provider
	httpc    *http.Client // built once at init, SSRF/TLS-hardened (ssrf.go)

	// allowInsecureIssuers configures the http client built once at
	// construction (newSecureHTTPClient). leeway/maxLifetime/maxAge/
	// maxTokenBytes are read LIVE from the provider on every Validate() call
	// instead (see currentConfig), so a hot config reload takes effect
	// immediately, like the registry.
	allowInsecureIssuers bool

	// timeNow is the clock used for lifetime/age checks and the refetch
	// limiter's cooldown windows. Defaults to time.Now; overridable via
	// WithTimeNow for deterministic tests.
	timeNow func() time.Time

	// refetch rate-limits forced (cache-bypassing) JWKS refetches per
	// (issuer, kid), with a per-issuer backstop. keyMemo caches parsed,
	// re-validated public keys per (issuer, kid, key material) so repeated
	// requests for the same key skip re-parsing. jwksURICache memoizes a
	// discovery-resolved jwks_uri per issuer so steady-state requests skip
	// re-discovery. sfGroup collapses concurrent cold JWKS fetches for the
	// same issuer into a single upstream call.
	refetch      *refetchLimiter
	keyMemo      *keyMemo
	jwksURICache sync.Map
	sfGroup      singleflight.Group

	// builtFrom records which config pointer snap was built from, so
	// currentSnapshot can detect a hot reload with a cheap pointer compare
	// instead of rebuilding on every call.
	builtFrom atomic.Pointer[config.Config]
}

// TokenValidatorOption customizes a TokenValidator at construction time.
type TokenValidatorOption func(*TokenValidator)

// WithTimeNow overrides the clock TokenValidator uses for lifetime/age checks
// and the refetch limiter's cooldown windows. For tests only; production
// callers should rely on the time.Now default.
func WithTimeNow(now func() time.Time) TokenValidatorOption {
	return func(t *TokenValidator) {
		t.timeNow = now
	}
}

// NewTokenValidator creates a TokenValidator that reads its issuer registry
// from provider on every Validate call, so a hot-reloaded config change
// (new/removed issuer, audience, mapping) takes effect without a restart.
// All expensive setup (the shared http.Client, the initial registry
// snapshot) happens once here — call this once during bootstrap, never per
// request.
func NewTokenValidator(provider *config.Provider, jwksCache cache.Cache, opts ...TokenValidatorOption) *TokenValidator {
	cfg := provider.Get()

	t := &TokenValidator{
		cache:                jwksCache,
		provider:             provider,
		allowInsecureIssuers: cfg.AllowInsecureIssuers,
		timeNow:              time.Now,
	}
	t.httpc = newSecureHTTPClient(t.allowInsecureIssuers, 5*time.Second)

	for _, opt := range opts {
		opt(t)
	}

	t.refetch = newRefetchLimiter(t.timeNow, cfg.JWKSRefetchCooldown)
	t.keyMemo = newKeyMemo()
	t.rebuildSnapshot(cfg)
	return t
}

// currentConfig returns the provider's active configuration.
func (t *TokenValidator) currentConfig() *config.Config {
	return t.provider.Get()
}

// currentSnapshot returns the registry snapshot for the provider's current
// config, rebuilding and atomically publishing it if the config pointer
// changed since the last build.
func (t *TokenValidator) currentSnapshot() *snapshot {
	return t.snapshotFor(t.currentConfig())
}

// snapshotFor returns the registry snapshot for cfg, rebuilding and
// atomically publishing it if the config pointer changed since the last
// build. Concurrent callers racing a rebuild for the same new pointer redo
// the (idempotent) work harmlessly — atomic.Pointer loads/stores are
// torn-read-free, so this stays race-free without a lock. Accepting cfg
// (rather than re-reading the provider) lets Validate() do a single
// provider.Get() and reuse it for both the snapshot and the live time
// bounds.
func (t *TokenValidator) snapshotFor(cfg *config.Config) *snapshot {
	if t.builtFrom.Load() == cfg {
		if snap := t.snap.Load(); snap != nil {
			return snap
		}
	}
	return t.rebuildSnapshot(cfg)
}

// rebuildSnapshot builds a fresh registry from cfg and publishes it.
func (t *TokenValidator) rebuildSnapshot(cfg *config.Config) *snapshot {
	snap := buildSnapshot(cfg)
	t.snap.Store(snap)
	t.builtFrom.Store(cfg)
	return snap
}

// WarmPrefetch fetches and caches the JWKS for every configured issuer.
// Intended to run once during cold-start (e.g. Lambda INIT) so the first
// real request doesn't pay a cold JWKS fetch. Failures are logged and
// otherwise ignored: a prefetch miss just means the next Validate() for that
// issuer pays the fetch cost — it must never fail bootstrap.
func (t *TokenValidator) WarmPrefetch(ctx context.Context) {
	for _, spec := range t.currentSnapshot().registry {
		select {
		case <-ctx.Done():
			return
		default:
		}
		if _, err := t.fetchJWKS(spec, false); err != nil {
			slog.Warn("JWKS warm-prefetch failed; will fetch on first request",
				slog.String("issuer", spec.Issuer), slog.String("error", err.Error()))
		}
	}
}

// Validate implements the self-mode verification flow. The hardening steps
// (key-pinning refinement, sub/nbf enforcement, lifetime/age caps, refetch
// rate limiting) layer on top of the non-hardening baseline the
// parser/GenKeyFunc below already provide (algorithm allowlist,
// WithLeeway/WithIssuedAt/WithExpirationRequired, kid match).
func (t *TokenValidator) Validate(tokenString string) (*types.Claims, error) {
	// Read config once; time bounds and the length guard are derived live
	// from it (not frozen at construction) so a hot config reload takes
	// effect immediately, like the registry.
	cfg := t.currentConfig()

	maxTokenBytes := cfg.MaxTokenBytes
	if maxTokenBytes <= 0 {
		maxTokenBytes = defaultMaxTokenBytes
	}

	// Step 0: length guard before any parsing.
	if len(tokenString) > maxTokenBytes {
		return nil, fmt.Errorf("%w: %d bytes (max %d)", ErrTokenTooLarge, len(tokenString), maxTokenBytes)
	}

	// Step 1: unverified iss peek — routing only, never used for identity or
	// authorization decisions.
	unverified := jwt.MapClaims{}
	if _, _, err := jwt.NewParser().ParseUnverified(tokenString, unverified); err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}
	unverifiedIssuer, err := unverified.GetIssuer()
	if err != nil || unverifiedIssuer == "" {
		return nil, fmt.Errorf("%w: missing or invalid iss claim", ErrUnknownIssuer)
	}

	// Step 2: registry lookup by exact issuer match. An unknown issuer denies
	// before any JWKS fetch is attempted.
	spec, ok := t.snapshotFor(cfg).registry[unverifiedIssuer]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrUnknownIssuer, unverifiedIssuer)
	}

	leeway := cfg.LeewayOrDefault()

	// Step 3: per-call parser scoped to this issuer.
	parser := jwt.NewParser(
		jwt.WithIssuer(spec.Issuer),
		jwt.WithValidMethods([]string{
			jwt.SigningMethodRS256.Name,
			jwt.SigningMethodRS384.Name,
			jwt.SigningMethodRS512.Name,
			jwt.SigningMethodES256.Name,
			jwt.SigningMethodES384.Name,
			jwt.SigningMethodES512.Name,
		}),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
		jwt.WithLeeway(leeway),
	)

	// Step 4: verify signature against this issuer's cached JWKS.
	jwks, err := t.fetchJWKS(spec, false)
	if err != nil {
		return nil, err
	}

	raw := jwt.MapClaims{}
	token, err := parser.ParseWithClaims(tokenString, raw, t.genKeyFuncForIssuer(spec.Issuer, jwks))

	// If the signing key was not found, the issuer may have rotated its keys.
	// Force a single cache-bypassing JWKS refetch and retry once, subject to
	// the per-(issuer,kid) refetch limiter (a genuinely new kid always passes
	// on its first miss; repeated misses for the same bogus kid, or a flood
	// of distinct bogus kids for one issuer, are throttled).
	if err != nil && errors.Is(err, ErrKeyNotFound) {
		kid, _ := token.Header["kid"].(string)
		if t.refetch.allow(spec.Issuer, kid) {
			slog.Info("signing key not found in cached JWKS; refetching",
				slog.String("issuer", spec.Issuer), slog.String("kid", kid))
			if jwks, err = t.fetchJWKS(spec, true); err != nil {
				return nil, err
			}
			raw = jwt.MapClaims{}
			token, err = parser.ParseWithClaims(tokenString, raw, t.genKeyFuncForIssuer(spec.Issuer, jwks))
		} else {
			slog.Warn("forced JWKS refetch rate-limited; denying token",
				slog.String("issuer", spec.Issuer), slog.String("kid", kid))
		}
	}

	if err != nil {
		return nil, fmt.Errorf("jwt parse error: %w", err)
	}
	if !token.Valid {
		return nil, errors.New("token is invalid")
	}

	// Step 4b: re-assert the now-verified issuer against this call's spec.
	// Guards the gap between the registry lookup (step 2) and here, in case a
	// concurrent hot reload swapped the registry mid-call.
	verifiedIssuer, err := raw.GetIssuer()
	if err != nil || verifiedIssuer != spec.Issuer {
		return nil, fmt.Errorf("%w: verified issuer changed during validation", ErrUnknownIssuer)
	}

	// Steps 6-10: sub/iat/exp/nbf enforcement, lifetime/age caps, audience
	// ANY-match, required_claims, and normalization all run through the same
	// helper the delegated (apigw/alb) extractors use, so self mode and
	// delegated modes can never silently drift apart. Redundant with the
	// parser options above (WithExpirationRequired,
	// WithIssuedAt, WithLeeway already ran during ParseWithClaims) but
	// harmless — delegated modes have no such parser, so this is the only
	// place those checks run for them.
	bounds := claimBounds{leeway: leeway, maxLifetime: cfg.MaxTokenLifetime, maxAge: cfg.MaxTokenAge}
	return checkAndNormalizeClaims(raw, spec, bounds, t.timeNow())
}

// audienceMatches reports whether any of the token's audiences matches any of
// the issuer's configured audiences (ANY-match). A missing/empty audience on
// either side denies.
func audienceMatches(tokenAudiences jwt.ClaimStrings, expected []string) bool {
	if len(tokenAudiences) == 0 || len(expected) == 0 {
		return false
	}
	for _, got := range tokenAudiences {
		for _, want := range expected {
			if got == want {
				return true
			}
		}
	}
	return false
}

// providerAdapter derives canonical claims from an issuer's verified raw
// claims for one provider. Adding a new provider = implement this interface
// and register it in providerAdapters; no core Validate()/normalizeClaims
// edits required (open/closed).
type providerAdapter interface {
	// subject returns the canonical subject for raw, given the issuer's
	// configured claim_mappings (may be nil).
	subject(raw jwt.MapClaims, mappings map[string]string) (string, error)
	// populate does provider-specific native struct population on top of the
	// registered claims already set by populateRegisteredClaims. Must never
	// set claims.Subject — that is set once, afterward, by normalizeClaims
	// from subject() (no self-asserted identity).
	populate(raw jwt.MapClaims, claims *types.Claims) error
}

// githubAdapter is the native GitHub Actions OIDC provider: it unmarshals the
// full set of GitHub claims into types.Claims and defaults the canonical
// subject to the "repository" claim (overridable via claim_mappings.subject).
type githubAdapter struct{}

func (githubAdapter) subject(raw jwt.MapClaims, mappings map[string]string) (string, error) {
	if claimName, ok := mappings["subject"]; ok && claimName != "" {
		return stringClaim(raw, claimName)
	}
	return stringClaim(raw, "repository")
}

func (githubAdapter) populate(raw jwt.MapClaims, claims *types.Claims) error {
	// Native unmarshal: round-trip the verified raw claims through JSON into
	// the GitHub-specific struct fields. Safe only for provider: github — the
	// canonical Subject is set separately, never by this unmarshal.
	data, err := json.Marshal(map[string]any(raw))
	if err != nil {
		return fmt.Errorf("failed to marshal raw claims: %w", err)
	}
	if err := json.Unmarshal(data, claims); err != nil {
		return fmt.Errorf("failed to unmarshal github claims: %w", err)
	}
	return nil
}

// genericAdapter is the mapped-only provider for any non-GitHub issuer: no
// native struct unmarshal, so the canonical subject must come from an
// explicit claim_mappings.subject entry (enforced already at config.Validate,
// re-checked here as defense in depth).
type genericAdapter struct{}

func (genericAdapter) subject(raw jwt.MapClaims, mappings map[string]string) (string, error) {
	claimName, ok := mappings["subject"]
	if !ok || claimName == "" {
		return "", errors.New("non-github issuer requires claim_mappings.subject")
	}
	return stringClaim(raw, claimName)
}

func (genericAdapter) populate(jwt.MapClaims, *types.Claims) error { return nil }

// providerAdapters is the open/closed registry of known providers.
var providerAdapters = map[string]providerAdapter{
	"github":  githubAdapter{},
	"generic": genericAdapter{},
}

// stringClaim reads a required non-empty string claim from raw.
func stringClaim(raw jwt.MapClaims, name string) (string, error) {
	v, ok := raw[name]
	if !ok {
		return "", fmt.Errorf("claim %q not present", name)
	}
	s, ok := v.(string)
	if !ok || s == "" {
		return "", fmt.Errorf("claim %q is empty or not a string", name)
	}
	return s, nil
}

// populateRegisteredClaims copies the standard registered claims (iss, aud,
// exp, iat, nbf, jti) from the verified raw claims into claims.RegisteredClaims.
// Runs for every provider, before the provider-specific adapter. Deliberately
// does NOT set claims.Subject — see the types.Claims doc.
func populateRegisteredClaims(raw jwt.MapClaims, claims *types.Claims) error {
	iss, err := raw.GetIssuer()
	if err != nil {
		return fmt.Errorf("invalid iss claim: %w", err)
	}
	claims.Issuer = iss

	aud, err := raw.GetAudience()
	if err != nil {
		return fmt.Errorf("invalid aud claim: %w", err)
	}
	claims.Audience = aud

	exp, err := raw.GetExpirationTime()
	if err != nil {
		return fmt.Errorf("invalid exp claim: %w", err)
	}
	claims.ExpiresAt = exp

	iat, err := raw.GetIssuedAt()
	if err != nil {
		return fmt.Errorf("invalid iat claim: %w", err)
	}
	claims.IssuedAt = iat

	nbf, err := raw.GetNotBefore()
	if err != nil {
		return fmt.Errorf("invalid nbf claim: %w", err)
	}
	claims.NotBefore = nbf

	if jti, ok := raw["jti"].(string); ok {
		claims.ID = jti
	}
	return nil
}

// normalizeClaims converts verified raw claims into the canonical
// types.Claims for the given provider: populates the standard registered
// claims for every provider, does a native struct unmarshal only for
// provider "github", and always sets the canonical Subject from the
// provider's subject() — never from raw JSON directly. Fails closed on any
// error, missing required claim, or type mismatch.
func normalizeClaims(raw jwt.MapClaims, provider string, mappings map[string]string) (*types.Claims, error) {
	adapter, ok := providerAdapters[provider]
	if !ok {
		return nil, fmt.Errorf("no provider adapter registered for %q", provider)
	}

	claims := &types.Claims{Raw: map[string]any(raw)}

	if err := populateRegisteredClaims(raw, claims); err != nil {
		return nil, err
	}
	if err := adapter.populate(raw, claims); err != nil {
		return nil, err
	}

	// Sub retains the raw "sub" claim for every provider, so the audit record's
	// pre-canonicalization jwtSub is populated for generic issuers too (github's
	// adapter already sets it via native unmarshal).
	if sub, ok := raw["sub"].(string); ok {
		claims.Sub = sub
	}

	subject, err := adapter.subject(raw, mappings)
	if err != nil {
		return nil, fmt.Errorf("failed to derive canonical subject: %w", err)
	}
	claims.Subject = subject

	return claims, nil
}

// genKeyFuncForIssuer generates a jwt.Keyfunc scoped to issuer that validates
// JWT tokens using jwks keys. Supports RSA (RS256/384/512) and ECDSA
// (ES256/384/512) key types. Beyond a kid match, a candidate key must also
// satisfy: use is "sig" or unset; alg, if the JWKS entry sets one, matches
// the token's alg; and the key's type matches the token alg's family (RSA
// keys only for RS*, EC keys only for ES*). This blocks an alg-confusion or
// duplicate-kid-different-type attack from having a mismatched key selected
// for a kid it doesn't actually belong to. Scanning continues past a kid
// match that fails these checks (rather than stopping), so a duplicate kid
// with one matching and one non-matching key still resolves to the correct
// key. issuer scopes the key memo (keymemo.go) so the same kid string from
// different issuers is never conflated.
func (t *TokenValidator) genKeyFuncForIssuer(issuer string, jwks *types.JWKS) jwt.Keyfunc {
	return func(token *jwt.Token) (any, error) {
		kid, ok := token.Header["kid"].(string)
		if !ok {
			return nil, errors.New("missing or invalid kid in token header")
		}
		tokenAlg, _ := token.Header["alg"].(string)

		kidPresent := false
		for _, key := range jwks.Keys {
			if key.KeyID != kid {
				continue
			}
			kidPresent = true
			if key.Use != "" && key.Use != "sig" {
				continue
			}
			if key.Algorithm != "" && key.Algorithm != tokenAlg {
				continue
			}
			switch {
			case key.KeyType == "RSA" && strings.HasPrefix(tokenAlg, "RS"):
				return t.resolveKey(issuer, key)
			case key.KeyType == "EC" && strings.HasPrefix(tokenAlg, "ES"):
				return t.resolveKey(issuer, key)
			}
			// Key-type/alg-family mismatch (or unsupported kty) — keep
			// scanning in case another key shares this kid.
		}
		if kidPresent {
			return nil, fmt.Errorf("kid %q present but no key matches required use/alg/key-type", kid)
		}
		return nil, ErrKeyNotFound
	}
}

// GenKeyFunc generates a jwt.Keyfunc using JWKS keys, with no issuer scoping
// for the key memo. Kept for the TokenValidatorInterface/test call sites that
// predate multi-issuer key memoization; Validate itself calls
// genKeyFuncForIssuer with the matched issuer.
func (t *TokenValidator) GenKeyFunc(jwks *types.JWKS) jwt.Keyfunc {
	return t.genKeyFuncForIssuer("", jwks)
}

func parseRSAKey(key types.JSONWebKey) (*rsa.PublicKey, error) {
	if key.N == "" || key.E == "" {
		return nil, errors.New("RSA key missing modulus or exponent")
	}
	nBytes, err := base64.RawURLEncoding.DecodeString(key.N)
	if err != nil {
		return nil, fmt.Errorf("failed to decode RSA modulus: %w", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(key.E)
	if err != nil {
		return nil, fmt.Errorf("failed to decode RSA exponent: %w", err)
	}
	pub := &rsa.PublicKey{
		N: new(big.Int).SetBytes(nBytes),
		E: int(new(big.Int).SetBytes(eBytes).Int64()),
	}
	// Defense-in-depth: reject undersized keys that could be served by a
	// compromised JWKS source to enable offline signature forgery.
	if pub.N.BitLen() < 2048 {
		return nil, fmt.Errorf("RSA key too short: %d bits (minimum 2048)", pub.N.BitLen())
	}
	return pub, nil
}

func parseECKey(key types.JSONWebKey) (*ecdsa.PublicKey, error) {
	if key.X == "" || key.Y == "" || key.Crv == "" {
		return nil, errors.New("EC key missing x, y, or crv field")
	}
	curve, err := ecCurve(key.Crv)
	if err != nil {
		return nil, err
	}
	xBytes, err := base64.RawURLEncoding.DecodeString(key.X)
	if err != nil {
		return nil, fmt.Errorf("failed to decode EC x coordinate: %w", err)
	}
	yBytes, err := base64.RawURLEncoding.DecodeString(key.Y)
	if err != nil {
		return nil, fmt.Errorf("failed to decode EC y coordinate: %w", err)
	}
	pub := &ecdsa.PublicKey{
		Curve: curve,
		X:     new(big.Int).SetBytes(xBytes),
		Y:     new(big.Int).SetBytes(yBytes),
	}
	// Validate the point lies on the declared curve (and is not the identity).
	// ECDH() round-trips through crypto/ecdh, which rejects off-curve points —
	// a non-deprecated alternative to elliptic.Curve.IsOnCurve.
	if _, err := pub.ECDH(); err != nil {
		return nil, fmt.Errorf("EC key point is not valid for curve %s: %w", key.Crv, err)
	}
	return pub, nil
}

func ecCurve(crv string) (elliptic.Curve, error) {
	switch crv {
	case "P-256":
		return elliptic.P256(), nil
	case "P-384":
		return elliptic.P384(), nil
	case "P-521":
		return elliptic.P521(), nil
	}
	return nil, fmt.Errorf("unsupported EC curve %q", crv)
}
