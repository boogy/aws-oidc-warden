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
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/url"
	"sync/atomic"
	"time"

	"github.com/boogy/aws-oidc-warden/internal/cache"
	"github.com/boogy/aws-oidc-warden/internal/config"
	"github.com/boogy/aws-oidc-warden/internal/types"
	"github.com/golang-jwt/jwt/v5"
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
		registry[ic.Issuer] = &issuerSpec{
			Issuer:         ic.Issuer,
			Provider:       ic.Provider,
			JWKSURI:        ic.JWKSURI,
			Audiences:      ic.Audiences,
			ClaimMappings:  ic.ClaimMappings,
			RequiredClaims: ic.RequiredClaims,
		}
	}
	return &snapshot{registry: registry}
}

// TokenValidator routes an incoming token to its issuer's spec via an
// atomically-published registry snapshot, verifies it, and normalizes the
// result. Safe for concurrent use; a hot config reload swaps the snapshot
// without locking the read path.
type TokenValidator struct {
	snap     atomic.Pointer[snapshot]
	cache    cache.Cache
	provider *config.Provider
	httpc    *http.Client // built once at init (Group C hardens: SSRF/TLS)

	// leeway/maxLifetime/maxAge/maxTokenBytes are read once from the config in
	// effect at construction time. Unlike the registry, they are not re-derived
	// on hot reload (see CLAUDE.md); Group C's per-(issuer,kid) refetch limiter
	// is added here too.
	leeway        time.Duration
	maxLifetime   time.Duration
	maxAge        time.Duration
	maxTokenBytes int

	// builtFrom records which config pointer snap was built from, so
	// currentSnapshot can detect a hot reload with a cheap pointer compare
	// instead of rebuilding on every call.
	builtFrom atomic.Pointer[config.Config]
}

// NewTokenValidator creates a TokenValidator that reads its issuer registry
// from provider on every Validate call, so a hot-reloaded config change
// (new/removed issuer, audience, mapping) takes effect without a restart.
// All expensive setup (the shared http.Client, the initial registry
// snapshot) happens once here — call this once during bootstrap, never per
// request.
func NewTokenValidator(provider *config.Provider, jwksCache cache.Cache) *TokenValidator {
	cfg := provider.Get()

	maxTokenBytes := cfg.MaxTokenBytes
	if maxTokenBytes <= 0 {
		maxTokenBytes = defaultMaxTokenBytes
	}

	t := &TokenValidator{
		cache:         jwksCache,
		provider:      provider,
		httpc:         &http.Client{Timeout: 5 * time.Second},
		leeway:        cfg.JWTLeeway,
		maxLifetime:   cfg.MaxTokenLifetime,
		maxAge:        cfg.MaxTokenAge,
		maxTokenBytes: maxTokenBytes,
	}
	t.rebuildSnapshot(cfg)
	return t
}

// currentConfig returns the provider's active configuration.
func (t *TokenValidator) currentConfig() *config.Config {
	return t.provider.Get()
}

// currentSnapshot returns the registry snapshot for the provider's current
// config, rebuilding and atomically publishing it if the config pointer
// changed since the last build. Concurrent callers racing a rebuild for the
// same new pointer redo the (idempotent) work harmlessly — atomic.Pointer
// loads/stores are torn-read-free, so this stays race-free without a lock.
func (t *TokenValidator) currentSnapshot() *snapshot {
	cfg := t.currentConfig()
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

// Validate implements the self-mode verification flow (SHARED.md steps
// 0-4b, 8-10). Steps 5-7 (key-pinning refinement, sub/nbf enforcement,
// lifetime/age caps, refetch rate limiting) are Group C's hardening layer;
// the parser/GenKeyFunc below already provide the non-hardening baseline
// (algorithm allowlist, WithLeeway/WithIssuedAt/WithExpirationRequired, kid
// match) that Group C extends in place.
func (t *TokenValidator) Validate(tokenString string) (*types.Claims, error) {
	// Step 0: length guard before any parsing.
	if len(tokenString) > t.maxTokenBytes {
		return nil, fmt.Errorf("%w: %d bytes (max %d)", ErrTokenTooLarge, len(tokenString), t.maxTokenBytes)
	}

	// Step 1: unverified iss peek — routing only, never used for identity or
	// authorization decisions (SHARED.md invariant #2).
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
	spec, ok := t.currentSnapshot().registry[unverifiedIssuer]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrUnknownIssuer, unverifiedIssuer)
	}

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
		jwt.WithLeeway(t.leeway),
	)

	// Step 4: verify signature against this issuer's cached JWKS.
	jwks, err := t.fetchJWKS(spec, false)
	if err != nil {
		return nil, err
	}

	raw := jwt.MapClaims{}
	token, err := parser.ParseWithClaims(tokenString, raw, t.GenKeyFunc(jwks))

	// If the signing key was not found, the issuer may have rotated its keys.
	// Force a single cache-bypassing JWKS refetch and retry once.
	if err != nil && errors.Is(err, ErrKeyNotFound) {
		slog.Info("signing key not found in cached JWKS; refetching", slog.String("issuer", spec.Issuer))
		if jwks, err = t.fetchJWKS(spec, true); err != nil {
			return nil, err
		}
		raw = jwt.MapClaims{}
		token, err = parser.ParseWithClaims(tokenString, raw, t.GenKeyFunc(jwks))
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

	// Step 8: audience ANY-match against this issuer's configured audiences.
	tokenAudience, err := raw.GetAudience()
	if err != nil {
		return nil, fmt.Errorf("invalid aud claim: %w", err)
	}
	if !audienceMatches(tokenAudience, spec.Audiences) {
		return nil, fmt.Errorf("%w: got %v, want one of %v", ErrInvalidAudience, tokenAudience, spec.Audiences)
	}

	// Step 9: required_claims present and non-empty, checked on raw verified
	// claims — replaces the old hard-coded "repository" requirement.
	for _, name := range spec.RequiredClaims {
		v, present := raw[name]
		if !present {
			return nil, fmt.Errorf("%w: %q", ErrMissingRequiredClaim, name)
		}
		if s, isStr := v.(string); isStr && s == "" {
			return nil, fmt.Errorf("%w: %q", ErrMissingRequiredClaim, name)
		}
	}

	// Step 10: normalize to canonical subject + raw claims map.
	return normalizeClaims(raw, spec.Provider, spec.ClaimMappings)
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
// edits required (open/closed, SHARED.md engineering standards).
type providerAdapter interface {
	// subject returns the canonical subject for raw, given the issuer's
	// configured claim_mappings (may be nil).
	subject(raw jwt.MapClaims, mappings map[string]string) (string, error)
	// populate does provider-specific native struct population on top of the
	// registered claims already set by populateRegisteredClaims. Must never
	// set claims.Subject — that is set once, afterward, by normalizeClaims
	// from subject() (SHARED.md invariant #4: no self-asserted identity).
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
// does NOT set claims.Subject — see types.Claims doc and invariant #4.
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

	subject, err := adapter.subject(raw, mappings)
	if err != nil {
		return nil, fmt.Errorf("failed to derive canonical subject: %w", err)
	}
	claims.Subject = subject

	return claims, nil
}

// FetchJWKS fetches the JWKS for the given issuer, using the cache when
// available. Exposed standalone (no jwks_uri override) for testing and
// warm-prefetch of issuers outside the registry; Validate uses the issuer's
// registered spec instead, which may carry a jwks_uri override.
func (t *TokenValidator) FetchJWKS(issuer string) (*types.JWKS, error) {
	return t.fetchJWKS(&issuerSpec{Issuer: issuer}, false)
}

// fetchJWKS fetches (or serves from cache) the JWKS for spec.Issuer. When
// spec.JWKSURI is set, OIDC discovery is skipped and that URL is fetched
// directly (still required to be a secure URL). When force is true the cache
// is bypassed and the freshly fetched JWKS replaces any cached entry — used
// to recover from signing-key rotation.
func (t *TokenValidator) fetchJWKS(spec *issuerSpec, force bool) (*types.JWKS, error) {
	if !force {
		if cachedJWKS, found := t.cache.Get(spec.Issuer); found && cachedJWKS != nil {
			return cachedJWKS, nil
		}
	}

	jwksURI := spec.JWKSURI
	if jwksURI == "" {
		var err error
		jwksURI, err = t.discoverJWKSURI(spec.Issuer)
		if err != nil {
			return nil, err
		}
	}

	// The (discovered or configured) JWKS URI must also use a secure transport.
	if err := requireSecureURL(jwksURI); err != nil {
		return nil, fmt.Errorf("invalid jwks_uri: %w", err)
	}

	jwks, err := t.getJWKS(jwksURI)
	if err != nil {
		return nil, err
	}

	t.cache.Set(spec.Issuer, jwks, cache.GetConfiguredTTL(t.currentConfig()))
	return jwks, nil
}

// discoverJWKSURI fetches issuer's OIDC discovery document
// (issuer + /.well-known/openid-configuration) and returns its jwks_uri.
func (t *TokenValidator) discoverJWKSURI(issuer string) (string, error) {
	// Enforce a secure transport for the issuer (loopback hosts excepted for
	// tests/local).
	if err := requireSecureURL(issuer); err != nil {
		return "", fmt.Errorf("invalid issuer URL: %w", err)
	}

	resp, err := t.httpc.Get(issuer + "/.well-known/openid-configuration")
	if err != nil {
		slog.Error("Failed to fetch OIDC configuration", "error", err)
		return "", fmt.Errorf("failed to fetch OIDC configuration: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			slog.Error("Failed to close OIDC configuration response body", "error", err)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		slog.Error("Received non-200 status code when fetching OIDC configuration", "status", resp.StatusCode)
		return "", fmt.Errorf("received non-200 status code when fetching OIDC configuration: %d", resp.StatusCode)
	}

	var discovery struct {
		JwksURI string `json:"jwks_uri"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&discovery); err != nil {
		slog.Error("Failed to parse OIDC configuration", "error", err)
		return "", fmt.Errorf("failed to parse OIDC configuration: %w", err)
	}
	return discovery.JwksURI, nil
}

// getJWKS fetches and decodes the JWKS document at jwksURI.
func (t *TokenValidator) getJWKS(jwksURI string) (*types.JWKS, error) {
	resp, err := t.httpc.Get(jwksURI)
	if err != nil {
		slog.Error("Failed to fetch JWKS", "error", err)
		return nil, fmt.Errorf("failed to fetch JWKS: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			slog.Error("Failed to close JWKS response body", "error", err)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		slog.Error("Received non-200 status code when fetching JWKS", "status", resp.StatusCode)
		return nil, fmt.Errorf("received non-200 status code when fetching JWKS: %d", resp.StatusCode)
	}

	var jwks types.JWKS
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&jwks); err != nil {
		slog.Error("Failed to parse JWKS", "error", err)
		return nil, fmt.Errorf("failed to parse JWKS: %w", err)
	}
	if len(jwks.Keys) == 0 {
		return nil, errors.New("jwks contains no keys")
	}
	const maxJWKSKeys = 20
	if len(jwks.Keys) > maxJWKSKeys {
		return nil, fmt.Errorf("jwks contains too many keys (%d > %d)", len(jwks.Keys), maxJWKSKeys)
	}
	return &jwks, nil
}

// GenKeyFunc generates a jwt.Keyfunc that validates JWT tokens using JWKS keys.
// Supports RSA (RS256/384/512) and ECDSA (ES256/384/512) key types.
func (t *TokenValidator) GenKeyFunc(jwks *types.JWKS) jwt.Keyfunc {
	return func(token *jwt.Token) (any, error) {
		kid, ok := token.Header["kid"].(string)
		if !ok {
			return nil, errors.New("missing or invalid kid in token header")
		}

		for _, key := range jwks.Keys {
			if key.KeyID != kid {
				continue
			}
			switch key.KeyType {
			case "RSA":
				return parseRSAKey(key)
			case "EC":
				return parseECKey(key)
			default:
				return nil, fmt.Errorf("unsupported key type %q for kid %q", key.KeyType, kid)
			}
		}
		return nil, ErrKeyNotFound
	}
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

// requireSecureURL ensures u uses HTTPS. Plain HTTP is permitted only for
// loopback hosts (127.0.0.1, ::1, localhost) to support local servers and tests.
func requireSecureURL(u string) error {
	parsed, err := url.Parse(u)
	if err != nil {
		return fmt.Errorf("malformed URL %q: %w", u, err)
	}

	switch parsed.Scheme {
	case "https":
		return nil
	case "http":
		switch parsed.Hostname() {
		case "127.0.0.1", "::1", "localhost":
			return nil
		}
	}

	return fmt.Errorf("insecure scheme %q for host %q (https required)", parsed.Scheme, parsed.Hostname())
}
