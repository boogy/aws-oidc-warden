package validator

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/boogy/aws-oidc-warden/internal/config"
	"github.com/boogy/aws-oidc-warden/internal/types"
	"github.com/golang-jwt/jwt/v5"
)

const defaultALBKeyEndpoint = "https://public-keys.auth.elb.%s.amazonaws.com/%s"

// albRegionRe constrains AWS_REGION before it is interpolated into the key
// endpoint URL. AWS_REGION is operator-set (trusted), so this is an explicit,
// testable guard rather than a fix for an exploit.
var albRegionRe = regexp.MustCompile(`^[a-z]{2}-[a-z]+-\d+$`)

// albKeyCache is a short-lived in-memory cache for ALB EC public keys, keyed by kid.
// Avoids a per-request HTTPS round-trip to the AWS key endpoint.
type albKeyCache struct {
	mu      sync.RWMutex
	entries map[string]albKeyCacheEntry
}

type albKeyCacheEntry struct {
	key       *ecdsa.PublicKey
	expiresAt time.Time
}

const albKeyCacheTTL = 5 * time.Minute

func (c *albKeyCache) get(kid string) (*ecdsa.PublicKey, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[kid]
	if !ok || time.Now().After(e.expiresAt) {
		delete(c.entries, kid)
		return nil, false
	}
	return e.key, true
}

func (c *albKeyCache) set(kid string, key *ecdsa.PublicKey) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.entries == nil {
		c.entries = make(map[string]albKeyCacheEntry)
	}
	c.entries[kid] = albKeyCacheEntry{key: key, expiresAt: time.Now().Add(albKeyCacheTTL)}
}

// ALBExtractor verifies the ALB-signed x-amzn-oidc-data JWT (ES256) and
// extracts GitHub OIDC claims. If expectedSigner is non-empty, the JWT
// header's "signer" field must match exactly (prevents cross-ALB injection).
// Defense-in-depth: re-validates issuer and every other claim self mode
// checks (sub, iat, nbf, audience, lifetime/age caps, required_claims)
// through the same checkAndNormalizeClaims path Validate() uses — ALB signs
// the token itself, so only signature *trust* differs from self mode
// (SHARED.md invariant #6).
type ALBExtractor struct {
	provider       *config.Provider
	keyEndpointFmt string // format string for the public key URL
	testEndpoint   bool   // true when keyEndpointFmt uses a single %s (test override)
	httpClient     *http.Client
	keyCache       albKeyCache
}

// ALBOption configures ALBExtractor (functional option pattern).
type ALBOption func(*ALBExtractor)

// WithALBKeyEndpoint overrides the public key URL format (for testing).
// The format string receives one %s: the kid.
func WithALBKeyEndpoint(fmtURL string) ALBOption {
	return func(a *ALBExtractor) { a.keyEndpointFmt = fmtURL }
}

// WithALBHTTPClient overrides the http.Client used to fetch the ALB public
// key (for testing). Production always gets the SSRF-hardened default
// (newSecureHTTPClient(false, ...)), which blocks loopback; tests dialing an
// httptest server on 127.0.0.1 must inject a client that allows it (e.g.
// newSecureHTTPClient(true, ...)).
func WithALBHTTPClient(c *http.Client) ALBOption {
	return func(a *ALBExtractor) { a.httpClient = c }
}

// NewALBExtractor creates an ALBExtractor for the delegated "alb" mode's
// single configured issuer. provider is read on every Extract() call (via
// resolveDelegatedSpec, plus a live read of JWTValidation.ALBExpectedSigner),
// so a hot-reloaded audiences/claim_mappings/required_claims/jwt_leeway/
// alb_expected_signer change takes effect without a restart, matching self
// mode.
func NewALBExtractor(provider *config.Provider, opts ...ALBOption) *ALBExtractor {
	a := &ALBExtractor{
		provider:       provider,
		keyEndpointFmt: defaultALBKeyEndpoint,
		httpClient:     newSecureHTTPClient(false, 5*time.Second),
	}
	for _, o := range opts {
		o(a)
	}
	a.testEndpoint = strings.Count(a.keyEndpointFmt, "%s") == 1
	return a
}

// isValidALBKid rejects kid values that could manipulate the key endpoint URL.
// Only ASCII alphanumeric, hyphen, and underscore are permitted (max 128 chars).
func isValidALBKid(kid string) bool {
	if len(kid) == 0 || len(kid) > 128 {
		return false
	}
	for _, r := range kid {
		if (r < 'A' || r > 'Z') && (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' && r != '_' {
			return false
		}
	}
	return true
}

// Extract verifies the ALB-signed JWT and returns the embedded OIDC claims.
func (a *ALBExtractor) Extract(ctx context.Context, input ExtractionInput) (*types.Claims, error) {
	if input.ALBOIDCData == "" {
		return nil, fmt.Errorf("x-amzn-oidc-data header is absent: request may have bypassed ALB OIDC")
	}

	// Parse without verification to extract kid and signer from header.
	unverified, _, err := jwt.NewParser().ParseUnverified(input.ALBOIDCData, jwt.MapClaims{})
	if err != nil {
		return nil, fmt.Errorf("failed to parse ALB OIDC JWT: %w", err)
	}

	kid, _ := unverified.Header["kid"].(string)
	// Validate kid before using it in a URL — prevents SSRF via path traversal or
	// URL injection in the key endpoint format string.
	if !isValidALBKid(kid) {
		return nil, fmt.Errorf("ALB JWT kid contains invalid characters: %q", kid)
	}

	cfg := a.provider.Get()
	spec, bounds, err := resolveDelegatedSpec(cfg)
	if err != nil {
		return nil, err
	}

	expectedSigner := cfg.JWTValidation.ALBExpectedSigner
	signer, _ := unverified.Header["signer"].(string)
	if expectedSigner != "" && signer != expectedSigner {
		return nil, fmt.Errorf("ALB JWT signer mismatch: got %q, want %q", signer, expectedSigner)
	}

	// Fetch ALB public key.
	ecKey, err := a.fetchPublicKey(ctx, input.AWSRegion, kid)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch ALB public key: %w", err)
	}

	// Verify JWT with the EC key; ES256 enforced via WithValidMethods.
	// Match self-mode strictness: require exp and validate iat at the library level.
	token, err := jwt.ParseWithClaims(
		input.ALBOIDCData,
		jwt.MapClaims{},
		func(t *jwt.Token) (any, error) { return ecKey, nil },
		jwt.WithValidMethods([]string{"ES256"}),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
	)
	if err != nil {
		return nil, fmt.Errorf("ALB OIDC JWT verification failed: %w", err)
	}

	mc, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("unexpected ALB JWT claims type")
	}

	// Re-validate issuer — guards against a reused or misconfigured ALB OIDC
	// setup, and against a token from a different, unconfigured issuer.
	verifiedIssuer, err := mc.GetIssuer()
	if err != nil || verifiedIssuer != spec.Issuer {
		return nil, fmt.Errorf("iss mismatch: got %q, want %q", verifiedIssuer, spec.Issuer)
	}

	return checkAndNormalizeClaims(mc, spec, bounds, time.Now())
}

func (a *ALBExtractor) fetchPublicKey(ctx context.Context, region, kid string) (*ecdsa.PublicKey, error) {
	if key, ok := a.keyCache.get(kid); ok {
		return key, nil
	}

	if !a.testEndpoint {
		if region == "" {
			return nil, fmt.Errorf("AWSRegion is required for ALB public key lookup; set AWS_REGION env var")
		}
		if !albRegionRe.MatchString(region) {
			return nil, fmt.Errorf("AWSRegion %q is not a valid AWS region", region)
		}
	}

	var keyURL string
	if !a.testEndpoint {
		keyURL = fmt.Sprintf(a.keyEndpointFmt, region, kid)
	} else {
		keyURL = fmt.Sprintf(a.keyEndpointFmt, kid)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, keyURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil {
			slog.Error("failed to close ALB key endpoint response body", "error", cerr)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ALB key endpoint returned HTTP %d for kid %q", resp.StatusCode, kid)
	}

	pemBytes, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block from ALB key endpoint")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse ALB public key: %w", err)
	}
	ecKey, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("ALB public key is not an EC key")
	}
	// Enforce P-256 — ES256 requires P-256; other curves cause unexpected behaviour.
	if ecKey.Curve != elliptic.P256() {
		return nil, fmt.Errorf("ALB public key uses unexpected curve %s, expected P-256", ecKey.Curve.Params().Name)
	}
	a.keyCache.set(kid, ecKey)
	return ecKey, nil
}
