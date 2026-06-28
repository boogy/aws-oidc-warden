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
	"strconv"
	"strings"
	"time"

	"github.com/boogy/aws-oidc-warden/internal/types"
	"github.com/golang-jwt/jwt/v5"
)

const defaultALBKeyEndpoint = "https://public-keys.auth.elb.%s.amazonaws.com/%s"

// ALBExtractor verifies the ALB-signed x-amzn-oidc-data JWT (ES256) and
// extracts GitHub OIDC claims. If expectedSigner is non-empty, the JWT
// header's "signer" field must match exactly (prevents cross-ALB injection).
// Defense-in-depth: re-validates issuer and audience after signature verification.
type ALBExtractor struct {
	expectedSigner    string
	expectedIssuer    string
	expectedAudiences []string
	keyEndpointFmt    string // format string with two %s: region, kid
	httpClient        *http.Client
}

// ALBOption configures ALBExtractor (functional option pattern).
type ALBOption func(*ALBExtractor)

// WithALBKeyEndpoint overrides the public key URL format (for testing).
// The format string receives one %s: the kid.
func WithALBKeyEndpoint(fmtURL string) ALBOption {
	return func(a *ALBExtractor) { a.keyEndpointFmt = fmtURL }
}

// NewALBExtractor creates an ALBExtractor.
// expectedSigner: ALB ARN that must match the JWT "signer" header (empty disables the check).
// expectedIssuer / expectedAudiences: validated after signature verification for defense in depth.
func NewALBExtractor(expectedSigner, expectedIssuer string, expectedAudiences []string, opts ...ALBOption) *ALBExtractor {
	a := &ALBExtractor{
		expectedSigner:    expectedSigner,
		expectedIssuer:    expectedIssuer,
		expectedAudiences: expectedAudiences,
		keyEndpointFmt:    defaultALBKeyEndpoint,
		httpClient:        &http.Client{Timeout: 5 * time.Second},
	}
	for _, o := range opts {
		o(a)
	}
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
func (a *ALBExtractor) Extract(ctx context.Context, input ExtractionInput) (*types.GithubClaims, error) {
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

	signer, _ := unverified.Header["signer"].(string)
	if a.expectedSigner != "" && signer != a.expectedSigner {
		return nil, fmt.Errorf("ALB JWT signer mismatch: got %q, want %q", signer, a.expectedSigner)
	}

	// Fetch ALB public key.
	ecKey, err := a.fetchPublicKey(ctx, input.AWSRegion, kid)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch ALB public key: %w", err)
	}

	// Verify JWT with the EC key; ES256 enforced via WithValidMethods.
	token, err := jwt.ParseWithClaims(
		input.ALBOIDCData,
		jwt.MapClaims{},
		func(t *jwt.Token) (any, error) { return ecKey, nil },
		jwt.WithValidMethods([]string{"ES256"}),
	)
	if err != nil {
		return nil, fmt.Errorf("ALB OIDC JWT verification failed: %w", err)
	}

	mc, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("unexpected ALB JWT claims type")
	}
	return a.mapALBClaims(mc)
}

func (a *ALBExtractor) fetchPublicKey(ctx context.Context, region, kid string) (*ecdsa.PublicKey, error) {
	placeholderCount := strings.Count(a.keyEndpointFmt, "%s")
	if region == "" && placeholderCount == 2 {
		return nil, fmt.Errorf("AWSRegion is required for ALB public key lookup; set AWS_REGION env var")
	}

	var keyURL string
	if placeholderCount == 2 {
		keyURL = fmt.Sprintf(a.keyEndpointFmt, region, kid)
	} else {
		// test override with single %s (just kid)
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
	return ecKey, nil
}

func (a *ALBExtractor) mapALBClaims(mc jwt.MapClaims) (*types.GithubClaims, error) {
	// Convert MapClaims to map[string]string for reuse with mapAPIGWClaims.
	// jwt.MapClaims stores numeric values as float64; use FormatInt to avoid
	// scientific notation (e.g. "1.75e+09") that breaks ParseInt.
	raw := make(map[string]string, len(mc))
	for k, v := range mc {
		switch val := v.(type) {
		case string:
			raw[k] = val
		case float64:
			raw[k] = strconv.FormatInt(int64(val), 10)
		default:
			raw[k] = fmt.Sprintf("%v", val)
		}
	}

	// Defense-in-depth: re-validate issuer and audience after signature verification.
	// Guards against an ALB misconfigured with a different OIDC provider.
	iss := raw["iss"]
	if iss != a.expectedIssuer {
		return nil, fmt.Errorf("ALB JWT iss mismatch: got %q, want %q", iss, a.expectedIssuer)
	}
	aud := raw["aud"]
	matched := false
	for _, want := range a.expectedAudiences {
		if aud == want {
			matched = true
			break
		}
	}
	if !matched {
		return nil, fmt.Errorf("ALB JWT aud mismatch: got %q, not in allowed set %v", aud, a.expectedAudiences)
	}

	return (&APIGWExtractor{
		expectedIssuer:    a.expectedIssuer,
		expectedAudiences: a.expectedAudiences,
	}).mapAPIGWClaims(raw)
}
