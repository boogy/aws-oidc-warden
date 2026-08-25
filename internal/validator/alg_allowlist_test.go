package validator_test

// Signing-algorithm restriction: only RS/ES 256-384-512 may ever verify.
//
// Three independent guards enforce this, and none of them was pinned by a test
// that could fail — deleting jwt.WithValidMethods left the entire suite green:
//
//  1. the parser's allowlist (jwt.WithValidMethods in validator.go);
//  2. the keyfunc's key-type/alg-family check (RSA+"RS*", EC+"ES*");
//  3. the JWKS key's own declared `alg`, when the issuer publishes one.
//
// They overlap, so removing any single one changes no observable behavior.
// This test therefore pins the *property* rather than one mechanism, and the
// fixture deliberately publishes a JWKS with NO declared `alg` — permitted by
// RFC 7517 and common in the wild — so guard 3 is out of the picture and the
// test exercises the two guards that are always present. It fails when guards
// 1 and 2 are both removed; that pair is what actually holds the line.
//
// PS256 is the interesting probe: jwt-go verifies RSA-PSS against the very same
// *rsa.PublicKey the keyfunc returns, and the token below is signed with the
// issuer's real private key, so nothing about the key stops it. `none` and
// HS256 additionally die on key type (the keyfunc returns only *rsa.PublicKey /
// *ecdsa.PublicKey, and HMAC demands []byte), but are pinned here so a future
// keyfunc change cannot open them silently.

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/boogy/aws-oidc-warden/internal/cache"
	"github.com/boogy/aws-oidc-warden/internal/config"
	"github.com/boogy/aws-oidc-warden/internal/types"
	"github.com/boogy/aws-oidc-warden/internal/validator"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidate_RejectsAlgorithmsOutsideTheAllowlist(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	pub := &privateKey.PublicKey
	const keyID = "alg-allowlist-key"
	const audience = "test-audience"

	jwks := &types.JWKS{Keys: []types.JSONWebKey{{
		KeyID:     keyID,
		KeyType:   "RSA",
		Algorithm: "", // no declared alg: the weakest realistic JWKS (see above)
		Use:       "sig",
		N:         base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		E:         base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}}}

	var serverURL string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			w.Header().Set("Content-Type", "application/json")
			require.NoError(t, json.NewEncoder(w).Encode(struct {
				Issuer  string `json:"issuer"`
				JwksURI string `json:"jwks_uri"`
			}{serverURL, fmt.Sprintf("http://%s/jwks", r.Host)}))
		case "/jwks":
			w.Header().Set("Content-Type", "application/json")
			require.NoError(t, json.NewEncoder(w).Encode(jwks))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	serverURL = server.URL
	issuer := server.URL

	newClaims := func() *types.Claims {
		return &types.Claims{
			RegisteredClaims: jwt.RegisteredClaims{
				Issuer:    issuer,
				Subject:   "owner/repo",
				Audience:  jwt.ClaimStrings{audience},
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(10 * time.Minute)),
				IssuedAt:  jwt.NewNumericDate(time.Now()),
			},
			Sub:             "owner/repo",
			Repository:      "owner/repo",
			RepositoryOwner: "owner",
		}
	}

	cfg := &config.Config{
		Issuers: []config.IssuerConfig{{
			Issuer: issuer, Provider: "github",
			Audiences: []string{audience}, RequiredClaims: []string{"repository"},
		}},
		RoleSessionName:      "aws-oidc-warden",
		Cache:                &config.Cache{TTL: 10 * time.Minute},
		AllowInsecureIssuers: true,
	}
	require.NoError(t, cfg.Validate())
	v := validator.NewTokenValidator(config.NewStaticProvider(cfg), cache.NewMemoryCache())

	// Control: RS256 is on the allowlist and must verify, so a rejection below
	// is attributable to the algorithm and not to the fixture.
	t.Run("RS256 is accepted", func(t *testing.T) {
		tok := jwt.NewWithClaims(jwt.SigningMethodRS256, newClaims())
		tok.Header["kid"] = keyID
		signed, err := tok.SignedString(privateKey)
		require.NoError(t, err)

		claims, err := v.Validate(signed)
		require.NoError(t, err)
		require.NotNil(t, claims)
		assert.Equal(t, "owner/repo", claims.Repository)
	})

	// PS256: verifies against the same *rsa.PublicKey the keyfunc returns, and
	// is signed here with the issuer's real private key. With no declared
	// `alg` in the JWKS, only the parser allowlist and the keyfunc's RS/ES
	// family check stand between this token and a successful validation.
	t.Run("PS256 signed with the real issuer key is rejected", func(t *testing.T) {
		tok := jwt.NewWithClaims(jwt.SigningMethodPS256, newClaims())
		tok.Header["kid"] = keyID
		signed, err := tok.SignedString(privateKey)
		require.NoError(t, err)

		claims, err := v.Validate(signed)
		require.Error(t, err, "PS256 is not on the allowlist and must be refused")
		assert.Nil(t, claims)
	})

	// These also die on key type, but pin them so a future keyfunc change
	// cannot open them silently.
	t.Run("alg none is rejected", func(t *testing.T) {
		tok := jwt.NewWithClaims(jwt.SigningMethodNone, newClaims())
		tok.Header["kid"] = keyID
		signed, err := tok.SignedString(jwt.UnsafeAllowNoneSignatureType)
		require.NoError(t, err)

		claims, err := v.Validate(signed)
		require.Error(t, err)
		assert.Nil(t, claims)
	})

	t.Run("HS256 signed with the RSA public key is rejected", func(t *testing.T) {
		tok := jwt.NewWithClaims(jwt.SigningMethodHS256, newClaims())
		tok.Header["kid"] = keyID
		signed, err := tok.SignedString(pub.N.Bytes())
		require.NoError(t, err)

		claims, err := v.Validate(signed)
		require.Error(t, err)
		assert.Nil(t, claims)
	})
}
