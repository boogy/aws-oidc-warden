package validator_test

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
	awsconsumer "github.com/boogy/aws-oidc-warden/internal/aws"
	"github.com/boogy/aws-oidc-warden/internal/cache"
	"github.com/boogy/aws-oidc-warden/internal/config"
	"github.com/boogy/aws-oidc-warden/internal/types"
	"github.com/boogy/aws-oidc-warden/internal/validator"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSelfDelegatedParity proves the "delegated modes are not a weaker path"
// invariant end-to-end: the SAME claim set validated in self
// mode (full signature verification) and in delegated apigw mode (trusting an
// upstream verifier) yields the identical canonical Subject and the identical
// session tags. Both paths route through checkAndNormalizeClaims →
// normalizeClaims, so this guards against them ever drifting apart.
func TestSelfDelegatedParity(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	pub := &privateKey.PublicKey
	const keyID = "parity-key"

	jwks := &types.JWKS{Keys: []types.JSONWebKey{{
		KeyID: keyID, KeyType: "RSA", Algorithm: "RS256", Use: "sig",
		N: base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		E: base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}}}

	var serverURL string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(struct {
				Issuer  string `json:"issuer"`
				JwksURI string `json:"jwks_uri"`
			}{Issuer: serverURL, JwksURI: fmt.Sprintf("http://%s/jwks", r.Host)})
		case "/jwks":
			_ = json.NewEncoder(w).Encode(jwks)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	serverURL = server.URL

	issuer := server.URL
	const audience = "sts.amazonaws.com"
	const repository = "owner/repo"
	exp := time.Now().Add(10 * time.Minute)
	iat := time.Now().Add(-1 * time.Minute)

	cfg := &config.Config{
		Issuers: []config.IssuerConfig{{
			Issuer:         issuer,
			Provider:       "github",
			Audiences:      []string{audience},
			RequiredClaims: []string{"repository"},
			SessionTags:    map[string]string{"repo": "repository", "actor": "actor", "ref": "ref"},
		}},
		RoleSessionName:      "aws-oidc-warden",
		Cache:                &config.Cache{TTL: 10 * time.Minute},
		AllowInsecureIssuers: true,
	}
	require.NoError(t, cfg.Validate())
	issCfg := &cfg.Issuers[0]

	// --- self mode: sign + full verification ---
	selfClaims := &types.Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    issuer,
			Subject:   repository,
			Audience:  jwt.ClaimStrings{audience},
			ExpiresAt: jwt.NewNumericDate(exp),
			IssuedAt:  jwt.NewNumericDate(iat),
		},
		Sub:             repository,
		Actor:           "testuser",
		Repository:      repository,
		RepositoryOwner: "owner",
		Ref:             "refs/heads/main",
		RefType:         "branch",
		EventName:       "push",
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, selfClaims)
	tok.Header["kid"] = keyID
	signed, err := tok.SignedString(privateKey)
	require.NoError(t, err)

	v := validator.NewTokenValidator(config.NewStaticProvider(cfg), cache.NewMemoryCache())
	fromSelf, err := v.Validate(signed)
	require.NoError(t, err)

	// --- delegated apigw mode: same claims as the authorizer's string map ---
	fromDelegated, err := validator.NewAPIGWExtractor(config.NewStaticProvider(cfg)).
		Extract(t.Context(), validator.ExtractionInput{AuthorizerClaims: map[string]string{
			"iss":              issuer,
			"sub":              repository,
			"aud":              audience,
			"exp":              strconv.FormatInt(exp.Unix(), 10),
			"iat":              strconv.FormatInt(iat.Unix(), 10),
			"repository":       repository,
			"repository_owner": "owner",
			"actor":            "testuser",
			"ref":              "refs/heads/main",
			"ref_type":         "branch",
			"event_name":       "push",
		}})
	require.NoError(t, err)

	// Canonical identity parity — the security-critical projection.
	assert.Equal(t, repository, fromSelf.Subject)
	assert.Equal(t, fromSelf.Subject, fromDelegated.Subject, "canonical subject must match across modes")
	assert.Equal(t, fromSelf.Repository, fromDelegated.Repository)
	assert.Equal(t, fromSelf.Actor, fromDelegated.Actor)
	assert.Equal(t, fromSelf.Ref, fromDelegated.Ref)

	// Session-tag parity — same spec + same raw claims => byte-identical tags.
	spec := issCfg.SessionTags
	tagsSelf := awsconsumer.BuildSessionTags(fromSelf.Raw, spec)
	tagsDelegated := awsconsumer.BuildSessionTags(fromDelegated.Raw, spec)
	assert.Equal(t, tagMap(tagsSelf), tagMap(tagsDelegated), "session tags must match across modes")
	assert.Equal(t, map[string]string{"repo": repository, "actor": "testuser", "ref": "refs/heads/main"}, tagMap(tagsSelf))
}

// tagMap flattens STS tags to a comparable key->value map.
func tagMap(tags []ststypes.Tag) map[string]string {
	m := make(map[string]string, len(tags))
	for _, t := range tags {
		m[*t.Key] = *t.Value
	}
	return m
}
