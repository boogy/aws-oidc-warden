package validator_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/boogy/aws-oidc-warden/internal/validator"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func makeALBJWT(t *testing.T, key *ecdsa.PrivateKey, kid, signer string, claims map[string]any) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims(claims))
	tok.Header["kid"] = kid
	tok.Header["signer"] = signer
	signed, err := tok.SignedString(key)
	require.NoError(t, err)
	return signed
}

func TestALBExtractor_Extract(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	kid := "test-kid-123"
	alb := "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/my-alb/abc"

	pubDER, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})

	// Mock key endpoint
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(pubPEM)
	}))
	defer srv.Close()

	token := makeALBJWT(t, priv, kid, alb, map[string]any{
		"iss":        "https://token.actions.githubusercontent.com",
		"sub":        "repo:org/repo:ref:refs/heads/main",
		"aud":        "sts.amazonaws.com",
		"exp":        time.Now().Add(time.Hour).Unix(),
		"iat":        time.Now().Unix(),
		"repository": "org/repo",
		"ref":        "refs/heads/main",
		"ref_type":   "branch",
		"actor":      "octocat",
	})

	ex := validator.NewALBExtractor("", "https://token.actions.githubusercontent.com", []string{"sts.amazonaws.com"}, validator.WithALBKeyEndpoint(srv.URL+"/%s"))
	claims, err := ex.Extract(context.Background(), validator.ExtractionInput{
		ALBOIDCData: token,
		AWSRegion:   "us-east-1",
	})
	require.NoError(t, err)
	assert.Equal(t, "org/repo", claims.Repository)
	assert.Equal(t, "octocat", claims.Actor)
}

func TestALBExtractor_MissingHeader(t *testing.T) {
	ex := validator.NewALBExtractor("", "https://token.actions.githubusercontent.com", []string{"sts.amazonaws.com"})
	_, err := ex.Extract(context.Background(), validator.ExtractionInput{ALBOIDCData: ""})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "x-amzn-oidc-data")
}

func TestALBExtractor_WrongSigner(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	kid := "test-kid-456"
	alb := "arn:aws:elasticloadbalancing:us-east-1:999:loadbalancer/app/evil/xyz"

	pubDER, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(pubPEM) }))
	defer srv.Close()

	token := makeALBJWT(t, priv, kid, alb, map[string]any{
		"iss": "https://token.actions.githubusercontent.com", "aud": "sts.amazonaws.com",
		"repository": "org/repo", "exp": time.Now().Add(time.Hour).Unix(),
	})

	expected := "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/my-alb/abc"
	ex := validator.NewALBExtractor(expected, "https://token.actions.githubusercontent.com", []string{"sts.amazonaws.com"}, validator.WithALBKeyEndpoint(srv.URL+"/%s"))
	_, err := ex.Extract(context.Background(), validator.ExtractionInput{
		ALBOIDCData: token, AWSRegion: "us-east-1",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "signer")
}

func TestALBExtractor_MaliciousKID(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	for _, badKid := range []string{"../../etc/passwd", "?redirect=http://evil", "http://attacker.com/key", " ", ""} {
		token := makeALBJWT(t, priv, badKid, "", map[string]any{
			"repository": "org/repo", "exp": time.Now().Add(time.Hour).Unix(),
		})
		ex := validator.NewALBExtractor("", "https://token.actions.githubusercontent.com", []string{"sts.amazonaws.com"})
		_, err := ex.Extract(context.Background(), validator.ExtractionInput{ALBOIDCData: token, AWSRegion: "us-east-1"})
		require.Errorf(t, err, "expected error for kid=%q", badKid)
		assert.Contains(t, err.Error(), "kid")
	}
}

func TestALBExtractor_IssuerMismatch(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	kid := "test-kid-iss"
	pubDER, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(pubPEM) }))
	defer srv.Close()

	token := makeALBJWT(t, priv, kid, "", map[string]any{
		"iss": "https://evil.example.com", "aud": "sts.amazonaws.com",
		"repository": "org/repo", "exp": time.Now().Add(time.Hour).Unix(),
	})
	ex := validator.NewALBExtractor("", "https://token.actions.githubusercontent.com", []string{"sts.amazonaws.com"}, validator.WithALBKeyEndpoint(srv.URL+"/%s"))
	_, err := ex.Extract(context.Background(), validator.ExtractionInput{ALBOIDCData: token, AWSRegion: "us-east-1"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "iss")
}

func TestALBExtractor_KeyCache(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	kid := "cache-test-kid"
	pubDER, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})

	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		_, _ = w.Write(pubPEM)
	}))
	defer srv.Close()

	token := makeALBJWT(t, priv, kid, "", map[string]any{
		"iss": "https://token.actions.githubusercontent.com", "aud": "sts.amazonaws.com",
		"repository": "org/repo",
		"exp":        time.Now().Add(time.Hour).Unix(),
	})

	ex := validator.NewALBExtractor("", "https://token.actions.githubusercontent.com", []string{"sts.amazonaws.com"}, validator.WithALBKeyEndpoint(srv.URL+"/%s"))
	input := validator.ExtractionInput{ALBOIDCData: token, AWSRegion: "us-east-1"}

	_, err := ex.Extract(context.Background(), input)
	require.NoError(t, err)
	assert.Equal(t, 1, callCount)

	// Second call must use cache, not hit HTTP again.
	_, err = ex.Extract(context.Background(), input)
	require.NoError(t, err)
	assert.Equal(t, 1, callCount, "expected cache hit; key endpoint called again")
}

func TestALBExtractor_MissingRegion(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	token := makeALBJWT(t, priv, "valid-kid", "", map[string]any{
		"iss": "https://token.actions.githubusercontent.com", "aud": "sts.amazonaws.com",
		"repository": "org/repo",
		"exp":        time.Now().Add(time.Hour).Unix(),
	})
	ex := validator.NewALBExtractor("", "https://token.actions.githubusercontent.com", []string{"sts.amazonaws.com"})
	_, err := ex.Extract(context.Background(), validator.ExtractionInput{ALBOIDCData: token, AWSRegion: ""})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "AWSRegion")
}
