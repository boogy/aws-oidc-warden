package validator_test

// Adversarial verification of the token trust boundary: cross-issuer key and
// audience isolation, signature/algorithm attacks, time bounds, required
// claims, and canonical-subject derivation.

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/boogy/aws-oidc-warden/internal/cache"
	"github.com/boogy/aws-oidc-warden/internal/config"
	"github.com/boogy/aws-oidc-warden/internal/types"
	"github.com/boogy/aws-oidc-warden/internal/validator"
	"github.com/golang-jwt/jwt/v5"
)

type vIssuerSrv struct {
	url    string
	key    *rsa.PrivateKey
	kid    string
	server *httptest.Server
	hits   *int32
}

func newVIssuer(t *testing.T, kid string) *vIssuerSrv {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	var hits int32
	is := &vIssuerSrv{key: key, kid: kid, hits: &hits}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer": is.url, "jwks_uri": is.url + "/jwks",
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		_ = json.NewEncoder(w).Encode(&types.JWKS{Keys: []types.JSONWebKey{{
			KeyID: kid, KeyType: "RSA", Algorithm: "RS256", Use: "sig",
			N: base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
			E: base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.PublicKey.E)).Bytes()),
		}}})
	})
	srv := httptest.NewServer(mux)
	is.server = srv
	is.url = srv.URL
	t.Cleanup(srv.Close)
	return is
}

// sign issues a token with the given claims signed by this issuer's key.
func (is *vIssuerSrv) sign(t *testing.T, claims jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = is.kid
	s, err := tok.SignedString(is.key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func vclaims(iss, aud, sub string) jwt.MapClaims {
	now := time.Now()
	return jwt.MapClaims{
		"iss": iss, "aud": aud, "sub": sub,
		"repository": "myorg/repo", "repository_owner": "myorg",
		"iat": now.Unix(), "exp": now.Add(10 * time.Minute).Unix(),
	}
}

func vvalidator(t *testing.T, issuers []config.IssuerConfig) *validator.TokenValidator {
	t.Helper()
	cfg := &config.Config{
		Issuers: issuers, RoleSessionName: "aow", AllowInsecureIssuers: true,
		Cache: &config.Cache{Type: "memory", TTL: time.Minute, MaxLocalSize: 10},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	ch, err := cache.NewCache(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return validator.NewTokenValidator(config.NewStaticProvider(cfg), ch)
}

// ---------- V1: cross-issuer isolation ----------

// TestCrossIssuerKeyConfusion is the central multi-issuer property:
// issuer A's signing key must never validate a token that CLAIMS issuer B.
func TestCrossIssuerKeyConfusion(t *testing.T) {
	a := newVIssuer(t, "kid-a")
	b := newVIssuer(t, "kid-b")
	v := vvalidator(t, []config.IssuerConfig{
		{Issuer: a.url, Provider: "github", Audiences: []string{"aud-a"}},
		{Issuer: b.url, Provider: "github", Audiences: []string{"aud-b"}},
	})

	// Sanity: each issuer's own token validates.
	if _, err := v.Validate(a.sign(t, vclaims(a.url, "aud-a", "repo:myorg/repo:ref:refs/heads/main"))); err != nil {
		t.Fatalf("legitimate issuer-A token rejected: %v", err)
	}
	if _, err := v.Validate(b.sign(t, vclaims(b.url, "aud-b", "repo:myorg/repo:ref:refs/heads/main"))); err != nil {
		t.Fatalf("legitimate issuer-B token rejected: %v", err)
	}

	// Attack: sign with A's key but claim to be B.
	forged := a.sign(t, vclaims(b.url, "aud-b", "repo:myorg/repo:ref:refs/heads/main"))
	if _, err := v.Validate(forged); err == nil {
		t.Error("CROSS-ISSUER KEY CONFUSION: issuer A's key validated a token claiming issuer B")
	}

	// Attack: A's token presenting B's audience.
	if _, err := v.Validate(a.sign(t, vclaims(a.url, "aud-b", "s"))); err == nil {
		t.Error("AUDIENCE LEAK: issuer A accepted issuer B's audience")
	}
	// Attack: B's token presenting A's audience.
	if _, err := v.Validate(b.sign(t, vclaims(b.url, "aud-a", "s"))); err == nil {
		t.Error("AUDIENCE LEAK: issuer B accepted issuer A's audience")
	}
}

// TestUnknownIssuerNoNetworkFetch proves an unknown issuer is denied
// with no JWKS/discovery request — no SSRF primitive via the iss claim.
func TestUnknownIssuerNoNetworkFetch(t *testing.T) {
	a := newVIssuer(t, "kid-a")
	rogue := newVIssuer(t, "kid-r")
	v := vvalidator(t, []config.IssuerConfig{
		{Issuer: a.url, Provider: "github", Audiences: []string{"aud-a"}},
	})
	before := atomic.LoadInt32(rogue.hits)
	if _, err := v.Validate(rogue.sign(t, vclaims(rogue.url, "aud-a", "s"))); err == nil {
		t.Fatal("FAIL-OPEN: unconfigured issuer accepted")
	}
	if got := atomic.LoadInt32(rogue.hits) - before; got != 0 {
		t.Errorf("SSRF: %d request(s) made to the unconfigured issuer's host", got)
	}
}

// ---------- V2: signature / algorithm ----------

func TestAlgNoneAndTampering(t *testing.T) {
	a := newVIssuer(t, "kid-a")
	v := vvalidator(t, []config.IssuerConfig{
		{Issuer: a.url, Provider: "github", Audiences: []string{"aud-a"}},
	})

	// alg: none
	noneTok := jwt.NewWithClaims(jwt.SigningMethodNone, vclaims(a.url, "aud-a", "s"))
	noneTok.Header["kid"] = a.kid
	s, err := noneTok.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Validate(s); err == nil {
		t.Error("CRITICAL: alg=none token accepted")
	}

	// HMAC confusion: sign with HS256 using the RSA public modulus as secret.
	hs := jwt.NewWithClaims(jwt.SigningMethodHS256, vclaims(a.url, "aud-a", "s"))
	hs.Header["kid"] = a.kid
	hsTok, err := hs.SignedString(a.key.N.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Validate(hsTok); err == nil {
		t.Error("CRITICAL: HS256/RSA algorithm-confusion token accepted")
	}

	// Payload tampering: swap the claims segment, keep the signature.
	good := a.sign(t, vclaims(a.url, "aud-a", "repo:myorg/repo"))
	evil := a.sign(t, vclaims(a.url, "aud-a", "repo:evil/repo"))
	gp, ep := strings.Split(good, "."), strings.Split(evil, ".")
	spliced := gp[0] + "." + ep[1] + "." + gp[2]
	if _, err := v.Validate(spliced); err == nil {
		t.Error("CRITICAL: payload-tampered token accepted")
	}

	// Unknown kid.
	unk := jwt.NewWithClaims(jwt.SigningMethodRS256, vclaims(a.url, "aud-a", "s"))
	unk.Header["kid"] = "no-such-kid"
	uTok, err := unk.SignedString(a.key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Validate(uTok); err == nil {
		t.Error("unknown kid accepted")
	}
}

// ---------- V3: time bounds ----------

func TestTimeBounds(t *testing.T) {
	a := newVIssuer(t, "kid-a")
	v := vvalidator(t, []config.IssuerConfig{
		{Issuer: a.url, Provider: "github", Audiences: []string{"aud-a"}},
	})
	now := time.Now()

	cases := map[string]jwt.MapClaims{
		"expired": {"iss": a.url, "aud": "aud-a", "sub": "s", "repository": "myorg/repo",
			"iat": now.Add(-2 * time.Hour).Unix(), "exp": now.Add(-1 * time.Hour).Unix()},
		"iat in future": {"iss": a.url, "aud": "aud-a", "sub": "s", "repository": "myorg/repo",
			"iat": now.Add(1 * time.Hour).Unix(), "exp": now.Add(2 * time.Hour).Unix()},
		"nbf in future": {"iss": a.url, "aud": "aud-a", "sub": "s", "repository": "myorg/repo",
			"iat": now.Unix(), "nbf": now.Add(1 * time.Hour).Unix(), "exp": now.Add(2 * time.Hour).Unix()},
		"no exp": {"iss": a.url, "aud": "aud-a", "sub": "s", "repository": "myorg/repo",
			"iat": now.Unix()},
		"lifetime over cap": {"iss": a.url, "aud": "aud-a", "sub": "s", "repository": "myorg/repo",
			"iat": now.Unix(), "exp": now.Add(6 * time.Hour).Unix()},
		"too old": {"iss": a.url, "aud": "aud-a", "sub": "s", "repository": "myorg/repo",
			"iat": now.Add(-3 * time.Hour).Unix(), "exp": now.Add(1 * time.Hour).Unix()},
		"empty sub": {"iss": a.url, "aud": "aud-a", "sub": "", "repository": "myorg/repo",
			"iat": now.Unix(), "exp": now.Add(10 * time.Minute).Unix()},
		"no aud": {"iss": a.url, "sub": "s", "repository": "myorg/repo",
			"iat": now.Unix(), "exp": now.Add(10 * time.Minute).Unix()},
	}
	for name, c := range cases {
		if _, err := v.Validate(a.sign(t, c)); err == nil {
			t.Errorf("FAIL-OPEN: %q token accepted", name)
		}
	}
}

// ---------- V4: required claims + subject derivation ----------

func TestRequiredClaimsAndSubject(t *testing.T) {
	a := newVIssuer(t, "kid-a")
	v := vvalidator(t, []config.IssuerConfig{{
		Issuer: a.url, Provider: "github", Audiences: []string{"aud-a"},
		RequiredClaims: []string{"repository", "environment"},
	}})
	now := time.Now()
	base := func() jwt.MapClaims {
		return jwt.MapClaims{"iss": a.url, "aud": "aud-a", "sub": "s",
			"iat": now.Unix(), "exp": now.Add(10 * time.Minute).Unix()}
	}
	// Missing required claim.
	c := base()
	c["repository"] = "myorg/repo"
	if _, err := v.Validate(a.sign(t, c)); err == nil {
		t.Error("FAIL-OPEN: missing required claim accepted")
	}
	// Empty-string required claim.
	c = base()
	c["repository"] = "myorg/repo"
	c["environment"] = ""
	if _, err := v.Validate(a.sign(t, c)); err == nil {
		t.Error("FAIL-OPEN: empty required claim accepted")
	}
	// JSON null required claim.
	c = base()
	c["repository"] = "myorg/repo"
	c["environment"] = nil
	if _, err := v.Validate(a.sign(t, c)); err == nil {
		t.Error("FAIL-OPEN: null required claim accepted")
	}
	// All present -> canonical subject is the repository claim, NOT the raw sub.
	c = base()
	c["repository"] = "myorg/repo"
	c["environment"] = "prod"
	got, err := v.Validate(a.sign(t, c))
	if err != nil {
		t.Fatal(err)
	}
	if got.Subject != "myorg/repo" {
		t.Errorf("canonical subject wrong: %q", got.Subject)
	}
	if got.Sub != "s" {
		t.Errorf("raw sub not preserved: %q", got.Sub)
	}
}

// TestSelfAssertedSubjectIgnored proves a token cannot dictate its own
// canonical subject by including a "subject" claim.
func TestSelfAssertedSubjectIgnored(t *testing.T) {
	a := newVIssuer(t, "kid-a")
	v := vvalidator(t, []config.IssuerConfig{
		{Issuer: a.url, Provider: "github", Audiences: []string{"aud-a"}},
	})
	c := vclaims(a.url, "aud-a", "s")
	c["subject"] = "privileged/repo"
	c["Subject"] = "privileged/repo"
	got, err := v.Validate(a.sign(t, c))
	if err != nil {
		t.Fatal(err)
	}
	if got.Subject != "myorg/repo" {
		t.Errorf("SELF-ASSERTED IDENTITY: canonical subject became %q", got.Subject)
	}
}

// TestTokenSizeCap proves the length guard runs before parsing.
func TestTokenSizeCap(t *testing.T) {
	a := newVIssuer(t, "kid-a")
	cfg := &config.Config{
		Issuers:         []config.IssuerConfig{{Issuer: a.url, Provider: "github", Audiences: []string{"aud-a"}}},
		RoleSessionName: "aow", AllowInsecureIssuers: true, MaxTokenBytes: 100,
		Cache: &config.Cache{Type: "memory", TTL: time.Minute, MaxLocalSize: 10},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	ch, _ := cache.NewCache(cfg)
	v := validator.NewTokenValidator(config.NewStaticProvider(cfg), ch)
	if _, err := v.Validate(a.sign(t, vclaims(a.url, "aud-a", "s"))); err == nil {
		t.Error("oversized token accepted")
	} else if !strings.Contains(err.Error(), "maximum allowed size") {
		t.Errorf("wrong rejection reason: %v", err)
	}
}
