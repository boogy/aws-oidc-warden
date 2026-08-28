package validator_test

// Delegated validation (apigw/alb modes): the claim-check path must stay
// identical to self mode, and the trust boundary must hold — a delegated
// front-end may assert claims, never widen them.
import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
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

// TestSelfDelegatedParityMultiIssuer extends the parity proof to a
// multi-issuer config: a token from the SECOND configured issuer must yield the
// identical canonical Subject and session tags in self mode and in delegated
// apigw mode. A decoy issuer sits at index 0 with a different provider,
// audience and claim_mappings, so resolving the wrong spec cannot silently
// produce the right answer.
func TestSelfDelegatedParityMultiIssuer(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	pub := &privateKey.PublicKey
	const keyID = "parity-multi-key"

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
		Issuers: []config.IssuerConfig{
			{
				// Decoy: different provider, audience, mappings and tag spec.
				Issuer:         "https://gitlab.example.com",
				Provider:       "generic",
				Audiences:      []string{"aws-oidc-warden"},
				ClaimMappings:  map[string]string{"subject": "project_path"},
				RequiredClaims: []string{"project_path"},
				SessionTags:    map[string]string{"project": "project_path"},
			},
			{
				Issuer:         issuer,
				Provider:       "github",
				Audiences:      []string{audience},
				RequiredClaims: []string{"repository"},
				SessionTags:    map[string]string{"repo": "repository", "actor": "actor", "ref": "ref"},
			},
		},
		RoleSessionName:      "aws-oidc-warden",
		Cache:                &config.Cache{TTL: 10 * time.Minute},
		AllowInsecureIssuers: true,
	}
	require.NoError(t, cfg.Validate())
	issCfg := &cfg.Issuers[1]

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

	// Session-tag parity, using the MATCHED issuer's spec (index 1, not 0).
	tagsSelf := awsconsumer.BuildSessionTags(fromSelf.Raw, issCfg.SessionTags)
	tagsDelegated := awsconsumer.BuildSessionTags(fromDelegated.Raw, issCfg.SessionTags)
	assert.Equal(t, tagMap(tagsSelf), tagMap(tagsDelegated), "session tags must match across modes")
	assert.Equal(t, map[string]string{"repo": repository, "actor": "testuser", "ref": "refs/heads/main"}, tagMap(tagsSelf))
}

// ---------- trust boundary ----------

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

// durPtr returns a pointer to d, for config.Config.JWTLeeway's *time.Duration
// field.
func durPtr(d time.Duration) *time.Duration { return &d }

// apigwOpaqueParityFixture builds the JWKS server, signing key and config
// shared by TestApigwNoneOfDenyListOpaqueClaimParity and
// TestApigwPositiveConditionMatchesOpaqueClaimVerbatim.
func apigwOpaqueParityFixture(t *testing.T) (cfg *config.Config, privateKey *rsa.PrivateKey, keyID string, issuer string) {
	t.Helper()
	pk, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	pub := &pk.PublicKey
	const kid = "opaque-claim-key"

	jwks := &types.JWKS{Keys: []types.JSONWebKey{{
		KeyID: kid, KeyType: "RSA", Algorithm: "RS256", Use: "sig",
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
	t.Cleanup(server.Close)
	serverURL = server.URL

	c := &config.Config{
		Issuers: []config.IssuerConfig{{
			Issuer:         serverURL,
			Provider:       "generic",
			Audiences:      []string{"sts.amazonaws.com"},
			ClaimMappings:  map[string]string{"subject": "project_path"},
			RequiredClaims: []string{"project_path"},
		}},
		RoleMappings: []config.RoleMapping{{
			Subject: "grp/prj",
			Roles:   []string{"arn:aws:iam::123456789012:role/deploy"},
			Conditions: &config.Condition{NoneOf: []*config.Condition{
				{Claims: map[string]config.Patterns{"groups": {"break-glass"}}},
			}},
		}},
		RoleSessionName:      "aws-oidc-warden",
		JWTLeeway:            durPtr(30 * time.Second),
		Cache:                &config.Cache{TTL: 10 * time.Minute},
		AllowInsecureIssuers: true,
	}
	require.NoError(t, c.Validate())
	return c, pk, kid, serverURL
}

// signOpaqueParityToken signs a jwt.MapClaims token over the fixture's key.
func signOpaqueParityToken(t *testing.T, pk *rsa.PrivateKey, kid, issuer string, groups any) string {
	t.Helper()
	now := time.Now()
	claims := jwt.MapClaims{
		"iss":          issuer,
		"sub":          "grp/prj",
		"aud":          "sts.amazonaws.com",
		"project_path": "grp/prj",
		"iat":          now.Add(-1 * time.Minute).Unix(),
		"exp":          now.Add(30 * time.Minute).Unix(),
		"groups":       groups,
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = kid
	signed, err := tok.SignedString(pk)
	require.NoError(t, err)
	return signed
}

func TestApigwNoneOfDenyListOpaqueClaimParity(t *testing.T) {
	cfg, pk, kid, issuer := apigwOpaqueParityFixture(t)

	cases := []struct {
		name              string
		groups            any
		authorizerRawText string
	}{
		{"array claim", []string{"break-glass"}, "[break-glass]"},
		{"object claim", map[string]bool{"break-glass": true}, "map[break-glass:true]"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			signed := signOpaqueParityToken(t, pk, kid, issuer, tc.groups)
			v := validator.NewTokenValidator(config.NewStaticProvider(cfg), cache.NewMemoryCache())
			selfClaims, err := v.Validate(signed)
			require.NoError(t, err, "self mode must accept the token itself (the deny-list is an authorization concern, not a validation one)")
			selfAuthorized, selfRoles := cfg.AuthorizeRoles(selfClaims.Issuer, selfClaims.Subject, selfClaims.Raw)
			assert.False(t, selfAuthorized, "self mode: none_of on a real %s must veto and deny", tc.name)
			assert.Empty(t, selfRoles)

			delegatedClaims, err := validator.NewAPIGWExtractor(config.NewStaticProvider(cfg)).
				Extract(t.Context(), validator.ExtractionInput{AuthorizerClaims: map[string]string{
					"iss":          issuer,
					"sub":          "grp/prj",
					"aud":          "sts.amazonaws.com",
					"project_path": "grp/prj",
					"iat":          strconv.FormatInt(time.Now().Add(-1*time.Minute).Unix(), 10),
					"exp":          strconv.FormatInt(time.Now().Add(30*time.Minute).Unix(), 10),
					"groups":       tc.authorizerRawText,
				}})
			require.NoError(t, err)
			delegatedAuthorized, delegatedRoles := cfg.AuthorizeRoles(delegatedClaims.Issuer, delegatedClaims.Subject, delegatedClaims.Raw)

			assert.False(t, delegatedAuthorized, "F-1 REGRESSION: apigw mode granted a role to a caller carrying the vetoed %s, via the stringified rendering %q", tc.name, tc.authorizerRawText)
			assert.Empty(t, delegatedRoles)

			assert.Equal(t, selfAuthorized, delegatedAuthorized, "self mode and apigw mode must reach the same authorization decision for the same logical token")
		})
	}
}

func TestApigwPositiveConditionMatchesOpaqueClaimVerbatim(t *testing.T) {
	pk, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	pub := &pk.PublicKey
	const kid = "opaque-positive-key"

	jwks := &types.JWKS{Keys: []types.JSONWebKey{{
		KeyID: kid, KeyType: "RSA", Algorithm: "RS256", Use: "sig",
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
	t.Cleanup(server.Close)
	serverURL = server.URL
	issuer := serverURL

	cfg := &config.Config{
		Issuers: []config.IssuerConfig{{
			Issuer:         issuer,
			Provider:       "generic",
			Audiences:      []string{"sts.amazonaws.com"},
			ClaimMappings:  map[string]string{"subject": "project_path"},
			RequiredClaims: []string{"project_path"},
		}},
		RoleMappings: []config.RoleMapping{{
			Subject: "grp/prj",
			Roles:   []string{"arn:aws:iam::123456789012:role/deploy"},
			Conditions: &config.Condition{
				Claims: map[string]config.Patterns{"groups": {regexp.QuoteMeta("[break-glass]")}},
			},
		}},
		RoleSessionName: "aws-oidc-warden",
		JWTLeeway:       durPtr(30 * time.Second),
		Cache:           &config.Cache{TTL: 10 * time.Minute},
	}
	require.NoError(t, cfg.Validate())

	delegatedClaims, err := validator.NewAPIGWExtractor(config.NewStaticProvider(cfg)).
		Extract(t.Context(), validator.ExtractionInput{AuthorizerClaims: map[string]string{
			"iss":          issuer,
			"sub":          "grp/prj",
			"aud":          "sts.amazonaws.com",
			"project_path": "grp/prj",
			"iat":          strconv.FormatInt(time.Now().Add(-1*time.Minute).Unix(), 10),
			"exp":          strconv.FormatInt(time.Now().Add(30*time.Minute).Unix(), 10),
			"groups":       "[break-glass]",
		}})
	require.NoError(t, err)

	authorized, roles := cfg.AuthorizeRoles(delegatedClaims.Issuer, delegatedClaims.Subject, delegatedClaims.Raw)
	assert.True(t, authorized, "a positive condition matching an OpaqueClaim's verbatim literal text must still authorize")
	assert.Equal(t, []string{"arn:aws:iam::123456789012:role/deploy"}, roles)
}
