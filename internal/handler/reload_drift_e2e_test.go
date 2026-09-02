package handler_test

// Full-pipeline regression guard for the cross-stage config-generation drift
// fixed in commit dac6c13 ("fix(validator): pin one config generation across
// extraction and authz"). Unlike internal/validator's
// TestSelfExtractorIsDecidedByThePinnedConfig (deterministic, single-shot,
// validator package only) or TestProvider_FragmentReload_Race /
// TestValidate_ConcurrentHotSwap_Race (each confined to one package), this
// drives the REAL wiring — config.Provider, validator.NewTokenValidator,
// validator.NewSelfExtractor, handler.NewRequestProcessor — through
// ProcessRequest concurrently with a real hot reload, and checks for the
// specific illegal-authorization combination the fix rules out: a request
// validated under one config generation but authorized under another,
// producing an outcome NEITHER generation would allow on its own.
//
// Scenario: generation A trusts audience "aud-v1" and has a role mapping for
// subject "owner/repo" -> role "Allowed". A reload rotates the audience to
// "aud-v2" and, in the same push, retires that role mapping (empty
// role_mappings). Every worker sends a token whose audience is ONLY valid
// under generation B ("aud-v2") and requests ONLY the role that is ONLY
// valid under generation A ("Allowed"):
//   - pure generation A: token rejected (audience mismatch) -> deny.
//   - pure generation B: token accepted, but no role mapping exists -> deny.
//   - drifted (validated under B, authorized under A): accepted AND
//     authorized -> ALLOW. This is the combination that must never happen.

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	awsiam "github.com/aws/aws-sdk-go-v2/service/iam"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
	"github.com/boogy/aws-oidc-warden/internal/cache"
	"github.com/boogy/aws-oidc-warden/internal/config"
	"github.com/boogy/aws-oidc-warden/internal/handler"
	"github.com/boogy/aws-oidc-warden/internal/types"
	"github.com/boogy/aws-oidc-warden/internal/validator"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
)

const driftAllowedRole = "arn:aws:iam::111111111111:role/Allowed"

// --- minimal JWKS/signing helpers (adapted from internal/validator/jwks_test.go;
// duplicated here because they're unexported in that package). ---

func driftJWK(kid string, pub *rsa.PublicKey) types.JSONWebKey {
	return types.JSONWebKey{
		KeyID: kid, KeyType: "RSA", Algorithm: "RS256", Use: "sig",
		N: base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		E: base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}
}

func driftSignToken(t *testing.T, key *rsa.PrivateKey, kid, issuer, audience string) string {
	t.Helper()
	claims := &types.Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer: issuer, Subject: "owner/repo", Audience: jwt.ClaimStrings{audience},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(10 * time.Minute)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
		Sub: "owner/repo", Repository: "owner/repo", Ref: "refs/heads/main",
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = kid
	signed, err := token.SignedString(key)
	require.NoError(t, err)
	return signed
}

func driftOIDCServer(t *testing.T, jwks *types.JWKS) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(struct {
				Issuer  string `json:"issuer"`
				JwksURI string `json:"jwks_uri"`
			}{Issuer: "http://" + r.Host, JwksURI: fmt.Sprintf("http://%s/jwks", r.Host)})
		case "/jwks":
			_ = json.NewEncoder(w).Encode(jwks)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// --- fake AWS consumer: records every AssumeRole call's (role, audience) pair. ---

type driftCall struct {
	role string
	aud  string
}

type driftConsumer struct {
	mu    sync.Mutex
	calls []driftCall
}

func (c *driftConsumer) ReadS3Configuration() error { return nil }
func (c *driftConsumer) GetS3Object(string, string) (io.ReadCloser, error) {
	return nil, fmt.Errorf("unused")
}
func (c *driftConsumer) GetRole(string) (*awsiam.GetRoleOutput, error) { return nil, nil }
func (c *driftConsumer) GetRoleTags(string) (map[string]string, error) { return nil, nil }
func (c *driftConsumer) IsTargetAccountAllowed(string) (bool, error)   { return true, nil }
func (c *driftConsumer) AssumeRole(roleARN, _ string, _ *string, _ *int32, claims *types.Claims, _ map[string]string) (*ststypes.Credentials, error) {
	aud := ""
	if len(claims.Audience) > 0 {
		aud = claims.Audience[0]
	}
	c.mu.Lock()
	c.calls = append(c.calls, driftCall{role: roleARN, aud: aud})
	c.mu.Unlock()
	return &ststypes.Credentials{
		AccessKeyId: awssdk.String("AKIA"), SecretAccessKey: awssdk.String("s"),
		SessionToken: awssdk.String("t"), Expiration: awssdk.Time(time.Now().Add(time.Hour)),
	}, nil
}

// delayedValidator embeds the real *validator.TokenValidator (so it still
// satisfies the unexported pinnedValidator seam via promotion, exactly like
// the production type) and only widens the fallback (unpinned) path's
// internal provider.Get() timing, to give a concurrent hot reload a realistic
// chance to land in the gap. See the comment where it's constructed.
type delayedValidator struct {
	*validator.TokenValidator
}

func (d *delayedValidator) Validate(token string) (*types.Claims, error) {
	// DO NOT REMOVE THIS SLEEP. It is load-bearing, and its removal is silent:
	// with the fix reverted and this sleep deleted, the test still PASSES (3/3
	// runs measured), because the gap it widens is a few hundred nanoseconds of
	// pure CPU with a warm in-memory JWKS cache. The sleep is what makes the
	// regression detectable at all — verified by mutation: fix reverted + sleep
	// present => FAIL with ~1000 illegal authorizations; fix reverted + sleep
	// removed => PASS. A future reader tidying away an "unnecessary" sleep would
	// leave a test that can no longer fail.
	time.Sleep(2 * time.Millisecond)
	return d.TokenValidator.Validate(token)
}

// driftGenA is the pristine base: audience aud-v1, role mapping present.
func driftGenA(issuer string) *config.Config {
	return &config.Config{
		Issuers: []config.IssuerConfig{{
			Issuer: issuer, Provider: "github", Audiences: []string{"aud-v1"},
			RequiredClaims: []string{"repository"},
		}},
		RoleSessionName:      "aws-oidc-warden",
		Cache:                &config.Cache{TTL: 10 * time.Minute},
		AllowInsecureIssuers: true,
		RoleMappings: []config.RoleMapping{{
			Subject: config.Patterns{"owner/repo"},
			Roles:   []string{driftAllowedRole},
		}},
	}
}

// driftGenBJSON is the reload payload: audience rotated to aud-v2 AND the
// role mapping retired (empty role_mappings), in the same push.
func driftGenBJSON(issuer string) []byte {
	return []byte(fmt.Sprintf(`{
		"issuers": [{"issuer": %q, "provider": "github", "audiences": ["aud-v2"], "required_claims": ["repository"]}],
		"role_mappings": []
	}`, issuer))
}

// driftGenAJSON is the same shape as driftGenA, as an overlay payload — used
// to flip the provider back to generation A so the fetch function keeps
// oscillating A<->B for the whole test run instead of settling on B after
// the first refresh (a single one-shot transition gives the race only a
// handful of chances to land in the window; continuous oscillation gives it
// thousands).
func driftGenAJSON(issuer string) []byte {
	return []byte(fmt.Sprintf(`{
		"issuers": [{"issuer": %q, "provider": "github", "audiences": ["aud-v1"], "required_claims": ["repository"]}],
		"role_mappings": [{"subject": "owner/repo", "roles": [%q]}]
	}`, issuer, driftAllowedRole))
}

// runDrift wires the real pipeline and hammers it concurrently with a hot
// reload in flight; returns every recorded AssumeRole call.
func runDrift(t *testing.T, refreshInterval time.Duration) []driftCall {
	t.Helper()
	silenceDefaultLogger(t)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	jwks := &types.JWKS{Keys: []types.JSONWebKey{driftJWK("k1", &key.PublicKey)}}
	srv := driftOIDCServer(t, jwks)

	base := driftGenA(srv.URL)
	require.NoError(t, base.Validate())

	var refreshCount int64
	provider := config.NewProvider(base, refreshInterval, "json", func(context.Context) ([]byte, error) {
		n := atomic.AddInt64(&refreshCount, 1)
		if n%2 == 0 {
			return driftGenAJSON(srv.URL), nil
		}
		return driftGenBJSON(srv.URL), nil
	})

	tv := validator.NewTokenValidator(provider, cache.NewMemoryCache())
	// Widen the window between processor.go's own provider.Get() and the
	// provider.Get() inside Validate() (reached only on the unpinned/fallback
	// path, i.e. when input.Config is nil). With an in-memory JWKS cache warm,
	// that gap is a few hundred nanoseconds of pure CPU work — far narrower
	// than the real-world gap the bug was found in (a network JWKS/S3 fetch
	// sat in between). The sleep models that realistic latency instead of
	// relying on a scheduling accident; it never runs on the pinned path
	// (validateWith, called directly, bypasses this wrapper's Validate()
	// override entirely), so it cannot mask anything once the fix is back in
	// place.
	dv := &delayedValidator{TokenValidator: tv}
	extractor := validator.NewSelfExtractor(dv)
	consumer := &driftConsumer{}
	proc := handler.NewRequestProcessor(provider, consumer, extractor, nil, "test")

	// Every worker sends the SAME token: audience aud-v2 (only valid under
	// generation B) requesting ONLY the role that is only valid under
	// generation A. Neither generation alone can produce a successful
	// AssumeRole for this combination.
	token := driftSignToken(t, key, "k1", srv.URL, "aud-v2")

	const workers = 24
	const itersPerWorker = 150
	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < itersPerWorker; j++ {
				_, _ = proc.ProcessRequest(context.Background(),
					&handler.RequestData{Token: token, Role: driftAllowedRole},
					validator.ExtractionInput{Token: token},
					"req", noopLogger())
			}
		}()
	}
	wg.Wait()

	consumer.mu.Lock()
	defer consumer.mu.Unlock()
	return append([]driftCall(nil), consumer.calls...)
}

// TestProcessRequestNeverAuthorizesAcrossGenerations is the full-pipeline
// drift guard. With the fix in place, every successful AssumeRole call must
// be self-consistent: a call authorized for driftAllowedRole must never
// carry aud-v2 (the audience only generation B accepts, which is also the
// generation with the role retired).
func TestProcessRequestNeverAuthorizesAcrossGenerations(t *testing.T) {
	calls := runDrift(t, time.Nanosecond)

	var illegal []driftCall
	for _, c := range calls {
		if c.role == driftAllowedRole && c.aud == "aud-v2" {
			illegal = append(illegal, c)
		}
	}
	if len(illegal) > 0 {
		t.Fatalf("cross-generation drift: %d AssumeRole call(s) authorized %q for a token "+
			"validated under generation B's audience (aud-v2) — a combination neither "+
			"generation A (audience rejects aud-v2) nor generation B (role retired) permits "+
			"alone. Example: %+v", len(illegal), driftAllowedRole, illegal[0])
	}
	t.Logf("%d total AssumeRole calls, 0 illegal cross-generation authorizations", len(calls))
}

func noopLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// silenceDefaultLogger mutes the package-level logger for the duration of a
// test. config.Provider logs "Configuration reloaded" through slog's default on
// every refresh, and this test refreshes on essentially every request — without
// this the suite emits thousands of lines that bury real failures.
func silenceDefaultLogger(t *testing.T) {
	t.Helper()
	prev := slog.Default()
	slog.SetDefault(noopLogger())
	t.Cleanup(func() { slog.SetDefault(prev) })
}

// TestDriftSanity_HappyPathAllows keeps the drift guard above honest. That test
// asserts an ABSENCE (zero illegal AssumeRole calls), so it would pass just as
// happily if the harness were broken and no request ever reached AssumeRole at
// all. This pins all three legs of the argument: the happy path really does
// ALLOW (so the pipeline works end to end), pure generation A really does deny
// the aud-v2 token (audience mismatch), and pure generation B really does deny
// it too (role mapping retired). Only with all three true does "zero calls"
// mean the fix worked rather than the harness being inert.
func TestDriftSanity_HappyPathAllows(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	jwks := &types.JWKS{Keys: []types.JSONWebKey{driftJWK("k1", &key.PublicKey)}}
	srv := driftOIDCServer(t, jwks)

	base := driftGenA(srv.URL)
	require.NoError(t, base.Validate())
	provider := config.NewStaticProvider(base)

	tv := validator.NewTokenValidator(provider, cache.NewMemoryCache())
	extractor := validator.NewSelfExtractor(tv)
	consumer := &driftConsumer{}
	proc := handler.NewRequestProcessor(provider, consumer, extractor, nil, "test")

	token := driftSignToken(t, key, "k1", srv.URL, "aud-v1")
	_, err = proc.ProcessRequest(context.Background(),
		&handler.RequestData{Token: token, Role: driftAllowedRole},
		validator.ExtractionInput{Token: token},
		"req", noopLogger())
	t.Logf("happy-path result: err=%v calls=%+v", err, consumer.calls)
	require.NoError(t, err, "happy path should ALLOW")

	// Now the drift token (aud-v2) against the SAME pure generation A: must deny.
	consumer.calls = nil
	badToken := driftSignToken(t, key, "k1", srv.URL, "aud-v2")
	_, err = proc.ProcessRequest(context.Background(),
		&handler.RequestData{Token: badToken, Role: driftAllowedRole},
		validator.ExtractionInput{Token: badToken},
		"req", noopLogger())
	t.Logf("pure-A with aud-v2 token result: err=%v calls=%+v", err, consumer.calls)
	require.Error(t, err, "pure generation A must reject an aud-v2 token")

	// Pure generation B (aud-v2, no role mappings) with the aud-v2 token: must deny too.
	genB := driftGenA(srv.URL)
	genB.Issuers[0].Audiences = []string{"aud-v2"}
	genB.RoleMappings = nil
	require.NoError(t, genB.Validate())
	providerB := config.NewStaticProvider(genB)
	tvB := validator.NewTokenValidator(providerB, cache.NewMemoryCache())
	extractorB := validator.NewSelfExtractor(tvB)
	consumerB := &driftConsumer{}
	procB := handler.NewRequestProcessor(providerB, consumerB, extractorB, nil, "test")
	_, err = procB.ProcessRequest(context.Background(),
		&handler.RequestData{Token: badToken, Role: driftAllowedRole},
		validator.ExtractionInput{Token: badToken},
		"req", noopLogger())
	t.Logf("pure-B with aud-v2 token result: err=%v calls=%+v", err, consumerB.calls)
	require.Error(t, err, "pure generation B must reject: no role mapping")
}
