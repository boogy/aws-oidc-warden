package idp

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"testing"

	"github.com/boogy/aws-oidc-warden/internal/config"
	"github.com/stretchr/testify/require"
)

func testCfg() config.IdPConfig {
	return config.IdPConfig{
		Issuer: "https://idp.example.com", Audience: "sts.amazonaws.com",
		JWKSURI:         "https://idp.example.com/.well-known/jwks.json",
		SubjectTemplate: config.IdPDefaultSubjectTemplate,
	}
}

func newTestRSASigner(tb testing.TB) Signer {
	tb.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(tb, err)
	s, err := NewPEMSigner(writeKeyTB(tb, key, 0o600), "RS256")
	require.NoError(tb, err)
	return s
}

type edSigner struct{}

func (edSigner) Algorithm() string { return "EdDSA" }
func (edSigner) KeyID() string     { return "ed" }
func (edSigner) Public() crypto.PublicKey {
	return ed25519.PublicKey(make([]byte, ed25519.PublicKeySize))
}
func (edSigner) Sign(context.Context, []byte) ([]byte, error) {
	return nil, nil
}

func TestKeySetDocuments(t *testing.T) {
	a, b := newTestSigner(t), newTestSigner(t)
	ks, err := NewKeySet(testCfg(), []LoadedKey{
		{Signer: a, Status: config.IdPKeyActive},
		{Signer: b, Status: config.IdPKeyVerifyOnly},
	})
	require.NoError(t, err)
	require.Equal(t, a.KeyID(), ks.Active().KeyID())

	var jwks struct{ Keys []JWK }
	require.NoError(t, json.Unmarshal(ks.JWKS(), &jwks))
	require.Len(t, jwks.Keys, 2)
	require.Equal(t, "sig", jwks.Keys[0].Use)
	require.Equal(t, a.KeyID(), jwks.Keys[0].Kid)
	for _, k := range jwks.Keys {
		require.Equal(t, "ES256", k.Alg)
		require.Equal(t, "EC", k.Kty)
	}

	var raw struct {
		Keys []map[string]any `json:"keys"`
	}
	require.NoError(t, json.Unmarshal(ks.JWKS(), &raw))
	for _, k := range raw.Keys {
		got := make([]string, 0, len(k))
		for m := range k {
			got = append(got, m)
		}
		require.ElementsMatch(t, []string{"kty", "use", "alg", "kid", "crv", "x", "y"}, got)
	}

	var disc map[string]any
	require.NoError(t, json.Unmarshal(ks.Discovery(), &disc))
	require.Equal(t, "https://idp.example.com", disc["issuer"])
	require.Equal(t, "https://idp.example.com/.well-known/jwks.json", disc["jwks_uri"])
	require.ElementsMatch(t, []any{"ES256"}, disc["id_token_signing_alg_values_supported"])
}

func TestKeySetRejectsDuplicateKid(t *testing.T) {
	a := newTestSigner(t)
	_, err := NewKeySet(testCfg(), []LoadedKey{
		{Signer: a, Status: config.IdPKeyActive},
		{Signer: a, Status: config.IdPKeyVerifyOnly},
	})
	require.ErrorContains(t, err, "duplicate kid")
}

func TestKeySetActiveSelection(t *testing.T) {
	a, b := newTestSigner(t), newTestSigner(t)
	tests := []struct {
		name    string
		keys    []LoadedKey
		wantErr string
		wantKid string
	}{
		{name: "no keys", wantErr: "no active signing key"},
		{name: "only verify_only", keys: []LoadedKey{{Signer: a, Status: config.IdPKeyVerifyOnly}}, wantErr: "no active signing key"},
		{name: "two active", keys: []LoadedKey{{Signer: a, Status: config.IdPKeyActive}, {Signer: b, Status: config.IdPKeyActive}}, wantErr: "multiple active"},
		{name: "active second in list", keys: []LoadedKey{{Signer: a, Status: config.IdPKeyVerifyOnly}, {Signer: b, Status: config.IdPKeyActive}}, wantKid: b.KeyID()},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ks, err := NewKeySet(testCfg(), tt.keys)
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				require.Nil(t, ks)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.wantKid, ks.Active().KeyID())
		})
	}
}

func TestKeySetJWKSIncludesVerifyOnly(t *testing.T) {
	ks, err := NewKeySet(testCfg(), []LoadedKey{
		{Signer: newTestSigner(t), Status: config.IdPKeyActive},
		{Signer: newTestSigner(t), Status: config.IdPKeyVerifyOnly},
		{Signer: newTestSigner(t), Status: config.IdPKeyVerifyOnly},
	})
	require.NoError(t, err)
	var jwks struct{ Keys []JWK }
	require.NoError(t, json.Unmarshal(ks.JWKS(), &jwks))
	require.Len(t, jwks.Keys, 3)
}

func TestKeySetMixedAlgorithms(t *testing.T) {
	ks, err := NewKeySet(testCfg(), []LoadedKey{
		{Signer: newTestSigner(t), Status: config.IdPKeyActive},
		{Signer: newTestRSASigner(t), Status: config.IdPKeyVerifyOnly},
	})
	require.NoError(t, err)
	var disc map[string]any
	require.NoError(t, json.Unmarshal(ks.Discovery(), &disc))
	require.ElementsMatch(t, []any{"ES256", "RS256"}, disc["id_token_signing_alg_values_supported"])
}

func TestDiscovery(t *testing.T) {
	ks, err := NewKeySet(testCfg(), []LoadedKey{{Signer: newTestSigner(t), Status: config.IdPKeyActive}})
	require.NoError(t, err)
	var disc map[string]any
	require.NoError(t, json.Unmarshal(ks.Discovery(), &disc))
	require.Equal(t, "https://idp.example.com", disc["issuer"])
	require.Equal(t, "https://idp.example.com/.well-known/jwks.json", disc["jwks_uri"])
	require.Equal(t, []any{"id_token"}, disc["response_types_supported"])
	require.Equal(t, []any{"public"}, disc["subject_types_supported"])
	require.ElementsMatch(t, []any{"iss", "sub", "aud", "exp", "iat", "nbf", "jti", "src_iss", "src_sub", "request_id",
		"https://aws.amazon.com/tags", "https://aws.amazon.com/source_identity"}, disc["claims_supported"])
}

func TestKeySetDocumentsAreImmutableCopies(t *testing.T) {
	ks, err := NewKeySet(testCfg(), []LoadedKey{{Signer: newTestSigner(t), Status: config.IdPKeyActive}})
	require.NoError(t, err)
	for name, get := range map[string]func() []byte{"JWKS": ks.JWKS, "Discovery": ks.Discovery} {
		t.Run(name, func(t *testing.T) {
			b := get()
			b[0] = 'X'
			require.Equal(t, byte('{'), get()[0])
		})
	}
}

func TestNewKeySetRejectsUnsupportedKey(t *testing.T) {
	_, err := NewKeySet(testCfg(), []LoadedKey{{Signer: edSigner{}, Status: config.IdPKeyActive}})
	require.Error(t, err)
}
