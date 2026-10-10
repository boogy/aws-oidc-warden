package idp

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"math/big"
	"testing"

	"github.com/boogy/aws-oidc-warden/internal/types"
	"github.com/stretchr/testify/require"
)

func TestThumbprintRFC7638Vector(t *testing.T) {
	n, _ := base64.RawURLEncoding.DecodeString("0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw")
	pub := &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: 65537}
	kid, err := Thumbprint(pub)
	require.NoError(t, err)
	require.Equal(t, "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs", kid)
}

func TestThumbprintECCanonical(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	pt, err := key.PublicKey.Bytes()
	require.NoError(t, err)
	x, y := base64.RawURLEncoding.EncodeToString(pt[1:33]), base64.RawURLEncoding.EncodeToString(pt[33:65])
	sum := sha256.Sum256(fmt.Appendf(nil, `{"crv":"P-256","kty":"EC","x":"%s","y":"%s"}`, x, y))
	kid, err := Thumbprint(&key.PublicKey)
	require.NoError(t, err)
	require.Equal(t, base64.RawURLEncoding.EncodeToString(sum[:]), kid)
}

func TestPublicJWK(t *testing.T) {
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	rsa2k, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	tests := []struct {
		name  string
		alg   string
		pub   any
		check func(t *testing.T, j types.JSONWebKey)
	}{
		{"es256", "ES256", &ec.PublicKey, func(t *testing.T, j types.JSONWebKey) {
			require.Equal(t, "EC", j.KeyType)
			require.Equal(t, "P-256", j.Crv)
			require.Len(t, j.X, 43)
			require.Len(t, j.Y, 43)
		}},
		{"rs256", "RS256", &rsa2k.PublicKey, func(t *testing.T, j types.JSONWebKey) {
			require.Equal(t, "RSA", j.KeyType)
			require.Equal(t, "AQAB", j.E)
			require.NotEmpty(t, j.N)
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			j, err := PublicJWK(tt.alg, tt.pub)
			require.NoError(t, err)
			require.Equal(t, "sig", j.Use)
			require.Equal(t, tt.alg, j.Algorithm)
			kid, err := Thumbprint(tt.pub)
			require.NoError(t, err)
			require.Equal(t, kid, j.KeyID)
			tt.check(t, j)
		})
	}
}

func TestPublicJWKUnsupportedKey(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	_, err = PublicJWK("ES256", pub)
	require.Error(t, err)
}
