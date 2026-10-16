package idp

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/boogy/aws-oidc-warden/internal/types"
)

var b64 = base64.RawURLEncoding

func members(pub crypto.PublicKey) (types.JSONWebKey, error) {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		return types.JSONWebKey{KeyType: "RSA", N: b64.EncodeToString(k.N.Bytes()), E: b64.EncodeToString(big.NewInt(int64(k.E)).Bytes())}, nil
	case *ecdsa.PublicKey:
		pt, err := k.Bytes()
		if err != nil || len(pt) != 65 {
			return types.JSONWebKey{}, fmt.Errorf("invalid EC public key")
		}
		return types.JSONWebKey{KeyType: "EC", Crv: "P-256", X: b64.EncodeToString(pt[1:33]), Y: b64.EncodeToString(pt[33:65])}, nil
	}
	return types.JSONWebKey{}, fmt.Errorf("unsupported public key type %T", pub)
}

// Thumbprint returns the RFC 7638 SHA-256 JWK thumbprint, used as kid.
func Thumbprint(pub crypto.PublicKey) (string, error) {
	m, err := members(pub)
	if err != nil {
		return "", err
	}
	var canon []byte
	if m.KeyType == "RSA" {
		canon, _ = json.Marshal(struct {
			E   string `json:"e"`
			Kty string `json:"kty"`
			N   string `json:"n"`
		}{m.E, m.KeyType, m.N})
	} else {
		canon, _ = json.Marshal(struct {
			Crv string `json:"crv"`
			Kty string `json:"kty"`
			X   string `json:"x"`
			Y   string `json:"y"`
		}{m.Crv, m.KeyType, m.X, m.Y})
	}
	sum := sha256.Sum256(canon)
	return b64.EncodeToString(sum[:]), nil
}

// PublicJWK renders pub as a JWKS entry.
func PublicJWK(alg string, pub crypto.PublicKey) (types.JSONWebKey, error) {
	m, err := members(pub)
	if err != nil {
		return types.JSONWebKey{}, err
	}
	kid, err := Thumbprint(pub)
	if err != nil {
		return types.JSONWebKey{}, err
	}
	m.Use, m.Algorithm, m.KeyID = "sig", alg, kid
	return m, nil
}
