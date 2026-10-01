package idp

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"fmt"
)

// Signer produces JOSE-format JWS signatures over a signing input.
type Signer interface {
	Algorithm() string
	KeyID() string
	Public() crypto.PublicKey
	Sign(ctx context.Context, signingInput []byte) ([]byte, error)
}

func checkKeyMatchesAlg(alg string, pub crypto.PublicKey) error {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		if alg != "RS256" {
			return fmt.Errorf("RSA key does not match algorithm %s", alg)
		}
		if k.N.BitLen() < 2048 {
			return fmt.Errorf("RSA key must be at least 2048 bits, got %d", k.N.BitLen())
		}
	case *ecdsa.PublicKey:
		if alg != "ES256" {
			return fmt.Errorf("EC key does not match algorithm %s", alg)
		}
		if k.Curve != elliptic.P256() {
			return fmt.Errorf("EC key must use curve P-256")
		}
	default:
		return fmt.Errorf("unsupported public key type %T", pub)
	}
	return nil
}
