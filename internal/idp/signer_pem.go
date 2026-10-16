package idp

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"

	"github.com/golang-jwt/jwt/v5"
)

const maxKeyFileBytes = 64 << 10

type pemSigner struct {
	alg  string
	kid  string
	pub  crypto.PublicKey
	sign func([]byte) ([]byte, error)
}

// NewPEMSigner loads a dev-only private key from a file readable by its owner only.
func NewPEMSigner(path, alg string) (Signer, error) {
	f, err := openKeyFile(path)
	if err != nil {
		return nil, fmt.Errorf("idp key file: %w", err)
	}
	defer func() { _ = f.Close() }()
	// Stat the open fd, not the path, so the checked file is the one read.
	st, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("idp key file: %w", err)
	}
	if err := checkKeyFileMode(path, st.Mode()); err != nil {
		return nil, err
	}
	raw, err := io.ReadAll(io.LimitReader(f, maxKeyFileBytes))
	if err != nil {
		return nil, fmt.Errorf("idp key file: %w", err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, errors.New("idp key file: no PEM block")
	}
	priv, err := parsePrivateKey(block)
	if err != nil {
		return nil, err
	}
	if err := checkKeyMatchesAlg(alg, priv.Public()); err != nil {
		return nil, err
	}
	kid, err := Thumbprint(priv.Public())
	if err != nil {
		return nil, err
	}
	m := jwt.GetSigningMethod(alg)
	if m == nil {
		return nil, fmt.Errorf("unsupported algorithm %s", alg)
	}
	sign := func(in []byte) ([]byte, error) { return m.Sign(string(in), priv) }
	return &pemSigner{alg: alg, kid: kid, pub: priv.Public(), sign: sign}, nil
}

func parsePrivateKey(b *pem.Block) (crypto.Signer, error) {
	if k, err := x509.ParsePKCS8PrivateKey(b.Bytes); err == nil {
		if s, ok := k.(crypto.Signer); ok {
			return s, nil
		}
	}
	if k, err := x509.ParseECPrivateKey(b.Bytes); err == nil {
		return k, nil
	}
	if k, err := x509.ParsePKCS1PrivateKey(b.Bytes); err == nil {
		return k, nil
	}
	return nil, errors.New("idp key file: unsupported private key encoding")
}

func (s *pemSigner) Algorithm() string        { return s.alg }
func (s *pemSigner) KeyID() string            { return s.kid }
func (s *pemSigner) Public() crypto.PublicKey { return s.pub }

func (s *pemSigner) Sign(_ context.Context, in []byte) ([]byte, error) { return s.sign(in) }
