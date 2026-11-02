package idptest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/boogy/aws-oidc-warden/internal/idp"
)

// NewSigner returns an ES256 PEM-backed signer over a throwaway key.
func NewSigner(tb testing.TB) idp.Signer {
	tb.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		tb.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		tb.Fatal(err)
	}
	p := filepath.Join(tb.TempDir(), "k.pem")
	if err := os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		tb.Fatal(err)
	}
	s, err := idp.NewPEMSigner(p, "ES256")
	if err != nil {
		tb.Fatal(err)
	}
	return s
}
