package idp

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func newTestSigner(tb testing.TB) Signer {
	tb.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		tb.Fatal(err)
	}
	s, err := NewPEMSigner(writeKeyTB(tb, key, 0o600), "ES256")
	if err != nil {
		tb.Fatal(err)
	}
	return s
}

func writeKeyTB(tb testing.TB, key crypto.Signer, mode os.FileMode) string {
	tb.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(tb, err)
	p := filepath.Join(tb.TempDir(), "key.pem")
	require.NoError(tb, os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), mode))
	require.NoError(tb, os.Chmod(p, mode))
	return p
}
