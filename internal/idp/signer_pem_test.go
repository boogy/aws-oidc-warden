package idp

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
)

func writeKey(t *testing.T, key crypto.Signer, mode os.FileMode) string {
	t.Helper()
	return writeKeyTB(t, key, mode)
}

func TestPEMSigner(t *testing.T) {
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ec384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	rsa2k, _ := rsa.GenerateKey(rand.Reader, 2048)
	rsa1k, _ := rsa.GenerateKey(rand.Reader, 1024)
	_, ed, _ := ed25519.GenerateKey(rand.Reader)
	edDER, err := x509.MarshalPKCS8PrivateKey(ed)
	require.NoError(t, err)

	writeRaw := func(b []byte) func(*testing.T) string {
		return func(t *testing.T) string {
			p := filepath.Join(t.TempDir(), "k.pem")
			require.NoError(t, os.WriteFile(p, b, 0o600))
			return p
		}
	}
	tests := []struct {
		name    string
		key     crypto.Signer
		alg     string
		mode    os.FileMode
		path    func(t *testing.T) string
		wantErr string
	}{
		{name: "es256", key: ec, alg: "ES256", mode: 0o600},
		{name: "rs256", key: rsa2k, alg: "RS256", mode: 0o400},
		{name: "group readable", key: ec, alg: "ES256", mode: 0o640, wantErr: "group/world access"},
		{name: "world readable", key: ec, alg: "ES256", mode: 0o604, wantErr: "group/world access"},
		{name: "alg mismatch", key: ec, alg: "RS256", mode: 0o600, wantErr: "does not match"},
		{name: "rsa key with ES256", key: rsa2k, alg: "ES256", mode: 0o600, wantErr: "does not match"},
		{name: "p384 rejected", key: ec384, alg: "ES256", mode: 0o600, wantErr: "P-256"},
		{name: "rsa too small", key: rsa1k, alg: "RS256", mode: 0o600, wantErr: "2048"},
		{name: "wrong pem type", alg: "ES256", path: writeRaw(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("x")})), wantErr: "unsupported private key encoding"},
		{name: "not pem", alg: "ES256", path: writeRaw([]byte("not pem")), wantErr: "no PEM block"},
		{name: "ed25519 pkcs8", alg: "ES256", path: writeRaw(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: edDER})), wantErr: "unsupported public key type"},
		{name: "missing file", alg: "ES256", path: func(t *testing.T) string { return filepath.Join(t.TempDir(), "absent.pem") }, wantErr: "idp key file"},
		{name: "directory", alg: "ES256", path: func(t *testing.T) string { return t.TempDir() }, wantErr: "regular file"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if runtime.GOOS == "windows" && (strings.HasPrefix(tt.name, "group") || strings.HasPrefix(tt.name, "world")) {
				t.Skip("unix permission bits")
			}
			path := tt.path
			if path == nil {
				path = func(t *testing.T) string { return writeKey(t, tt.key, tt.mode) }
			}
			s, err := NewPEMSigner(path(t), tt.alg)
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			input := []byte("header.payload")
			sig, err := s.Sign(context.Background(), input)
			require.NoError(t, err)
			require.NoError(t, jwt.GetSigningMethod(tt.alg).Verify(string(input), sig, s.Public()))
			kid, _ := Thumbprint(s.Public())
			require.Equal(t, kid, s.KeyID())
			require.Equal(t, tt.alg, s.Algorithm())
		})
	}
}

func TestPEMSignerES256SignatureIsRaw(t *testing.T) {
	sig, err := newTestSigner(t).Sign(context.Background(), []byte("header.payload"))
	require.NoError(t, err)
	require.Len(t, sig, 64)
}

func TestPEMSignerRejectsSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation needs privileges")
	}
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	link := filepath.Join(t.TempDir(), "link.pem")
	require.NoError(t, os.Symlink(writeKey(t, ec, 0o600), link))
	_, err := NewPEMSigner(link, "ES256")
	require.Error(t, err)
}
