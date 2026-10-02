package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/boogy/aws-oidc-warden/internal/config"
)

func writeTestKey(t *testing.T) (path string, pemBytes []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	path = filepath.Join(t.TempDir(), "k.pem")
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	return path, pemBytes
}

func testConfig(t *testing.T, issuer, jwksURI string, paths config.IdPPaths) (*config.Config, []byte) {
	t.Helper()
	keyPath, pemBytes := writeTestKey(t)
	return &config.Config{IdP: &config.IdPConfig{
		Enabled:     true,
		Issuer:      issuer,
		Audience:    "sts.amazonaws.com",
		JWKSURI:     jwksURI,
		Paths:       paths,
		SigningKeys: []config.IdPSigningKey{{File: keyPath, Algorithm: "ES256", Status: "active"}},
	}}, pemBytes
}

func TestRunWritesDocuments(t *testing.T) {
	tests := []struct {
		name    string
		issuer  string
		jwksURI string
		paths   config.IdPPaths
		wantDir string
	}{
		{
			name:    "default paths",
			issuer:  "https://idp.example.com",
			jwksURI: "https://idp.example.com/.well-known/jwks.json",
			paths:   config.IdPPaths{Discovery: "/.well-known/openid-configuration", JWKS: "/.well-known/jwks.json"},
			wantDir: ".well-known",
		},
		{
			name:    "issuer path",
			issuer:  "https://h/x",
			jwksURI: "https://h/x/.well-known/jwks.json",
			paths:   config.IdPPaths{Discovery: "/x/.well-known/openid-configuration", JWKS: "/x/.well-known/jwks.json"},
			wantDir: "x/.well-known",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, _ := testConfig(t, tt.issuer, tt.jwksURI, tt.paths)
			out := t.TempDir()
			if err := run(context.Background(), cfg, nil, out); err != nil {
				t.Fatal(err)
			}
			dir := filepath.Join(out, filepath.FromSlash(tt.wantDir))
			jwks, err := os.ReadFile(filepath.Join(dir, "jwks.json"))
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(jwks), `"kid"`) {
				t.Errorf("jwks lacks kid: %s", jwks)
			}
			disc, err := os.ReadFile(filepath.Join(dir, "openid-configuration"))
			if err != nil {
				t.Fatal(err)
			}
			var doc map[string]any
			if err := json.Unmarshal(disc, &doc); err != nil {
				t.Fatal(err)
			}
			if doc["issuer"] != tt.issuer {
				t.Errorf("issuer = %v, want %s", doc["issuer"], tt.issuer)
			}
			di, err := os.Stat(dir)
			if err != nil {
				t.Fatal(err)
			}
			if di.Mode().Perm() != 0o755 {
				t.Errorf("dir mode = %o, want 755", di.Mode().Perm())
			}
			fi, err := os.Stat(filepath.Join(dir, "jwks.json"))
			if err != nil {
				t.Fatal(err)
			}
			if fi.Mode().Perm() != 0o644 {
				t.Errorf("file mode = %o, want 644", fi.Mode().Perm())
			}
		})
	}
}

func TestRunRequiresEnabledIdP(t *testing.T) {
	tests := []struct {
		name string
		cfg  *config.Config
	}{
		{"no idp block", &config.Config{}},
		{"disabled idp", &config.Config{IdP: &config.IdPConfig{Enabled: false}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := run(context.Background(), tt.cfg, nil, t.TempDir())
			if err == nil || !strings.Contains(err.Error(), "idp") {
				t.Fatalf("err = %v, want idp error", err)
			}
		})
	}
}

func TestRunWritesOnlyPublicMaterial(t *testing.T) {
	cfg, pemBytes := testConfig(t, "https://idp.example.com", "https://idp.example.com/.well-known/jwks.json",
		config.IdPPaths{Discovery: "/.well-known/openid-configuration", JWKS: "/.well-known/jwks.json"})
	out := t.TempDir()
	if err := run(context.Background(), cfg, nil, out); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"jwks.json", "openid-configuration"} {
		b, err := os.ReadFile(filepath.Join(out, ".well-known", name))
		if err != nil {
			t.Fatal(err)
		}
		s := string(b)
		for _, bad := range []string{`"d"`, "BEGIN PRIVATE KEY", string(pemBytes)} {
			if strings.Contains(s, bad) {
				t.Errorf("%s contains private material %q", name, bad)
			}
		}
	}
}
