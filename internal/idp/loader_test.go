package idp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/boogy/aws-oidc-warden/internal/config"
)

func TestLoaderAllOrNothing(t *testing.T) {
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	good := config.IdPSigningKey{File: writeKey(t, ec, 0o600), Algorithm: "ES256", Status: "active"}
	bad := config.IdPSigningKey{File: "/does/not/exist", Algorithm: "ES256", Status: "verify_only"}

	tests := []struct {
		name    string
		keys    []config.IdPSigningKey
		wantErr bool
		wantLen int
	}{
		{"good only", []config.IdPSigningKey{good}, false, 1},
		{"good plus missing", []config.IdPSigningKey{good, bad}, true, 0},
		{"missing first", []config.IdPSigningKey{bad, good}, true, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := testCfg()
			cfg.SigningKeys = tt.keys
			load := NewLoader(cfg, func() KMSAPI {
				t.Fatal("kms must not be used for PEM-only config")
				return nil
			}, nil)
			got, err := load(t.Context())
			if tt.wantErr {
				require.Error(t, err)
				require.Nil(t, got)
				return
			}
			require.NoError(t, err)
			require.Len(t, got, tt.wantLen)
			require.Equal(t, "active", got[0].Status)
		})
	}
}
