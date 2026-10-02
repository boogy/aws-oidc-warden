package handler

import (
	"testing"

	"github.com/boogy/aws-oidc-warden/internal/config"
	"github.com/boogy/aws-oidc-warden/internal/idp"
	"github.com/stretchr/testify/assert"
)

func TestRoute(t *testing.T) {
	paths := config.IdPPaths{Discovery: "/.well-known/openid-configuration", JWKS: "/.well-known/jwks.json"}
	withIdP := func(enabled bool) *RequestProcessor {
		return (&RequestProcessor{}).WithIdP(idp.NewService(config.IdPConfig{Enabled: enabled, Paths: paths}, nil))
	}

	tests := []struct {
		name         string
		proc         *RequestProcessor
		method, path string
		want         routeKind
	}{
		{"old token path is the credential path", withIdP(true), "POST", "/idp/token", routeAssume},
		{"discovery", withIdP(true), "GET", "/.well-known/openid-configuration", routeDiscovery},
		{"jwks head", withIdP(true), "HEAD", "/.well-known/jwks.json", routeJWKS},
		{"jwks post", withIdP(true), "POST", "/.well-known/jwks.json", routeMethodNotAllowed},
		{"verify", withIdP(true), "POST", "/verify", routeAssume},
		{"trailing slash", withIdP(true), "GET", "/.well-known/jwks.json/", routeNotFound},
		{"upper case", withIdP(true), "GET", "/.WELL-KNOWN/JWKS.JSON", routeNotFound},
		{"stage prefix jwks", withIdP(true), "GET", "/prod/.well-known/jwks.json", routeNotFound},
		{"empty path", withIdP(true), "POST", "", routeAssume},
		{"other well-known", withIdP(true), "POST", "/.well-known/other", routeAssume},
		{"no idp", &RequestProcessor{}, "GET", "/.well-known/jwks.json", routeAssume},
		{"kill switch still serves documents", withIdP(false), "GET", "/.well-known/jwks.json", routeJWKS},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.proc.route(tt.method, tt.path))
		})
	}
}
