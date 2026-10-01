package handler

import (
	"testing"

	"github.com/boogy/aws-oidc-warden/internal/config"
	"github.com/boogy/aws-oidc-warden/internal/idp"
	"github.com/stretchr/testify/assert"
)

func TestRoute(t *testing.T) {
	paths := config.IdPPaths{Token: "/idp/token", Discovery: "/.well-known/openid-configuration", JWKS: "/.well-known/jwks.json"}
	withIdP := func(enabled bool) *RequestProcessor {
		return (&RequestProcessor{}).WithIdP(idp.NewService(config.IdPConfig{Enabled: enabled, Paths: paths}, nil))
	}

	tests := []struct {
		name         string
		proc         *RequestProcessor
		method, path string
		want         routeKind
	}{
		{"mint", withIdP(true), "POST", "/idp/token", routeMint},
		{"token wrong method", withIdP(true), "GET", "/idp/token", routeMethodNotAllowed},
		{"discovery", withIdP(true), "GET", "/.well-known/openid-configuration", routeDiscovery},
		{"jwks head", withIdP(true), "HEAD", "/.well-known/jwks.json", routeJWKS},
		{"jwks post", withIdP(true), "POST", "/.well-known/jwks.json", routeMethodNotAllowed},
		{"verify", withIdP(true), "POST", "/verify", routeAssume},
		{"trailing slash", withIdP(true), "POST", "/idp/token/", routeNotFound},
		{"upper case", withIdP(true), "POST", "/IDP/TOKEN", routeNotFound},
		{"stage prefix token", withIdP(true), "POST", "/prod/idp/token", routeNotFound},
		{"stage prefix jwks", withIdP(true), "GET", "/prod/.well-known/jwks.json", routeNotFound},
		{"empty path", withIdP(true), "POST", "", routeAssume},
		{"other well-known", withIdP(true), "POST", "/.well-known/other", routeAssume},
		{"no idp", &RequestProcessor{}, "POST", "/idp/token", routeAssume},
		{"kill switch still routes", withIdP(false), "POST", "/idp/token", routeMint},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.proc.route(tt.method, tt.path))
		})
	}
}
