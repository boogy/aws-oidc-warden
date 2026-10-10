package handler

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/boogy/aws-oidc-warden/internal/config"
	"github.com/boogy/aws-oidc-warden/internal/idp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRoute(t *testing.T) {
	paths := config.IdPPaths{Discovery: "/.well-known/openid-configuration", JWKS: "/.well-known/jwks.json"}
	withIdP := func(enabled bool) *RequestProcessor {
		idpCfg := config.IdPConfig{Enabled: enabled, Paths: paths}
		p := config.NewStaticProvider(&config.Config{IdP: &idpCfg})
		return (&RequestProcessor{provider: p}).WithIdP(idp.NewService(idpCfg, nil))
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
		{"kill switch hides jwks", withIdP(false), "GET", "/.well-known/jwks.json", routeIdPDisabled},
		{"kill switch hides discovery", withIdP(false), "GET", "/.well-known/openid-configuration", routeIdPDisabled},
		{"wrong method is 405 whatever the kill switch", withIdP(false), "POST", "/.well-known/jwks.json", routeMethodNotAllowed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.proc.route(context.Background(), tt.method, tt.path))
		})
	}
}

func TestRouteRefreshesBeforeKillSwitchCheck(t *testing.T) {
	newCfg := func(enabled bool) *config.Config {
		return &config.Config{
			Issuers:         []config.IssuerConfig{{Issuer: "https://token.actions.githubusercontent.com", Provider: "github", Audiences: []string{"sts.amazonaws.com"}}},
			RoleSessionName: "test",
			Cache:           &config.Cache{TTL: 0},
			IdP: &config.IdPConfig{
				Enabled:     enabled,
				Issuer:      "https://idp.example.com",
				Audience:    "sts.amazonaws.com",
				SigningKeys: []config.IdPSigningKey{{File: "/unused", Algorithm: "ES256", Status: config.IdPKeyActive}},
			},
		}
	}
	tests := []struct {
		name          string
		base, overlay bool
		want          routeKind
	}{
		{"re-enabled remotely", false, true, routeJWKS},
		{"killed remotely", true, false, routeIdPDisabled},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			base := newCfg(tt.base)
			require.NoError(t, base.Validate())
			overlay, err := json.Marshal(newCfg(tt.overlay))
			require.NoError(t, err)
			p := config.NewProvider(base, time.Hour, "json", func(context.Context) ([]byte, error) { return overlay, nil })
			proc := (&RequestProcessor{provider: p}).WithIdP(idp.NewService(*base.IdP, nil))
			assert.Equal(t, tt.want, proc.route(context.Background(), "GET", proc.idp.Config().Paths.JWKS))
		})
	}
}

func TestIdPRoutesShaped(t *testing.T) {
	rt := newIdPRoutes(config.IdPPaths{Discovery: "/Warden/.well-known/openid-configuration", JWKS: "/Warden/keys"})
	tests := []struct {
		path string
		want bool
	}{
		{"/warden/keys", true},
		{"/WARDEN/KEYS/", true},
		{"/prod/Warden/keys", true},
		{"/prod/warden/.well-known/openid-configuration", true},
		{"/a/b/warden/keys", false},
		{"/warden", false},
		{"", false},
		{"/verify", false},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			assert.Equal(t, tt.want, rt.shaped(tt.path))
		})
	}
}
