package config

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

const idpKMSARN = "arn:aws:kms:eu-west-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab"

func kmsARN(n int) string {
	return fmt.Sprintf("arn:aws:kms:eu-west-1:111122223333:key/%08x-12ab-34cd-56ef-1234567890ab", n)
}

func validIdP() *IdPConfig {
	return &IdPConfig{
		Enabled:  true,
		Issuer:   "https://idp.example.com",
		Audience: "sts.amazonaws.com",
		SigningKeys: []IdPSigningKey{
			{KMSKeyID: idpKMSARN, Algorithm: "RS256", Status: IdPKeyActive},
		},
	}
}

func TestIdPValidate(t *testing.T) {
	inbound := []IssuerConfig{{Issuer: "https://token.actions.githubusercontent.com"}}
	tests := []struct {
		name    string
		mutate  func(c *IdPConfig)
		insec   bool
		lambda  bool
		wantErr string
	}{
		{name: "valid", mutate: func(c *IdPConfig) {}},
		{name: "http issuer rejected", mutate: func(c *IdPConfig) { c.Issuer = "http://idp.example.com" }, wantErr: "https"},
		{name: "http issuer allowed insecure", mutate: func(c *IdPConfig) { c.Issuer = "http://localhost:8080" }, insec: true},
		{name: "trailing slash", mutate: func(c *IdPConfig) { c.Issuer = "https://idp.example.com/" }, wantErr: "trailing slash"},
		{name: "query", mutate: func(c *IdPConfig) { c.Issuer = "https://idp.example.com?a=b" }, wantErr: "query"},
		{name: "fragment", mutate: func(c *IdPConfig) { c.Issuer = "https://idp.example.com#x" }, wantErr: "fragment"},
		{name: "userinfo", mutate: func(c *IdPConfig) { c.Issuer = "https://u:p@idp.example.com" }, wantErr: "userinfo"},
		{name: "port without insecure", mutate: func(c *IdPConfig) { c.Issuer = "https://idp.example.com:8443" }, wantErr: "port"},
		{name: "uppercase host", mutate: func(c *IdPConfig) { c.Issuer = "https://IDP.example.com" }, wantErr: "lowercase"},
		{name: "collides with inbound", mutate: func(c *IdPConfig) { c.Issuer = "https://token.actions.githubusercontent.com" }, wantErr: "inbound issuer"},
		{name: "issuer not absolute", mutate: func(c *IdPConfig) { c.Issuer = "idp.example.com" }, wantErr: "absolute URL"},
		{name: "jwks_uri http", mutate: func(c *IdPConfig) { c.JWKSURI = "http://idp.example.com/.well-known/jwks.json" }, wantErr: "idp.jwks_uri must use https"},

		{name: "empty audience", mutate: func(c *IdPConfig) { c.Audience = "" }, wantErr: "audience"},
		{name: "ttl too short", mutate: func(c *IdPConfig) { c.TokenTTL = 30 * time.Second }, wantErr: "token_ttl"},
		{name: "ttl too long", mutate: func(c *IdPConfig) { c.TokenTTL = 2 * time.Hour }, wantErr: "token_ttl"},
		{name: "ttl over 5m", mutate: func(c *IdPConfig) { c.TokenTTL = 6 * time.Minute }, wantErr: "token_ttl"},
		{name: "ttl at 5m", mutate: func(c *IdPConfig) { c.TokenTTL = 5 * time.Minute }},
		{name: "ttl at 1m", mutate: func(c *IdPConfig) { c.TokenTTL = time.Minute }},
		{name: "audience_mode role_arn", mutate: func(c *IdPConfig) { c.AudienceMode = IdPAudienceRoleARN }},
		{name: "audience_mode invalid", mutate: func(c *IdPConfig) { c.AudienceMode = "subject" }, wantErr: "audience_mode"},
		{name: "source_identity_overflow reject", mutate: func(c *IdPConfig) { c.SourceIdentityOverflow = IdPOverflowReject }},
		{name: "source_identity_overflow invalid", mutate: func(c *IdPConfig) { c.SourceIdentityOverflow = "clip" }, wantErr: "source_identity_overflow"},
		{name: "negative sign_timeout", mutate: func(c *IdPConfig) { c.SignTimeout = -1 }, wantErr: "sign_timeout"},
		{name: "negative jwks_cache_max_age", mutate: func(c *IdPConfig) { c.JWKSCacheMaxAge = -1 }, wantErr: "jwks_cache_max_age"},

		{name: "allowed_roles arn", mutate: func(c *IdPConfig) { c.AllowedRoles = []string{"arn:aws:iam::123456789012:role/R"} }},
		{name: "allowed_roles govcloud", mutate: func(c *IdPConfig) { c.AllowedRoles = []string{"arn:aws-us-gov:iam::123456789012:role/R"} }},
		{name: "allowed_roles china", mutate: func(c *IdPConfig) { c.AllowedRoles = []string{"arn:aws-cn:iam::123456789012:role/R"} }},
		{name: "allowed_roles set ref", mutate: func(c *IdPConfig) { c.AllowedRoles = []string{"@idp"} }},
		{name: "allowed_roles bad entry", mutate: func(c *IdPConfig) { c.AllowedRoles = []string{"R"} }, wantErr: "allowed_roles"},
		{name: "allowed_roles bare @", mutate: func(c *IdPConfig) { c.AllowedRoles = []string{"@"} }, wantErr: "allowed_roles"},
		{name: "allowed_roles user arn", mutate: func(c *IdPConfig) { c.AllowedRoles = []string{"arn:aws:iam::123456789012:user/U"} }, wantErr: "allowed_roles"},

		{name: "bad alg", mutate: func(c *IdPConfig) { c.SigningKeys[0].Algorithm = "HS256" }, wantErr: "algorithm"},
		{name: "bad key status", mutate: func(c *IdPConfig) { c.SigningKeys[0].Status = "retired" }, wantErr: "status must be"},
		{name: "no active key", mutate: func(c *IdPConfig) { c.SigningKeys[0].Status = IdPKeyVerifyOnly }, wantErr: "exactly one active"},
		{name: "two active keys", mutate: func(c *IdPConfig) {
			c.SigningKeys = append(c.SigningKeys, IdPSigningKey{KMSKeyID: kmsARN(2), Algorithm: "ES256", Status: IdPKeyActive})
		}, wantErr: "exactly one active"},
		{name: "both sources", mutate: func(c *IdPConfig) { c.SigningKeys[0].File = "/k.pem" }, wantErr: "exactly one of"},
		{name: "no source", mutate: func(c *IdPConfig) { c.SigningKeys[0].KMSKeyID = "" }, wantErr: "exactly one of"},
		{name: "too many keys", mutate: func(c *IdPConfig) {
			for i := range 5 {
				c.SigningKeys = append(c.SigningKeys, IdPSigningKey{KMSKeyID: kmsARN(i + 10), Algorithm: "RS256", Status: IdPKeyVerifyOnly})
			}
		}, wantErr: "at most 5"},
		{name: "duplicate key source", mutate: func(c *IdPConfig) {
			c.SigningKeys = append(c.SigningKeys, IdPSigningKey{KMSKeyID: idpKMSARN, Algorithm: "RS256", Status: IdPKeyVerifyOnly})
		}, wantErr: "duplicate"},
		{name: "kms alias rejected", mutate: func(c *IdPConfig) { c.SigningKeys[0].KMSKeyID = "alias/my-key" }, wantErr: "key ARN"},
		{name: "kms key id bare uuid rejected", mutate: func(c *IdPConfig) { c.SigningKeys[0].KMSKeyID = "1234abcd-12ab-34cd-56ef-1234567890ab" }, wantErr: "key ARN"},
		{name: "kms alias arn rejected", mutate: func(c *IdPConfig) { c.SigningKeys[0].KMSKeyID = "arn:aws:kms:eu-west-1:111122223333:alias/k" }, wantErr: "key ARN"},
		{name: "kms mrk arn rejected", mutate: func(c *IdPConfig) {
			c.SigningKeys[0].KMSKeyID = "arn:aws:kms:eu-west-1:111122223333:key/mrk-0123456789abcdef0123456789abcdef"
		}, wantErr: "multi-region"},
		{name: "kms govcloud arn ok", mutate: func(c *IdPConfig) {
			c.SigningKeys[0].KMSKeyID = "arn:aws-us-gov:kms:us-gov-west-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab"
		}},
		{name: "file key on lambda rejected", mutate: func(c *IdPConfig) { c.SigningKeys[0].KMSKeyID, c.SigningKeys[0].File = "", "/k.pem" }, lambda: true, wantErr: "Lambda"},
		{name: "file key on lambda with allow_insecure", mutate: func(c *IdPConfig) { c.SigningKeys[0].KMSKeyID, c.SigningKeys[0].File = "", "/k.pem" }, lambda: true, insec: true},
		{name: "file key off lambda ok", mutate: func(c *IdPConfig) { c.SigningKeys[0].KMSKeyID, c.SigningKeys[0].File = "", "/k.pem" }},

		{name: "bad discovery path", mutate: func(c *IdPConfig) { c.Paths.Discovery = "/openid" }, wantErr: "/.well-known/openid-configuration"},
		{name: "jwks path collides", mutate: func(c *IdPConfig) { c.Paths.JWKS = "/.well-known/openid-configuration" }, wantErr: "distinct"},
		{name: "relative path", mutate: func(c *IdPConfig) { c.Paths.JWKS = "keys.json" }, wantErr: "must start with /"},
		{name: "unclean path", mutate: func(c *IdPConfig) { c.Paths.JWKS = "/a/../jwks.json" }, wantErr: "clean"},
		{name: "discovery not at issuer path", mutate: func(c *IdPConfig) {
			c.Issuer = "https://idp.example.com/warden"
			c.Paths.Discovery = "/other/.well-known/openid-configuration"
		}, wantErr: "issuer path"},
		{name: "jwks outside issuer prefix", mutate: func(c *IdPConfig) {
			c.Issuer = "https://idp.example.com/warden"
			c.JWKSURI = ""
			c.Paths.JWKS = "/other/.well-known/jwks.json"
		}, wantErr: "issuer path"},
		{name: "jwks path is /verify", mutate: func(c *IdPConfig) { c.Paths.JWKS = "/verify" }, wantErr: "conflicts with /verify"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.lambda {
				t.Setenv("AWS_LAMBDA_FUNCTION_NAME", "fn")
			} else {
				t.Setenv("AWS_LAMBDA_FUNCTION_NAME", "")
			}
			c := validIdP()
			tt.mutate(c)
			c.applyDefaults()
			err := c.validate(tt.insec, inbound)
			if tt.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.ErrorContains(t, err, tt.wantErr)
		})
	}
}

func TestIdPValidateRejectsHashInInboundIssuer(t *testing.T) {
	c := validIdP()
	c.applyDefaults()
	err := c.validate(false, []IssuerConfig{{Issuer: "https://evil.example.com/a#b"}})
	require.ErrorContains(t, err, "#")
}

func TestIdPDefaults(t *testing.T) {
	c := &IdPConfig{Issuer: "https://h.example.com/warden"}
	c.applyDefaults()
	require.Equal(t, 2*time.Minute, c.TokenTTL)
	require.Equal(t, IdPDefaultSourceIdentity, c.SourceIdentity)
	require.Equal(t, IdPOverflowTruncate, c.SourceIdentityOverflow)
	require.Equal(t, "{role_arn}", c.SubjectTemplate)
	require.Equal(t, 2*time.Second, c.SignTimeout)
	require.Equal(t, 5*time.Minute, c.JWKSCacheMaxAge)
	require.Equal(t, "/warden/.well-known/openid-configuration", c.Paths.Discovery)
	require.Equal(t, "/warden/.well-known/jwks.json", c.Paths.JWKS)
	require.Equal(t, "https://h.example.com/warden/.well-known/jwks.json", c.JWKSURI)
	require.Equal(t, IdPAudienceStatic, c.AudienceMode)
	require.True(t, c.IncludeSourceIdentityClaim())
	require.Empty(t, c.AllowedRoles)
}

func TestIdPFingerprintIgnoresReloadableFields(t *testing.T) {
	a, b := validIdP(), validIdP()
	b.Enabled = false
	b.AllowedRoles = []string{"@idp"}
	require.Equal(t, a.Fingerprint(), b.Fingerprint())
	b.TokenTTL = time.Minute
	require.NotEqual(t, a.Fingerprint(), b.Fingerprint())
}

const idpTestIssuerYAML = `
issuers:
  - issuer: "https://token.actions.githubusercontent.com"
    provider: github
    audiences: ["sts.amazonaws.com"]
`

const idpTestBlockYAML = `
idp:
  enabled: true
  issuer: "https://idp.example.com"
  audience: "sts.amazonaws.com"
  token_ttl: 3m
  audience_mode: role_arn
  source_identity: "{subject}"
  allowed_roles:
    - "arn:aws:iam::123456789012:role/R"
  paths:
    discovery: /.well-known/openid-configuration
    jwks: /.well-known/jwks.json
  signing_keys:
    - kms_key_id: "` + idpKMSARN + `"
      algorithm: RS256
      status: active
`

func loadIdPYAML(t *testing.T, body string) (*Config, error) {
	t.Helper()
	viper.Reset()
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(body), 0o600))
	t.Setenv("CONFIG_PATH", dir)
	t.Setenv("CONFIG_NAME", "config")
	c := &Config{}
	return c, c.LoadConfig()
}

func TestIdPEnvOnlyAppliesToExistingBlock(t *testing.T) {
	t.Run("env only, no block", func(t *testing.T) {
		t.Setenv("AOW_IDP_ENABLED", "true")
		c, err := loadIdPYAML(t, idpTestIssuerYAML)
		require.NoError(t, err)
		require.Nil(t, c.IdP)
	})
	t.Run("env beats file", func(t *testing.T) {
		t.Setenv("AOW_IDP_ISSUER", "https://env.example.com")
		c, err := loadIdPYAML(t, idpTestIssuerYAML+idpTestBlockYAML)
		require.NoError(t, err)
		require.NotNil(t, c.IdP)
		require.Equal(t, "https://env.example.com", c.IdP.Issuer)
	})
	t.Run("reapply without block", func(t *testing.T) {
		t.Setenv("AOW_IDP_ENABLED", "true")
		c := &Config{}
		reapplyEnvOverrides(c)
		require.Nil(t, c.IdP)
	})
	t.Run("bad duration keeps value", func(t *testing.T) {
		c, err := loadIdPYAML(t, idpTestIssuerYAML+idpTestBlockYAML)
		require.NoError(t, err)
		t.Setenv("AOW_IDP_TOKEN_TTL", "notaduration")
		reapplyEnvOverrides(c)
		require.Equal(t, 3*time.Minute, c.IdP.TokenTTL)
	})
}

func TestIdPYAMLRoundTrip(t *testing.T) {
	c, err := loadIdPYAML(t, idpTestIssuerYAML+idpTestBlockYAML)
	require.NoError(t, err)
	require.NotNil(t, c.IdP)
	require.True(t, c.IdP.Enabled)
	require.Equal(t, "https://idp.example.com", c.IdP.Issuer)
	require.Equal(t, "sts.amazonaws.com", c.IdP.Audience)
	require.Equal(t, 3*time.Minute, c.IdP.TokenTTL)
	require.Equal(t, IdPAudienceRoleARN, c.IdP.AudienceMode)
	require.Equal(t, "{subject}", c.IdP.SourceIdentity)
	require.Equal(t, []string{"arn:aws:iam::123456789012:role/R"}, c.IdP.AllowedRoles)
	require.Equal(t, "/.well-known/openid-configuration", c.IdP.Paths.Discovery)
	require.Equal(t, "/.well-known/jwks.json", c.IdP.Paths.JWKS)
	require.Equal(t, []IdPSigningKey{{KMSKeyID: idpKMSARN, Algorithm: "RS256", Status: IdPKeyActive}}, c.IdP.SigningKeys)

	cl, err := cloneConfig(c)
	require.NoError(t, err)
	require.Equal(t, c.IdP, cl.IdP)
}

func TestIdPValidatedWhileDisabled(t *testing.T) {
	base := func(idp *IdPConfig) *Config {
		return &Config{
			Issuers:         singleIssuer("https://token.actions.githubusercontent.com", "sts.amazonaws.com"),
			RoleSessionName: "aow",
			IdP:             idp,
		}
	}
	bad := validIdP()
	bad.Enabled = false
	bad.Issuer = "http://idp.example.com"
	require.Error(t, base(bad).Validate())
	require.NoError(t, base(nil).Validate())
}
