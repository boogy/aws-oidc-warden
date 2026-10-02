package config

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path"
	"regexp"
	"strings"
	"time"

	"github.com/boogy/aws-oidc-warden/internal/utils"
)

const (
	IdPKeyActive     = "active"
	IdPKeyVerifyOnly = "verify_only"

	IdPDefaultSubjectTemplate = "{role_arn}"
	IdPDefaultSourceIdentity  = "{issuer}:{subject}"

	IdPDefaultMaxSessionDuration = time.Hour

	IdPOverflowTruncate = "truncate"
	IdPOverflowReject   = "reject"

	IdPAudienceStatic  = "static"
	IdPAudienceRoleARN = "role_arn"

	idpMaxKeys       = 5
	idpMinTTL        = time.Minute
	idpMaxTTL        = 5 * time.Minute
	idpDiscoverySufx = "/.well-known/openid-configuration"
	idpJWKSSufx      = "/.well-known/jwks.json"
)

var idpKMSKeyARN = regexp.MustCompile(`^arn:aws[a-z-]*:kms:[a-z0-9-]+:\d{12}:key/[0-9a-f-]{36}$`)

// IdPConfig configures the optional token-minting identity provider.
type IdPConfig struct {
	Enabled                bool            `mapstructure:"enabled"                  json:"enabled"`
	Issuer                 string          `mapstructure:"issuer"                   json:"issuer"`
	Audience               string          `mapstructure:"audience"                 json:"audience"`
	AudienceMode           string          `mapstructure:"audience_mode"            json:"audience_mode,omitempty"`
	TokenTTL               time.Duration   `mapstructure:"token_ttl"                json:"token_ttl,omitempty"`
	IncludeSourceIdentity  *bool           `mapstructure:"include_source_identity"  json:"include_source_identity,omitempty"`
	SourceIdentity         string          `mapstructure:"source_identity"          json:"source_identity,omitempty"`
	SourceIdentityOverflow string          `mapstructure:"source_identity_overflow" json:"source_identity_overflow,omitempty"`
	AllowedRoles           []string        `mapstructure:"allowed_roles"            json:"allowed_roles,omitempty"`
	SubjectTemplate        string          `mapstructure:"subject_template"         json:"subject_template,omitempty"`
	JWKSURI                string          `mapstructure:"jwks_uri"                 json:"jwks_uri,omitempty"`
	Paths                  IdPPaths        `mapstructure:"paths"                    json:"paths"`
	SignTimeout            time.Duration   `mapstructure:"sign_timeout"             json:"sign_timeout,omitempty"`
	JWKSCacheMaxAge        time.Duration   `mapstructure:"jwks_cache_max_age"       json:"jwks_cache_max_age,omitempty"`
	MaxSessionDuration     time.Duration   `mapstructure:"max_session_duration"     json:"max_session_duration,omitempty"`
	AllowSessionName       bool            `mapstructure:"allow_session_name"       json:"allow_session_name,omitempty"`
	SigningKeys            []IdPSigningKey `mapstructure:"signing_keys"             json:"signing_keys"`
}

// IdPPaths are the exact request paths the IdP endpoints answer on.
type IdPPaths struct {
	Token     string `mapstructure:"token"     json:"token,omitempty"`
	Discovery string `mapstructure:"discovery" json:"discovery,omitempty"`
	JWKS      string `mapstructure:"jwks"      json:"jwks,omitempty"`
}

// IdPSigningKey is one signing key: KMS (production) or PEM file (dev only).
type IdPSigningKey struct {
	KMSKeyID  string `mapstructure:"kms_key_id" json:"kms_key_id,omitempty"`
	File      string `mapstructure:"file"       json:"file,omitempty"`
	Algorithm string `mapstructure:"algorithm"  json:"algorithm"`
	Status    string `mapstructure:"status"     json:"status"`
}

// Source identifies the key's backing store for logs and duplicate detection.
func (k IdPSigningKey) Source() string {
	if k.KMSKeyID != "" {
		return "kms:" + k.KMSKeyID
	}
	return "file:" + k.File
}

// IncludeSourceIdentityClaim reports whether minted tokens carry the AWS source_identity claim.
func (c IdPConfig) IncludeSourceIdentityClaim() bool {
	return c.IncludeSourceIdentity == nil || *c.IncludeSourceIdentity
}

// Fingerprint identifies the cold-start-frozen settings (everything but the live fields).
func (c IdPConfig) Fingerprint() string {
	c.Enabled, c.AllowedRoles, c.MaxSessionDuration, c.AllowSessionName = false, nil, 0, false
	b, _ := json.Marshal(c)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func (c *IdPConfig) applyDefaults() {
	if c.TokenTTL == 0 {
		c.TokenTTL = 2 * time.Minute
	}
	if c.SourceIdentity == "" {
		c.SourceIdentity = IdPDefaultSourceIdentity
	}
	if c.SourceIdentityOverflow == "" {
		c.SourceIdentityOverflow = IdPOverflowTruncate
	}
	if c.AudienceMode == "" {
		c.AudienceMode = IdPAudienceStatic
	}
	if c.SubjectTemplate == "" {
		c.SubjectTemplate = IdPDefaultSubjectTemplate
	}
	if c.SignTimeout == 0 {
		c.SignTimeout = 2 * time.Second
	}
	if c.JWKSCacheMaxAge == 0 {
		c.JWKSCacheMaxAge = 5 * time.Minute
	}
	if c.MaxSessionDuration == 0 {
		c.MaxSessionDuration = IdPDefaultMaxSessionDuration
	}
	base := ""
	if u, err := url.Parse(c.Issuer); err == nil {
		base = strings.TrimSuffix(u.Path, "/")
	}
	if c.Paths.Token == "" {
		c.Paths.Token = base + "/idp/token"
	}
	if c.Paths.Discovery == "" {
		c.Paths.Discovery = base + idpDiscoverySufx
	}
	if c.Paths.JWKS == "" {
		c.Paths.JWKS = base + idpJWKSSufx
	}
	if c.JWKSURI == "" && c.Issuer != "" {
		c.JWKSURI = c.Issuer + idpJWKSSufx
	}
}

func (c *IdPConfig) validate(allowInsecure bool, inbound []IssuerConfig) error {
	if err := validateIdPURL("idp.issuer", c.Issuer, allowInsecure); err != nil {
		return err
	}
	if err := validateIdPURL("idp.jwks_uri", c.JWKSURI, allowInsecure); err != nil {
		return err
	}
	if err := c.checkInbound(inbound); err != nil {
		return err
	}
	if strings.TrimSpace(c.Audience) == "" {
		return errors.New("idp.audience is required")
	}
	if c.AudienceMode != IdPAudienceStatic && c.AudienceMode != IdPAudienceRoleARN {
		return fmt.Errorf("idp.audience_mode must be %s or %s", IdPAudienceStatic, IdPAudienceRoleARN)
	}
	if err := c.validateAllowedRoles(); err != nil {
		return err
	}
	if c.TokenTTL < idpMinTTL || c.TokenTTL > idpMaxTTL {
		return fmt.Errorf("idp.token_ttl must be between %s and %s", idpMinTTL, idpMaxTTL)
	}
	if c.MaxSessionDuration < idpMinSessionCap || c.MaxSessionDuration > idpMaxSessionCap {
		return fmt.Errorf("idp.max_session_duration must be between %s and %s", idpMinSessionCap, idpMaxSessionCap)
	}
	if c.MaxSessionDuration%time.Second != 0 {
		return errors.New("idp.max_session_duration must be a whole number of seconds")
	}
	if c.SignTimeout <= 0 || c.JWKSCacheMaxAge < 0 {
		return errors.New("idp.sign_timeout must be > 0 and idp.jwks_cache_max_age >= 0")
	}
	if err := c.validateTemplates(len(inbound)); err != nil {
		return err
	}
	if c.SourceIdentityOverflow != IdPOverflowTruncate && c.SourceIdentityOverflow != IdPOverflowReject {
		return fmt.Errorf("idp.source_identity_overflow must be %s or %s", IdPOverflowTruncate, IdPOverflowReject)
	}
	if err := c.validatePaths(); err != nil {
		return err
	}
	return c.validateKeys(allowInsecure)
}

func (c *IdPConfig) validateAllowedRoles() error {
	for i, r := range c.AllowedRoles {
		if name, ok := strings.CutPrefix(r, "@"); ok && name != "" {
			continue
		}
		if _, _, err := utils.ParseRoleARN(r); err != nil {
			return fmt.Errorf("idp.allowed_roles[%d] %q must be a role ARN or @role_set", i, r)
		}
	}
	return nil
}

// checkInbound rejects inbound issuers that collide with the IdP issuer or break the # sub separator.
func (c *IdPConfig) checkInbound(inbound []IssuerConfig) error {
	for _, in := range inbound {
		if in.Issuer == c.Issuer {
			return fmt.Errorf("idp.issuer %q must differ from every inbound issuer (issuers[])", c.Issuer)
		}
		if strings.Contains(in.Issuer, "#") {
			return fmt.Errorf("issuers[] %q must not contain # when idp is configured", in.Issuer)
		}
	}
	return nil
}

func (c *IdPConfig) validatePaths() error {
	seen := map[string]bool{}
	for _, e := range []struct{ name, p string }{
		{"token", c.Paths.Token}, {"discovery", c.Paths.Discovery}, {"jwks", c.Paths.JWKS},
	} {
		if !strings.HasPrefix(e.p, "/") || path.Clean(e.p) != e.p {
			return fmt.Errorf("idp.paths.%s %q must start with / and be clean", e.name, e.p)
		}
		if e.p == "/verify" {
			return fmt.Errorf("idp.paths.%s conflicts with /verify", e.name)
		}
		if seen[e.p] {
			return errors.New("idp.paths must be distinct")
		}
		seen[e.p] = true
	}
	if !strings.HasSuffix(c.Paths.Discovery, idpDiscoverySufx) {
		return fmt.Errorf("idp.paths.discovery must end with %s", idpDiscoverySufx)
	}
	u, err := url.Parse(c.Issuer)
	if err != nil {
		return fmt.Errorf("idp.issuer %q must be an absolute URL", c.Issuer)
	}
	issuerPath := strings.TrimSuffix(u.Path, "/")
	if c.Paths.Discovery != issuerPath+idpDiscoverySufx ||
		!strings.HasPrefix(c.Paths.Token, issuerPath+"/") ||
		!strings.HasPrefix(c.Paths.JWKS, issuerPath+"/") {
		return fmt.Errorf("idp.paths must be under the issuer path %q", issuerPath)
	}
	return nil
}

func (c *IdPConfig) validateKeys(allowInsecure bool) error {
	if len(c.SigningKeys) > idpMaxKeys {
		return fmt.Errorf("idp.signing_keys: at most %d keys", idpMaxKeys)
	}
	active := 0
	seen := map[string]bool{}
	for i, k := range c.SigningKeys {
		if (k.KMSKeyID == "") == (k.File == "") {
			return fmt.Errorf("idp.signing_keys[%d]: exactly one of kms_key_id or file", i)
		}
		if strings.Contains(k.KMSKeyID, ":key/mrk-") {
			return fmt.Errorf("idp.signing_keys[%d]: kms_key_id is a multi-region key; use a single-region key", i)
		}
		if k.KMSKeyID != "" && !idpKMSKeyARN.MatchString(k.KMSKeyID) {
			return fmt.Errorf("idp.signing_keys[%d]: kms_key_id must be a full key ARN (aliases and bare IDs are rejected)", i)
		}
		if k.File != "" && os.Getenv("AWS_LAMBDA_FUNCTION_NAME") != "" && !allowInsecure {
			return fmt.Errorf("idp.signing_keys[%d]: file keys are not allowed on Lambda (the key would ship in the deployment package); use kms_key_id", i)
		}
		if k.Algorithm != "RS256" && k.Algorithm != "ES256" {
			return fmt.Errorf("idp.signing_keys[%d]: algorithm must be RS256 or ES256", i)
		}
		switch k.Status {
		case IdPKeyActive:
			active++
		case IdPKeyVerifyOnly:
		default:
			return fmt.Errorf("idp.signing_keys[%d]: status must be %s or %s", i, IdPKeyActive, IdPKeyVerifyOnly)
		}
		if seen[k.Source()] {
			return fmt.Errorf("idp.signing_keys[%d]: duplicate key %s", i, k.Source())
		}
		seen[k.Source()] = true
	}
	if active != 1 {
		return errors.New("idp.signing_keys: exactly one active key is required")
	}
	return nil
}

func validateIdPURL(field, raw string, allowInsecure bool) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return fmt.Errorf("%s %q must be an absolute URL", field, raw)
	}
	if u.Scheme != "https" && (!allowInsecure || u.Scheme != "http") {
		return fmt.Errorf("%s must use https", field)
	}
	if u.User != nil {
		return fmt.Errorf("%s must not contain userinfo", field)
	}
	if u.Port() != "" && !allowInsecure {
		return fmt.Errorf("%s must not contain a port", field)
	}
	if u.Host != strings.ToLower(u.Host) {
		return fmt.Errorf("%s host must be lowercase", field)
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("%s must not contain a query or fragment", field)
	}
	if strings.HasSuffix(raw, "/") {
		return fmt.Errorf("%s must not have a trailing slash", field)
	}
	return nil
}
