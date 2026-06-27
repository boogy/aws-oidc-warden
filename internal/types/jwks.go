package types

// JSONWebKey is a JSON web key as specified by RFC 7517.
type JSONWebKey struct {
	Algorithm string   `json:"alg,omitempty"`
	KeyID     string   `json:"kid,omitempty"`
	KeyType   string   `json:"kty,omitempty"`
	Use       string   `json:"use,omitempty"`
	N         string   `json:"n,omitempty"`   // RSA modulus
	E         string   `json:"e,omitempty"`   // RSA public exponent
	X         string   `json:"x,omitempty"`   // EC x coordinate
	Y         string   `json:"y,omitempty"`   // EC y coordinate
	Crv       string   `json:"crv,omitempty"` // EC curve
	X5c       []string `json:"x5c,omitempty"` // X.509 certificate chain
	X5u       string   `json:"x5u,omitempty"` // X.509 URL
}

// JWKS represents a set of JSON Web Keys retrieved from a JWKS endpoint
type JWKS struct {
	Keys []JSONWebKey `json:"keys"`
}

// For backward compatibility and to maintain the existing interface
// These aliases are provided to allow code to adapt gradually
type JSONWebKeySet = JWKS
