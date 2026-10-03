package idp

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"

	"github.com/boogy/aws-oidc-warden/internal/config"
	"github.com/boogy/aws-oidc-warden/internal/types"
)

// mintedClaims is every claim the minter can emit; discovery advertises exactly this set.
var mintedClaims = []string{"iss", "sub", "aud", "exp", "iat", "nbf", "jti", "src_iss", "src_sub", "request_id",
	"https://aws.amazon.com/tags", "https://aws.amazon.com/source_identity"}

// LoadedKey is a ready signer plus its configured rotation status.
type LoadedKey struct {
	Signer Signer
	Status string
}

// KeySet holds the active signer and the precomputed public documents.
type KeySet struct {
	active    Signer
	jwks      []byte
	discovery []byte
}

// NewKeySet validates keys and precomputes the JWKS and discovery documents.
func NewKeySet(cfg config.IdPConfig, keys []LoadedKey) (*KeySet, error) {
	var ks KeySet
	var jwks types.JWKS
	seen := map[string]bool{}
	var algs []string
	for _, k := range keys {
		kid := k.Signer.KeyID()
		if seen[kid] {
			return nil, fmt.Errorf("duplicate kid %s", kid)
		}
		seen[kid] = true
		j, err := PublicJWK(k.Signer.Algorithm(), k.Signer.Public())
		if err != nil {
			return nil, err
		}
		jwks.Keys = append(jwks.Keys, j)
		if !slices.Contains(algs, j.Algorithm) {
			algs = append(algs, j.Algorithm)
		}
		if k.Status == config.IdPKeyActive {
			if ks.active != nil {
				return nil, errors.New("multiple active signing keys")
			}
			ks.active = k.Signer
		}
	}
	if ks.active == nil {
		return nil, errors.New("no active signing key")
	}
	var err error
	if ks.jwks, err = json.Marshal(jwks); err != nil {
		return nil, err
	}
	if ks.discovery, err = json.Marshal(map[string]any{
		"issuer":                                cfg.Issuer,
		"jwks_uri":                              cfg.JWKSURI,
		"response_types_supported":              []string{"id_token"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": algs,
		"claims_supported":                      mintedClaims,
	}); err != nil {
		return nil, err
	}
	return &ks, nil
}

// Active returns the signer for new tokens.
func (k *KeySet) Active() Signer { return k.active }

// JWKS returns a copy of the JWKS document.
func (k *KeySet) JWKS() []byte { return slices.Clone(k.jwks) }

// Discovery returns a copy of the OIDC discovery document.
func (k *KeySet) Discovery() []byte { return slices.Clone(k.discovery) }
