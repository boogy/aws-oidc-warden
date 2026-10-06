package validator

import (
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/boogy/aws-oidc-warden/internal/types"
)

// maxKeyMemoEntries bounds the in-process pre-parsed-key memo so churn of
// distinct (issuer, kid) pairs can't grow it unboundedly. Hitting the cap just
// clears the memo — perf cost only, never a security regression.
const maxKeyMemoEntries = 4096

// keyMemoKey identifies a memo slot; the key material is compared on lookup.
type keyMemoKey struct{ issuer, kid string }

// keyMaterial is the part of a JWK that determines the parsed key.
type keyMaterial struct{ kty, n, e, crv, x, y string }

func materialOf(k types.JSONWebKey) keyMaterial {
	return keyMaterial{kty: k.KeyType, n: k.N, e: k.E, crv: k.Crv, x: k.X, y: k.Y}
}

type keyMemoEntry struct {
	material keyMaterial
	key      any
}

// keyMemo caches parsed, re-validated (RSA >=2048 / EC on-curve) public keys
// per (issuer, kid). An entry is served only while its stored key material
// equals the JWK's, so a key rotated under a reused kid misses and is
// re-parsed + re-validated instead of serving a stale key.
type keyMemo struct {
	entries sync.Map // keyMemoKey -> keyMemoEntry
	size    atomic.Int64
}

func newKeyMemo() *keyMemo {
	return &keyMemo{}
}

func (m *keyMemo) load(issuer string, jwk types.JSONWebKey) (any, bool) {
	v, ok := m.entries.Load(keyMemoKey{issuer, jwk.KeyID})
	if !ok {
		return nil, false
	}
	e := v.(keyMemoEntry)
	if e.material != materialOf(jwk) {
		return nil, false
	}
	return e.key, true
}

func (m *keyMemo) store(issuer string, jwk types.JSONWebKey, key any) {
	if m.size.Load() >= maxKeyMemoEntries {
		m.entries.Clear()
		m.size.Store(0)
	}
	if _, loaded := m.entries.Swap(keyMemoKey{issuer, jwk.KeyID}, keyMemoEntry{materialOf(jwk), key}); !loaded {
		m.size.Add(1)
	}
}

// resolveKey returns the parsed, re-validated public key for key, using the
// in-process memo when it holds this (issuer, kid) with identical key
// material, and populating it otherwise.
func (t *TokenValidator) resolveKey(issuer string, key types.JSONWebKey) (any, error) {
	if cached, ok := t.keyMemo.load(issuer, key); ok {
		return cached, nil
	}

	var (
		parsed any
		err    error
	)
	switch key.KeyType {
	case "RSA":
		parsed, err = parseRSAKey(key)
	case "EC":
		parsed, err = parseECKey(key)
	default:
		return nil, fmt.Errorf("unsupported key type %q for kid %q", key.KeyType, key.KeyID)
	}
	if err != nil {
		return nil, err
	}

	t.keyMemo.store(issuer, key, parsed)
	return parsed, nil
}
