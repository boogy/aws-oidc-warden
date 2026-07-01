package validator

import (
	"fmt"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/boogy/aws-oidc-warden/internal/types"
)

// maxKeyMemoEntries bounds the in-process pre-parsed-key memo so churn of
// distinct (issuer, kid, key-material) fingerprints -- e.g. repeated key
// rotation over a long-running process -- can't grow it unboundedly. Hitting
// the cap just clears the memo; the next lookups re-parse and re-validate
// (S4) -- never a security regression, only a perf one.
const maxKeyMemoEntries = 4096

// keyMemo caches parsed, S4-revalidated (RSA >=2048 / EC on-curve) public
// keys keyed by a fingerprint of (issuer, kid, key material) -- not just
// (issuer, kid) -- so a key rotated under a reused kid naturally misses the
// memo and gets re-parsed + re-validated instead of serving a stale key.
type keyMemo struct {
	entries sync.Map // fingerprint string -> crypto public key (any)
	size    atomic.Int64
}

func newKeyMemo() *keyMemo {
	return &keyMemo{}
}

func (m *keyMemo) load(fp string) (any, bool) {
	return m.entries.Load(fp)
}

func (m *keyMemo) store(fp string, key any) {
	if m.size.Load() >= maxKeyMemoEntries {
		m.entries.Clear()
		m.size.Store(0)
	}
	if _, loaded := m.entries.LoadOrStore(fp, key); !loaded {
		m.size.Add(1)
	}
}

// keyFingerprint derives a stable identity for a JWKS key's actual material,
// scoped to issuer + kid, so a key rotated under a reused kid gets a
// different fingerprint (fresh parse + S4 revalidation) instead of silently
// reusing a stale cached key.
func keyFingerprint(issuer string, key types.JSONWebKey) string {
	var b strings.Builder
	b.WriteString(issuer)
	b.WriteByte('|')
	b.WriteString(key.KeyID)
	b.WriteByte('|')
	b.WriteString(key.KeyType)
	b.WriteByte('|')
	switch key.KeyType {
	case "RSA":
		b.WriteString(key.N)
		b.WriteByte('.')
		b.WriteString(key.E)
	case "EC":
		b.WriteString(key.Crv)
		b.WriteByte('.')
		b.WriteString(key.X)
		b.WriteByte('.')
		b.WriteString(key.Y)
	}
	return b.String()
}

// resolveKey returns the parsed, S4-revalidated public key for key, using the
// in-process memo when the (issuer, kid, key-material) fingerprint has been
// seen before, and populating it (after the same RSA>=2048/EC-on-curve
// validation parseRSAKey/parseECKey always perform) otherwise.
func (t *TokenValidator) resolveKey(issuer string, key types.JSONWebKey) (any, error) {
	fp := keyFingerprint(issuer, key)
	if cached, ok := t.keyMemo.load(fp); ok {
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

	t.keyMemo.store(fp, parsed)
	return parsed, nil
}
