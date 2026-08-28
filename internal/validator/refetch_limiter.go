package validator

import (
	"sync"
	"time"
)

const (
	// defaultRefetchKeyCooldown bounds how often a forced JWKS refetch may be
	// triggered for the same (issuer, kid). A genuinely new kid has no prior
	// entry, so key rotation always passes on its first miss.
	defaultRefetchKeyCooldown = 60 * time.Second
	// defaultRefetchIssuerCooldown is the per-issuer global backstop: even
	// when every kid in a flood is new, forced refetches for one issuer are
	// throttled to roughly this rate.
	defaultRefetchIssuerCooldown = 2 * time.Second
	// maxTrackedRefetchKeys bounds refetchLimiter.perKey's growth. Hitting the
	// cap clears it — security-neutral, still subject to the per-issuer backstop.
	maxTrackedRefetchKeys = 4096
)

// refetchLimiter rate-limits forced (cache-bypassing) JWKS refetches. Keyed
// per (issuer, kid) so key rotation keeps working, with a per-issuer global
// cooldown bounding the rate even under a flood of distinct bogus kids.
type refetchLimiter struct {
	mu             sync.Mutex
	perKey         map[string]time.Time
	perIssuer      map[string]time.Time
	keyCooldown    time.Duration
	issuerCooldown time.Duration
	now            func() time.Time
}

// newRefetchLimiter builds a limiter with the given per-(issuer,kid) cooldown
// (normally cfg.JWKSRefetchCooldown, already defaulted by config.Validate();
// keyCooldown<=0 falls back to the same default here too).
func newRefetchLimiter(now func() time.Time, keyCooldown time.Duration) *refetchLimiter {
	if keyCooldown <= 0 {
		keyCooldown = defaultRefetchKeyCooldown
	}
	return &refetchLimiter{
		perKey:         make(map[string]time.Time),
		perIssuer:      make(map[string]time.Time),
		keyCooldown:    keyCooldown,
		issuerCooldown: defaultRefetchIssuerCooldown,
		now:            now,
	}
}

// allow reports whether a forced refetch for (issuer, kid) may proceed right
// now, and records that decision so subsequent calls within the cooldown
// windows are denied.
func (l *refetchLimiter) allow(issuer, kid string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	key := issuer + "|" + kid

	if last, ok := l.perKey[key]; ok && now.Sub(last) < l.keyCooldown {
		return false
	}
	if last, ok := l.perIssuer[issuer]; ok && now.Sub(last) < l.issuerCooldown {
		return false
	}

	if len(l.perKey) >= maxTrackedRefetchKeys {
		l.perKey = make(map[string]time.Time)
	}
	l.perKey[key] = now
	l.perIssuer[issuer] = now
	return true
}
