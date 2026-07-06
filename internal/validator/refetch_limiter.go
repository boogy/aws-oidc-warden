package validator

import (
	"sync"
	"time"
)

const (
	// defaultRefetchKeyCooldown bounds how often a forced JWKS refetch may be
	// triggered for the same (issuer, kid). Long enough to blunt repeated
	// hammering of one bogus kid; short enough that legitimate key rotation
	// (a genuinely new kid) is never blocked -- a new kid has no prior entry,
	// so it always passes on its first miss.
	defaultRefetchKeyCooldown = 60 * time.Second
	// defaultRefetchIssuerCooldown is the per-issuer global backstop: even
	// when every kid in a flood is "new" (never seen before), forced
	// refetches for one issuer are throttled to roughly this rate, so an
	// attacker sending many distinct bogus kids can't force unbounded
	// upstream JWKS fetches.
	defaultRefetchIssuerCooldown = 2 * time.Second
	// maxTrackedRefetchKeys bounds refetchLimiter.perKey's growth. Hitting the
	// cap clears it -- a rare, security-neutral degrade (worst case: a kid
	// that already refetched recently is allowed to refetch again, still
	// subject to the per-issuer backstop).
	maxTrackedRefetchKeys = 4096
)

// refetchLimiter rate-limits forced (cache-bypassing) JWKS refetches. It is
// keyed per (issuer, kid) so a genuinely new signing key still triggers a
// prompt refetch -- key rotation must keep working -- while a per-issuer
// global cooldown bounds the *rate* of upstream calls even when an attacker
// sends a flood of distinct, never-before-seen bogus kids for one issuer.
type refetchLimiter struct {
	mu             sync.Mutex
	perKey         map[string]time.Time
	perIssuer      map[string]time.Time
	keyCooldown    time.Duration
	issuerCooldown time.Duration
	now            func() time.Time
}

// newRefetchLimiter builds a limiter with the given per-(issuer,kid) cooldown
// (normally cfg.JWKSRefetchCooldown, already defaulted to
// defaultRefetchKeyCooldown by config.Validate(); keyCooldown<=0 falls back
// to the same default here too, so a hand-built config in a test is never
// left with an unbounded-refetch limiter).
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
