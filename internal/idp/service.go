package idp

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sync/singleflight"

	"github.com/boogy/aws-oidc-warden/internal/config"
)

const (
	loadCooldownMin = 5 * time.Second
	loadTimeout     = 3 * time.Second
)

// ErrUnavailable means signing keys are not loaded; IdP endpoints answer 503.
var ErrUnavailable = errors.New("idp signing keys unavailable")

// Loader builds every configured signer; it must fail if any key fails.
type Loader func(ctx context.Context) ([]LoadedKey, error)

// Service owns the frozen IdP config and the lazily loaded KeySet.
type Service struct {
	cfg      config.IdPConfig
	load     Loader
	ks       atomic.Pointer[KeySet]
	sf       singleflight.Group
	mu       sync.Mutex // guards lastFail and cooldown
	lastFail time.Time
	cooldown time.Duration
	now      func() time.Time
}

// NewService freezes a deep copy of cfg and defers key loading to load.
func NewService(cfg config.IdPConfig, load Loader) *Service {
	c := cfg
	c.SigningKeys = slices.Clone(c.SigningKeys)
	c.AllowedRoles = slices.Clone(c.AllowedRoles)
	if c.IncludeSourceIdentity != nil {
		v := *c.IncludeSourceIdentity
		c.IncludeSourceIdentity = &v
	}
	return &Service{cfg: c, load: load, now: time.Now}
}

// Config returns the config frozen at construction.
func (s *Service) Config() config.IdPConfig { return s.cfg }

// Warm loads keys at bootstrap, ignoring the failure cooldown.
func (s *Service) Warm(ctx context.Context) error {
	_, err := s.loadOnce(ctx)
	return err
}

// KeySet returns the loaded key set, loading it lazily outside the failure cooldown.
func (s *Service) KeySet(ctx context.Context) (*KeySet, error) {
	if ks := s.ks.Load(); ks != nil {
		return ks, nil
	}
	if s.coolingDown() {
		return nil, ErrUnavailable
	}
	ks, err := s.loadOnce(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	return ks, nil
}

// Mint signs a self-verified token for req with the active key.
func (s *Service) Mint(ctx context.Context, req MintRequest) (*Token, error) {
	ks, err := s.KeySet(ctx)
	if err != nil {
		return nil, err
	}
	return mint(ctx, s.cfg, ks, req, s.now())
}

func (s *Service) coolingDown() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return !s.lastFail.IsZero() && s.now().Sub(s.lastFail) < s.cooldown
}

func (s *Service) loadOnce(ctx context.Context) (*KeySet, error) {
	v, err, _ := s.sf.Do("load", func() (any, error) {
		if ks := s.ks.Load(); ks != nil {
			return ks, nil
		}
		lctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), loadTimeout)
		defer cancel()
		keys, err := s.load(lctx)
		var ks *KeySet
		if err == nil {
			ks, err = NewKeySet(s.cfg, keys)
		}
		if err != nil {
			s.mu.Lock()
			s.lastFail = s.now()
			s.cooldown = loadCooldownMin + rand.N(loadCooldownMin)
			s.mu.Unlock()
			return nil, err
		}
		s.ks.Store(ks)
		return ks, nil
	})
	if err != nil {
		return nil, err
	}
	return v.(*KeySet), nil
}
