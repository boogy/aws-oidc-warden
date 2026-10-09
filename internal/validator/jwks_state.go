package validator

import (
	"crypto/sha256"
	"encoding/json"
	"sync"
	"time"

	"github.com/boogy/aws-oidc-warden/internal/types"
)

const (
	// jwksFailureMemoTTL is how long a failed fetch suppresses retries for its cache key.
	jwksFailureMemoTTL = 5 * time.Second
	// maxJWKSStateEntries bounds each map below; hitting it clears the map.
	maxJWKSStateEntries = 256
)

type jwksFailure struct {
	at  time.Time
	err error
}

type jwksWrite struct {
	hash [sha256.Size]byte
	at   time.Time
}

// jwksState holds per-key failure memos and last-cache-write hash/time.
type jwksState struct {
	mu       sync.Mutex
	failures map[string]jwksFailure
	writes   map[string]jwksWrite
}

// recentFailure returns key's fetch error within jwksFailureMemoTTL of now, or nil.
func (s *jwksState) recentFailure(key string, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if f, ok := s.failures[key]; ok && now.Sub(f.at) < jwksFailureMemoTTL {
		return f.err
	}
	return nil
}

func (s *jwksState) recordFailure(key string, now time.Time, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failures == nil || len(s.failures) >= maxJWKSStateEntries {
		s.failures = make(map[string]jwksFailure)
	}
	s.failures[key] = jwksFailure{at: now, err: err}
}

func (s *jwksState) clearFailure(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.failures, key)
}

// writtenRecently reports whether key was written with hash less than maxAge before now.
func (s *jwksState) writtenRecently(key string, hash [sha256.Size]byte, now time.Time, maxAge time.Duration) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	w, ok := s.writes[key]
	return ok && w.hash == hash && now.Sub(w.at) < maxAge
}

func (s *jwksState) recordWrite(key string, hash [sha256.Size]byte, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.writes == nil || len(s.writes) >= maxJWKSStateEntries {
		s.writes = make(map[string]jwksWrite)
	}
	s.writes[key] = jwksWrite{hash: hash, at: now}
}

// hashJWKS hashes the JWKS' JSON encoding; ok is false if it can't be encoded.
func hashJWKS(jwks *types.JWKS) (h [sha256.Size]byte, ok bool) {
	b, err := json.Marshal(jwks)
	if err != nil {
		return h, false
	}
	return sha256.Sum256(b), true
}
