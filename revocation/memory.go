package revocation

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/dcadolph/jwtsmith/claims"
	"github.com/dcadolph/jwtsmith/pkgerr"
)

// KeyExtractor returns the revocation key for a token.
//
// The bool reports whether a key was found; tokens without a key are treated as
// not-revoked (since there is nothing to compare against). Implementations should
// be deterministic.
type KeyExtractor func(token *jwt.Token) (string, bool)

// JTIExtractor extracts the jti registered claim. Tokens without a jti are not revokable
// by jti-based MemRevokers; mint tokens with a jti if you need per-token revocation.
func JTIExtractor(token *jwt.Token) (string, bool) {
	mc, err := claims.ToMapClaims(token.Claims)
	if err != nil {
		return "", false
	}
	jti, err := claims.JTI(mc)
	if err != nil || jti == "" {
		return "", false
	}
	return jti, true
}

// SubjectExtractor extracts the sub registered claim. Useful when revoking every token
// for a given user (e.g. on password change or account suspension).
func SubjectExtractor(token *jwt.Token) (string, bool) {
	mc, err := claims.ToMapClaims(token.Claims)
	if err != nil {
		return "", false
	}
	sub, err := claims.Subject(mc)
	if err != nil || sub == "" {
		return "", false
	}
	return sub, true
}

// MemOpt configures a MemRevoker.
type MemOpt func(*MemRevoker) error

// WithKeyExtractor overrides the function used to derive the revocation key from a
// token. Defaults to JTIExtractor.
func WithKeyExtractor(fn KeyExtractor) MemOpt {
	return func(m *MemRevoker) error {
		if fn == nil {
			return fmt.Errorf("%w: WithKeyExtractor: fn cannot be nil", pkgerr.ErrInvalidValue)
		}
		m.keyFn = fn
		return nil
	}
}

// WithClock overrides the clock used for TTL expiration. Intended for tests.
func WithClock(now func() time.Time) MemOpt {
	return func(m *MemRevoker) error {
		if now == nil {
			return fmt.Errorf("%w: WithClock: now cannot be nil", pkgerr.ErrInvalidValue)
		}
		m.now = now
		return nil
	}
}

// MemRevoker is an in-process Revoker backed by a map of revoked keys to optional
// expiry times. Suitable for single-replica deployments and tests; for distributed
// fleets, implement Revoker against a shared store and use Chain to front it with
// a MemRevoker cache.
//
// Zero-value MemRevoker is not usable; construct via NewMemRevoker.
type MemRevoker struct {
	mu      sync.RWMutex
	revoked map[string]time.Time
	keyFn   KeyExtractor
	now     func() time.Time
}

// NewMemRevoker returns a MemRevoker. By default it extracts keys via JTIExtractor and
// uses time.Now for TTL expiration; override either with WithKeyExtractor / WithClock.
func NewMemRevoker(opts ...MemOpt) (*MemRevoker, error) {
	m := &MemRevoker{
		revoked: make(map[string]time.Time),
		keyFn:   JTIExtractor,
		now:     time.Now,
	}
	for _, opt := range opts {
		if err := opt(m); err != nil {
			return nil, err
		}
	}
	return m, nil
}

// Revoke marks key as revoked indefinitely.
//
// Indefinite entries never expire; prefer RevokeUntil(key, originalExp) so the entry
// can be reaped once the underlying token would have expired anyway.
func (m *MemRevoker) Revoke(key string) {
	m.RevokeUntil(key, time.Time{})
}

// RevokeUntil marks key as revoked until the given time. A zero until means "forever".
//
// The recommended pattern is to pass the token's own exp as until: once the token
// would have expired naturally, the entry can be reaped via Cleanup.
func (m *MemRevoker) RevokeUntil(key string, until time.Time) {
	if key == "" {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.revoked[key] = until
}

// Unrevoke removes key from the revocation set. No-op if the key is not revoked.
func (m *MemRevoker) Unrevoke(key string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.revoked, key)
}

// Cleanup removes entries whose until is non-zero and in the past. Returns the
// number of entries removed. Safe to call on a hot path; takes the write lock once.
func (m *MemRevoker) Cleanup() int {
	now := m.now()
	m.mu.Lock()
	defer m.mu.Unlock()
	var removed int
	for k, until := range m.revoked {
		if !until.IsZero() && !now.Before(until) {
			delete(m.revoked, k)
			removed++
		}
	}
	return removed
}

// Len reports the number of revocation entries currently held.
func (m *MemRevoker) Len() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.revoked)
}

// Revoked extracts the revocation key from token and reports whether it is currently
// revoked. Tokens whose key cannot be extracted are reported as not-revoked.
func (m *MemRevoker) Revoked(_ context.Context, token *jwt.Token) (bool, error) {
	if token == nil {
		return false, fmt.Errorf("%w: token cannot be nil", pkgerr.ErrInvalidValue)
	}
	key, ok := m.keyFn(token)
	if !ok {
		return false, nil
	}
	m.mu.RLock()
	until, present := m.revoked[key]
	m.mu.RUnlock()
	if !present {
		return false, nil
	}
	if !until.IsZero() && !m.now().Before(until) {
		return false, nil
	}
	return true, nil
}
