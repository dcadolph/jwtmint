package signing

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/dcadolph/jwtmint/pkgerr"
)

// Opt configures a Signer at construction. Returning an error from an Opt aborts NewSigner.
type Opt func(*signer) error

// WithStaticHeaders attaches headers to every token signed by the Signer.
//
// "alg" is rejected (returns an error at construction). "typ" is allowed; per-call headers
// override static headers. Pass nil to clear.
func WithStaticHeaders(h map[string]any) Opt {
	return func(s *signer) error {
		if _, ok := h[HeaderKeyAlg]; ok {
			return fmt.Errorf("%w: %q (static header)", ErrReservedHeader, HeaderKeyAlg)
		}
		s.staticHeaders = h
		return nil
	}
}

// WithStaticClaims overlays the given claims onto every signing call. Per-call claims
// passed to Sign override these fields when keys collide.
func WithStaticClaims(c jwt.MapClaims) Opt {
	return func(s *signer) error {
		s.staticClaims = c
		return nil
	}
}

// WithDefaultExpiration sets the duration added to time.Now when a signing call omits "exp".
//
// Returns an error for non-positive durations rather than silently ignoring.
func WithDefaultExpiration(d time.Duration) Opt {
	return func(s *signer) error {
		if d <= 0 {
			return fmt.Errorf("%w: WithDefaultExpiration: duration must be > 0", pkgerr.ErrInvalidValue)
		}
		s.expiration = d
		return nil
	}
}

// WithDefaultIssuer sets the value used for "iss" when a signing call omits it.
//
// Returns an error for empty issuer rather than silently ignoring.
func WithDefaultIssuer(iss string) Opt {
	return func(s *signer) error {
		if iss == "" {
			return fmt.Errorf("%w: WithDefaultIssuer: issuer cannot be empty", pkgerr.ErrInvalidValue)
		}
		s.issuer = iss
		return nil
	}
}

// WithDefaultTyp overrides the typ header set when a signing call omits typ.
//
// Use to mint tokens with non-default typ (e.g. "at+jwt" for RFC 9068 access tokens).
// Returns an error for empty typ.
func WithDefaultTyp(typ string) Opt {
	return func(s *signer) error {
		if typ == "" {
			return fmt.Errorf("%w: WithDefaultTyp: typ cannot be empty", pkgerr.ErrInvalidValue)
		}
		s.typ = typ
		return nil
	}
}
