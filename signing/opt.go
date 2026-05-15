package signing

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Opt configures a Signer at construction.
type Opt func(*signer)

// WithStaticHeaders attaches headers to every token signed by the Signer.
//
// "alg" and "typ" are reserved and are silently ignored if present in the map.
func WithStaticHeaders(h map[string]any) Opt {
	return func(s *signer) { s.staticHeaders = h }
}

// WithStaticClaims overlays the given claims onto every signing call. Per-call claims
// passed to Sign override these fields when keys collide.
func WithStaticClaims(c jwt.MapClaims) Opt {
	return func(s *signer) { s.staticClaims = c }
}

// WithDefaultExpiration sets the duration added to time.Now when a signing call omits "exp".
func WithDefaultExpiration(d time.Duration) Opt {
	return func(s *signer) {
		if d > 0 {
			s.expiration = d
		}
	}
}

// WithDefaultIssuer sets the value used for "iss" when a signing call omits it.
func WithDefaultIssuer(iss string) Opt {
	return func(s *signer) {
		if iss != "" {
			s.issuer = iss
		}
	}
}
