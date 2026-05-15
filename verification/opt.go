package verification

import (
	"context"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/dcadolph/jwtsmith/pkgerr"
	"github.com/dcadolph/jwtsmith/revocation"
)

// Opt configures a Verifier at construction. Returning an error from an Opt aborts
// NewVerifier / NewMultiKeyVerifier.
type Opt func(*verifierBase) error

// WithStaticChecks registers TokenCheckFunc that run on every Verify call,
// before any per-call extras passed to Verify.
func WithStaticChecks(checks ...TokenCheckFunc) Opt {
	return func(b *verifierBase) error {
		b.staticCheck = append(b.staticCheck, checks...)
		return nil
	}
}

// WithLeeway sets the clock-skew tolerance applied by the underlying jwt parser to
// exp and nbf. Defaults to DefaultLeeway. Pass zero to disable leeway entirely.
//
// Negative values return an error.
func WithLeeway(d time.Duration) Opt {
	return func(b *verifierBase) error {
		if d < 0 {
			return fmt.Errorf("%w: WithLeeway: duration must be >= 0", pkgerr.ErrInvalidValue)
		}
		b.leeway = d
		return nil
	}
}

// WithoutRegisteredClaimsValidation turns off the jwt parser's built-in exp/nbf/iat checks.
//
// Only use when you intend to validate these via TokenCheckFunc yourself. The default is on.
func WithoutRegisteredClaimsValidation() Opt {
	return func(b *verifierBase) error {
		b.skipRegisteredClaims = true
		return nil
	}
}

// WithRevoker registers a revocation.Revoker that is consulted on every Verify call,
// after signature and registered-claims validation succeed.
//
// A Revoker reporting Revoked=true causes Verify to fail with pkgerr.ErrRevoked.
// A Revoker returning a non-nil error causes Verify to fail with that error wrapped
// in pkgerr.ErrCheck — backend failures should not be treated as "not revoked".
func WithRevoker(r revocation.Revoker) Opt {
	return func(b *verifierBase) error {
		if r == nil {
			return fmt.Errorf("%w: WithRevoker: revoker cannot be nil", pkgerr.ErrInvalidValue)
		}
		b.staticCheck = append(b.staticCheck, func(ctx context.Context, token *jwt.Token) error {
			revoked, err := r.Revoked(ctx, token)
			if err != nil {
				return err
			}
			if revoked {
				return fmt.Errorf("%w: token revoked", pkgerr.ErrRevoked)
			}
			return nil
		})
		return nil
	}
}
