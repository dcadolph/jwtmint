// Package revocation provides Revoker, an interface for rejecting otherwise-valid
// JWTs that have been explicitly revoked.
//
// A Revoker is consulted by verification.Verifier (via WithRevoker) after signature
// and registered-claims validation succeed but before the result is returned to the
// caller. Returning Revoked=true causes verification to fail with pkgerr.ErrRevoked.
//
// The package ships two implementations:
//   - MemRevoker: in-process map of revoked keys (typically jti), suitable for
//     single-replica deployments and tests.
//   - Chain: composes multiple Revokers (e.g. an in-process cache fronting a remote
//     denylist).
//
// Backends for distributed denylists (Redis, etcd, a database) are out of scope here;
// implement Revoker against your store of choice.
package revocation

import (
	"context"
	"fmt"

	"github.com/golang-jwt/jwt/v5"

	"github.com/dcadolph/jwtsmith/pkgerr"
)

// Revoker reports whether a parsed JWT has been revoked.
//
// Revoker is consulted after signature and registered-claims validation succeed.
// Implementations should be safe for concurrent use; Verifier may invoke them from
// many goroutines simultaneously.
type Revoker interface {
	// Revoked reports whether the token has been revoked. A non-nil error indicates
	// the lookup itself failed (e.g. backend unavailable); callers should treat such
	// failures as fatal to the verification, not as "not revoked".
	Revoked(ctx context.Context, token *jwt.Token) (bool, error)
}

// RevokerFunc adapts a function to the Revoker interface.
type RevokerFunc func(ctx context.Context, token *jwt.Token) (bool, error)

// Revoked calls the receiver, implementing Revoker.
func (f RevokerFunc) Revoked(ctx context.Context, token *jwt.Token) (bool, error) {
	return f(ctx, token)
}

// Chain returns a Revoker that consults each underlying Revoker in order.
//
// The chain short-circuits on the first Revoked=true (returning true) or the first
// non-nil error (returning that error). nil entries are skipped.
//
// Common pattern: Chain(localCache, remoteStore) — fast in-process check first,
// expensive remote lookup only on cache miss.
func Chain(revokers ...Revoker) Revoker {
	return RevokerFunc(func(ctx context.Context, token *jwt.Token) (bool, error) {
		for _, r := range revokers {
			if r == nil {
				continue
			}
			revoked, err := r.Revoked(ctx, token)
			if err != nil {
				return false, fmt.Errorf("%w: chained revoker: %w", pkgerr.ErrCheck, err)
			}
			if revoked {
				return true, nil
			}
		}
		return false, nil
	})
}
