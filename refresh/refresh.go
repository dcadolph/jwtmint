// Package refresh rotates an existing JWT, preserving the original expiration window
// while updating iat, nbf, and exp to reflect the new issuance time.
//
// Refresh accepts a signed token string only — never a *jwt.Token directly. The token
// is parsed using the supplied public key (signature is verified, registered claims are
// not — an expired token can still be refreshed). The new exp is computed from the
// original (exp - iat) duration; if either is missing, the configured default is used.
//
// Refreshing has two important guards:
//   - MaxAge bounds how old (by original iat) a token can be and still refresh,
//     preventing a deprovisioned user's token from being refreshed indefinitely.
//   - ClaimsResolver, when set, is invoked with the parsed claims and may rewrite them
//     (for instance to drop revoked groups or look up the latest entitlements).
//     If the resolver returns an error, refresh fails — useful for revocation.
package refresh

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/dcadolph/jwtmint/claims"
	"github.com/dcadolph/jwtmint/keys"
	"github.com/dcadolph/jwtmint/pkgerr"
)

// DefaultExpiration is used when the original token has no recoverable expiration window.
const DefaultExpiration = time.Hour

// ClaimsResolver lets callers rewrite or reject the claim set during refresh.
//
// Called with the parsed claims of the (verified) original token. The returned map
// becomes the claims of the refreshed token. Returning an error aborts the refresh.
//
// Use to: drop revoked groups, re-check entitlements, deny refresh for deprovisioned
// users, etc. Run inside the refresh request's context — honor ctx.Done().
type ClaimsResolver func(ctx context.Context, original jwt.MapClaims) (jwt.MapClaims, error)

// Refresher rotates a token, returning the refreshed *jwt.Token and its signed string form.
//
// Accepts only a signed token string; *jwt.Token is intentionally not accepted because
// it would let a caller construct claims and bypass signature verification.
type Refresher interface {
	Refresh(ctx context.Context, signed string) (*jwt.Token, string, error)
}

// Func adapts a function to the Refresher interface.
type Func func(ctx context.Context, signed string) (*jwt.Token, string, error)

// Refresh calls the receiver, implementing Refresher.
func (f Func) Refresh(ctx context.Context, signed string) (*jwt.Token, string, error) {
	return f(ctx, signed)
}

// Opt configures a Refresher at construction.
type Opt func(*config) error

type config struct {
	defaultExpiration time.Duration
	maxAge            time.Duration
	resolver          ClaimsResolver
}

// WithDefaultExpiration sets the lifetime applied to refreshed tokens when the original
// has no recoverable (exp - iat) window. Must be > 0; the package-level DefaultExpiration
// applies when this option is not used.
func WithDefaultExpiration(d time.Duration) Opt {
	return func(c *config) error {
		if d <= 0 {
			return fmt.Errorf("%w: WithDefaultExpiration: must be > 0", pkgerr.ErrInvalidValue)
		}
		c.defaultExpiration = d
		return nil
	}
}

// WithMaxAge caps how old (measured by the original iat claim) a token can be and still
// be refreshable. Pass 0 to disable (no cap).
//
// Defaults to 24h. A zero or missing iat with a non-zero MaxAge causes refresh to fail.
func WithMaxAge(d time.Duration) Opt {
	return func(c *config) error {
		if d < 0 {
			return fmt.Errorf("%w: WithMaxAge: must be >= 0", pkgerr.ErrInvalidValue)
		}
		c.maxAge = d
		return nil
	}
}

// WithClaimsResolver installs a ClaimsResolver. See ClaimsResolver for semantics.
func WithClaimsResolver(r ClaimsResolver) Opt {
	return func(c *config) error {
		c.resolver = r
		return nil
	}
}

// NewRefresher returns a Refresher for the given asymmetric signing method, public key, and private key.
//
// Public/private key types must match the method family. The keypair is validated up front;
// mismatched pairs return an error.
func NewRefresher(method jwt.SigningMethod, publicKey, privateKey any, opts ...Opt) (Refresher, error) {

	if method == nil {
		return nil, fmt.Errorf("%w: method cannot be nil", pkgerr.ErrInvalidValue)
	}
	if method.Alg() == "" {
		return nil, fmt.Errorf("%w: method algorithm cannot be empty", pkgerr.ErrInvalidValue)
	}
	if publicKey == nil {
		return nil, fmt.Errorf("%w: public key cannot be nil", pkgerr.ErrInvalidValue)
	}
	if privateKey == nil {
		return nil, fmt.Errorf("%w: private key cannot be nil", pkgerr.ErrInvalidValue)
	}
	if err := keys.ValidatePair(publicKey, privateKey); err != nil {
		return nil, err
	}

	keyFunc, err := keys.PublicKeyFunc(method, publicKey)
	if err != nil {
		return nil, fmt.Errorf("%w: building key function: %w", pkgerr.ErrInvalidValue, err)
	}

	cfg := &config{
		defaultExpiration: DefaultExpiration,
		maxAge:            24 * time.Hour,
	}
	for _, opt := range opts {
		if err := opt(cfg); err != nil {
			return nil, err
		}
	}

	parser := jwt.NewParser(jwt.WithoutClaimsValidation())

	return Func(func(ctx context.Context, signed string) (*jwt.Token, string, error) {
		if err := ctx.Err(); err != nil {
			return nil, "", err
		}
		return refresh(ctx, method, parser, keyFunc, privateKey, cfg, signed)
	}), nil
}

// refresh parses the signed token, applies ClaimsResolver if set, computes the new
// expiration window, and re-signs.
func refresh(ctx context.Context, method jwt.SigningMethod, parser *jwt.Parser, keyFunc jwt.Keyfunc, privateKey any, cfg *config, signed string) (*jwt.Token, string, error) { //nolint:lll // Argument list inherently long.

	if strings.TrimSpace(signed) == "" {
		return nil, "", fmt.Errorf("%w: token cannot be empty", pkgerr.ErrInvalidValue)
	}

	parsed := jwt.MapClaims{}
	if _, err := parser.ParseWithClaims(signed, parsed, keyFunc); err != nil {
		return nil, "", errors.Join(pkgerr.ErrInvalidToken, err)
	}

	now := time.Now()

	iat, iatErr := claims.IssuedAt(parsed)
	if cfg.maxAge > 0 {
		if iatErr != nil {
			return nil, "", fmt.Errorf("%w: cannot enforce MaxAge: original iat unreadable: %w", pkgerr.ErrInvalidClaims, iatErr)
		}
		if now.Sub(iat) > cfg.maxAge {
			return nil, "", fmt.Errorf("%w: token original iat is older than MaxAge", pkgerr.ErrExpired)
		}
	}

	if cfg.resolver != nil {
		resolved, err := cfg.resolver(ctx, claims.DeepCopy(parsed))
		if err != nil {
			return nil, "", fmt.Errorf("%w: claims resolver: %w", pkgerr.ErrCheck, err)
		}
		if resolved == nil {
			return nil, "", fmt.Errorf("%w: claims resolver returned nil", pkgerr.ErrInvalidClaims)
		}
		parsed = resolved
	}

	newExp := now.Add(cfg.defaultExpiration)
	exp, expErr := claims.ExpiresAt(parsed)
	switch {
	case iatErr == nil && expErr == nil:
		newExp = now.Add(exp.Sub(iat))
	case errors.Is(expErr, pkgerr.ErrNotFound):
		// Use defaultExp; nothing to do.
	case expErr != nil:
		return nil, "", fmt.Errorf("invalid exp claim: %w", expErr)
	}

	claims.SetExpiresAt(parsed, newExp)
	claims.SetNotBefore(parsed, now)
	claims.SetIssuedAt(parsed, now)

	refreshed := jwt.NewWithClaims(method, parsed)
	signedRefreshed, err := refreshed.SignedString(privateKey)
	if err != nil {
		return nil, "", fmt.Errorf("%w: signing refreshed token: %w", pkgerr.ErrSign, err)
	}
	return refreshed, signedRefreshed, nil
}
