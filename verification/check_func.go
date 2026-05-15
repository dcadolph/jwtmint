package verification

import (
	"fmt"

	"github.com/golang-jwt/jwt/v5"

	"github.com/dcadolph/jwtsmith/claims"
	"github.com/dcadolph/jwtsmith/pkgerr"
)

// TokenCheckFunc inspects a parsed token (headers and claims) and reports whether it passes.
type TokenCheckFunc func(token *jwt.Token) error

// Check calls the receiver, implementing the TokenCheckFunc interface for adapter use.
func (f TokenCheckFunc) Check(token *jwt.Token) error { return f(token) }

// ChainTokenChecks returns a TokenCheckFunc that runs every given check in order.
//
// nil entries are skipped. The first non-nil error short-circuits the chain.
func ChainTokenChecks(checks ...TokenCheckFunc) TokenCheckFunc {
	return func(token *jwt.Token) error {
		for _, check := range checks {
			if check == nil {
				continue
			}
			if err := check(token); err != nil {
				return err
			}
		}
		return nil
	}
}

// CheckClaims returns a TokenCheckFunc that converts the token's claims to jwt.MapClaims
// and applies each claims.CheckFunc in order.
func CheckClaims(checks ...claims.CheckFunc) TokenCheckFunc {
	return func(token *jwt.Token) error {
		mc, err := claims.ToMapClaims(token.Claims)
		if err != nil {
			return fmt.Errorf("%w: extracting claims: %w", pkgerr.ErrInvalidClaims, err)
		}
		for _, check := range checks {
			if check == nil {
				continue
			}
			if err := check(mc); err != nil {
				return err
			}
		}
		return nil
	}
}

// CheckBannedHeaders returns a TokenCheckFunc that rejects tokens carrying any of the given header keys.
func CheckBannedHeaders(banned ...string) TokenCheckFunc {
	return func(token *jwt.Token) error {
		for _, k := range banned {
			if _, ok := token.Header[k]; ok {
				return fmt.Errorf("%w: banned header %q present", pkgerr.ErrCheck, k)
			}
		}
		return nil
	}
}

// CheckRequiredHeaders returns a TokenCheckFunc that rejects tokens missing any of the given header keys.
func CheckRequiredHeaders(required ...string) TokenCheckFunc {
	return func(token *jwt.Token) error {
		for _, k := range required {
			if _, ok := token.Header[k]; !ok {
				return fmt.Errorf("%w: required header %q missing", pkgerr.ErrCheck, k)
			}
		}
		return nil
	}
}

// CheckRequiredHeaderValues returns a TokenCheckFunc that requires each header to equal the given value.
//
// Equality is checked with == ; comparable types only.
func CheckRequiredHeaderValues(required map[string]any) TokenCheckFunc {
	return func(token *jwt.Token) error {
		for k, want := range required {
			got, ok := token.Header[k]
			if !ok {
				return fmt.Errorf("%w: required header %q missing", pkgerr.ErrCheck, k)
			}
			if got != want {
				return fmt.Errorf("%w: header %q want %v got %v", pkgerr.ErrCheck, k, want, got)
			}
		}
		return nil
	}
}
