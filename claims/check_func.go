package claims

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/dcadolph/jwtsmith/pkgerr"
)

// CheckFunc inspects claims and reports whether they pass an arbitrary check.
type CheckFunc func(c jwt.MapClaims) error

// Check calls the receiver, implementing the CheckFunc interface for adapter use.
func (f CheckFunc) Check(c jwt.MapClaims) error { return f(c) }

// Chain returns a CheckFunc that runs every given CheckFunc in order, returning the first error.
//
// A nil-or-empty input chain produces a no-op CheckFunc.
func Chain(checks ...CheckFunc) CheckFunc {
	return func(c jwt.MapClaims) error {
		for _, check := range checks {
			if check == nil {
				continue
			}
			if err := check(c); err != nil {
				return err
			}
		}
		return nil
	}
}

// CheckRequiredKeys returns a CheckFunc that errors if any of the given claim keys are missing.
func CheckRequiredKeys(keys ...string) CheckFunc {
	return func(c jwt.MapClaims) error {
		for _, k := range keys {
			if _, ok := c[k]; !ok {
				return fmt.Errorf("%w: required claim %q missing", pkgerr.ErrNotFound, k)
			}
		}
		return nil
	}
}

// CheckIssuer returns a CheckFunc that errors unless the "iss" claim matches one of the allowed values.
func CheckIssuer(allowed ...string) CheckFunc {
	return func(c jwt.MapClaims) error {
		iss, err := Issuer(c)
		if err != nil {
			return err
		}
		for _, a := range allowed {
			if iss == a {
				return nil
			}
		}
		return fmt.Errorf("%w: issuer %q not in allowed set", pkgerr.ErrCheck, iss)
	}
}

// CheckAudience returns a CheckFunc that errors unless any of the given audiences appear in the "aud" claim.
func CheckAudience(required ...string) CheckFunc {
	return func(c jwt.MapClaims) error {
		_, err := MatchingAudience(c, required...)
		return err
	}
}

// CheckHasGroups returns a CheckFunc that errors unless any of the given groups appear in the "groups" claim.
func CheckHasGroups(required ...string) CheckFunc {
	return func(c jwt.MapClaims) error {
		_, err := MatchingGroups(c, required...)
		return err
	}
}

// CheckHasRoles returns a CheckFunc that errors unless any of the given roles appear in the "roles" claim.
func CheckHasRoles(required ...string) CheckFunc {
	return func(c jwt.MapClaims) error {
		_, err := MatchingRoles(c, required...)
		return err
	}
}

// CheckNotExpired returns a CheckFunc that errors if the "exp" claim is missing or in the past.
func CheckNotExpired() CheckFunc {
	return func(c jwt.MapClaims) error {
		exp, err := ExpiresAt(c)
		if err != nil {
			return err
		}
		if exp.Before(time.Now()) {
			return fmt.Errorf("%w: token expired at %s", pkgerr.ErrExpired, exp)
		}
		return nil
	}
}

// CheckNotBeforeReady returns a CheckFunc that errors if the "nbf" claim is in the future.
//
// Missing "nbf" is treated as ready (no error).
func CheckNotBeforeReady() CheckFunc {
	return func(c jwt.MapClaims) error {
		nbf, err := NotBefore(c)
		if err != nil {
			return nil
		}
		if nbf.After(time.Now()) {
			return fmt.Errorf("%w: token not usable until %s", pkgerr.ErrNotReady, nbf)
		}
		return nil
	}
}
