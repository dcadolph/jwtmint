// Package refresh rotates an existing JWT, preserving the original expiration window
// while updating iat, nbf, and exp to reflect the new issuance time.
//
// Refresh accepts either a *jwt.Token or a signed token string. When given a string,
// the token is parsed using the supplied public key (signature is verified, registered
// claims are not — an expired token can still be refreshed). The new exp is computed
// from the original (exp - iat) duration; if either is missing, the configured default
// expiration is used.
package refresh

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/dcadolph/jwtsmith/claims"
	"github.com/dcadolph/jwtsmith/keys"
	"github.com/dcadolph/jwtsmith/pkgerr"
)

// DefaultExpiration is used when the original token has no recoverable expiration window.
const DefaultExpiration = time.Hour

// Refresher rotates a token, returning the refreshed *jwt.Token and its signed string form.
type Refresher interface {
	Refresh(token any) (*jwt.Token, string, error)
}

// Func adapts a function to the Refresher interface.
type Func func(token any) (*jwt.Token, string, error)

// Refresh calls the receiver, implementing Refresher.
func (f Func) Refresh(token any) (*jwt.Token, string, error) { return f(token) }

// New returns a Refresher for the given asymmetric signing method, public key, and private key.
//
// Public/private key types must match the method family. The keypair is validated up front;
// mismatched pairs return an error.
//
// defaultExpiration is used when the original token has no recoverable (exp - iat) window;
// pass 0 to fall back to DefaultExpiration.
func New(method jwt.SigningMethod, publicKey, privateKey any, defaultExpiration time.Duration) (Refresher, error) {

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

	if defaultExpiration <= 0 {
		defaultExpiration = DefaultExpiration
	}

	parser := jwt.NewParser(jwt.WithoutClaimsValidation())

	return Func(func(token any) (*jwt.Token, string, error) {

		var signed string
		switch t := token.(type) {
		case *jwt.Token:
			s, err := t.SignedString(privateKey)
			if err != nil {
				return nil, "", fmt.Errorf("%w: re-signing input token: %w", pkgerr.ErrSign, err)
			}
			signed = s
		case string:
			signed = t
		default:
			return nil, "", fmt.Errorf(
				"%w: token must be *jwt.Token or string: got %T",
				pkgerr.ErrInvalidType, token,
			)
		}

		return refresh(method, parser, keyFunc, privateKey, defaultExpiration, signed)
	}), nil
}

// refresh parses the signed token, computes the new expiration window, and re-signs.
func refresh(method jwt.SigningMethod, parser *jwt.Parser, keyFunc jwt.Keyfunc, privateKey any, defaultExp time.Duration, signed string) (*jwt.Token, string, error) { //nolint:lll // Argument list inherently long.

	if strings.TrimSpace(signed) == "" {
		return nil, "", fmt.Errorf("%w: token cannot be empty", pkgerr.ErrInvalidValue)
	}

	parsed := jwt.MapClaims{}
	if _, err := parser.ParseWithClaims(signed, parsed, keyFunc); err != nil {
		return nil, "", errors.Join(pkgerr.ErrInvalidToken, err)
	}

	now := time.Now()
	newExp := now.Add(defaultExp)

	iat, iatErr := claims.IssuedAt(parsed)
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
