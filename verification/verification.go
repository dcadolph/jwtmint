// Package verification parses and verifies signed JWTs.
//
// A Verifier parses a signed token string, asserts the signing method matches the one
// it was constructed with, validates the signature, runs registered-claims validation
// (exp, nbf), and finally runs any TokenCheckFunc — both the static ones registered at
// construction and any extras passed to Verify.
package verification

import (
	"fmt"
	"strings"
	"sync"

	"github.com/golang-jwt/jwt/v5"

	"github.com/dcadolph/jwtsmith/keys"
	"github.com/dcadolph/jwtsmith/pkgerr"
)

// Verifier verifies a signed JWT and runs configured checks against it.
type Verifier interface {
	Verify(signed string, extra ...TokenCheckFunc) (*jwt.Token, error)
}

// Func adapts a function to the Verifier interface.
type Func func(signed string, extra ...TokenCheckFunc) (*jwt.Token, error)

// Verify calls the receiver, implementing Verifier.
func (f Func) Verify(signed string, extra ...TokenCheckFunc) (*jwt.Token, error) {
	return f(signed, extra...)
}

// verifier is the default Verifier implementation.
type verifier struct {
	method      jwt.SigningMethod
	publicKey   any
	keyFunc     jwt.Keyfunc
	staticCheck []TokenCheckFunc

	mu     sync.RWMutex
	parser *jwt.Parser
}

// NewVerifier returns a Verifier for the given asymmetric signing method and public key.
//
// The publicKey must match the method family (*ecdsa.PublicKey for ES*, *rsa.PublicKey
// for RS*/PS*, ed25519.PublicKey for EdDSA). Static TokenCheckFunc are run on every
// Verify call before any per-call extras.
func NewVerifier(method jwt.SigningMethod, publicKey any, opts ...Opt) (Verifier, error) {

	if method == nil {
		return nil, fmt.Errorf("%w: method cannot be nil", pkgerr.ErrInvalidValue)
	}
	if method.Alg() == "" {
		return nil, fmt.Errorf("%w: method algorithm cannot be empty", pkgerr.ErrInvalidValue)
	}

	keyFunc, err := keys.PublicKeyFunc(method, publicKey)
	if err != nil {
		return nil, fmt.Errorf("%w: building key function: %w", pkgerr.ErrInvalidValue, err)
	}

	v := &verifier{
		method:    method,
		publicKey: publicKey,
		keyFunc:   keyFunc,
		parser:    jwt.NewParser(jwt.WithValidMethods([]string{method.Alg()})),
	}
	for _, opt := range opts {
		opt(v)
	}
	return v, nil
}

// Verify parses signed, asserts its method matches, validates the signature and registered
// claims, then runs static and per-call TokenCheckFunc in that order.
func (v *verifier) Verify(signed string, extra ...TokenCheckFunc) (*jwt.Token, error) {

	if strings.TrimSpace(signed) == "" {
		return nil, fmt.Errorf("%w: token cannot be empty", pkgerr.ErrInvalidValue)
	}

	parsedClaims := jwt.MapClaims{}

	v.mu.RLock()
	parser := v.parser
	v.mu.RUnlock()

	parsed, err := parser.ParseWithClaims(signed, parsedClaims, v.keyFunc)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", pkgerr.ErrParse, err)
	}

	for _, check := range v.staticCheck {
		if check == nil {
			continue
		}
		if err := check(parsed); err != nil {
			return nil, fmt.Errorf("%w: static check: %w", pkgerr.ErrCheck, err)
		}
	}

	for _, check := range extra {
		if check == nil {
			continue
		}
		if err := check(parsed); err != nil {
			return nil, fmt.Errorf("%w: %w", pkgerr.ErrCheck, err)
		}
	}

	return parsed, nil
}

// DisableRegisteredClaimsValidation turns off jwt.Parser's built-in exp/nbf/iat checks.
//
// Only call this if you have a compelling reason — typically when you intend to validate
// these fields yourself via TokenCheckFunc.
func (v *verifier) DisableRegisteredClaimsValidation() {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.parser = jwt.NewParser(
		jwt.WithValidMethods([]string{v.method.Alg()}),
		jwt.WithoutClaimsValidation(),
	)
}

// EnableRegisteredClaimsValidation re-enables jwt.Parser's built-in exp/nbf/iat checks.
//
// Registered-claims validation is on by default; this only matters after a prior call
// to DisableRegisteredClaimsValidation.
func (v *verifier) EnableRegisteredClaimsValidation() {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.parser = jwt.NewParser(jwt.WithValidMethods([]string{v.method.Alg()}))
}
