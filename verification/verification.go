// Package verification parses and verifies signed JWTs.
//
// A Verifier parses a signed token, asserts the signing method matches one of the
// configured methods, validates the signature, runs registered-claims validation
// (exp, nbf — with optional clock-skew leeway), and finally runs any TokenCheckFunc
// — both the static ones registered at construction and any extras passed to Verify.
//
// Use NewVerifier for the typical single-key case. Use NewMultiKeyVerifier when the
// daemon publishes multiple kids (e.g. during key rotation).
package verification

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/dcadolph/jwtsmith/keys"
	"github.com/dcadolph/jwtsmith/pkgerr"
)

// DefaultLeeway is the clock-skew tolerance applied to exp and nbf when callers do not
// override it. Real fleets need a few seconds of slack; ~30s is a defensible default.
const DefaultLeeway = 30 * time.Second

// TokenCheckFunc inspects a parsed token (headers and claims) and reports whether it passes.
//
// ctx allows checks to honor request deadlines and to fan out to remote services
// (e.g. denylist lookups) without blocking forever.
type TokenCheckFunc func(ctx context.Context, token *jwt.Token) error

// Check calls the receiver, implementing the TokenCheckFunc interface for adapter use.
func (f TokenCheckFunc) Check(ctx context.Context, token *jwt.Token) error {
	return f(ctx, token)
}

// Verifier verifies a signed JWT and runs configured checks against it.
type Verifier interface {
	Verify(ctx context.Context, signed string, extra ...TokenCheckFunc) (*jwt.Token, error)
}

// Func adapts a function to the Verifier interface.
type Func func(ctx context.Context, signed string, extra ...TokenCheckFunc) (*jwt.Token, error)

// Verify calls the receiver, implementing Verifier.
func (f Func) Verify(ctx context.Context, signed string, extra ...TokenCheckFunc) (*jwt.Token, error) {
	return f(ctx, signed, extra...)
}

// verifierBase is the shared state between single-key and multi-key verifiers.
//
// It owns the parser and the static check chain; the embedding type provides the
// Keyfunc that resolves the verification key for a parsed token. The parser is built
// once at construction and never mutated after, so no synchronization is needed.
type verifierBase struct {
	staticCheck          []TokenCheckFunc
	parser               *jwt.Parser
	leeway               time.Duration
	skipRegisteredClaims bool
	algs                 []string
}

// buildParser produces a jwt.Parser honoring the verifier's algs, leeway, and registered-claims toggle.
func (b *verifierBase) buildParser() *jwt.Parser {
	opts := []jwt.ParserOption{jwt.WithValidMethods(b.algs)}
	if b.leeway > 0 {
		opts = append(opts, jwt.WithLeeway(b.leeway))
	}
	if b.skipRegisteredClaims {
		opts = append(opts, jwt.WithoutClaimsValidation())
	}
	return jwt.NewParser(opts...)
}

// runChecks applies static and per-call TokenCheckFuncs to parsed.
func (b *verifierBase) runChecks(ctx context.Context, parsed *jwt.Token, extra []TokenCheckFunc) error {

	for _, check := range b.staticCheck {
		if check == nil {
			continue
		}
		if err := check(ctx, parsed); err != nil {
			return fmt.Errorf("%w: static check: %w", pkgerr.ErrCheck, err)
		}
	}
	for _, check := range extra {
		if check == nil {
			continue
		}
		if err := check(ctx, parsed); err != nil {
			return fmt.Errorf("%w: %w", pkgerr.ErrCheck, err)
		}
	}
	return nil
}

// applyOpts processes Opts and returns the resulting base + any error.
func applyOpts(algs []string, opts ...Opt) (*verifierBase, error) {
	b := &verifierBase{
		algs:   algs,
		leeway: DefaultLeeway,
	}
	for _, opt := range opts {
		if err := opt(b); err != nil {
			return nil, err
		}
	}
	b.parser = b.buildParser()
	return b, nil
}

// verifier is the default single-key Verifier implementation.
type verifier struct {
	*verifierBase
	method    jwt.SigningMethod
	publicKey any
	keyFunc   jwt.Keyfunc
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

	base, err := applyOpts([]string{method.Alg()}, opts...)
	if err != nil {
		return nil, err
	}

	return &verifier{
		verifierBase: base,
		method:       method,
		publicKey:    publicKey,
		keyFunc:      keyFunc,
	}, nil
}

// Verify parses signed, asserts its method matches, validates the signature and registered
// claims, then runs static and per-call TokenCheckFunc in that order.
func (v *verifier) Verify(ctx context.Context, signed string, extra ...TokenCheckFunc) (*jwt.Token, error) {

	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if strings.TrimSpace(signed) == "" {
		return nil, fmt.Errorf("%w: token cannot be empty", pkgerr.ErrInvalidValue)
	}

	parsed, err := v.parser.ParseWithClaims(signed, jwt.MapClaims{}, v.keyFunc)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", pkgerr.ErrParse, err)
	}

	if err := v.runChecks(ctx, parsed, extra); err != nil {
		return nil, err
	}
	return parsed, nil
}
