// Package signing builds and signs JWTs.
//
// A Signer takes jwt.MapClaims and returns a signed token string plus the *jwt.Token used
// to produce it. Sensible defaults are applied when the caller omits common registered
// claims (exp, iat, nbf, jti, iss). Use the per-algorithm constructors when you know the
// signing method up front, or NewSigner with a method/key pair.
package signing

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/dcadolph/jwtsmith/claims"
	"github.com/dcadolph/jwtsmith/pkgerr"
)

// Defaults applied when the caller omits the corresponding claim.
const (
	// DefaultExpiration is added to time.Now when "exp" is not set in the input claims.
	DefaultExpiration = time.Hour
	// DefaultIssuer is set as "iss" when not set in the input claims.
	DefaultIssuer = "jwtsmith"
)

// Reserved JWT header keys. Callers cannot override these via static or per-call headers;
// they are set automatically when the token is signed.
const (
	HeaderKeyAlg = "alg"
	HeaderKeyTyp = "typ"
)

// Signer signs claims, returning a signed token string and the *jwt.Token used to produce it.
type Signer interface {
	Sign(c jwt.MapClaims) (string, *jwt.Token, error)
}

// Func adapts a function to the Signer interface.
type Func func(c jwt.MapClaims) (string, *jwt.Token, error)

// Sign calls the receiver, implementing Signer.
func (f Func) Sign(c jwt.MapClaims) (string, *jwt.Token, error) { return f(c) }

// signer is the default Signer implementation.
type signer struct {
	method        jwt.SigningMethod
	signingKey    any
	staticHeaders map[string]any
	staticClaims  jwt.MapClaims
	expiration    time.Duration
	issuer        string
}

// NewSigner returns a Signer for the given asymmetric signing method and private key.
//
// HMAC methods are not supported. The private key type must match the method family
// (*ecdsa.PrivateKey for ES*, *rsa.PrivateKey for RS*/PS*, ed25519.PrivateKey for EdDSA).
func NewSigner(method jwt.SigningMethod, signingKey any, opts ...Opt) (Signer, error) {

	if err := validateMethodAndKey(method, signingKey); err != nil {
		return nil, err
	}

	s := &signer{
		method:     method,
		signingKey: signingKey,
		expiration: DefaultExpiration,
		issuer:     DefaultIssuer,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s, nil
}

// Sign builds a signed token from the given claims, applying defaults and static fields.
func (s *signer) Sign(c jwt.MapClaims) (string, *jwt.Token, error) {
	return signWith(s.method, s.signingKey, s.staticHeaders, s.mergedClaims(c), s.expiration, s.issuer)
}

// mergedClaims overlays the per-call claims on top of the signer's static claims.
func (s *signer) mergedClaims(c jwt.MapClaims) jwt.MapClaims {
	if len(s.staticClaims) == 0 {
		return c
	}
	merged := claims.DeepCopy(s.staticClaims)
	for k, v := range c {
		merged[k] = v
	}
	return merged
}

// Signed returns a signed token string built from the given method, signing key,
// headers, and claims, applying jwtsmith's defaults for missing exp/iat/nbf/jti/iss.
//
// Reserved header keys ("alg", "typ") in the headers map are silently ignored; they
// are always set by the underlying jwt library at sign time.
func Signed(method jwt.SigningMethod, signingKey any, headers map[string]any, c jwt.MapClaims) (string, *jwt.Token, error) {
	if err := validateMethodAndKey(method, signingKey); err != nil {
		return "", nil, err
	}
	return signWith(method, signingKey, headers, c, DefaultExpiration, DefaultIssuer)
}

// SignedWithExpiration is Signed with the expiration provided as an argument.
//
// Any "exp" in the input claims is overwritten with time.Now().Add(expiration).
func SignedWithExpiration(expiration time.Duration, method jwt.SigningMethod, signingKey any, headers map[string]any, c jwt.MapClaims) (string, *jwt.Token, error) { //nolint:lll // Argument list inherently long.
	if expiration <= 0 {
		return "", nil, fmt.Errorf("%w: expiration must be > 0", pkgerr.ErrInvalidParam)
	}
	if err := validateMethodAndKey(method, signingKey); err != nil {
		return "", nil, err
	}
	if c == nil {
		c = jwt.MapClaims{}
	}
	c[claims.KeyExpiresAt] = jwt.NewNumericDate(time.Now().Add(expiration))
	return signWith(method, signingKey, headers, c, expiration, DefaultIssuer)
}

// SignedFromContext is Signed but pulls headers and claims from the context.
//
// See WrapContextHeaders and WrapContextClaims for installing them.
func SignedFromContext(ctx context.Context, method jwt.SigningMethod, signingKey any) (string, *jwt.Token, error) {
	return Signed(method, signingKey, UnwrapContextHeaders(ctx), UnwrapContextClaims(ctx))
}

// signWith is the shared core that copies claims, applies defaults, attaches headers, and signs.
func signWith(method jwt.SigningMethod, signingKey any, headers map[string]any, in jwt.MapClaims, defaultExp time.Duration, defaultIss string) (string, *jwt.Token, error) { //nolint:lll // Argument list inherently long.

	var c jwt.MapClaims
	if len(in) == 0 {
		c = jwt.MapClaims{}
	} else {
		c = claims.DeepCopy(in)
	}

	now := time.Now()

	exp, expErr := claims.ExpiresAt(c)
	switch {
	case expErr == nil && exp.Before(now):
		return "", nil, fmt.Errorf("%w: exp is in the past", pkgerr.ErrExpired)
	case expErr == nil:
		claims.SetExpiresAt(c, exp)
	default:
		claims.SetExpiresAt(c, now.Add(defaultExp))
	}

	iat, iatErr := claims.IssuedAt(c)
	switch {
	case iatErr == nil && iat.After(now):
		return "", nil, fmt.Errorf("%w: iat is in the future", pkgerr.ErrNotReady)
	case iatErr == nil:
		claims.SetIssuedAt(c, iat)
	default:
		claims.SetIssuedAt(c, now)
	}

	if nbf, err := claims.NotBefore(c); err == nil {
		claims.SetNotBefore(c, nbf)
	} else {
		claims.SetNotBefore(c, now)
	}

	if _, err := claims.Issuer(c); errors.Is(err, pkgerr.ErrNotFound) {
		claims.SetIssuer(c, defaultIss)
	} else if err != nil && !errors.Is(err, pkgerr.ErrEmptyValue) {
		return "", nil, fmt.Errorf("%w: reading issuer claim: %w", pkgerr.ErrInvalidClaims, err)
	}

	if _, err := claims.ID(c); errors.Is(err, pkgerr.ErrNotFound) {
		claims.SetID(c, uuid.NewString())
	}

	token := jwt.NewWithClaims(method, c)

	for k, v := range headers {
		if k == HeaderKeyAlg || k == HeaderKeyTyp {
			continue
		}
		token.Header[k] = v
	}

	signed, err := token.SignedString(signingKey)
	if err != nil {
		return "", nil, fmt.Errorf("%w: signing token: %w", pkgerr.ErrSign, err)
	}

	return signed, token, nil
}
