// Package signing builds and signs JWTs.
//
// A Signer takes claims plus optional headers and returns a signed token string and
// the underlying *jwt.Token. Sensible defaults are applied when callers omit common
// registered claims (exp, iat, nbf, jti, iss); callers may override the typ header
// (defaulting to "JWT") to mint OAuth2-flavored tokens such as RFC 9068 at+jwt access
// tokens. The "alg" header is set automatically and may not be overridden.
//
// Use NewSigner with a method/key pair for the typical case. Use Signed for low-level,
// stateless calls (no configured defaults — falls back to package constants).
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

// ErrReservedHeader is returned when a caller tries to set a reserved JWT header (currently "alg").
var ErrReservedHeader = errors.New("reserved jwt header cannot be overridden")

// Defaults applied when the caller omits the corresponding claim or header.
const (
	// DefaultExpiration is added to time.Now when "exp" is not set in the input claims.
	DefaultExpiration = time.Hour
	// DefaultIssuer is set as "iss" when not set in the input claims.
	DefaultIssuer = "jwtsmith"
	// DefaultTyp is the "typ" header set when callers do not override it.
	DefaultTyp = "JWT"
)

// Reserved JWT header keys. "alg" is set by the underlying jwt library at sign time and
// cannot be overridden via static or per-call headers — overriding it would lie about
// the signature algorithm. "typ" *can* be overridden (e.g. "at+jwt" for RFC 9068).
const (
	HeaderKeyAlg = "alg"
	HeaderKeyTyp = "typ"
)

// Signer signs claims, returning a signed token string and the *jwt.Token used to produce it.
//
// headers are merged onto the signer's static headers (per-call wins on collision, except
// for "alg" which is rejected). Pass nil headers when the call carries none.
type Signer interface {
	Sign(ctx context.Context, c jwt.MapClaims, headers map[string]any) (string, *jwt.Token, error)
}

// Func adapts a function to the Signer interface.
type Func func(ctx context.Context, c jwt.MapClaims, headers map[string]any) (string, *jwt.Token, error)

// Sign calls the receiver, implementing Signer.
func (f Func) Sign(ctx context.Context, c jwt.MapClaims, headers map[string]any) (string, *jwt.Token, error) {
	return f(ctx, c, headers)
}

// signer is the default Signer implementation.
type signer struct {
	method        jwt.SigningMethod
	signingKey    any
	staticHeaders map[string]any
	staticClaims  jwt.MapClaims
	expiration    time.Duration
	issuer        string
	typ           string
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
		typ:        DefaultTyp,
	}
	for _, opt := range opts {
		if err := opt(s); err != nil {
			return nil, err
		}
	}
	return s, nil
}

// Sign builds a signed token from the given claims and per-call headers, applying
// signer defaults and merging static fields.
//
// Rejects per-call headers that include "alg"; that header is set by the underlying
// jwt library and overriding it would lie about the signature algorithm.
func (s *signer) Sign(ctx context.Context, c jwt.MapClaims, headers map[string]any) (string, *jwt.Token, error) {
	if err := ctx.Err(); err != nil {
		return "", nil, err
	}
	if _, present := headers[HeaderKeyAlg]; present {
		return "", nil, fmt.Errorf("%w: %q", ErrReservedHeader, HeaderKeyAlg)
	}
	merged := mergeHeaders(s.staticHeaders, headers)
	return signWith(s.method, s.signingKey, merged, s.mergedClaims(c), s.expiration, s.issuer, s.typ)
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
// headers, and claims, applying jwtsmith's package-level defaults for missing
// exp/iat/nbf/jti/iss/typ.
//
// "alg" in the headers map is rejected. "typ" is honored if present; defaults to "JWT".
func Signed(method jwt.SigningMethod, signingKey any, headers map[string]any, c jwt.MapClaims) (string, *jwt.Token, error) {
	if err := validateMethodAndKey(method, signingKey); err != nil {
		return "", nil, err
	}
	if _, present := headers[HeaderKeyAlg]; present {
		return "", nil, fmt.Errorf("%w: %q", ErrReservedHeader, HeaderKeyAlg)
	}
	return signWith(method, signingKey, headers, c, DefaultExpiration, DefaultIssuer, DefaultTyp)
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
	if _, present := headers[HeaderKeyAlg]; present {
		return "", nil, fmt.Errorf("%w: %q", ErrReservedHeader, HeaderKeyAlg)
	}
	if c == nil {
		c = jwt.MapClaims{}
	}
	c[claims.KeyExpiresAt] = jwt.NewNumericDate(time.Now().Add(expiration))
	return signWith(method, signingKey, headers, c, expiration, DefaultIssuer, DefaultTyp)
}

// SignedFromContext is Signed but pulls headers and claims from the context.
//
// See WrapContextHeaders and WrapContextClaims for installing them.
func SignedFromContext(ctx context.Context, method jwt.SigningMethod, signingKey any) (string, *jwt.Token, error) {
	if err := ctx.Err(); err != nil {
		return "", nil, err
	}
	return Signed(method, signingKey, UnwrapContextHeaders(ctx), UnwrapContextClaims(ctx))
}

// mergeHeaders overlays per-call headers on top of static headers.
//
// Both inputs are guaranteed alg-free by the entry points (Signer.Sign / Signed reject
// alg up front; WithStaticHeaders does the same at construction).
func mergeHeaders(staticHeaders, perCall map[string]any) map[string]any {
	if len(staticHeaders) == 0 && len(perCall) == 0 {
		return nil
	}
	out := make(map[string]any, len(staticHeaders)+len(perCall))
	for k, v := range staticHeaders {
		out[k] = v
	}
	for k, v := range perCall {
		out[k] = v
	}
	return out
}

// signWith is the shared core that copies claims, applies defaults, attaches headers, and signs.
func signWith(method jwt.SigningMethod, signingKey any, headers map[string]any, in jwt.MapClaims, defaultExp time.Duration, defaultIss, defaultTyp string) (string, *jwt.Token, error) { //nolint:lll // Argument list inherently long.

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

	if _, ok := headers[HeaderKeyTyp]; !ok {
		token.Header[HeaderKeyTyp] = defaultTyp
	}

	for k, v := range headers {
		token.Header[k] = v
	}

	signed, err := token.SignedString(signingKey)
	if err != nil {
		return "", nil, fmt.Errorf("%w: signing token: %w", pkgerr.ErrSign, err)
	}

	return signed, token, nil
}
