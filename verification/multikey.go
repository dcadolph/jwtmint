package verification

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"fmt"
	"strings"

	"github.com/golang-jwt/jwt/v5"

	"github.com/dcadolph/jwtmint/pkgerr"
)

// KeyEntry describes one verification key — its identifier, the signing method that
// produced tokens with it, and the public key itself.
type KeyEntry struct {
	// Kid is the JWT "kid" header value to match against. Required.
	Kid string
	// Method is the signing method tokens with this Kid use. Required.
	Method jwt.SigningMethod
	// PublicKey verifies the signature. Type must match Method's family.
	PublicKey any
}

// multiKeyVerifier resolves the verification key from the token's kid header.
type multiKeyVerifier struct {
	*verifierBase
	entries map[string]KeyEntry // kid -> entry
}

// NewMultiKeyVerifier returns a Verifier that selects the verification key by the
// token's kid header.
//
// Tokens carrying a kid not present in entries are rejected. Tokens with no kid header
// are also rejected — multi-key mode requires kid for unambiguous selection.
func NewMultiKeyVerifier(entries []KeyEntry, opts ...Opt) (Verifier, error) {

	if len(entries) == 0 {
		return nil, fmt.Errorf("%w: at least one KeyEntry required", pkgerr.ErrInvalidValue)
	}

	byKid := make(map[string]KeyEntry, len(entries))
	algSet := map[string]struct{}{}
	for i, e := range entries {
		if e.Kid == "" {
			return nil, fmt.Errorf("%w: entry %d: Kid required", pkgerr.ErrInvalidValue, i)
		}
		if e.Method == nil {
			return nil, fmt.Errorf("%w: entry %d (%s): Method required", pkgerr.ErrInvalidValue, i, e.Kid)
		}
		if e.PublicKey == nil {
			return nil, fmt.Errorf("%w: entry %d (%s): PublicKey required", pkgerr.ErrInvalidValue, i, e.Kid)
		}
		switch e.PublicKey.(type) {
		case *ecdsa.PublicKey, *rsa.PublicKey, ed25519.PublicKey:
		default:
			return nil, fmt.Errorf(
				"%w: entry %d (%s): PublicKey type %T not supported",
				pkgerr.ErrInvalidType, i, e.Kid, e.PublicKey,
			)
		}
		if _, dup := byKid[e.Kid]; dup {
			return nil, fmt.Errorf("%w: duplicate kid %q in entries", pkgerr.ErrInvalidValue, e.Kid)
		}
		byKid[e.Kid] = e
		algSet[e.Method.Alg()] = struct{}{}
	}

	algs := make([]string, 0, len(algSet))
	for a := range algSet {
		algs = append(algs, a)
	}

	base, err := applyOpts(algs, opts...)
	if err != nil {
		return nil, err
	}

	return &multiKeyVerifier{verifierBase: base, entries: byKid}, nil
}

// Verify implements Verifier.
func (v *multiKeyVerifier) Verify(ctx context.Context, signed string, extra ...TokenCheckFunc) (*jwt.Token, error) {

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

// keyFunc resolves the public key by the token's kid header.
func (v *multiKeyVerifier) keyFunc(token *jwt.Token) (any, error) {

	kid, _ := token.Header["kid"].(string)
	if kid == "" {
		return nil, fmt.Errorf("%w: token has no kid header (multi-key verifier requires it)", pkgerr.ErrInvalidValue)
	}

	entry, ok := v.entries[kid]
	if !ok {
		return nil, fmt.Errorf("%w: no key registered for kid %q", pkgerr.ErrNotFound, kid)
	}
	if token.Method.Alg() != entry.Method.Alg() {
		return nil, fmt.Errorf(
			"%w: token alg %q does not match registered alg %q for kid %q",
			pkgerr.ErrInvalidMethod, token.Method.Alg(), entry.Method.Alg(), kid,
		)
	}
	return entry.PublicKey, nil
}
