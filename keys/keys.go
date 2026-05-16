// Package keys generates, loads, validates, and persists asymmetric key material
// used to sign and verify JWTs.
//
// Each algorithm family (ECDSA, RSA, RSAPSS, Ed25519) has dedicated constructors,
// plus shared helpers for PEM and base64-PEM encoding. PublicKeyFunc returns a
// jwt.Keyfunc suitable for jwt.Parser, asserting the token's algorithm matches the
// expected signing method before returning the key.
package keys

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"fmt"

	"github.com/golang-jwt/jwt/v5"

	"github.com/dcadolph/jwtmint/pkgerr"
)

// PublicKeyFunc returns a jwt.Keyfunc that asserts the token's signing method matches
// the expected method, then returns the given public key.
//
// Supported public key types: *ecdsa.PublicKey, *rsa.PublicKey, ed25519.PublicKey.
// Mismatched algorithms or unsupported method types return an error from the Keyfunc.
func PublicKeyFunc(method jwt.SigningMethod, publicKey any) (jwt.Keyfunc, error) {

	if method == nil {
		return nil, fmt.Errorf("%w: method cannot be nil", pkgerr.ErrInvalidValue)
	}
	if method.Alg() == "" {
		return nil, fmt.Errorf("%w: method algorithm cannot be empty", pkgerr.ErrInvalidValue)
	}
	if publicKey == nil {
		return nil, fmt.Errorf("%w: public key cannot be nil", pkgerr.ErrInvalidValue)
	}

	switch publicKey.(type) {
	case *ecdsa.PublicKey, *rsa.PublicKey, ed25519.PublicKey:
	default:
		return nil, fmt.Errorf(
			"%w: public key must be *ecdsa.PublicKey, *rsa.PublicKey, or ed25519.PublicKey: got %T",
			pkgerr.ErrInvalidType, publicKey,
		)
	}

	expected := method.Alg()

	return func(token *jwt.Token) (any, error) {

		got := token.Method.Alg()
		if got == "" {
			return nil, fmt.Errorf(
				"%w: token method algorithm empty: token likely unsigned",
				pkgerr.ErrInvalidValue,
			)
		}

		switch token.Method.(type) {
		case *jwt.SigningMethodECDSA, *jwt.SigningMethodRSA, *jwt.SigningMethodRSAPSS, *jwt.SigningMethodEd25519:
			if got != expected {
				return nil, fmt.Errorf(
					"%w: want %s got %s", pkgerr.ErrInvalidMethod, expected, got,
				)
			}
			return publicKey, nil
		default:
			return nil, fmt.Errorf(
				"%w: unsupported method type %T: expected ECDSA, RSA, RSAPSS, or Ed25519",
				pkgerr.ErrInvalidMethod, token.Method,
			)
		}
	}, nil
}

// ValidatePair verifies that the given public and private key are a matching pair by
// signing a fixed message with the private key and verifying with the public key.
//
// Both keys must be of the same family (ECDSA, RSA, or Ed25519) and must be a matching pair
// or ErrInvalidKeyPair is returned.
func ValidatePair(publicKey, privateKey any) error {

	switch priv := privateKey.(type) {
	case *ecdsa.PrivateKey:
		pub, ok := publicKey.(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf(
				"%w: public key must be *ecdsa.PublicKey to match *ecdsa.PrivateKey: got %T",
				pkgerr.ErrInvalidType, publicKey,
			)
		}
		return ValidateECDSAPair(pub, priv)
	case *rsa.PrivateKey:
		pub, ok := publicKey.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf(
				"%w: public key must be *rsa.PublicKey to match *rsa.PrivateKey: got %T",
				pkgerr.ErrInvalidType, publicKey,
			)
		}
		return ValidateRSAPair(pub, priv)
	case ed25519.PrivateKey:
		pub, ok := publicKey.(ed25519.PublicKey)
		if !ok {
			return fmt.Errorf(
				"%w: public key must be ed25519.PublicKey to match ed25519.PrivateKey: got %T",
				pkgerr.ErrInvalidType, publicKey,
			)
		}
		return ValidateEd25519Pair(pub, priv)
	default:
		return fmt.Errorf(
			"%w: private key must be *ecdsa.PrivateKey, *rsa.PrivateKey, or ed25519.PrivateKey: got %T",
			pkgerr.ErrInvalidType, privateKey,
		)
	}
}
