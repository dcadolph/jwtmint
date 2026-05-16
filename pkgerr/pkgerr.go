// Package pkgerr defines the root sentinel errors shared across jwtmint packages.
//
// All packages wrap these roots with fmt.Errorf("%w: ...", pkgerr.ErrFoo, ...) so callers
// can use errors.Is to classify failures without depending on the specific package that
// produced them.
package pkgerr

import "errors"

var (
	// ErrParse is returned when parsing fails.
	ErrParse = errors.New("parse failed")

	// ErrEncode is returned when encoding fails.
	ErrEncode = errors.New("encode failed")

	// ErrDecode is returned when decoding fails.
	ErrDecode = errors.New("decode failed")

	// ErrSign is returned when signing fails.
	ErrSign = errors.New("sign failed")

	// ErrVerify is returned when signature verification fails.
	ErrVerify = errors.New("verify failed")

	// ErrCheck is returned when a configured check function rejects the input.
	ErrCheck = errors.New("check failed")

	// ErrRead is returned when a read from disk or io.Reader fails.
	ErrRead = errors.New("read failed")

	// ErrWrite is returned when a write to disk or io.Writer fails.
	ErrWrite = errors.New("write failed")

	// ErrInvalidValue is returned when a value is invalid (wrong format, out of range, etc.).
	ErrInvalidValue = errors.New("invalid value")

	// ErrInvalidType is returned when a value has the wrong concrete type.
	ErrInvalidType = errors.New("invalid type")

	// ErrInvalidMethod is returned when a JWT signing method is unsupported or unrecognized.
	ErrInvalidMethod = errors.New("invalid method")

	// ErrInvalidSize is returned when a key or value has the wrong size for an algorithm.
	ErrInvalidSize = errors.New("invalid size")

	// ErrInvalidKeyPair is returned when a public and private key are not a matching pair.
	ErrInvalidKeyPair = errors.New("invalid key pair")

	// ErrInvalidToken is returned when a token cannot be accepted (malformed, wrong shape).
	ErrInvalidToken = errors.New("invalid token")

	// ErrInvalidClaims is returned when claims are structurally invalid.
	ErrInvalidClaims = errors.New("invalid claims")

	// ErrInvalidParam is returned when an argument to an exported function is invalid.
	ErrInvalidParam = errors.New("invalid parameter")

	// ErrNotFound is returned when a requested item is not present.
	ErrNotFound = errors.New("not found")

	// ErrEmptyValue is returned when a value is present but empty/zero.
	ErrEmptyValue = errors.New("empty value")

	// ErrExpired is returned when a token or value has passed its expiration.
	ErrExpired = errors.New("expired")

	// ErrNotReady is returned when a token is not yet usable (nbf in the future, iat in the future).
	ErrNotReady = errors.New("not ready")

	// ErrRevoked is returned when a token has been explicitly revoked by a Revoker.
	ErrRevoked = errors.New("revoked")
)
