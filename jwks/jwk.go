// Package jwks implements RFC 7517 JSON Web Keys and Key Sets, plus a remote fetcher
// with TTL caching suitable for distributing public keys to verifiers.
//
// Supported key types: RSA ("RSA"), ECDSA ("EC"), Ed25519 ("OKP" with crv "Ed25519").
package jwks

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"math/big"

	"github.com/dcadolph/jwtsmith/pkgerr"
)

// JWK key types per RFC 7518 section 6.
const (
	KeyTypeRSA = "RSA"
	KeyTypeEC  = "EC"
	KeyTypeOKP = "OKP"
)

// EC and OKP curve names per RFC 7518 / RFC 8037.
const (
	CurveP256    = "P-256"
	CurveP384    = "P-384"
	CurveP521    = "P-521"
	CurveEd25519 = "Ed25519"
)

// Use values per RFC 7517 section 4.2.
const (
	UseSig = "sig"
	UseEnc = "enc"
)

// JWK represents a single JSON Web Key. Only fields jwtsmith reads or writes are present;
// unknown fields are preserved by the JSON encoder when re-marshaling parsed JWKs.
type JWK struct {
	// Kty is the key type ("RSA", "EC", "OKP"). Required.
	Kty string `json:"kty"`
	// Kid is the key ID. Recommended for key set lookup.
	Kid string `json:"kid,omitempty"`
	// Use is the public key intended use ("sig" or "enc").
	Use string `json:"use,omitempty"`
	// Alg is the algorithm intended for use with this key (e.g. "RS256", "ES256", "EdDSA").
	Alg string `json:"alg,omitempty"`

	// RSA fields.
	N string `json:"n,omitempty"`
	E string `json:"e,omitempty"`

	// EC and OKP curve.
	Crv string `json:"crv,omitempty"`
	// EC coordinates and OKP public bytes.
	X string `json:"x,omitempty"`
	Y string `json:"y,omitempty"`
}

// JWKS is a set of JSON Web Keys per RFC 7517 section 5.
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// PublicKeyFromJWK converts the parsed JWK to a Go public key value.
//
// Returned types: *rsa.PublicKey, *ecdsa.PublicKey, ed25519.PublicKey.
func PublicKeyFromJWK(j JWK) (any, error) {

	switch j.Kty {
	case KeyTypeRSA:
		return rsaPublicFromJWK(j)
	case KeyTypeEC:
		return ecPublicFromJWK(j)
	case KeyTypeOKP:
		return okpPublicFromJWK(j)
	case "":
		return nil, fmt.Errorf("%w: jwk kty is required", pkgerr.ErrInvalidValue)
	default:
		return nil, fmt.Errorf("%w: unsupported jwk kty %q", pkgerr.ErrInvalidValue, j.Kty)
	}
}

// JWKFromPublicKey builds a JWK from a Go public key. The kid is set to the given value
// (empty string is allowed).
func JWKFromPublicKey(publicKey any, kid string) (JWK, error) {

	switch k := publicKey.(type) {
	case *rsa.PublicKey:
		return jwkFromRSA(k, kid), nil
	case *ecdsa.PublicKey:
		return jwkFromECDSA(k, kid)
	case ed25519.PublicKey:
		return jwkFromEd25519(k, kid), nil
	default:
		return JWK{}, fmt.Errorf(
			"%w: unsupported public key type %T",
			pkgerr.ErrInvalidType, publicKey,
		)
	}
}

func rsaPublicFromJWK(j JWK) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(j.N)
	if err != nil {
		return nil, fmt.Errorf("%w: decoding rsa n: %w", pkgerr.ErrDecode, err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(j.E)
	if err != nil {
		return nil, fmt.Errorf("%w: decoding rsa e: %w", pkgerr.ErrDecode, err)
	}
	if len(nBytes) == 0 || len(eBytes) == 0 {
		return nil, fmt.Errorf("%w: rsa n and e required", pkgerr.ErrInvalidValue)
	}
	return &rsa.PublicKey{
		N: new(big.Int).SetBytes(nBytes),
		E: int(new(big.Int).SetBytes(eBytes).Int64()),
	}, nil
}

func ecPublicFromJWK(j JWK) (*ecdsa.PublicKey, error) {
	curve, err := curveFromName(j.Crv)
	if err != nil {
		return nil, err
	}
	x, err := base64.RawURLEncoding.DecodeString(j.X)
	if err != nil {
		return nil, fmt.Errorf("%w: decoding ec x: %w", pkgerr.ErrDecode, err)
	}
	y, err := base64.RawURLEncoding.DecodeString(j.Y)
	if err != nil {
		return nil, fmt.Errorf("%w: decoding ec y: %w", pkgerr.ErrDecode, err)
	}
	if len(x) == 0 || len(y) == 0 {
		return nil, fmt.Errorf("%w: ec x and y required", pkgerr.ErrInvalidValue)
	}
	return &ecdsa.PublicKey{
		Curve: curve,
		X:     new(big.Int).SetBytes(x),
		Y:     new(big.Int).SetBytes(y),
	}, nil
}

func okpPublicFromJWK(j JWK) (ed25519.PublicKey, error) {
	if j.Crv != CurveEd25519 {
		return nil, fmt.Errorf(
			"%w: unsupported OKP crv %q: only %q is supported",
			pkgerr.ErrInvalidValue, j.Crv, CurveEd25519,
		)
	}
	x, err := base64.RawURLEncoding.DecodeString(j.X)
	if err != nil {
		return nil, fmt.Errorf("%w: decoding okp x: %w", pkgerr.ErrDecode, err)
	}
	if len(x) != ed25519.PublicKeySize {
		return nil, fmt.Errorf(
			"%w: ed25519 public key must be %d bytes: got %d",
			pkgerr.ErrInvalidSize, ed25519.PublicKeySize, len(x),
		)
	}
	return ed25519.PublicKey(x), nil
}

func jwkFromRSA(k *rsa.PublicKey, kid string) JWK {
	return JWK{
		Kty: KeyTypeRSA,
		Kid: kid,
		Use: UseSig,
		N:   base64.RawURLEncoding.EncodeToString(k.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(k.E)).Bytes()),
	}
}

func jwkFromECDSA(k *ecdsa.PublicKey, kid string) (JWK, error) {
	crv, err := nameFromCurve(k.Curve)
	if err != nil {
		return JWK{}, err
	}
	byteLen := (k.Curve.Params().BitSize + 7) / 8
	return JWK{
		Kty: KeyTypeEC,
		Kid: kid,
		Use: UseSig,
		Crv: crv,
		X:   base64.RawURLEncoding.EncodeToString(leftPad(k.X.Bytes(), byteLen)),
		Y:   base64.RawURLEncoding.EncodeToString(leftPad(k.Y.Bytes(), byteLen)),
	}, nil
}

func jwkFromEd25519(k ed25519.PublicKey, kid string) JWK {
	return JWK{
		Kty: KeyTypeOKP,
		Kid: kid,
		Use: UseSig,
		Alg: "EdDSA",
		Crv: CurveEd25519,
		X:   base64.RawURLEncoding.EncodeToString(k),
	}
}

func curveFromName(name string) (elliptic.Curve, error) {
	switch name {
	case CurveP256:
		return elliptic.P256(), nil
	case CurveP384:
		return elliptic.P384(), nil
	case CurveP521:
		return elliptic.P521(), nil
	case "":
		return nil, fmt.Errorf("%w: ec crv required", pkgerr.ErrInvalidValue)
	default:
		return nil, fmt.Errorf("%w: unsupported ec crv %q", pkgerr.ErrInvalidValue, name)
	}
}

func nameFromCurve(c elliptic.Curve) (string, error) {
	switch c {
	case elliptic.P256():
		return CurveP256, nil
	case elliptic.P384():
		return CurveP384, nil
	case elliptic.P521():
		return CurveP521, nil
	default:
		return "", fmt.Errorf("%w: unsupported ec curve %v", pkgerr.ErrInvalidValue, c)
	}
}

// leftPad returns b left-padded with zero bytes to length n. b is returned unchanged when len(b) >= n.
func leftPad(b []byte, n int) []byte {
	if len(b) >= n {
		return b
	}
	out := make([]byte, n)
	copy(out[n-len(b):], b)
	return out
}
