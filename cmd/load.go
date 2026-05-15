package cmd

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"fmt"
	"strings"

	"github.com/golang-jwt/jwt/v5"

	"github.com/dcadolph/jwtsmith/keys"
	"github.com/dcadolph/jwtsmith/pkgerr"
)

// loadPrivateKeyForMethod reads a PEM file and parses it into the right private key type for method.
//
// Supports the same algorithm families as signing.NewSigner.
func loadPrivateKeyForMethod(method jwt.SigningMethod, pemPath string) (any, error) {

	if pemPath == "" {
		return nil, fmt.Errorf("%w: --priv is required", ErrUsage)
	}

	pemBytes, err := keys.ReadPEMFile(pemPath)
	if err != nil {
		return nil, err
	}

	switch m := method.(type) {
	case *jwt.SigningMethodECDSA:
		return keys.LoadECDSAPrivateFromPEM(pemBytes)
	case *jwt.SigningMethodRSA, *jwt.SigningMethodRSAPSS:
		return keys.LoadRSAPrivateFromPEM(pemBytes)
	case *jwt.SigningMethodEd25519:
		return keys.LoadEd25519PrivateFromPEM(pemBytes)
	default:
		return nil, fmt.Errorf("%w: unsupported method type %T", pkgerr.ErrInvalidMethod, m)
	}
}

// loadPublicKeyForMethod reads a PEM file and parses it into the right public key type for method.
func loadPublicKeyForMethod(method jwt.SigningMethod, pemPath string) (any, error) {

	if pemPath == "" {
		return nil, fmt.Errorf("%w: --pub is required", ErrUsage)
	}

	pemBytes, err := keys.ReadPEMFile(pemPath)
	if err != nil {
		return nil, err
	}

	switch m := method.(type) {
	case *jwt.SigningMethodECDSA:
		return keys.LoadECDSAPublicFromPEM(pemBytes)
	case *jwt.SigningMethodRSA, *jwt.SigningMethodRSAPSS:
		return keys.LoadRSAPublicFromPEM(pemBytes)
	case *jwt.SigningMethodEd25519:
		return keys.LoadEd25519PublicFromPEM(pemBytes)
	default:
		return nil, fmt.Errorf("%w: unsupported method type %T", pkgerr.ErrInvalidMethod, m)
	}
}

// _ ensures these standard library types are referenced so go vet doesn't drop the imports
// when this file is read in isolation. They are all used through the keys package.
var (
	_ = (*ecdsa.PublicKey)(nil)
	_ = (*rsa.PublicKey)(nil)
	_ = ed25519.PublicKey(nil)
)

// trimAll trims whitespace from each element and drops empty results.
func trimAll(in []string) []string {
	out := in[:0]
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}
