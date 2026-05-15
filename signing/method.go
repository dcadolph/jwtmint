package signing

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"fmt"

	"github.com/golang-jwt/jwt/v5"

	"github.com/dcadolph/jwtsmith/keys"
	"github.com/dcadolph/jwtsmith/pkgerr"
)

// SigningMethod returns the jwt.SigningMethod for the given JWS "alg" string.
//
// HMAC methods (HS256/HS384/HS512) are explicitly rejected — jwtsmith supports asymmetric
// methods only.
func SigningMethod(alg string) (jwt.SigningMethod, error) { //nolint:ireturn // Interface return is required.
	switch alg {
	case "":
		return nil, fmt.Errorf("%w: signing method cannot be empty", pkgerr.ErrInvalidMethod)
	case jwt.SigningMethodES256.Alg():
		return jwt.SigningMethodES256, nil
	case jwt.SigningMethodES384.Alg():
		return jwt.SigningMethodES384, nil
	case jwt.SigningMethodES512.Alg():
		return jwt.SigningMethodES512, nil
	case jwt.SigningMethodRS256.Alg():
		return jwt.SigningMethodRS256, nil
	case jwt.SigningMethodRS384.Alg():
		return jwt.SigningMethodRS384, nil
	case jwt.SigningMethodRS512.Alg():
		return jwt.SigningMethodRS512, nil
	case jwt.SigningMethodPS256.Alg():
		return jwt.SigningMethodPS256, nil
	case jwt.SigningMethodPS384.Alg():
		return jwt.SigningMethodPS384, nil
	case jwt.SigningMethodPS512.Alg():
		return jwt.SigningMethodPS512, nil
	case jwt.SigningMethodEdDSA.Alg():
		return jwt.SigningMethodEdDSA, nil
	case jwt.SigningMethodHS256.Alg(),
		jwt.SigningMethodHS384.Alg(),
		jwt.SigningMethodHS512.Alg():
		return nil, fmt.Errorf(
			"%w: %s: HMAC methods not supported: jwtsmith uses asymmetric methods only",
			pkgerr.ErrInvalidMethod, alg,
		)
	default:
		return nil, fmt.Errorf("%w: unsupported signing method: %s", pkgerr.ErrInvalidMethod, alg)
	}
}

// validateMethodAndKey verifies the signing key type matches the method family.
func validateMethodAndKey(method jwt.SigningMethod, signingKey any) error {

	if method == nil {
		return fmt.Errorf("%w: method cannot be nil", pkgerr.ErrInvalidValue)
	}
	if method.Alg() == "" {
		return fmt.Errorf("%w: method algorithm cannot be empty", pkgerr.ErrInvalidValue)
	}
	if signingKey == nil {
		return fmt.Errorf("%w: signing key cannot be nil", pkgerr.ErrInvalidValue)
	}

	switch m := method.(type) {

	case *jwt.SigningMethodECDSA:
		priv, ok := signingKey.(*ecdsa.PrivateKey)
		if !ok {
			return fmt.Errorf(
				"%w: %s requires *ecdsa.PrivateKey: got %T",
				pkgerr.ErrInvalidType, m.Alg(), signingKey,
			)
		}
		return keys.ValidateECDSAMethodAndKey(m, priv)

	case *jwt.SigningMethodRSA:
		if _, ok := signingKey.(*rsa.PrivateKey); !ok {
			return fmt.Errorf(
				"%w: %s requires *rsa.PrivateKey: got %T",
				pkgerr.ErrInvalidType, m.Alg(), signingKey,
			)
		}

	case *jwt.SigningMethodRSAPSS:
		if _, ok := signingKey.(*rsa.PrivateKey); !ok {
			return fmt.Errorf(
				"%w: %s requires *rsa.PrivateKey: got %T",
				pkgerr.ErrInvalidType, m.Alg(), signingKey,
			)
		}

	case *jwt.SigningMethodEd25519:
		if _, ok := signingKey.(ed25519.PrivateKey); !ok {
			return fmt.Errorf(
				"%w: %s requires ed25519.PrivateKey: got %T",
				pkgerr.ErrInvalidType, m.Alg(), signingKey,
			)
		}

	default:
		return fmt.Errorf(
			"%w: unsupported method type %T: jwtsmith supports ECDSA, RSA, RSAPSS, Ed25519",
			pkgerr.ErrInvalidMethod, method,
		)
	}

	return nil
}
