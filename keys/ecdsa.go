package keys

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"fmt"

	"github.com/golang-jwt/jwt/v5"

	"github.com/dcadolph/jwtmint/pkgerr"
)

// GenerateECDSA generates a new ECDSA key pair on the given curve.
func GenerateECDSA(curve elliptic.Curve) (*ecdsa.PrivateKey, *ecdsa.PublicKey, error) {
	if curve == nil {
		return nil, nil, fmt.Errorf("%w: curve cannot be nil", pkgerr.ErrInvalidValue)
	}
	priv, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: generating ECDSA key pair: %w", pkgerr.ErrInvalidValue, err)
	}
	return priv, &priv.PublicKey, nil
}

// GenerateECDSAForMethod generates a key pair sized for the given ECDSA signing method.
func GenerateECDSAForMethod(method *jwt.SigningMethodECDSA) (*ecdsa.PrivateKey, *ecdsa.PublicKey, error) {
	if method == nil {
		return nil, nil, fmt.Errorf("%w: method cannot be nil", pkgerr.ErrInvalidValue)
	}
	curve, err := curveForECDSAMethod(method)
	if err != nil {
		return nil, nil, err
	}
	return GenerateECDSA(curve)
}

// LoadECDSAPrivateFromPEM parses a PEM-encoded ECDSA private key.
func LoadECDSAPrivateFromPEM(pem []byte) (*ecdsa.PrivateKey, error) {
	if len(pem) == 0 {
		return nil, fmt.Errorf("%w: empty pem bytes", pkgerr.ErrInvalidValue)
	}
	key, err := jwt.ParseECPrivateKeyFromPEM(pem)
	if err != nil {
		return nil, fmt.Errorf("%w: parsing ECDSA private key pem: %w", pkgerr.ErrParse, err)
	}
	return key, nil
}

// LoadECDSAPublicFromPEM parses a PEM-encoded ECDSA public key.
func LoadECDSAPublicFromPEM(pem []byte) (*ecdsa.PublicKey, error) {
	if len(pem) == 0 {
		return nil, fmt.Errorf("%w: empty pem bytes", pkgerr.ErrInvalidValue)
	}
	key, err := jwt.ParseECPublicKeyFromPEM(pem)
	if err != nil {
		return nil, fmt.Errorf("%w: parsing ECDSA public key pem: %w", pkgerr.ErrParse, err)
	}
	return key, nil
}

// ValidateECDSAPair verifies that the given ECDSA public and private keys are a matching pair.
func ValidateECDSAPair(publicKey *ecdsa.PublicKey, privateKey *ecdsa.PrivateKey) error {

	if publicKey == nil {
		return fmt.Errorf("%w: public key cannot be nil", pkgerr.ErrInvalidValue)
	}
	if privateKey == nil {
		return fmt.Errorf("%w: private key cannot be nil", pkgerr.ErrInvalidValue)
	}

	hash := sha256.Sum256([]byte("jwtmint ECDSA pair validation"))
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hash[:])
	if err != nil {
		return fmt.Errorf("%w: signing validation message: %w", pkgerr.ErrSign, err)
	}
	if !ecdsa.Verify(publicKey, hash[:], r, s) {
		return fmt.Errorf("%w: ECDSA public and private keys do not match", pkgerr.ErrInvalidKeyPair)
	}
	return nil
}

// ValidateECDSAMethodAndKey ensures the signing method and signing key are compatible by curve size.
func ValidateECDSAMethodAndKey(method jwt.SigningMethod, signingKey *ecdsa.PrivateKey) error {

	if method == nil {
		return fmt.Errorf("%w: method cannot be nil", pkgerr.ErrInvalidValue)
	}
	if signingKey == nil {
		return fmt.Errorf("%w: signing key cannot be nil", pkgerr.ErrInvalidValue)
	}

	ecdsaMethod, ok := method.(*jwt.SigningMethodECDSA)
	if !ok {
		return fmt.Errorf(
			"%w: expected *jwt.SigningMethodECDSA: got %T",
			pkgerr.ErrInvalidMethod, method,
		)
	}

	want := int(ecdsaMethod.CurveBits)
	got := signingKey.Curve.Params().BitSize
	if want != got {
		return fmt.Errorf(
			"%w: %s requires %d-bit curve: got %d",
			pkgerr.ErrInvalidSize, ecdsaMethod.Alg(), want, got,
		)
	}
	return nil
}

// curveForECDSAMethod returns the elliptic curve appropriate for the given ECDSA method.
func curveForECDSAMethod(method *jwt.SigningMethodECDSA) (elliptic.Curve, error) {
	switch method.CurveBits {
	case 256:
		return elliptic.P256(), nil
	case 384:
		return elliptic.P384(), nil
	case 521:
		return elliptic.P521(), nil
	default:
		return nil, fmt.Errorf(
			"%w: unsupported ECDSA curve size %d",
			pkgerr.ErrInvalidSize, method.CurveBits,
		)
	}
}
