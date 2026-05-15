package keys

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"

	"github.com/golang-jwt/jwt/v5"

	"github.com/dcadolph/jwtsmith/pkgerr"
)

// MinRSABits is the minimum acceptable RSA key size for new keys.
//
// Lower sizes are rejected at generation time per current cryptographic guidance.
const MinRSABits = 2048

// GenerateRSA generates a new RSA key pair of the given bit size.
func GenerateRSA(bits int) (*rsa.PrivateKey, *rsa.PublicKey, error) {
	if bits < MinRSABits {
		return nil, nil, fmt.Errorf(
			"%w: RSA bit size %d below minimum %d",
			pkgerr.ErrInvalidSize, bits, MinRSABits,
		)
	}
	priv, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: generating RSA key pair: %w", pkgerr.ErrInvalidValue, err)
	}
	return priv, &priv.PublicKey, nil
}

// LoadRSAPrivateFromPEM parses a PEM-encoded RSA private key.
//
// Accepts both PKCS#1 ("RSA PRIVATE KEY") and PKCS#8 ("PRIVATE KEY") formats.
func LoadRSAPrivateFromPEM(pem []byte) (*rsa.PrivateKey, error) {
	if len(pem) == 0 {
		return nil, fmt.Errorf("%w: empty pem bytes", pkgerr.ErrInvalidValue)
	}
	key, err := jwt.ParseRSAPrivateKeyFromPEM(pem)
	if err != nil {
		return nil, fmt.Errorf("%w: parsing RSA private key pem: %w", pkgerr.ErrParse, err)
	}
	return key, nil
}

// LoadRSAPublicFromPEM parses a PEM-encoded RSA public key.
//
// Accepts both PKCS#1 ("RSA PUBLIC KEY") and PKIX ("PUBLIC KEY") formats.
func LoadRSAPublicFromPEM(pem []byte) (*rsa.PublicKey, error) {
	if len(pem) == 0 {
		return nil, fmt.Errorf("%w: empty pem bytes", pkgerr.ErrInvalidValue)
	}
	key, err := jwt.ParseRSAPublicKeyFromPEM(pem)
	if err != nil {
		return nil, fmt.Errorf("%w: parsing RSA public key pem: %w", pkgerr.ErrParse, err)
	}
	return key, nil
}

// ValidateRSAPair verifies that the given RSA public and private keys are a matching pair.
func ValidateRSAPair(publicKey *rsa.PublicKey, privateKey *rsa.PrivateKey) error {

	if publicKey == nil {
		return fmt.Errorf("%w: public key cannot be nil", pkgerr.ErrInvalidValue)
	}
	if privateKey == nil {
		return fmt.Errorf("%w: private key cannot be nil", pkgerr.ErrInvalidValue)
	}

	hash := sha256.Sum256([]byte("jwtsmith RSA pair validation"))
	sig, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hash[:])
	if err != nil {
		return fmt.Errorf("%w: signing validation message: %w", pkgerr.ErrSign, err)
	}
	if err := rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hash[:], sig); err != nil {
		return fmt.Errorf("%w: RSA public and private keys do not match: %w", pkgerr.ErrInvalidKeyPair, err)
	}
	return nil
}
