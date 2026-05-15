package keys

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"

	"github.com/golang-jwt/jwt/v5"

	"github.com/dcadolph/jwtsmith/pkgerr"
)

// GenerateEd25519 generates a new Ed25519 key pair.
func GenerateEd25519() (ed25519.PrivateKey, ed25519.PublicKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: generating Ed25519 key pair: %w", pkgerr.ErrInvalidValue, err)
	}
	return priv, pub, nil
}

// LoadEd25519PrivateFromPEM parses a PEM-encoded Ed25519 private key.
func LoadEd25519PrivateFromPEM(pem []byte) (ed25519.PrivateKey, error) {
	if len(pem) == 0 {
		return nil, fmt.Errorf("%w: empty pem bytes", pkgerr.ErrInvalidValue)
	}
	raw, err := jwt.ParseEdPrivateKeyFromPEM(pem)
	if err != nil {
		return nil, fmt.Errorf("%w: parsing Ed25519 private key pem: %w", pkgerr.ErrParse, err)
	}
	priv, ok := raw.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf(
			"%w: parsed key is not ed25519.PrivateKey: got %T",
			pkgerr.ErrInvalidType, raw,
		)
	}
	return priv, nil
}

// LoadEd25519PublicFromPEM parses a PEM-encoded Ed25519 public key.
func LoadEd25519PublicFromPEM(pem []byte) (ed25519.PublicKey, error) {
	if len(pem) == 0 {
		return nil, fmt.Errorf("%w: empty pem bytes", pkgerr.ErrInvalidValue)
	}
	raw, err := jwt.ParseEdPublicKeyFromPEM(pem)
	if err != nil {
		return nil, fmt.Errorf("%w: parsing Ed25519 public key pem: %w", pkgerr.ErrParse, err)
	}
	pub, ok := raw.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf(
			"%w: parsed key is not ed25519.PublicKey: got %T",
			pkgerr.ErrInvalidType, raw,
		)
	}
	return pub, nil
}

// ValidateEd25519Pair verifies that the given Ed25519 public and private keys are a matching pair.
func ValidateEd25519Pair(publicKey ed25519.PublicKey, privateKey ed25519.PrivateKey) error {

	if len(publicKey) != ed25519.PublicKeySize {
		return fmt.Errorf(
			"%w: Ed25519 public key must be %d bytes: got %d",
			pkgerr.ErrInvalidSize, ed25519.PublicKeySize, len(publicKey),
		)
	}
	if len(privateKey) != ed25519.PrivateKeySize {
		return fmt.Errorf(
			"%w: Ed25519 private key must be %d bytes: got %d",
			pkgerr.ErrInvalidSize, ed25519.PrivateKeySize, len(privateKey),
		)
	}

	msg := []byte("jwtsmith Ed25519 pair validation")
	sig := ed25519.Sign(privateKey, msg)
	if !ed25519.Verify(publicKey, msg, sig) {
		return fmt.Errorf("%w: Ed25519 public and private keys do not match", pkgerr.ErrInvalidKeyPair)
	}
	return nil
}
