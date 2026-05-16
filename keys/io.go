package keys

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/dcadolph/jwtmint/pkgerr"
)

// PEM block types written by this package.
const (
	BlockTypeECPrivate     = "EC PRIVATE KEY"
	BlockTypeRSAPrivate    = "RSA PRIVATE KEY"
	BlockTypePKCS8Private  = "PRIVATE KEY"
	BlockTypePublic        = "PUBLIC KEY"
	PrivateKeyFilePerm     = 0o600
	PublicKeyFilePerm      = 0o644
)

// EncodePrivateKeyPEM encodes a supported private key (ECDSA, RSA, Ed25519) as PEM bytes.
//
// ECDSA keys use SEC1 ("EC PRIVATE KEY"), RSA uses PKCS#1 ("RSA PRIVATE KEY"),
// Ed25519 uses PKCS#8 ("PRIVATE KEY") since SEC1/PKCS#1 do not represent Ed25519.
func EncodePrivateKeyPEM(privateKey any) ([]byte, error) {

	switch k := privateKey.(type) {
	case *ecdsa.PrivateKey:
		der, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			return nil, fmt.Errorf("%w: marshaling ECDSA private key: %w", pkgerr.ErrEncode, err)
		}
		return pem.EncodeToMemory(&pem.Block{Type: BlockTypeECPrivate, Bytes: der}), nil

	case *rsa.PrivateKey:
		der := x509.MarshalPKCS1PrivateKey(k)
		return pem.EncodeToMemory(&pem.Block{Type: BlockTypeRSAPrivate, Bytes: der}), nil

	case ed25519.PrivateKey:
		der, err := x509.MarshalPKCS8PrivateKey(k)
		if err != nil {
			return nil, fmt.Errorf("%w: marshaling Ed25519 private key: %w", pkgerr.ErrEncode, err)
		}
		return pem.EncodeToMemory(&pem.Block{Type: BlockTypePKCS8Private, Bytes: der}), nil

	default:
		return nil, fmt.Errorf(
			"%w: unsupported private key type: %T",
			pkgerr.ErrInvalidType, privateKey,
		)
	}
}

// EncodePublicKeyPEM encodes a supported public key (ECDSA, RSA, Ed25519) as PKIX PEM bytes.
func EncodePublicKeyPEM(publicKey any) ([]byte, error) {

	switch publicKey.(type) {
	case *ecdsa.PublicKey, *rsa.PublicKey, ed25519.PublicKey:
	default:
		return nil, fmt.Errorf(
			"%w: unsupported public key type: %T",
			pkgerr.ErrInvalidType, publicKey,
		)
	}

	der, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, fmt.Errorf("%w: marshaling public key: %w", pkgerr.ErrEncode, err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: BlockTypePublic, Bytes: der}), nil
}

// SavePrivateKey writes the given private key to fileName as PEM, with 0600 permissions.
func SavePrivateKey(fileName string, privateKey any) error {

	data, err := EncodePrivateKeyPEM(privateKey)
	if err != nil {
		return err
	}
	if err := os.WriteFile(fileName, data, PrivateKeyFilePerm); err != nil {
		return fmt.Errorf("%w: writing private key to %s: %w", pkgerr.ErrWrite, fileName, err)
	}
	return nil
}

// SavePublicKey writes the given public key to fileName as PEM, with 0644 permissions.
func SavePublicKey(fileName string, publicKey any) error {

	data, err := EncodePublicKeyPEM(publicKey)
	if err != nil {
		return err
	}
	if err := os.WriteFile(fileName, data, PublicKeyFilePerm); err != nil {
		return fmt.Errorf("%w: writing public key to %s: %w", pkgerr.ErrWrite, fileName, err)
	}
	return nil
}

// ReadPEMFile reads PEM bytes from fileName.
func ReadPEMFile(fileName string) ([]byte, error) {
	data, err := os.ReadFile(fileName)
	if err != nil {
		return nil, fmt.Errorf("%w: reading pem file %s: %w", pkgerr.ErrRead, fileName, err)
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("%w: pem file %s empty", pkgerr.ErrInvalidValue, fileName)
	}
	return data, nil
}

// DecodeBase64PEM decodes a base64-encoded PEM blob to its raw PEM bytes.
func DecodeBase64PEM(encoded []byte) ([]byte, error) {
	if len(encoded) == 0 {
		return nil, fmt.Errorf("%w: empty base64 input", pkgerr.ErrInvalidValue)
	}
	decoded, err := base64.StdEncoding.DecodeString(string(encoded))
	if err != nil {
		return nil, fmt.Errorf("%w: decoding base64 pem: %w", pkgerr.ErrDecode, err)
	}
	return decoded, nil
}
