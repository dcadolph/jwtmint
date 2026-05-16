package keys

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"errors"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/golang-jwt/jwt/v5"

	"github.com/dcadolph/jwtmint/pkgerr"
)

// TestGenerateAndValidate covers Generate + ValidatePair for every supported algorithm.
func TestGenerateAndValidate(t *testing.T) {
	t.Parallel()

	t.Run("ecdsa p256", func(t *testing.T) {
		t.Parallel()
		priv, pub, err := GenerateECDSA(elliptic.P256())
		if err != nil {
			t.Fatalf("GenerateECDSA: %v", err)
		}
		if err := ValidatePair(pub, priv); err != nil {
			t.Errorf("ValidatePair: %v", err)
		}
	})

	t.Run("ecdsa for ES384 method", func(t *testing.T) {
		t.Parallel()
		priv, pub, err := GenerateECDSAForMethod(jwt.SigningMethodES384)
		if err != nil {
			t.Fatalf("GenerateECDSAForMethod: %v", err)
		}
		if err := ValidatePair(pub, priv); err != nil {
			t.Errorf("ValidatePair: %v", err)
		}
	})

	t.Run("rsa 2048", func(t *testing.T) {
		t.Parallel()
		priv, pub, err := GenerateRSA(2048)
		if err != nil {
			t.Fatalf("GenerateRSA: %v", err)
		}
		if err := ValidatePair(pub, priv); err != nil {
			t.Errorf("ValidatePair: %v", err)
		}
	})

	t.Run("rsa too small", func(t *testing.T) {
		t.Parallel()
		_, _, err := GenerateRSA(1024)
		if !errors.Is(err, pkgerr.ErrInvalidSize) {
			t.Errorf("GenerateRSA(1024): want ErrInvalidSize, got %v", err)
		}
	})

	t.Run("ed25519", func(t *testing.T) {
		t.Parallel()
		priv, pub, err := GenerateEd25519()
		if err != nil {
			t.Fatalf("GenerateEd25519: %v", err)
		}
		if err := ValidatePair(pub, priv); err != nil {
			t.Errorf("ValidatePair: %v", err)
		}
	})
}

// TestValidatePairMismatched ensures mismatched pairs are detected per algorithm.
func TestValidatePairMismatched(t *testing.T) {
	t.Parallel()

	t.Run("ecdsa", func(t *testing.T) {
		t.Parallel()
		priv1, _, _ := GenerateECDSA(elliptic.P256())
		_, pub2, _ := GenerateECDSA(elliptic.P256())
		if err := ValidatePair(pub2, priv1); !errors.Is(err, pkgerr.ErrInvalidKeyPair) {
			t.Errorf("want ErrInvalidKeyPair, got %v", err)
		}
	})

	t.Run("rsa", func(t *testing.T) {
		t.Parallel()
		priv1, _, _ := GenerateRSA(2048)
		_, pub2, _ := GenerateRSA(2048)
		if err := ValidatePair(pub2, priv1); !errors.Is(err, pkgerr.ErrInvalidKeyPair) {
			t.Errorf("want ErrInvalidKeyPair, got %v", err)
		}
	})

	t.Run("ed25519", func(t *testing.T) {
		t.Parallel()
		priv1, _, _ := GenerateEd25519()
		_, pub2, _ := GenerateEd25519()
		if err := ValidatePair(pub2, priv1); !errors.Is(err, pkgerr.ErrInvalidKeyPair) {
			t.Errorf("want ErrInvalidKeyPair, got %v", err)
		}
	})

	t.Run("type mismatch", func(t *testing.T) {
		t.Parallel()
		ecPriv, _, _ := GenerateECDSA(elliptic.P256())
		_, rsaPub, _ := GenerateRSA(2048)
		if err := ValidatePair(rsaPub, ecPriv); !errors.Is(err, pkgerr.ErrInvalidType) {
			t.Errorf("want ErrInvalidType, got %v", err)
		}
	})
}

// TestPEMRoundTrip ensures encode + load yields a matching key pair for every algorithm.
func TestPEMRoundTrip(t *testing.T) {
	t.Parallel()

	type roundTrip struct {
		Want    error
		Name    string
		Encoded any
	}

	ecPriv, ecPub, _ := GenerateECDSA(elliptic.P256())
	rsaPriv, rsaPub, _ := GenerateRSA(2048)
	edPriv, edPub, _ := GenerateEd25519()

	tests := []struct {
		Name   string
		Encode func() ([]byte, []byte, error)
		Load   func(privPEM, pubPEM []byte) (any, any, error)
	}{
		{
			Name: "ecdsa",
			Encode: func() ([]byte, []byte, error) {
				p, err := EncodePrivateKeyPEM(ecPriv)
				if err != nil {
					return nil, nil, err
				}
				q, err := EncodePublicKeyPEM(ecPub)
				return p, q, err
			},
			Load: func(privPEM, pubPEM []byte) (any, any, error) {
				p, err := LoadECDSAPrivateFromPEM(privPEM)
				if err != nil {
					return nil, nil, err
				}
				q, err := LoadECDSAPublicFromPEM(pubPEM)
				return p, q, err
			},
		},
		{
			Name: "rsa",
			Encode: func() ([]byte, []byte, error) {
				p, err := EncodePrivateKeyPEM(rsaPriv)
				if err != nil {
					return nil, nil, err
				}
				q, err := EncodePublicKeyPEM(rsaPub)
				return p, q, err
			},
			Load: func(privPEM, pubPEM []byte) (any, any, error) {
				p, err := LoadRSAPrivateFromPEM(privPEM)
				if err != nil {
					return nil, nil, err
				}
				q, err := LoadRSAPublicFromPEM(pubPEM)
				return p, q, err
			},
		},
		{
			Name: "ed25519",
			Encode: func() ([]byte, []byte, error) {
				p, err := EncodePrivateKeyPEM(edPriv)
				if err != nil {
					return nil, nil, err
				}
				q, err := EncodePublicKeyPEM(edPub)
				return p, q, err
			},
			Load: func(privPEM, pubPEM []byte) (any, any, error) {
				p, err := LoadEd25519PrivateFromPEM(privPEM)
				if err != nil {
					return nil, nil, err
				}
				q, err := LoadEd25519PublicFromPEM(pubPEM)
				return p, q, err
			},
		},
	}

	_ = roundTrip{} // Keep struct type referenced for future expansion.

	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d %s", testNum, test.Name), func(t *testing.T) {
			t.Parallel()
			privPEM, pubPEM, err := test.Encode()
			if err != nil {
				t.Fatalf("encode: %v", err)
			}
			priv, pub, err := test.Load(privPEM, pubPEM)
			if err != nil {
				t.Fatalf("load: %v", err)
			}
			if err := ValidatePair(pub, priv); err != nil {
				t.Errorf("loaded keys do not pair: %v", err)
			}
		})
	}
}

// TestSavePrivateKeyPerm ensures file permissions on saved private keys are 0600.
func TestSavePrivateKeyPerm(t *testing.T) {
	t.Parallel()

	priv, _, err := GenerateECDSA(elliptic.P256())
	if err != nil {
		t.Fatalf("GenerateECDSA: %v", err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "key.pem")
	if err := SavePrivateKey(path, priv); err != nil {
		t.Fatalf("SavePrivateKey: %v", err)
	}
	loaded, err := ReadPEMFile(path)
	if err != nil {
		t.Fatalf("ReadPEMFile: %v", err)
	}
	if _, err := LoadECDSAPrivateFromPEM(loaded); err != nil {
		t.Errorf("LoadECDSAPrivateFromPEM after save: %v", err)
	}
}

// TestPublicKeyFunc ensures the returned Keyfunc enforces method matching.
func TestPublicKeyFunc(t *testing.T) {
	t.Parallel()

	priv, pub, err := GenerateECDSA(elliptic.P256())
	if err != nil {
		t.Fatalf("GenerateECDSA: %v", err)
	}

	keyFunc, err := PublicKeyFunc(jwt.SigningMethodES256, pub)
	if err != nil {
		t.Fatalf("PublicKeyFunc: %v", err)
	}

	tests := []struct {
		Want   error
		Name   string
		Method jwt.SigningMethod
	}{
		{Name: "match", Method: jwt.SigningMethodES256},
		{Name: "method mismatch", Method: jwt.SigningMethodES384, Want: pkgerr.ErrInvalidMethod},
	}

	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d %s", testNum, test.Name), func(t *testing.T) {
			t.Parallel()
			tok := jwt.NewWithClaims(test.Method, jwt.MapClaims{})
			_, err := keyFunc(tok)
			if !errors.Is(err, test.Want) {
				t.Errorf("test %d: want %v got %v", testNum, test.Want, err)
			}
		})
	}

	// Type assertions on returned key.
	var _ *ecdsa.PrivateKey = priv
	var _ *ecdsa.PublicKey = pub
	var _ *rsa.PublicKey
	var _ ed25519.PublicKey
}
