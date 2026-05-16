package verification

import (
	"context"
	"crypto/elliptic"
	"errors"
	"fmt"
	"testing"

	"github.com/golang-jwt/jwt/v5"

	"github.com/dcadolph/jwtmint/keys"
	"github.com/dcadolph/jwtmint/pkgerr"
)

// TestMultiKeyVerifier covers the happy path, kid mismatch, missing kid, and unknown kid.
func TestMultiKeyVerifier(t *testing.T) {
	t.Parallel()

	priv1, pub1, _ := keys.GenerateECDSA(elliptic.P256())
	priv2, pub2, _ := keys.GenerateECDSA(elliptic.P256())

	v, err := NewMultiKeyVerifier([]KeyEntry{
		{Kid: "k1", Method: jwt.SigningMethodES256, PublicKey: pub1},
		{Kid: "k2", Method: jwt.SigningMethodES256, PublicKey: pub2},
	})
	if err != nil {
		t.Fatalf("NewMultiKeyVerifier: %v", err)
	}

	signWithKid := func(priv any, kid string) string {
		t.Helper()
		tok := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{"sub": "u1"})
		if kid != "" {
			tok.Header["kid"] = kid
		}
		signed, err := tok.SignedString(priv)
		if err != nil {
			t.Fatalf("sign: %v", err)
		}
		return signed
	}

	tests := []struct {
		Want   error
		Name   string
		Token  string
	}{
		{Name: "kid k1 verifies", Token: signWithKid(priv1, "k1")},
		{Name: "kid k2 verifies", Token: signWithKid(priv2, "k2")},
		{Name: "no kid header rejected", Token: signWithKid(priv1, ""), Want: pkgerr.ErrParse},
		{Name: "unknown kid rejected", Token: signWithKid(priv1, "nope"), Want: pkgerr.ErrParse},
		{Name: "wrong key for kid rejected", Token: signWithKid(priv2, "k1"), Want: pkgerr.ErrParse},
	}

	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d %s", testNum, test.Name), func(t *testing.T) {
			t.Parallel()
			_, err := v.Verify(context.Background(), test.Token)
			if !errors.Is(err, test.Want) {
				t.Errorf("test %d: want %v got %v", testNum, test.Want, err)
			}
		})
	}
}

// TestMultiKeyVerifierConstructionErrors covers required-field rejection and dup detection.
func TestMultiKeyVerifierConstructionErrors(t *testing.T) {
	t.Parallel()

	_, pub, _ := keys.GenerateECDSA(elliptic.P256())

	tests := []struct {
		Want    error
		Name    string
		Entries []KeyEntry
	}{
		{Name: "empty", Entries: nil, Want: pkgerr.ErrInvalidValue},
		{Name: "missing kid", Entries: []KeyEntry{{Method: jwt.SigningMethodES256, PublicKey: pub}}, Want: pkgerr.ErrInvalidValue},
		{Name: "missing method", Entries: []KeyEntry{{Kid: "k1", PublicKey: pub}}, Want: pkgerr.ErrInvalidValue},
		{Name: "missing key", Entries: []KeyEntry{{Kid: "k1", Method: jwt.SigningMethodES256}}, Want: pkgerr.ErrInvalidValue},
		{Name: "duplicate kid", Entries: []KeyEntry{
			{Kid: "k1", Method: jwt.SigningMethodES256, PublicKey: pub},
			{Kid: "k1", Method: jwt.SigningMethodES256, PublicKey: pub},
		}, Want: pkgerr.ErrInvalidValue},
	}

	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d %s", testNum, test.Name), func(t *testing.T) {
			t.Parallel()
			_, err := NewMultiKeyVerifier(test.Entries)
			if !errors.Is(err, test.Want) {
				t.Errorf("test %d: want %v got %v", testNum, test.Want, err)
			}
		})
	}
}
