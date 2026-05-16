package verification

import (
	"context"
	"crypto/elliptic"
	"testing"

	"github.com/golang-jwt/jwt/v5"

	"github.com/dcadolph/jwtmint/keys"
)

// FuzzVerifyParse exercises the verifier's Verify entrypoint against arbitrary input strings.
//
// The contract under fuzz: Verify must return an error (never panic, never accept) for
// inputs that aren't a valid token signed by the configured key. A clean panic-free run
// over millions of inputs is the goal; correctness is implied by the fact that no input
// can satisfy the signature check without the matching private key.
func FuzzVerifyParse(f *testing.F) {

	_, pub, err := keys.GenerateECDSA(elliptic.P256())
	if err != nil {
		f.Fatalf("GenerateECDSA: %v", err)
	}

	v, err := NewVerifier(jwt.SigningMethodES256, pub)
	if err != nil {
		f.Fatalf("NewVerifier: %v", err)
	}

	seeds := []string{
		"",
		" ",
		"not.a.jwt",
		"a.b.c",
		"eyJhbGciOiJub25lIn0..",
		"...",
		"a.b",
		"\x00\x01\x02",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, in string) {
		_, err := v.Verify(context.Background(), in)
		if err == nil {
			t.Errorf("input %q: Verify returned nil error (no fuzz input should authenticate)", in)
		}
	})
}
