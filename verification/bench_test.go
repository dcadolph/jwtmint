package verification_test

import (
	"context"
	"crypto/elliptic"
	"testing"

	"github.com/golang-jwt/jwt/v5"

	"github.com/dcadolph/jwtmint/claims"
	"github.com/dcadolph/jwtmint/keys"
	"github.com/dcadolph/jwtmint/signing"
	"github.com/dcadolph/jwtmint/verification"
)

// BenchmarkVerify measures verify throughput across the asymmetric algorithms.
//
// Use as: go test -run=- -bench=BenchmarkVerify -benchmem ./verification
//
// Verify is typically faster than sign for ECDSA and Ed25519, slower for RSA. Numbers
// here include parse, signature verification, and registered-claims validation.
func BenchmarkVerify(b *testing.B) {

	priv256, pub256, _ := keys.GenerateECDSA(elliptic.P256())
	priv384, pub384, _ := keys.GenerateECDSA(elliptic.P384())
	rsa2048Priv, rsa2048Pub, _ := keys.GenerateRSA(2048)
	edPriv, edPub, _ := keys.GenerateEd25519()

	cases := []struct {
		Name   string
		Method jwt.SigningMethod
		Priv   any
		Pub    any
	}{
		{Name: "ES256", Method: jwt.SigningMethodES256, Priv: priv256, Pub: pub256},
		{Name: "ES384", Method: jwt.SigningMethodES384, Priv: priv384, Pub: pub384},
		{Name: "RS256-2048", Method: jwt.SigningMethodRS256, Priv: rsa2048Priv, Pub: rsa2048Pub},
		{Name: "PS256-2048", Method: jwt.SigningMethodPS256, Priv: rsa2048Priv, Pub: rsa2048Pub},
		{Name: "EdDSA", Method: jwt.SigningMethodEdDSA, Priv: edPriv, Pub: edPub},
	}

	for _, c := range cases {
		signer, _ := signing.NewSigner(c.Method, c.Priv)
		signed, _, _ := signer.Sign(context.Background(),
			jwt.MapClaims{claims.KeySubject: "user-1"}, nil)

		v, err := verification.NewVerifier(c.Method, c.Pub)
		if err != nil {
			b.Fatalf("%s: NewVerifier: %v", c.Name, err)
		}

		b.Run(c.Name, func(b *testing.B) {
			b.ReportAllocs()
			ctx := context.Background()
			for i := 0; i < b.N; i++ {
				if _, err := v.Verify(ctx, signed); err != nil {
					b.Fatalf("Verify: %v", err)
				}
			}
		})
	}
}
