package signing_test

import (
	"context"
	"crypto/elliptic"
	"testing"

	"github.com/golang-jwt/jwt/v5"

	"github.com/dcadolph/jwtsmith/claims"
	"github.com/dcadolph/jwtsmith/keys"
	"github.com/dcadolph/jwtsmith/signing"
)

// BenchmarkSign measures sign throughput across the asymmetric algorithms jwtsmith supports.
//
// Use as: go test -run=- -bench=BenchmarkSign -benchmem ./signing
//
// ECDSA dominates the throughput chart; RSA-4096 is the slowest by an order of magnitude.
// Reported numbers are sign operations per second per goroutine, with allocations.
func BenchmarkSign(b *testing.B) {

	priv256, _, _ := keys.GenerateECDSA(elliptic.P256())
	priv384, _, _ := keys.GenerateECDSA(elliptic.P384())
	rsa2048, _, _ := keys.GenerateRSA(2048)
	ed25519Priv, _, _ := keys.GenerateEd25519()

	cases := []struct {
		Name   string
		Method jwt.SigningMethod
		Key    any
	}{
		{Name: "ES256", Method: jwt.SigningMethodES256, Key: priv256},
		{Name: "ES384", Method: jwt.SigningMethodES384, Key: priv384},
		{Name: "RS256-2048", Method: jwt.SigningMethodRS256, Key: rsa2048},
		{Name: "PS256-2048", Method: jwt.SigningMethodPS256, Key: rsa2048},
		{Name: "EdDSA", Method: jwt.SigningMethodEdDSA, Key: ed25519Priv},
	}

	mc := jwt.MapClaims{
		claims.KeySubject:  "user-1",
		claims.KeyAudience: []string{"api"},
	}

	for _, c := range cases {
		signer, err := signing.NewSigner(c.Method, c.Key)
		if err != nil {
			b.Fatalf("%s: NewSigner: %v", c.Name, err)
		}
		b.Run(c.Name, func(b *testing.B) {
			b.ReportAllocs()
			ctx := context.Background()
			for i := 0; i < b.N; i++ {
				if _, _, err := signer.Sign(ctx, mc, nil); err != nil {
					b.Fatalf("Sign: %v", err)
				}
			}
		})
	}
}
