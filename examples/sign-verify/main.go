// Command sign-verify demonstrates an end-to-end mint -> verify -> refresh -> revoke flow
// using only the jwtsmith library (no daemon).
//
// Run: go run ./examples/sign-verify
package main

import (
	"context"
	"crypto/elliptic"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/dcadolph/jwtsmith/claims"
	"github.com/dcadolph/jwtsmith/keys"
	"github.com/dcadolph/jwtsmith/pkgerr"
	"github.com/dcadolph/jwtsmith/refresh"
	"github.com/dcadolph/jwtsmith/revocation"
	"github.com/dcadolph/jwtsmith/signing"
	"github.com/dcadolph/jwtsmith/verification"
)

func main() {

	priv, pub, err := keys.GenerateECDSA(elliptic.P256())
	if err != nil {
		log.Fatalf("GenerateECDSA: %v", err)
	}

	signer, err := signing.NewSigner(jwt.SigningMethodES256, priv,
		signing.WithDefaultIssuer("examples/sign-verify"),
		signing.WithDefaultExpiration(15*time.Minute),
	)
	if err != nil {
		log.Fatalf("NewSigner: %v", err)
	}

	ctx := context.Background()

	signed, _, err := signer.Sign(ctx, jwt.MapClaims{
		claims.KeySubject:  "user-1",
		claims.KeyAudience: []string{"api"},
		claims.KeyGroups:   []string{"admins"},
	}, nil)
	if err != nil {
		log.Fatalf("Sign: %v", err)
	}
	fmt.Printf("minted token (%d bytes)\n", len(signed))

	rev, _ := revocation.NewMemRevoker()
	verifier, err := verification.NewVerifier(jwt.SigningMethodES256, pub,
		verification.WithStaticChecks(
			verification.CheckClaims(
				claims.CheckIssuer("examples/sign-verify"),
				claims.CheckRequiredKeys(claims.KeySubject),
			),
		),
		verification.WithRevoker(rev),
	)
	if err != nil {
		log.Fatalf("NewVerifier: %v", err)
	}

	tok, err := verifier.Verify(ctx, signed)
	if err != nil {
		log.Fatalf("Verify (initial): %v", err)
	}
	fmt.Printf("verified: valid=%v sub=%v\n", tok.Valid, tok.Claims.(jwt.MapClaims)[claims.KeySubject])

	refresher, err := refresh.NewRefresher(jwt.SigningMethodES256, pub, priv,
		refresh.WithDefaultExpiration(15*time.Minute),
	)
	if err != nil {
		log.Fatalf("NewRefresher: %v", err)
	}
	_, refreshed, err := refresher.Refresh(ctx, signed)
	if err != nil {
		log.Fatalf("Refresh: %v", err)
	}
	fmt.Printf("refreshed token (%d bytes)\n", len(refreshed))

	jti, _ := claims.JTI(tok.Claims.(jwt.MapClaims))
	rev.RevokeUntil(jti, time.Now().Add(time.Hour))

	if _, err := verifier.Verify(ctx, signed); errors.Is(err, pkgerr.ErrRevoked) {
		fmt.Println("revoked token rejected as expected")
	} else {
		log.Fatalf("expected ErrRevoked, got %v", err)
	}
}
