package verification_test

import (
	"context"
	"crypto/elliptic"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/dcadolph/jwtsmith/claims"
	"github.com/dcadolph/jwtsmith/keys"
	"github.com/dcadolph/jwtsmith/revocation"
	"github.com/dcadolph/jwtsmith/signing"
	"github.com/dcadolph/jwtsmith/verification"
)

// ExampleNewVerifier shows the typical sign-then-verify flow with a static issuer check.
func ExampleNewVerifier() {

	priv, pub, _ := keys.GenerateECDSA(elliptic.P256())
	signer, _ := signing.NewSigner(jwt.SigningMethodES256, priv,
		signing.WithDefaultIssuer("my-service"),
	)
	signed, _, _ := signer.Sign(context.Background(),
		jwt.MapClaims{claims.KeySubject: "user-1"}, nil)

	v, err := verification.NewVerifier(jwt.SigningMethodES256, pub,
		verification.WithStaticChecks(
			verification.CheckClaims(claims.CheckIssuer("my-service")),
		),
	)
	if err != nil {
		fmt.Println(err)
		return
	}

	tok, err := v.Verify(context.Background(), signed)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(tok.Valid)
	// Output: true
}

// ExampleNewMultiKeyVerifier covers the rotation case: two kids verifiable simultaneously.
func ExampleNewMultiKeyVerifier() {

	_, pub1, _ := keys.GenerateECDSA(elliptic.P256())
	_, pub2, _ := keys.GenerateECDSA(elliptic.P256())

	v, _ := verification.NewMultiKeyVerifier([]verification.KeyEntry{
		{Kid: "k1", Method: jwt.SigningMethodES256, PublicKey: pub1},
		{Kid: "k2", Method: jwt.SigningMethodES256, PublicKey: pub2},
	})
	_ = v // dispatches by token's "kid" header
}

// ExampleWithRevoker plugs an in-memory revocation list into verification.
func ExampleWithRevoker() {

	priv, pub, _ := keys.GenerateECDSA(elliptic.P256())
	signer, _ := signing.NewSigner(jwt.SigningMethodES256, priv)
	revoked, _, _ := signer.Sign(context.Background(),
		jwt.MapClaims{claims.KeyID: "jti-banned"}, nil)

	rev, _ := revocation.NewMemRevoker()
	rev.RevokeUntil("jti-banned", time.Now().Add(time.Hour))

	v, _ := verification.NewVerifier(jwt.SigningMethodES256, pub,
		verification.WithRevoker(rev),
	)

	_, err := v.Verify(context.Background(), revoked)
	fmt.Println(err != nil)
	// Output: true
}
