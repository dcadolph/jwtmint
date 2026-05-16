package signing_test

import (
	"context"
	"crypto/elliptic"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/dcadolph/jwtmint/claims"
	"github.com/dcadolph/jwtmint/keys"
	"github.com/dcadolph/jwtmint/signing"
)

// ExampleNewSigner demonstrates building a Signer with sensible defaults and minting a token.
func ExampleNewSigner() {

	priv, _, _ := keys.GenerateECDSA(elliptic.P256())

	signer, err := signing.NewSigner(jwt.SigningMethodES256, priv,
		signing.WithDefaultIssuer("my-service"),
		signing.WithDefaultExpiration(15*time.Minute),
	)
	if err != nil {
		fmt.Println(err)
		return
	}

	_, tok, err := signer.Sign(context.Background(),
		jwt.MapClaims{
			claims.KeySubject:  "user-1",
			claims.KeyAudience: []string{"api"},
		}, nil)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(tok.Method.Alg(), tok.Header[signing.HeaderKeyTyp])
	// Output: ES256 JWT
}

// ExampleNewSigner_at demonstrates minting an RFC 9068 access token by overriding the
// "typ" header.
func ExampleNewSigner_at() {

	priv, _, _ := keys.GenerateECDSA(elliptic.P256())

	signer, _ := signing.NewSigner(jwt.SigningMethodES256, priv,
		signing.WithDefaultTyp("at+jwt"),
	)

	_, tok, _ := signer.Sign(context.Background(),
		jwt.MapClaims{claims.KeySubject: "u1"}, nil)
	fmt.Println(tok.Header[signing.HeaderKeyTyp])
	// Output: at+jwt
}
