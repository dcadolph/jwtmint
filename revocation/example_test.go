package revocation_test

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/dcadolph/jwtsmith/claims"
	"github.com/dcadolph/jwtsmith/revocation"
)

// ExampleNewMemRevoker shows revoking a token by jti and confirming the verifier hook
// path (Revoked) reports true.
func ExampleNewMemRevoker() {

	r, _ := revocation.NewMemRevoker()
	r.Revoke("jti-abc")

	tok := &jwt.Token{Claims: jwt.MapClaims{claims.KeyID: "jti-abc"}}
	revoked, _ := r.Revoked(context.Background(), tok)
	fmt.Println(revoked)
	// Output: true
}

// ExampleChain shows fronting an expensive remote denylist with an in-process cache.
func ExampleChain() {

	cache, _ := revocation.NewMemRevoker()
	remote := revocation.RevokerFunc(func(_ context.Context, _ *jwt.Token) (bool, error) {
		// Simulated remote lookup; real callers would query Redis/etcd/DB here.
		return false, errors.New("backend offline")
	})

	chained := revocation.Chain(cache, remote)
	_ = chained

	_ = time.Now // keep imports honest
}
