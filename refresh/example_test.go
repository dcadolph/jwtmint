package refresh_test

import (
	"context"
	"crypto/elliptic"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/dcadolph/jwtmint/claims"
	"github.com/dcadolph/jwtmint/keys"
	"github.com/dcadolph/jwtmint/refresh"
	"github.com/dcadolph/jwtmint/signing"
)

// ExampleNewRefresher shows a basic refresh: original window is preserved, iat/nbf/exp slid forward.
func ExampleNewRefresher() {

	priv, pub, _ := keys.GenerateECDSA(elliptic.P256())
	signer, _ := signing.NewSigner(jwt.SigningMethodES256, priv,
		signing.WithDefaultExpiration(time.Hour),
	)
	original, _, _ := signer.Sign(context.Background(),
		jwt.MapClaims{claims.KeySubject: "user-1"}, nil)

	r, _ := refresh.NewRefresher(jwt.SigningMethodES256, pub, priv)

	_, refreshed, err := r.Refresh(context.Background(), original)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(refreshed != "" && refreshed != original)
	// Output: true
}

// ExampleWithClaimsResolver shows revoking a group at refresh time.
func ExampleWithClaimsResolver() {

	priv, pub, _ := keys.GenerateECDSA(elliptic.P256())
	signer, _ := signing.NewSigner(jwt.SigningMethodES256, priv)
	original, _, _ := signer.Sign(context.Background(),
		jwt.MapClaims{
			claims.KeySubject: "user-1",
			claims.KeyGroups:  []string{"old-group"},
		}, nil)

	r, _ := refresh.NewRefresher(jwt.SigningMethodES256, pub, priv,
		refresh.WithClaimsResolver(func(_ context.Context, c jwt.MapClaims) (jwt.MapClaims, error) {
			claims.SetGroups(c, "current-group")
			return c, nil
		}),
	)

	tok, _, _ := r.Refresh(context.Background(), original)
	groups, _ := claims.Groups(tok.Claims.(jwt.MapClaims))
	fmt.Println(groups)
	// Output: [current-group]
}
