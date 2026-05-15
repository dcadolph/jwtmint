package verification

import (
	"crypto/elliptic"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/dcadolph/jwtsmith/claims"
	"github.com/dcadolph/jwtsmith/keys"
	"github.com/dcadolph/jwtsmith/pkgerr"
	"github.com/dcadolph/jwtsmith/signing"
)

// TestVerifyRoundtrip exercises sign-then-verify with a static check.
func TestVerifyRoundtrip(t *testing.T) {
	t.Parallel()

	priv, pub, _ := keys.GenerateECDSA(elliptic.P256())
	signer, err := signing.NewSigner(jwt.SigningMethodES256, priv, signing.WithDefaultIssuer("issuer-x"))
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	signed, _, err := signer.Sign(jwt.MapClaims{claims.KeySubject: "user-1"})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	v, err := NewVerifier(
		jwt.SigningMethodES256, pub,
		WithStaticChecks(CheckClaims(claims.CheckIssuer("issuer-x"))),
	)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}

	tok, err := v.Verify(signed)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !tok.Valid {
		t.Error("token not Valid")
	}
}

// TestVerifyWrongMethod ensures method mismatch is rejected.
func TestVerifyWrongMethod(t *testing.T) {
	t.Parallel()

	es256Priv, _, _ := keys.GenerateECDSA(elliptic.P256())
	_, es384Pub, _ := keys.GenerateECDSAForMethod(jwt.SigningMethodES384)

	signer, _ := signing.NewSigner(jwt.SigningMethodES256, es256Priv)
	signed, _, _ := signer.Sign(jwt.MapClaims{})

	v, err := NewVerifier(jwt.SigningMethodES384, es384Pub)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}

	_, err = v.Verify(signed)
	if !errors.Is(err, pkgerr.ErrParse) {
		t.Errorf("want ErrParse, got %v", err)
	}
}

// TestVerifyExtraCheck ensures per-call checks run after static checks.
func TestVerifyExtraCheck(t *testing.T) {
	t.Parallel()

	priv, pub, _ := keys.GenerateECDSA(elliptic.P256())
	signer, _ := signing.NewSigner(jwt.SigningMethodES256, priv)
	signed, _, _ := signer.Sign(jwt.MapClaims{claims.KeySubject: "user-1"})

	v, err := NewVerifier(jwt.SigningMethodES256, pub)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}

	tests := []struct {
		Want  error
		Name  string
		Extra []TokenCheckFunc
	}{
		{Name: "passes", Extra: []TokenCheckFunc{CheckClaims(claims.CheckRequiredKeys(claims.KeySubject))}},
		{Name: "fails", Extra: []TokenCheckFunc{CheckClaims(claims.CheckRequiredKeys("missing"))}, Want: pkgerr.ErrCheck},
	}

	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d %s", testNum, test.Name), func(t *testing.T) {
			t.Parallel()
			_, err := v.Verify(signed, test.Extra...)
			if !errors.Is(err, test.Want) {
				t.Errorf("test %d: want %v got %v", testNum, test.Want, err)
			}
		})
	}
}

// TestExpiredTokenRejected ensures the parser rejects expired tokens by default.
func TestExpiredTokenRejected(t *testing.T) {
	t.Parallel()

	priv, pub, _ := keys.GenerateECDSA(elliptic.P256())

	c := jwt.MapClaims{}
	claims.SetExpiresAt(c, time.Now().Add(time.Second))
	claims.SetIssuedAt(c, time.Now().Add(-time.Hour))
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, c)
	signed, err := tok.SignedString(priv)
	if err != nil {
		t.Fatalf("SignedString: %v", err)
	}

	time.Sleep(1100 * time.Millisecond)

	v, _ := NewVerifier(jwt.SigningMethodES256, pub)
	_, err = v.Verify(signed)
	if !errors.Is(err, pkgerr.ErrParse) {
		t.Errorf("want ErrParse for expired token, got %v", err)
	}
}

// TestHeaderChecks covers banned and required header checks.
func TestHeaderChecks(t *testing.T) {
	t.Parallel()

	priv, pub, _ := keys.GenerateECDSA(elliptic.P256())
	signer, _ := signing.NewSigner(
		jwt.SigningMethodES256, priv,
		signing.WithStaticHeaders(map[string]any{"kid": "k1"}),
	)
	signed, _, _ := signer.Sign(jwt.MapClaims{})

	v, _ := NewVerifier(jwt.SigningMethodES256, pub)

	tests := []struct {
		Check TokenCheckFunc
		Want  error
		Name  string
	}{
		{Name: "required present", Check: CheckRequiredHeaders("kid")},
		{Name: "required missing", Check: CheckRequiredHeaders("missing"), Want: pkgerr.ErrCheck},
		{Name: "banned absent", Check: CheckBannedHeaders("x")},
		{Name: "banned present", Check: CheckBannedHeaders("kid"), Want: pkgerr.ErrCheck},
		{Name: "header value match", Check: CheckRequiredHeaderValues(map[string]any{"kid": "k1"})},
		{Name: "header value mismatch", Check: CheckRequiredHeaderValues(map[string]any{"kid": "k2"}), Want: pkgerr.ErrCheck},
	}

	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d %s", testNum, test.Name), func(t *testing.T) {
			t.Parallel()
			_, err := v.Verify(signed, test.Check)
			if !errors.Is(err, test.Want) {
				t.Errorf("test %d: want %v got %v", testNum, test.Want, err)
			}
		})
	}
}
