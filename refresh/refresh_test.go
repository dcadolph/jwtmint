package refresh

import (
	"crypto/elliptic"
	"errors"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/dcadolph/jwtsmith/claims"
	"github.com/dcadolph/jwtsmith/keys"
	"github.com/dcadolph/jwtsmith/pkgerr"
	"github.com/dcadolph/jwtsmith/signing"
)

// TestRefreshPreservesWindow checks the new exp - iat duration matches the original.
func TestRefreshPreservesWindow(t *testing.T) {
	t.Parallel()

	priv, pub, _ := keys.GenerateECDSA(elliptic.P256())
	signer, _ := signing.NewSigner(jwt.SigningMethodES256, priv, signing.WithDefaultExpiration(2*time.Hour))
	signed, _, err := signer.Sign(jwt.MapClaims{claims.KeySubject: "u1"})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	r, err := New(jwt.SigningMethodES256, pub, priv, time.Hour)
	if err != nil {
		t.Fatalf("New refresher: %v", err)
	}

	_, refreshed, err := r.Refresh(signed)
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}

	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	parsed := jwt.MapClaims{}
	keyFunc, _ := keys.PublicKeyFunc(jwt.SigningMethodES256, pub)
	if _, err := parser.ParseWithClaims(refreshed, parsed, keyFunc); err != nil {
		t.Fatalf("parse refreshed: %v", err)
	}

	exp, _ := claims.ExpiresAt(parsed)
	iat, _ := claims.IssuedAt(parsed)
	got := exp.Sub(iat)
	if got < (2*time.Hour-time.Second) || got > (2*time.Hour+time.Second) {
		t.Errorf("expected window ~2h, got %v", got)
	}
}

// TestRefreshExpiredToken ensures an expired token can still be refreshed.
func TestRefreshExpiredToken(t *testing.T) {
	t.Parallel()

	priv, pub, _ := keys.GenerateECDSA(elliptic.P256())

	c := jwt.MapClaims{}
	claims.SetIssuedAt(c, time.Now().Add(-2*time.Hour))
	claims.SetExpiresAt(c, time.Now().Add(-time.Hour))
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, c)
	signed, err := tok.SignedString(priv)
	if err != nil {
		t.Fatalf("SignedString: %v", err)
	}

	r, err := New(jwt.SigningMethodES256, pub, priv, time.Hour)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, refreshed, err := r.Refresh(signed)
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if refreshed == "" {
		t.Error("refreshed token empty")
	}
}

// TestRefreshInvalidInputs covers nil, empty string, and wrong type cases.
func TestRefreshInvalidInputs(t *testing.T) {
	t.Parallel()

	priv, pub, _ := keys.GenerateECDSA(elliptic.P256())
	r, _ := New(jwt.SigningMethodES256, pub, priv, 0)

	_, _, err := r.Refresh("")
	if !errors.Is(err, pkgerr.ErrInvalidValue) {
		t.Errorf("empty string: want ErrInvalidValue, got %v", err)
	}
	_, _, err = r.Refresh(42)
	if !errors.Is(err, pkgerr.ErrInvalidType) {
		t.Errorf("int input: want ErrInvalidType, got %v", err)
	}
}

// TestRefreshMismatchedPair ensures invalid key pairs are rejected at construction.
func TestRefreshMismatchedPair(t *testing.T) {
	t.Parallel()

	priv1, _, _ := keys.GenerateECDSA(elliptic.P256())
	_, pub2, _ := keys.GenerateECDSA(elliptic.P256())
	_, err := New(jwt.SigningMethodES256, pub2, priv1, 0)
	if !errors.Is(err, pkgerr.ErrInvalidKeyPair) {
		t.Errorf("want ErrInvalidKeyPair, got %v", err)
	}
}
