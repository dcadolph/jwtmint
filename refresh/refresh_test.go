package refresh

import (
	"context"
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
	signed, _, err := signer.Sign(context.Background(), jwt.MapClaims{claims.KeySubject: "u1"}, nil)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	r, err := NewRefresher(jwt.SigningMethodES256, pub, priv, WithDefaultExpiration(time.Hour))
	if err != nil {
		t.Fatalf("NewRefresher: %v", err)
	}

	_, refreshed, err := r.Refresh(context.Background(), signed)
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

	r, err := NewRefresher(jwt.SigningMethodES256, pub, priv,
		WithDefaultExpiration(time.Hour),
		WithMaxAge(0), // Disable MaxAge for this test (token is intentionally old).
	)
	if err != nil {
		t.Fatalf("NewRefresher: %v", err)
	}
	_, refreshed, err := r.Refresh(context.Background(), signed)
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if refreshed == "" {
		t.Error("refreshed token empty")
	}
}

// TestRefreshMaxAge ensures tokens older than MaxAge are rejected.
func TestRefreshMaxAge(t *testing.T) {
	t.Parallel()

	priv, pub, _ := keys.GenerateECDSA(elliptic.P256())

	c := jwt.MapClaims{}
	claims.SetIssuedAt(c, time.Now().Add(-2*time.Hour))
	claims.SetExpiresAt(c, time.Now().Add(time.Hour))
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, c)
	signed, _ := tok.SignedString(priv)

	r, err := NewRefresher(jwt.SigningMethodES256, pub, priv, WithMaxAge(time.Hour))
	if err != nil {
		t.Fatalf("NewRefresher: %v", err)
	}
	_, _, err = r.Refresh(context.Background(), signed)
	if !errors.Is(err, pkgerr.ErrExpired) {
		t.Errorf("want ErrExpired for token older than MaxAge, got %v", err)
	}
}

// TestRefreshClaimsResolver ensures the resolver can rewrite or reject claims.
func TestRefreshClaimsResolver(t *testing.T) {
	t.Parallel()

	priv, pub, _ := keys.GenerateECDSA(elliptic.P256())
	signer, _ := signing.NewSigner(jwt.SigningMethodES256, priv)
	signed, _, _ := signer.Sign(context.Background(), jwt.MapClaims{
		claims.KeySubject: "u1",
		claims.KeyGroups:  []string{"old-group"},
	}, nil)

	r, err := NewRefresher(jwt.SigningMethodES256, pub, priv,
		WithMaxAge(0),
		WithClaimsResolver(func(_ context.Context, original jwt.MapClaims) (jwt.MapClaims, error) {
			claims.SetGroups(original, "new-group")
			return original, nil
		}),
	)
	if err != nil {
		t.Fatalf("NewRefresher: %v", err)
	}
	_, refreshed, err := r.Refresh(context.Background(), signed)
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}

	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	parsed := jwt.MapClaims{}
	keyFunc, _ := keys.PublicKeyFunc(jwt.SigningMethodES256, pub)
	if _, err := parser.ParseWithClaims(refreshed, parsed, keyFunc); err != nil {
		t.Fatalf("parse refreshed: %v", err)
	}
	groups, _ := claims.Groups(parsed)
	if len(groups) != 1 || groups[0] != "new-group" {
		t.Errorf("groups after resolver: want [new-group] got %v", groups)
	}
}

// TestRefreshInvalidInputs covers empty string and (since *jwt.Token overload was removed) wrong types via direct call.
func TestRefreshInvalidInputs(t *testing.T) {
	t.Parallel()

	priv, pub, _ := keys.GenerateECDSA(elliptic.P256())
	r, _ := NewRefresher(jwt.SigningMethodES256, pub, priv)

	_, _, err := r.Refresh(context.Background(), "")
	if !errors.Is(err, pkgerr.ErrInvalidValue) {
		t.Errorf("empty string: want ErrInvalidValue, got %v", err)
	}
}

// TestRefreshMismatchedPair ensures invalid key pairs are rejected at construction.
func TestRefreshMismatchedPair(t *testing.T) {
	t.Parallel()

	priv1, _, _ := keys.GenerateECDSA(elliptic.P256())
	_, pub2, _ := keys.GenerateECDSA(elliptic.P256())
	_, err := NewRefresher(jwt.SigningMethodES256, pub2, priv1)
	if !errors.Is(err, pkgerr.ErrInvalidKeyPair) {
		t.Errorf("want ErrInvalidKeyPair, got %v", err)
	}
}
