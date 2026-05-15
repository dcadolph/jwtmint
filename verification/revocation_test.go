package verification

import (
	"context"
	"crypto/elliptic"
	"errors"
	"testing"

	"github.com/golang-jwt/jwt/v5"

	"github.com/dcadolph/jwtsmith/claims"
	"github.com/dcadolph/jwtsmith/keys"
	"github.com/dcadolph/jwtsmith/pkgerr"
	"github.com/dcadolph/jwtsmith/revocation"
	"github.com/dcadolph/jwtsmith/signing"
)

// TestVerifyWithRevoker exercises a revoked vs non-revoked jti through the verifier.
func TestVerifyWithRevoker(t *testing.T) {
	t.Parallel()

	priv, pub, _ := keys.GenerateECDSA(elliptic.P256())
	signer, _ := signing.NewSigner(jwt.SigningMethodES256, priv)

	bad, _, _ := signer.Sign(context.Background(), jwt.MapClaims{
		claims.KeySubject: "u1",
		claims.KeyID:      "jti-banned",
	}, nil)
	good, _, _ := signer.Sign(context.Background(), jwt.MapClaims{
		claims.KeySubject: "u2",
		claims.KeyID:      "jti-ok",
	}, nil)

	rev, err := revocation.NewMemRevoker()
	if err != nil {
		t.Fatalf("NewMemRevoker: %v", err)
	}
	rev.Revoke("jti-banned")

	v, err := NewVerifier(jwt.SigningMethodES256, pub, WithRevoker(rev))
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}

	if _, err := v.Verify(context.Background(), bad); !errors.Is(err, pkgerr.ErrRevoked) {
		t.Errorf("revoked: want ErrRevoked got %v", err)
	}
	if _, err := v.Verify(context.Background(), good); err != nil {
		t.Errorf("non-revoked: want nil got %v", err)
	}
}

// TestVerifyWithRevokerLookupError ensures backend errors fail the verification rather
// than being treated as "not revoked".
func TestVerifyWithRevokerLookupError(t *testing.T) {
	t.Parallel()

	priv, pub, _ := keys.GenerateECDSA(elliptic.P256())
	signer, _ := signing.NewSigner(jwt.SigningMethodES256, priv)
	signed, _, _ := signer.Sign(context.Background(), jwt.MapClaims{claims.KeyID: "any"}, nil)

	sentinel := errors.New("denylist offline")
	r := revocation.RevokerFunc(func(_ context.Context, _ *jwt.Token) (bool, error) {
		return false, sentinel
	})

	v, err := NewVerifier(jwt.SigningMethodES256, pub, WithRevoker(r))
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}

	_, err = v.Verify(context.Background(), signed)
	if !errors.Is(err, sentinel) {
		t.Errorf("want sentinel error in chain, got %v", err)
	}
	if !errors.Is(err, pkgerr.ErrCheck) {
		t.Errorf("want ErrCheck wrap, got %v", err)
	}
}

// TestVerifyWithRevokerNil ensures nil Revoker is rejected at construction.
func TestVerifyWithRevokerNil(t *testing.T) {
	t.Parallel()

	_, pub, _ := keys.GenerateECDSA(elliptic.P256())
	_, err := NewVerifier(jwt.SigningMethodES256, pub, WithRevoker(nil))
	if !errors.Is(err, pkgerr.ErrInvalidValue) {
		t.Errorf("want ErrInvalidValue got %v", err)
	}
}
