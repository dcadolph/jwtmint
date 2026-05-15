package signing

import (
	"context"
	"crypto/elliptic"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/dcadolph/jwtsmith/claims"
	"github.com/dcadolph/jwtsmith/keys"
	"github.com/dcadolph/jwtsmith/pkgerr"
)

// TestSigningMethod covers the supported algorithms and the rejected ones.
func TestSigningMethod(t *testing.T) {
	t.Parallel()

	tests := []struct {
		Want    error
		Alg     string
		WantNil bool
	}{
		{Alg: "ES256"},
		{Alg: "ES384"},
		{Alg: "ES512"},
		{Alg: "RS256"},
		{Alg: "RS384"},
		{Alg: "RS512"},
		{Alg: "PS256"},
		{Alg: "PS384"},
		{Alg: "PS512"},
		{Alg: "EdDSA"},
		{Alg: "HS256", Want: pkgerr.ErrInvalidMethod, WantNil: true},
		{Alg: "HS384", Want: pkgerr.ErrInvalidMethod, WantNil: true},
		{Alg: "HS512", Want: pkgerr.ErrInvalidMethod, WantNil: true},
		{Alg: "", Want: pkgerr.ErrInvalidMethod, WantNil: true},
		{Alg: "bogus", Want: pkgerr.ErrInvalidMethod, WantNil: true},
	}

	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d %s", testNum, test.Alg), func(t *testing.T) {
			t.Parallel()
			m, err := SigningMethod(test.Alg)
			if !errors.Is(err, test.Want) {
				t.Fatalf("test %d: error mismatch\nwant: %v\ngot:  %v", testNum, test.Want, err)
			}
			if test.WantNil && m != nil {
				t.Errorf("test %d: want nil method, got %v", testNum, m)
			}
		})
	}
}

// TestSignerRoundtripPerAlgorithm signs a token per algorithm and parses it back.
func TestSignerRoundtripPerAlgorithm(t *testing.T) {
	t.Parallel()

	ecPriv, ecPub, _ := keys.GenerateECDSA(elliptic.P256())
	rsaPriv, rsaPub, _ := keys.GenerateRSA(2048)
	edPriv, edPub, _ := keys.GenerateEd25519()

	tests := []struct {
		Method  jwt.SigningMethod
		Priv    any
		Pub     any
		Name    string
	}{
		{Name: "ES256", Method: jwt.SigningMethodES256, Priv: ecPriv, Pub: ecPub},
		{Name: "RS256", Method: jwt.SigningMethodRS256, Priv: rsaPriv, Pub: rsaPub},
		{Name: "PS256", Method: jwt.SigningMethodPS256, Priv: rsaPriv, Pub: rsaPub},
		{Name: "EdDSA", Method: jwt.SigningMethodEdDSA, Priv: edPriv, Pub: edPub},
	}

	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d %s", testNum, test.Name), func(t *testing.T) {
			t.Parallel()
			s, err := NewSigner(test.Method, test.Priv)
			if err != nil {
				t.Fatalf("NewSigner: %v", err)
			}
			signed, _, err := s.Sign(context.Background(), jwt.MapClaims{claims.KeySubject: "user-1"}, nil)
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}
			if signed == "" {
				t.Fatal("signed string empty")
			}
			keyFunc, err := keys.PublicKeyFunc(test.Method, test.Pub)
			if err != nil {
				t.Fatalf("PublicKeyFunc: %v", err)
			}
			parser := jwt.NewParser(jwt.WithValidMethods([]string{test.Method.Alg()}))
			parsed, err := parser.Parse(signed, keyFunc)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if !parsed.Valid {
				t.Error("parsed token not Valid")
			}
		})
	}
}

// TestSignDefaults covers default exp/iat/nbf/jti/iss application.
func TestSignDefaults(t *testing.T) {
	t.Parallel()

	priv, _, _ := keys.GenerateECDSA(elliptic.P256())
	s, err := NewSigner(jwt.SigningMethodES256, priv)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}

	_, tok, err := s.Sign(context.Background(), nil, nil)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	mc, err := claims.ToMapClaims(tok.Claims)
	if err != nil {
		t.Fatalf("ToMapClaims: %v", err)
	}
	if _, err := claims.ID(mc); err != nil {
		t.Errorf("default jti not set: %v", err)
	}
	iss, err := claims.Issuer(mc)
	if err != nil {
		t.Fatalf("Issuer: %v", err)
	}
	if iss != DefaultIssuer {
		t.Errorf("default iss: want %q got %q", DefaultIssuer, iss)
	}
	if _, err := claims.ExpiresAt(mc); err != nil {
		t.Errorf("default exp not set: %v", err)
	}
	if _, err := claims.IssuedAt(mc); err != nil {
		t.Errorf("default iat not set: %v", err)
	}
	if _, err := claims.NotBefore(mc); err != nil {
		t.Errorf("default nbf not set: %v", err)
	}
}

// TestSignRejectsPastExp covers the past-exp guard.
func TestSignRejectsPastExp(t *testing.T) {
	t.Parallel()

	priv, _, _ := keys.GenerateECDSA(elliptic.P256())
	s, _ := NewSigner(jwt.SigningMethodES256, priv)

	c := jwt.MapClaims{}
	claims.SetExpiresAt(c, time.Now().Add(-time.Hour))
	_, _, err := s.Sign(context.Background(), c, nil)
	if !errors.Is(err, pkgerr.ErrExpired) {
		t.Errorf("want ErrExpired, got %v", err)
	}
}

// TestNewSignerWrongKeyType ensures key/method mismatches are caught at construction.
func TestNewSignerWrongKeyType(t *testing.T) {
	t.Parallel()

	rsaPriv, _, _ := keys.GenerateRSA(2048)
	_, err := NewSigner(jwt.SigningMethodES256, rsaPriv)
	if !errors.Is(err, pkgerr.ErrInvalidType) {
		t.Errorf("want ErrInvalidType, got %v", err)
	}
}

// TestStaticHeadersAndClaims ensures static fields apply on every Sign.
func TestStaticHeadersAndClaims(t *testing.T) {
	t.Parallel()

	priv, _, _ := keys.GenerateECDSA(elliptic.P256())
	s, err := NewSigner(
		jwt.SigningMethodES256,
		priv,
		WithStaticHeaders(map[string]any{"kid": "k1"}),
		WithStaticClaims(jwt.MapClaims{"tenant": "t1"}),
		WithDefaultIssuer("static-issuer"),
	)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}

	_, tok, err := s.Sign(context.Background(), jwt.MapClaims{"sub": "u1"}, nil)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if tok.Header["kid"] != "k1" {
		t.Errorf("static header kid: want k1 got %v", tok.Header["kid"])
	}
	mc, _ := claims.ToMapClaims(tok.Claims)
	if mc["tenant"] != "t1" {
		t.Errorf("static claim tenant: want t1 got %v", mc["tenant"])
	}
	if mc[claims.KeySubject] != "u1" {
		t.Errorf("per-call sub overridden: got %v", mc[claims.KeySubject])
	}
	if iss, _ := claims.Issuer(mc); iss != "static-issuer" {
		t.Errorf("default iss override: want static-issuer got %q", iss)
	}
}
