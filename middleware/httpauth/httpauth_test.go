package httpauth

import (
	"context"
	"crypto/elliptic"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"

	"github.com/dcadolph/jwtmint/claims"
	"github.com/dcadolph/jwtmint/keys"
	"github.com/dcadolph/jwtmint/signing"
	"github.com/dcadolph/jwtmint/verification"
)

// TestMiddlewareRoundtrip covers happy path, missing token, bad token, and check failure.
func TestMiddlewareRoundtrip(t *testing.T) {
	t.Parallel()

	priv, pub, _ := keys.GenerateECDSA(elliptic.P256())
	signer, _ := signing.NewSigner(jwt.SigningMethodES256, priv, signing.WithDefaultIssuer("issuer-x"))
	signed, _, _ := signer.Sign(context.Background(), jwt.MapClaims{claims.KeySubject: "u1"}, nil)

	v, _ := verification.NewVerifier(jwt.SigningMethodES256, pub)

	tests := []struct {
		Name       string
		Authz      string
		Opts       []Opt
		WantStatus int
		WantInner  bool
	}{
		{Name: "happy", Authz: "Bearer " + signed, WantStatus: http.StatusOK, WantInner: true},
		{Name: "missing header", Authz: "", WantStatus: http.StatusUnauthorized},
		{Name: "wrong scheme", Authz: "Basic " + signed, WantStatus: http.StatusUnauthorized},
		{Name: "garbage token", Authz: "Bearer not.a.jwt", WantStatus: http.StatusUnauthorized},
		{
			Name:  "claims check fails",
			Authz: "Bearer " + signed,
			Opts: []Opt{
				WithClaimsCheck(claims.CheckIssuer("other-issuer")),
			},
			WantStatus: http.StatusForbidden,
		},
	}

	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d %s", testNum, test.Name), func(t *testing.T) {
			t.Parallel()

			var innerCalled bool
			inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				innerCalled = true
				if mc := ClaimsFromContext(r.Context()); mc != nil {
					if sub, _ := claims.Subject(mc); sub != "u1" {
						t.Errorf("subject in ctx: want u1 got %q", sub)
					}
				}
				w.WriteHeader(http.StatusOK)
			})

			handler := Middleware(v, test.Opts...)(inner)

			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if test.Authz != "" {
				req.Header.Set("Authorization", test.Authz)
			}
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != test.WantStatus {
				t.Errorf("status: want %d got %d body=%s", test.WantStatus, rec.Code, rec.Body.String())
			}
			if innerCalled != test.WantInner {
				t.Errorf("innerCalled: want %v got %v", test.WantInner, innerCalled)
			}
		})
	}
}

// TestCustomTokenSource confirms WithTokenSource is honored.
func TestCustomTokenSource(t *testing.T) {
	t.Parallel()

	priv, pub, _ := keys.GenerateECDSA(elliptic.P256())
	signer, _ := signing.NewSigner(jwt.SigningMethodES256, priv)
	signed, _, _ := signer.Sign(context.Background(), jwt.MapClaims{claims.KeySubject: "u1"}, nil)

	v, _ := verification.NewVerifier(jwt.SigningMethodES256, pub)

	src := func(r *http.Request) string {
		c, err := r.Cookie("session")
		if err != nil {
			return ""
		}
		return c.Value
	}

	called := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})
	handler := Middleware(v, WithTokenSource(src))(inner)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "session", Value: signed})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status: %d body=%s", rec.Code, rec.Body.String())
	}
	if !called {
		t.Error("inner handler not called")
	}
}

// TestCustomErrorHandler confirms WithErrorHandler is honored.
func TestCustomErrorHandler(t *testing.T) {
	t.Parallel()

	_, pub, _ := keys.GenerateECDSA(elliptic.P256())
	v, _ := verification.NewVerifier(jwt.SigningMethodES256, pub)

	handler := Middleware(v, WithErrorHandler(func(w http.ResponseWriter, _ *http.Request, _ error) {
		w.WriteHeader(http.StatusTeapot)
		_, _ = io.WriteString(w, "go away")
	}))(http.NotFoundHandler())

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusTeapot {
		t.Errorf("status: want 418 got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "go away") {
		t.Errorf("custom body missing: %s", rec.Body.String())
	}
}
