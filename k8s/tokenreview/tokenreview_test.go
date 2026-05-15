package tokenreview

import (
	"context"
	"bytes"
	"crypto/elliptic"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	authnv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/dcadolph/jwtsmith/claims"
	"github.com/dcadolph/jwtsmith/keys"
	"github.com/dcadolph/jwtsmith/signing"
	"github.com/dcadolph/jwtsmith/verification"
)

// TestHandlerAuthenticated covers a token that should be accepted.
func TestHandlerAuthenticated(t *testing.T) {
	t.Parallel()

	priv, pub, _ := keys.GenerateECDSA(elliptic.P256())
	signer, _ := signing.NewSigner(jwt.SigningMethodES256, priv)
	signed, _, _ := signer.Sign(context.Background(), jwt.MapClaims{
		claims.KeySubject:  "user-1",
		claims.KeyID:       "jti-abc",
		claims.KeyGroups:   []string{"admins", "devs"},
		claims.KeyAudience: []string{"k8s"},
		"tenant":           "acme",
	}, nil)

	v, _ := verification.NewVerifier(jwt.SigningMethodES256, pub)
	h := Handler(v)

	body := mustJSON(t, authnv1.TokenReview{
		TypeMeta: metav1.TypeMeta{Kind: "TokenReview", APIVersion: "authentication.k8s.io/v1"},
		Spec:     authnv1.TokenReviewSpec{Token: signed},
	})
	req := httptest.NewRequest(http.MethodPost, "/k8s/token-review", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status: %d body=%s", rec.Code, rec.Body.String())
	}

	var resp authnv1.TokenReview
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v body=%s", err, rec.Body.String())
	}

	if !resp.Status.Authenticated {
		t.Errorf("Authenticated false, body=%s", rec.Body.String())
	}
	if resp.Status.User.Username != "user-1" {
		t.Errorf("Username: want user-1 got %q", resp.Status.User.Username)
	}
	if resp.Status.User.UID != "jti-abc" {
		t.Errorf("UID: want jti-abc got %q", resp.Status.User.UID)
	}
	if got := resp.Status.User.Groups; len(got) != 2 || got[0] != "admins" || got[1] != "devs" {
		t.Errorf("Groups: want [admins devs] got %v", got)
	}
	if resp.Spec.Token != "" {
		t.Errorf("response should not echo Spec.Token, got %q", resp.Spec.Token)
	}
	if got := resp.Status.User.Extra["claim_tenant"]; len(got) != 1 || got[0] != "acme" {
		t.Errorf("Extra[claim_tenant]: want [acme] got %v", got)
	}
}

// TestHandlerRejections covers various failure modes that should produce Authenticated=false.
func TestHandlerRejections(t *testing.T) {
	t.Parallel()

	priv, pub, _ := keys.GenerateECDSA(elliptic.P256())
	signer, _ := signing.NewSigner(jwt.SigningMethodES256, priv)
	good, _, _ := signer.Sign(context.Background(), jwt.MapClaims{claims.KeySubject: "u1"}, nil)
	noSub, _, _ := signer.Sign(context.Background(), jwt.MapClaims{}, nil)

	v, _ := verification.NewVerifier(jwt.SigningMethodES256, pub)

	tests := []struct {
		Name       string
		Body       any
		Handler    http.Handler
		WantStatus int
		WantAuth   bool
	}{
		{
			Name:       "bad signature",
			Body:       authnv1.TokenReview{Spec: authnv1.TokenReviewSpec{Token: "not.a.jwt"}},
			Handler:    Handler(v),
			WantStatus: http.StatusOK,
			WantAuth:   false,
		},
		{
			Name:       "missing token",
			Body:       authnv1.TokenReview{Spec: authnv1.TokenReviewSpec{Token: ""}},
			Handler:    Handler(v),
			WantStatus: http.StatusBadRequest,
			WantAuth:   false,
		},
		{
			Name:       "missing sub claim",
			Body:       authnv1.TokenReview{Spec: authnv1.TokenReviewSpec{Token: noSub}},
			Handler:    Handler(v),
			WantStatus: http.StatusInternalServerError,
			WantAuth:   false,
		},
		{
			Name:       "audience mismatch",
			Body:       authnv1.TokenReview{Spec: authnv1.TokenReviewSpec{Token: good}},
			Handler:    Handler(v, WithAudiences("api")),
			WantStatus: http.StatusOK,
			WantAuth:   false,
		},
	}

	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d %s", testNum, test.Name), func(t *testing.T) {
			t.Parallel()
			body := mustJSON(t, test.Body)
			req := httptest.NewRequest(http.MethodPost, "/k8s/token-review", bytes.NewReader(body))
			rec := httptest.NewRecorder()
			test.Handler.ServeHTTP(rec, req)

			if rec.Code != test.WantStatus {
				t.Fatalf("status: want %d got %d body=%s", test.WantStatus, rec.Code, rec.Body.String())
			}

			var resp authnv1.TokenReview
			if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
				t.Fatalf("decode: %v body=%s", err, rec.Body.String())
			}
			if resp.Status.Authenticated != test.WantAuth {
				t.Errorf("Authenticated: want %v got %v body=%s", test.WantAuth, resp.Status.Authenticated, rec.Body.String())
			}
		})
	}
}

// mustJSON marshals v to JSON or fails the test.
func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}
