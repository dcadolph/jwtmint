package httpserver

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// Authenticator authorizes an inbound request, returning a non-nil error to reject it.
//
// Implementations should leave the response untouched on success and rely on requireAuth
// to write the rejection. The error's message is included in the response body, so it
// should be safe to expose.
type Authenticator interface {
	Authenticate(r *http.Request) error
}

// AuthenticatorFunc adapts a function to the Authenticator interface.
type AuthenticatorFunc func(r *http.Request) error

// Authenticate calls the receiver, implementing Authenticator.
func (f AuthenticatorFunc) Authenticate(r *http.Request) error { return f(r) }

// requireAuth wraps next, rejecting requests for which a is non-nil and Authenticate fails.
//
// A nil Authenticator means "no auth" — auth is opt-in via configuration.
func requireAuth(a Authenticator, next http.HandlerFunc) http.HandlerFunc {

	if a == nil {
		return next
	}

	return func(w http.ResponseWriter, r *http.Request) {
		if err := a.Authenticate(r); err != nil {
			w.Header().Set("WWW-Authenticate", `Bearer realm="jwtmintd"`)
			writeError(w, http.StatusUnauthorized, "unauthorized", err.Error())
			return
		}
		next(w, r)
	}
}

// StaticBearerAuthenticator returns an Authenticator that accepts requests carrying
// "Authorization: Bearer <expected>". Comparison is constant-time.
func StaticBearerAuthenticator(expected string) Authenticator {

	if expected == "" {
		return nil
	}

	return AuthenticatorFunc(func(r *http.Request) error {
		authz := r.Header.Get("Authorization")
		got := strings.TrimPrefix(authz, "Bearer ")
		if got == authz || subtle.ConstantTimeCompare([]byte(got), []byte(expected)) != 1 {
			return errors.New("valid bearer token required")
		}
		return nil
	})
}

// extractBearer returns the token portion of "Authorization: Bearer <token>", or "" if absent.
func extractBearer(r *http.Request) (string, error) {
	authz := r.Header.Get("Authorization")
	if authz == "" {
		return "", fmt.Errorf("missing Authorization header")
	}
	const prefix = "Bearer "
	if !strings.HasPrefix(authz, prefix) {
		return "", fmt.Errorf("Authorization is not a Bearer token")
	}
	tok := strings.TrimSpace(strings.TrimPrefix(authz, prefix))
	if tok == "" {
		return "", fmt.Errorf("empty bearer token")
	}
	return tok, nil
}
