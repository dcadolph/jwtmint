package httpserver

import (
	"crypto/subtle"
	"net/http"
	"strings"
)

// requireAuth wraps next in a bearer-token check. When expectedToken is empty, the
// returned handler is the unwrapped next — auth is opt-in via configuration.
//
// Comparison is constant-time to mitigate token leakage via response timing.
func requireAuth(expectedToken string, next http.HandlerFunc) http.HandlerFunc {

	if expectedToken == "" {
		return next
	}

	return func(w http.ResponseWriter, r *http.Request) {
		authz := r.Header.Get("Authorization")
		got := strings.TrimPrefix(authz, "Bearer ")
		if got == authz || subtle.ConstantTimeCompare([]byte(got), []byte(expectedToken)) != 1 {
			w.Header().Set("WWW-Authenticate", `Bearer realm="jwtsmithd"`)
			writeError(w, http.StatusUnauthorized, "unauthorized", "valid bearer token required")
			return
		}
		next(w, r)
	}
}
