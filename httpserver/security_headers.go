package httpserver

import "net/http"

// withSecurityHeaders wraps next, attaching X-Content-Type-Options on every response
// and HSTS when the connection is HTTPS.
//
// Per-route headers (e.g. CORS on JWKS, Cache-Control) are still set by the underlying
// handlers; this adds the global ones expected of a credential-issuing service.
func withSecurityHeaders(tlsEnabled bool, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if tlsEnabled || r.TLS != nil {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		next.ServeHTTP(w, r)
	})
}

// withCORS adds permissive CORS headers for the wrapped handler.
//
// Used on /.well-known/jwks.json and /.well-known/openid-configuration so browsers can
// fetch the public-key set and OIDC metadata cross-origin. Other endpoints stay
// CORS-free; they require credentials and the broad read-only metadata is the only
// thing browsers should reach for here.
func withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Access-Control-Allow-Origin", "*")
		h.Set("Access-Control-Allow-Methods", "GET, OPTIONS")
		h.Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
		h.Set("Access-Control-Max-Age", "300")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}
