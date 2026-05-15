package httpserver

import (
	"net/http"

	"github.com/dcadolph/jwtsmith/internal/jsonutil"
	"github.com/dcadolph/jwtsmith/jwks"
)

// handleJWKS returns a handler that publishes the server's public key as an RFC 7517 JWKS.
//
// The returned handler closes over the pre-built JWKS and is safe for concurrent use.
func handleJWKS(set jwks.JWKS) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=300")
		_ = jsonutil.Write(w, http.StatusOK, set)
	}
}
