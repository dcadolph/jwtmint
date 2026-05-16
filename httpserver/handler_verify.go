package httpserver

import (
	"encoding/json"
	"net/http"

	"go.uber.org/zap"

	"github.com/dcadolph/jwtmint/claims"
	"github.com/dcadolph/jwtmint/internal/jsonutil"
	"github.com/dcadolph/jwtmint/verification"
)

// MaxVerifyBodyBytes caps the /verify request body.
const MaxVerifyBodyBytes = 64 * 1024

// handleVerify returns a handler that verifies the token in the request body and returns
// its parsed claims and header on success.
//
// Returns 200 in all cases (unless the request is malformed); the client inspects
// response.valid. /verify is a query endpoint, not an auth-protected one — 401 would
// be wrong because the caller is not asserting their own identity.
//
// Panics on construction if v is nil — caller should never wire that up.
func handleVerify(v verification.Verifier, log *zap.Logger) http.HandlerFunc {

	if v == nil {
		panic("handleVerify: verifier required")
	}

	return func(w http.ResponseWriter, r *http.Request) {

		body := http.MaxBytesReader(w, r.Body, MaxVerifyBodyBytes)

		var req VerifyRequest
		if err := json.NewDecoder(body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid_body", "could not decode request body")
			return
		}
		if req.Token == "" {
			writeError(w, http.StatusBadRequest, "missing_token", "token required")
			return
		}

		tok, err := v.Verify(r.Context(), req.Token)
		if err != nil {
			if log != nil {
				log.Debug("verify failed", zap.Error(err))
			}
			_ = jsonutil.Write(w, http.StatusOK, VerifyResponse{Valid: false})
			return
		}

		mc, err := claims.ToMapClaims(tok.Claims)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "claims_extract_failed", "could not extract claims")
			return
		}
		_ = jsonutil.Write(w, http.StatusOK, VerifyResponse{Valid: true, Claims: mc, Header: tok.Header})
	}
}
