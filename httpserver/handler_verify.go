package httpserver

import (
	"encoding/json"
	"net/http"

	"go.uber.org/zap"

	"github.com/dcadolph/jwtsmith/claims"
	"github.com/dcadolph/jwtsmith/internal/jsonutil"
	"github.com/dcadolph/jwtsmith/verification"
)

// handleVerify returns a handler that verifies the token in the request body and returns
// its parsed claims and header on success.
//
// Panics on construction if v is nil — caller should never wire that up.
func handleVerify(v verification.Verifier, log *zap.Logger) http.HandlerFunc {

	if v == nil {
		panic("handleVerify: verifier required")
	}

	return func(w http.ResponseWriter, r *http.Request) {

		var req VerifyRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid_body", err.Error())
			return
		}
		if req.Token == "" {
			writeError(w, http.StatusBadRequest, "missing_token", "token required")
			return
		}

		tok, err := v.Verify(req.Token)
		if err != nil {
			if log != nil {
				log.Debug("verify failed", zap.Error(err))
			}
			_ = jsonutil.Write(w, http.StatusUnauthorized, VerifyResponse{Valid: false})
			return
		}

		mc, err := claims.ToMapClaims(tok.Claims)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "claims_extract_failed", err.Error())
			return
		}
		_ = jsonutil.Write(w, http.StatusOK, VerifyResponse{Valid: true, Claims: mc, Header: tok.Header})
	}
}
