package httpserver

import (
	"encoding/json"
	"net/http"

	"go.uber.org/zap"

	"github.com/dcadolph/jwtmint/claims"
	"github.com/dcadolph/jwtmint/internal/jsonutil"
	"github.com/dcadolph/jwtmint/refresh"
)

// MaxRefreshBodyBytes caps the /refresh request body.
const MaxRefreshBodyBytes = 64 * 1024

// handleRefresh returns a handler that rotates the token in the request body.
//
// Panics on construction if r is nil — caller should never wire that up.
func handleRefresh(r refresh.Refresher, log *zap.Logger) http.HandlerFunc {

	if r == nil {
		panic("handleRefresh: refresher required")
	}

	return func(w http.ResponseWriter, req *http.Request) {

		body := http.MaxBytesReader(w, req.Body, MaxRefreshBodyBytes)

		var in RefreshRequest
		if err := json.NewDecoder(body).Decode(&in); err != nil {
			writeError(w, http.StatusBadRequest, "invalid_body", "could not decode request body")
			return
		}
		if in.Token == "" {
			writeError(w, http.StatusBadRequest, "missing_token", "token required")
			return
		}

		tok, refreshed, err := r.Refresh(req.Context(), in.Token)
		if err != nil {
			if log != nil {
				log.Debug("refresh failed", zap.Error(err))
			}
			writeError(w, http.StatusBadRequest, "refresh_failed", "token could not be refreshed")
			return
		}

		mc, _ := claims.ToMapClaims(tok.Claims)
		var expSeconds int64
		if exp, err := claims.ExpiresAt(mc); err == nil {
			expSeconds = exp.Unix()
		}

		_ = jsonutil.Write(w, http.StatusOK, RefreshResponse{Token: refreshed, ExpiresAt: expSeconds})
	}
}
