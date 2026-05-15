package httpserver

import (
	"encoding/json"
	"net/http"

	"github.com/dcadolph/jwtsmith/claims"
	"github.com/dcadolph/jwtsmith/internal/jsonutil"
	"github.com/dcadolph/jwtsmith/refresh"
)

// handleRefresh returns a handler that rotates the token in the request body.
//
// Panics on construction if r is nil — caller should never wire that up.
func handleRefresh(r refresh.Refresher) http.HandlerFunc {

	if r == nil {
		panic("handleRefresh: refresher required")
	}

	return func(w http.ResponseWriter, req *http.Request) {

		var body RefreshRequest
		if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
			writeError(w, http.StatusBadRequest, "invalid_body", err.Error())
			return
		}
		if body.Token == "" {
			writeError(w, http.StatusBadRequest, "missing_token", "token required")
			return
		}

		tok, refreshed, err := r.Refresh(body.Token)
		if err != nil {
			writeError(w, http.StatusBadRequest, "refresh_failed", err.Error())
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
