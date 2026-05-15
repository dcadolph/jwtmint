package httpserver

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/dcadolph/jwtsmith/claims"
	"github.com/dcadolph/jwtsmith/internal/jsonutil"
	"github.com/dcadolph/jwtsmith/signing"
)

// handleSign returns a handler that signs the claims in the request body.
//
// Panics on construction if signer is nil — caller should never wire that up.
func handleSign(signer signing.Signer, cfg Config) http.HandlerFunc {

	if signer == nil {
		panic("handleSign: signer required")
	}

	return func(w http.ResponseWriter, r *http.Request) {

		var req SignRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid_body", err.Error())
			return
		}

		expiration := cfg.DefaultExpiration
		if req.ExpiresIn != "" {
			d, err := time.ParseDuration(req.ExpiresIn)
			if err != nil {
				writeError(w, http.StatusBadRequest, "invalid_expires_in", err.Error())
				return
			}
			if d <= 0 {
				writeError(w, http.StatusBadRequest, "invalid_expires_in", "must be > 0")
				return
			}
			expiration = d
		}

		c := req.Claims
		if c == nil {
			c = jwt.MapClaims{}
		}

		// expires_in semantics: server overrides any caller exp with now+expiration when expires_in given,
		// otherwise the signer applies its DefaultExpiration if exp is missing.
		if req.ExpiresIn != "" {
			claims.SetExpiresAt(c, time.Now().Add(expiration))
		}

		// Apply per-call headers atop server static headers (kid).
		token, parsed, err := signing.Signed(cfg.Method, cfg.PrivateKey, mergeHeaders(cfg, req.Headers), c)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "sign_failed", err.Error())
			return
		}

		mc, _ := claims.ToMapClaims(parsed.Claims)
		var expSeconds int64
		if exp, err := claims.ExpiresAt(mc); err == nil {
			expSeconds = exp.Unix()
		}

		_ = jsonutil.Write(w, http.StatusOK, SignResponse{Token: token, ExpiresAt: expSeconds})
	}
}

// mergeHeaders merges server static headers (kid) with per-request headers.
//
// Per-request headers win on collision except for "alg" and "typ", which are reserved.
func mergeHeaders(cfg Config, perCall map[string]any) map[string]any {
	out := map[string]any{}
	if cfg.Kid != "" {
		out["kid"] = cfg.Kid
	}
	for k, v := range perCall {
		out[k] = v
	}
	return out
}
