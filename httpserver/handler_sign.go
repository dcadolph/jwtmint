package httpserver

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"

	"github.com/dcadolph/jwtmint/claims"
	"github.com/dcadolph/jwtmint/internal/jsonutil"
	"github.com/dcadolph/jwtmint/signing"
)

// MaxSignBodyBytes caps the /sign request body. Tokens with megabytes of claims are
// almost always abuse; legitimate sign requests are well under 16 KiB.
const MaxSignBodyBytes = 64 * 1024

// handleSign returns a handler that signs the claims in the request body via the
// configured Signer (which applies the server's static headers and DefaultIssuer/
// DefaultExpiration).
//
// Panics on construction if signer is nil — caller should never wire that up.
func handleSign(signer signing.Signer, log *zap.Logger) http.HandlerFunc {

	if signer == nil {
		panic("handleSign: signer required")
	}

	return func(w http.ResponseWriter, r *http.Request) {

		body := http.MaxBytesReader(w, r.Body, MaxSignBodyBytes)

		var req SignRequest
		if err := json.NewDecoder(body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid_body", "could not decode request body")
			return
		}

		c := req.Claims
		if c == nil {
			c = jwt.MapClaims{}
		}

		// expires_in semantics: server overrides any caller exp with now+expiration when given.
		// Otherwise the configured Signer applies its WithDefaultExpiration.
		if req.ExpiresIn != "" {
			d, err := time.ParseDuration(req.ExpiresIn)
			if err != nil {
				writeError(w, http.StatusBadRequest, "invalid_expires_in", "expires_in must be a Go duration string")
				return
			}
			if d <= 0 {
				writeError(w, http.StatusBadRequest, "invalid_expires_in", "expires_in must be > 0")
				return
			}
			claims.SetExpiresAt(c, time.Now().Add(d))
		}

		token, parsed, err := signer.Sign(r.Context(), c, req.Headers)
		if err != nil {
			if errors.Is(err, signing.ErrReservedHeader) {
				writeError(w, http.StatusBadRequest, "reserved_header", err.Error())
				return
			}
			if log != nil {
				log.Debug("sign failed", zap.Error(err))
			}
			writeError(w, http.StatusInternalServerError, "sign_failed", "could not sign claims")
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
