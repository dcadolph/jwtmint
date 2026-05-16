package httpserver

import (
	"net/http"
	"time"

	"github.com/dcadolph/jwtmint/internal/jsonutil"
)

// handleHealth returns a liveness handler that always reports OK with the current server time.
func handleHealth() http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		_ = jsonutil.Write(w, http.StatusOK, HealthResponse{OK: true, Now: time.Now().UTC()})
	}
}
