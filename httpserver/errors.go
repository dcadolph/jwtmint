package httpserver

import (
	"net/http"

	"github.com/dcadolph/jwtmint/internal/jsonutil"
)

// writeError writes an ErrorResponse with the given status, error code, and detail.
func writeError(w http.ResponseWriter, status int, code, detail string) {
	_ = jsonutil.Write(w, status, ErrorResponse{Error: code, Detail: detail})
}
