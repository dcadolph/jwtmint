// Package jsonutil centralizes JSON encoding for the jwtmint CLI and HTTP server.
//
// Compact by default; pass pretty=true to indent. HTML escaping is disabled because
// jwtmint's outputs (tokens, claims) commonly contain characters that should not be
// HTML-escaped when displayed or piped to other tools.
package jsonutil

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/dcadolph/jwtmint/pkgerr"
)

// Marshal encodes v as JSON. When pretty is true, output is indented two spaces.
func Marshal(v any, pretty bool) ([]byte, error) {

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if pretty {
		enc.SetIndent("", "  ")
	}
	if err := enc.Encode(v); err != nil {
		return nil, fmt.Errorf("%w: encoding json: %w", pkgerr.ErrEncode, err)
	}
	return buf.Bytes(), nil
}

// Write encodes v as JSON to w with the given HTTP status code and Content-Type: application/json.
//
// Errors writing the body are returned but the status header is already sent.
func Write(w http.ResponseWriter, status int, v any) error {

	body, err := Marshal(v, false)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusInternalServerError)
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if _, err := w.Write(body); err != nil {
		return fmt.Errorf("%w: writing response body: %w", pkgerr.ErrWrite, err)
	}
	return nil
}
