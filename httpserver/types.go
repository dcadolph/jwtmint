package httpserver

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// SignRequest is the body for POST /sign.
type SignRequest struct {
	// Claims is the JWT payload. Server applies defaults for exp/iat/nbf/jti/iss when omitted.
	Claims jwt.MapClaims `json:"claims,omitempty"`
	// Headers are additional JWT headers. "alg" and "typ" are reserved.
	Headers map[string]any `json:"headers,omitempty"`
	// ExpiresIn overrides the server default token lifetime, parsed via time.ParseDuration.
	ExpiresIn string `json:"expires_in,omitempty"`
}

// SignResponse is the body for POST /sign.
type SignResponse struct {
	// Token is the signed JWT.
	Token string `json:"token"`
	// ExpiresAt is the unix-second expiration the server applied.
	ExpiresAt int64 `json:"expires_at,omitempty"`
}

// VerifyRequest is the body for POST /verify.
type VerifyRequest struct {
	// Token is the signed JWT to verify.
	Token string `json:"token"`
}

// VerifyResponse is the body for POST /verify.
type VerifyResponse struct {
	// Valid is true when the signature and registered claims pass.
	Valid bool `json:"valid"`
	// Claims are the parsed claims when Valid; empty otherwise.
	Claims jwt.MapClaims `json:"claims,omitempty"`
	// Header is the parsed JWT header when Valid; empty otherwise.
	Header map[string]any `json:"header,omitempty"`
}

// RefreshRequest is the body for POST /refresh.
type RefreshRequest struct {
	// Token is the signed JWT to refresh.
	Token string `json:"token"`
}

// RefreshResponse is the body for POST /refresh.
type RefreshResponse struct {
	// Token is the refreshed signed JWT.
	Token string `json:"token"`
	// ExpiresAt is the unix-second expiration of the refreshed token.
	ExpiresAt int64 `json:"expires_at,omitempty"`
}

// ErrorResponse is the body returned for non-2xx responses.
type ErrorResponse struct {
	// Error is a short machine-readable code.
	Error string `json:"error"`
	// Detail is a human-readable description suitable for logs.
	Detail string `json:"detail,omitempty"`
}

// HealthResponse is the body for GET /healthz.
type HealthResponse struct {
	// OK is true when the server is alive.
	OK bool `json:"ok"`
	// Now is the server's current time, useful for clock-skew debugging.
	Now time.Time `json:"now"`
}
