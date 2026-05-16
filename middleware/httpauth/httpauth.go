// Package httpauth wraps net/http handlers with JWT bearer-token authentication.
//
// Use Middleware when you control the *http.ServeMux; use HandlerFunc when you only
// need to wrap a single handler. On success, verified claims and the parsed token are
// available via ClaimsFromContext and TokenFromContext.
package httpauth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"

	"github.com/dcadolph/jwtmint/claims"
	"github.com/dcadolph/jwtmint/pkgerr"
	"github.com/dcadolph/jwtmint/verification"
)

// HeaderAuthorization is the header inspected for the bearer token.
const HeaderAuthorization = "Authorization"

// SchemeBearer is the auth scheme prefix expected before the token.
const SchemeBearer = "Bearer"

// ctxKey is unexported so callers can't collide with our context values.
type ctxKey int

const (
	ctxKeyClaims ctxKey = iota
	ctxKeyToken
)

// ErrorHandler responds to authentication failures. Implement to customize the error
// response; the default writes a JSON body and the appropriate status.
type ErrorHandler func(w http.ResponseWriter, r *http.Request, err error)

// Opt configures a Middleware.
type Opt func(*config)

type config struct {
	extra        []verification.TokenCheckFunc
	claimsChecks []claims.CheckFunc
	errorHandler ErrorHandler
	tokenSource  func(*http.Request) string
}

// WithCheck adds a TokenCheckFunc that runs after signature verification.
func WithCheck(checks ...verification.TokenCheckFunc) Opt {
	return func(c *config) { c.extra = append(c.extra, checks...) }
}

// WithClaimsCheck adds a claims.CheckFunc that runs after signature verification.
func WithClaimsCheck(checks ...claims.CheckFunc) Opt {
	return func(c *config) { c.claimsChecks = append(c.claimsChecks, checks...) }
}

// WithErrorHandler overrides the default ErrorHandler.
func WithErrorHandler(h ErrorHandler) Opt {
	return func(c *config) {
		if h != nil {
			c.errorHandler = h
		}
	}
}

// WithTokenSource overrides how the bearer token is extracted from the request.
//
// Default: the value after "Bearer " in the Authorization header.
func WithTokenSource(f func(*http.Request) string) Opt {
	return func(c *config) {
		if f != nil {
			c.tokenSource = f
		}
	}
}

// Middleware returns an http middleware that verifies the bearer token on every request,
// rejecting unauthorized requests via the configured ErrorHandler.
//
// Panics on construction if v is nil — required dependency.
func Middleware(v verification.Verifier, opts ...Opt) func(http.Handler) http.Handler {

	if v == nil {
		panic("httpauth.Middleware: verifier required")
	}

	cfg := config{
		errorHandler: defaultErrorHandler,
		tokenSource:  defaultTokenSource,
	}
	for _, opt := range opts {
		opt(&cfg)
	}
	if len(cfg.claimsChecks) > 0 {
		cfg.extra = append(cfg.extra, verification.CheckClaims(cfg.claimsChecks...))
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tok, err := authorize(v, &cfg, r)
			if err != nil {
				cfg.errorHandler(w, r, err)
				return
			}
			ctx := context.WithValue(r.Context(), ctxKeyToken, tok)
			mc, _ := claims.ToMapClaims(tok.Claims)
			ctx = context.WithValue(ctx, ctxKeyClaims, mc)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// HandlerFunc wraps next with JWT bearer authentication, returning a new http.HandlerFunc.
func HandlerFunc(v verification.Verifier, next http.HandlerFunc, opts ...Opt) http.HandlerFunc {
	mw := Middleware(v, opts...)
	wrapped := mw(next)
	return func(w http.ResponseWriter, r *http.Request) { wrapped.ServeHTTP(w, r) }
}

// authorize extracts the token, verifies it, and runs configured checks.
func authorize(v verification.Verifier, cfg *config, r *http.Request) (*jwt.Token, error) {

	token := cfg.tokenSource(r)
	if token == "" {
		return nil, fmt.Errorf("%w: missing bearer token", pkgerr.ErrInvalidValue)
	}
	tok, err := v.Verify(r.Context(), token, cfg.extra...)
	if err != nil {
		return nil, err
	}
	return tok, nil
}

// defaultTokenSource extracts the bearer token from the Authorization header.
func defaultTokenSource(r *http.Request) string {
	authz := r.Header.Get(HeaderAuthorization)
	if authz == "" {
		return ""
	}
	prefix := SchemeBearer + " "
	if !strings.HasPrefix(authz, prefix) {
		return ""
	}
	return strings.TrimSpace(strings.TrimPrefix(authz, prefix))
}

// defaultErrorHandler writes a small JSON body with the appropriate status code.
//
// Distinguishes between missing-token (401) and check-failure (403) where possible.
func defaultErrorHandler(w http.ResponseWriter, _ *http.Request, err error) {
	status := http.StatusUnauthorized
	switch {
	case errors.Is(err, pkgerr.ErrCheck):
		status = http.StatusForbidden
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("WWW-Authenticate", `Bearer realm="jwtmint"`)
	w.WriteHeader(status)
	fmt.Fprintf(w, `{"error":"unauthorized","detail":%q}`, err.Error())
}

// ClaimsFromContext returns the verified claims attached by Middleware, or nil if absent.
func ClaimsFromContext(ctx context.Context) jwt.MapClaims {
	v, _ := ctx.Value(ctxKeyClaims).(jwt.MapClaims)
	return v
}

// TokenFromContext returns the verified *jwt.Token attached by Middleware, or nil if absent.
func TokenFromContext(ctx context.Context) *jwt.Token {
	v, _ := ctx.Value(ctxKeyToken).(*jwt.Token)
	return v
}
