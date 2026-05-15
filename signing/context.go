package signing

import (
	"context"

	"github.com/golang-jwt/jwt/v5"
)

// ctxKey is unexported so callers can't collide with our context values.
type ctxKey int

const (
	ctxKeyHeaders ctxKey = iota
	ctxKeyClaims
)

// WrapContextHeaders returns a context carrying the given headers, retrievable via UnwrapContextHeaders.
func WrapContextHeaders(ctx context.Context, headers map[string]any) context.Context {
	return context.WithValue(ctx, ctxKeyHeaders, headers)
}

// UnwrapContextHeaders returns the headers wrapped via WrapContextHeaders, or nil if none present.
func UnwrapContextHeaders(ctx context.Context) map[string]any {
	v, _ := ctx.Value(ctxKeyHeaders).(map[string]any)
	return v
}

// WrapContextClaims returns a context carrying the given claims, retrievable via UnwrapContextClaims.
func WrapContextClaims(ctx context.Context, c jwt.MapClaims) context.Context {
	return context.WithValue(ctx, ctxKeyClaims, c)
}

// UnwrapContextClaims returns the claims wrapped via WrapContextClaims, or nil if none present.
func UnwrapContextClaims(ctx context.Context) jwt.MapClaims {
	v, _ := ctx.Value(ctxKeyClaims).(jwt.MapClaims)
	return v
}
