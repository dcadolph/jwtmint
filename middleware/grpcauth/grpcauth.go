// Package grpcauth provides gRPC interceptors that verify JWTs in request metadata.
//
// Tokens are read from the "authorization" metadata key with a "Bearer " prefix.
// On success, verified claims and the parsed token are attached to the per-call
// context, retrievable via ClaimsFromContext and TokenFromContext.
package grpcauth

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/dcadolph/jwtmint/claims"
	"github.com/dcadolph/jwtmint/pkgerr"
	"github.com/dcadolph/jwtmint/verification"
)

// MetadataKeyAuthorization is the metadata key inspected for the bearer token.
//
// gRPC metadata keys are case-insensitive on the wire and lower-cased by the framework
// when read back, so we use the canonical lower-case form here.
const MetadataKeyAuthorization = "authorization"

// SchemeBearer is the auth scheme prefix expected before the token.
const SchemeBearer = "Bearer"

// ctxKey is unexported so callers can't collide with our context values.
type ctxKey int

const (
	ctxKeyClaims ctxKey = iota
	ctxKeyToken
)

// Opt configures the interceptors.
type Opt func(*config)

type config struct {
	extra        []verification.TokenCheckFunc
	claimsChecks []claims.CheckFunc
}

// WithCheck adds a TokenCheckFunc that runs after signature verification.
func WithCheck(checks ...verification.TokenCheckFunc) Opt {
	return func(c *config) { c.extra = append(c.extra, checks...) }
}

// WithClaimsCheck adds a claims.CheckFunc that runs after signature verification.
func WithClaimsCheck(checks ...claims.CheckFunc) Opt {
	return func(c *config) { c.claimsChecks = append(c.claimsChecks, checks...) }
}

// UnaryServerInterceptor returns a gRPC unary interceptor that verifies the bearer token.
//
// Panics on construction if v is nil — required dependency.
func UnaryServerInterceptor(v verification.Verifier, opts ...Opt) grpc.UnaryServerInterceptor {

	if v == nil {
		panic("grpcauth.UnaryServerInterceptor: verifier required")
	}
	cfg := buildConfig(opts...)

	return func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		newCtx, err := authorize(ctx, v, &cfg)
		if err != nil {
			return nil, err
		}
		return handler(newCtx, req)
	}
}

// StreamServerInterceptor returns a gRPC stream interceptor that verifies the bearer token.
//
// Panics on construction if v is nil — required dependency.
func StreamServerInterceptor(v verification.Verifier, opts ...Opt) grpc.StreamServerInterceptor {

	if v == nil {
		panic("grpcauth.StreamServerInterceptor: verifier required")
	}
	cfg := buildConfig(opts...)

	return func(srv any, ss grpc.ServerStream, _ *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		newCtx, err := authorize(ss.Context(), v, &cfg)
		if err != nil {
			return err
		}
		wrapped := &serverStreamWithCtx{ServerStream: ss, ctx: newCtx}
		return handler(srv, wrapped)
	}
}

// buildConfig folds opts into a config and merges claim checks into the token-check chain.
func buildConfig(opts ...Opt) config {
	cfg := config{}
	for _, opt := range opts {
		opt(&cfg)
	}
	if len(cfg.claimsChecks) > 0 {
		cfg.extra = append(cfg.extra, verification.CheckClaims(cfg.claimsChecks...))
	}
	return cfg
}

// authorize extracts the bearer token from incoming gRPC metadata, verifies it, and
// returns a new context with the verified claims and token attached.
func authorize(ctx context.Context, v verification.Verifier, cfg *config) (context.Context, error) {

	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "missing metadata")
	}
	values := md.Get(MetadataKeyAuthorization)
	if len(values) == 0 {
		return nil, status.Error(codes.Unauthenticated, "missing authorization metadata")
	}

	token := bearerToken(values[0])
	if token == "" {
		return nil, status.Errorf(codes.Unauthenticated, "%s", fmt.Errorf("%w: malformed bearer header", pkgerr.ErrInvalidValue))
	}

	tok, err := v.Verify(ctx, token, cfg.extra...)
	if err != nil {
		// Distinguish auth failure (Unauthenticated) from policy failure (PermissionDenied).
		code := codes.Unauthenticated
		if isCheckFailure(err) {
			code = codes.PermissionDenied
		}
		return nil, status.Errorf(code, "verify failed: %s", err)
	}

	mc, _ := claims.ToMapClaims(tok.Claims)
	ctx = context.WithValue(ctx, ctxKeyToken, tok)
	ctx = context.WithValue(ctx, ctxKeyClaims, mc)
	return ctx, nil
}

// bearerToken extracts the token portion of a "Bearer <token>" header value.
func bearerToken(authz string) string {
	prefix := SchemeBearer + " "
	if !strings.HasPrefix(authz, prefix) {
		return ""
	}
	return strings.TrimSpace(strings.TrimPrefix(authz, prefix))
}

// isCheckFailure reports whether err wraps pkgerr.ErrCheck (a configured TokenCheckFunc rejected the token).
func isCheckFailure(err error) bool { return errors.Is(err, pkgerr.ErrCheck) }

// serverStreamWithCtx wraps grpc.ServerStream to expose a modified context.
type serverStreamWithCtx struct {
	grpc.ServerStream
	ctx context.Context
}

// Context returns the wrapped context with verified claims attached.
func (s *serverStreamWithCtx) Context() context.Context { return s.ctx }

// ClaimsFromContext returns the verified claims attached by an interceptor, or nil if absent.
func ClaimsFromContext(ctx context.Context) jwt.MapClaims {
	v, _ := ctx.Value(ctxKeyClaims).(jwt.MapClaims)
	return v
}

// TokenFromContext returns the verified *jwt.Token attached by an interceptor, or nil if absent.
func TokenFromContext(ctx context.Context) *jwt.Token {
	v, _ := ctx.Value(ctxKeyToken).(*jwt.Token)
	return v
}
