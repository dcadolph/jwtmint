package grpcauth

import (
	"context"
	"fmt"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	"github.com/dcadolph/jwtsmith/middleware/httpauth"
	"github.com/dcadolph/jwtsmith/pkgerr"
)

// UnaryClientInterceptor returns a gRPC unary client interceptor that attaches
// "authorization: Bearer <token>" metadata from src on every outbound call.
//
// Panics on construction if src is nil — required dependency.
func UnaryClientInterceptor(src httpauth.TokenSource) grpc.UnaryClientInterceptor {

	if src == nil {
		panic("grpcauth.UnaryClientInterceptor: TokenSource required")
	}

	return func(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		ctx, err := withBearer(ctx, src)
		if err != nil {
			return err
		}
		return invoker(ctx, method, req, reply, cc, opts...)
	}
}

// StreamClientInterceptor returns a gRPC stream client interceptor that attaches
// "authorization: Bearer <token>" metadata from src on every outbound stream.
//
// Panics on construction if src is nil — required dependency.
func StreamClientInterceptor(src httpauth.TokenSource) grpc.StreamClientInterceptor {

	if src == nil {
		panic("grpcauth.StreamClientInterceptor: TokenSource required")
	}

	return func(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, streamer grpc.Streamer, opts ...grpc.CallOption) (grpc.ClientStream, error) {
		ctx, err := withBearer(ctx, src)
		if err != nil {
			return nil, err
		}
		return streamer(ctx, desc, cc, method, opts...)
	}
}

// withBearer attaches a fresh bearer token from src to ctx as outgoing metadata.
func withBearer(ctx context.Context, src httpauth.TokenSource) (context.Context, error) {
	tok, err := src.Token()
	if err != nil {
		return ctx, fmt.Errorf("%w: fetching outbound token: %w", pkgerr.ErrRead, err)
	}
	return metadata.AppendToOutgoingContext(ctx, MetadataKeyAuthorization, "Bearer "+tok), nil
}
