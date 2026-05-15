package grpcauth

import (
	"context"
	"crypto/elliptic"
	"errors"
	"fmt"
	"net"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/reflection"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	healthsvc "google.golang.org/grpc/health"
	"google.golang.org/grpc/status"

	"github.com/dcadolph/jwtsmith/claims"
	"github.com/dcadolph/jwtsmith/keys"
	"github.com/dcadolph/jwtsmith/signing"
	"github.com/dcadolph/jwtsmith/verification"
)

// TestUnaryInterceptor exercises the interceptor against a real gRPC health server.
//
// Uses the standard grpc/health/grpc_health_v1 service so we don't have to vendor
// proto definitions for tests.
func TestUnaryInterceptor(t *testing.T) {
	t.Parallel()

	priv, pub, _ := keys.GenerateECDSA(elliptic.P256())
	signer, _ := signing.NewSigner(jwt.SigningMethodES256, priv, signing.WithDefaultIssuer("issuer-x"))
	signed, _, _ := signer.Sign(context.Background(), jwt.MapClaims{claims.KeySubject: "u1"}, nil)

	v, _ := verification.NewVerifier(jwt.SigningMethodES256, pub)

	srv := grpc.NewServer(grpc.UnaryInterceptor(UnaryServerInterceptor(v)))
	healthpb.RegisterHealthServer(srv, healthsvc.NewServer())
	reflection.Register(srv)

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)

	conn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	client := healthpb.NewHealthClient(conn)

	tests := []struct {
		Name     string
		MD       metadata.MD
		WantCode codes.Code
	}{
		{Name: "valid bearer", MD: metadata.Pairs("authorization", "Bearer "+signed), WantCode: codes.OK},
		{Name: "missing metadata", MD: metadata.MD{}, WantCode: codes.Unauthenticated},
		{Name: "wrong scheme", MD: metadata.Pairs("authorization", "Basic "+signed), WantCode: codes.Unauthenticated},
		{Name: "garbage token", MD: metadata.Pairs("authorization", "Bearer not.a.jwt"), WantCode: codes.Unauthenticated},
	}

	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d %s", testNum, test.Name), func(t *testing.T) {
			t.Parallel()
			ctx := metadata.NewOutgoingContext(context.Background(), test.MD)
			_, err := client.Check(ctx, &healthpb.HealthCheckRequest{})
			got := status.Code(err)
			if got != test.WantCode {
				t.Errorf("code: want %s got %s err=%v", test.WantCode, got, err)
			}
		})
	}
}

// TestUnaryInterceptorClaimsCheck confirms claim policy failures map to PermissionDenied.
func TestUnaryInterceptorClaimsCheck(t *testing.T) {
	t.Parallel()

	priv, pub, _ := keys.GenerateECDSA(elliptic.P256())
	signer, _ := signing.NewSigner(jwt.SigningMethodES256, priv, signing.WithDefaultIssuer("good"))
	signed, _, _ := signer.Sign(context.Background(), jwt.MapClaims{}, nil)

	v, _ := verification.NewVerifier(jwt.SigningMethodES256, pub)

	srv := grpc.NewServer(grpc.UnaryInterceptor(
		UnaryServerInterceptor(v, WithClaimsCheck(claims.CheckIssuer("nope"))),
	))
	healthpb.RegisterHealthServer(srv, healthsvc.NewServer())

	lis, _ := net.Listen("tcp", "127.0.0.1:0")
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)

	conn, _ := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	t.Cleanup(func() { _ = conn.Close() })
	client := healthpb.NewHealthClient(conn)

	ctx := metadata.NewOutgoingContext(context.Background(), metadata.Pairs("authorization", "Bearer "+signed))
	_, err := client.Check(ctx, &healthpb.HealthCheckRequest{})
	if status.Code(err) != codes.PermissionDenied {
		t.Errorf("want PermissionDenied, got %v", err)
	}
	if errors.Is(err, context.Canceled) {
		t.Error("expected gRPC status error, got ctx error")
	}
}
