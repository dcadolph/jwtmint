// jwtmintd is the jwtmint HTTP daemon.
//
// Exposes /sign, /verify, /refresh, /.well-known/jwks.json, and /healthz so non-Go
// services can issue and verify tokens through a single endpoint.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/dcadolph/jwtmint/cmd/jwtmintd/internal/cli"
	"github.com/dcadolph/jwtmint/httpserver"
	"github.com/dcadolph/jwtmint/httpserver/k8sauth"
	"github.com/dcadolph/jwtmint/keys"
	"github.com/dcadolph/jwtmint/signing"
	"github.com/dcadolph/jwtmint/verification"
)

// main parses flags, builds the server, and runs it until SIGINT or SIGTERM.
func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "jwtmintd: %s\n", err)
		os.Exit(1)
	}
}

// run encapsulates the full daemon lifecycle so test code can drive it.
func run() error {

	cfg, err := cli.Parse(flag.CommandLine, os.Args[1:])
	if err != nil {
		return err
	}

	log, err := newLogger(cfg.LogLevel)
	if err != nil {
		return err
	}
	defer func() { _ = log.Sync() }()

	method, err := signing.SigningMethod(cfg.Method)
	if err != nil {
		return err
	}

	privBytes, err := keys.ReadPEMFile(cfg.PrivPath)
	if err != nil {
		return err
	}
	pubBytes, err := keys.ReadPEMFile(cfg.PubPath)
	if err != nil {
		return err
	}

	priv, pub, err := loadKeyPairForMethod(cfg.Method, privBytes, pubBytes)
	if err != nil {
		return err
	}

	additional, err := loadAdditionalKeys(cfg.Method, method, cfg.AdditionalKeys)
	if err != nil {
		return err
	}

	authn, authToken, err := buildAuthenticator(cfg)
	if err != nil {
		return err
	}

	srv, err := httpserver.New(httpserver.Config{
		Logger:            log,
		Method:            method,
		PrivateKey:        priv,
		PublicKey:         pub,
		Kid:               cfg.Kid,
		AdditionalKeys:    additional,
		DefaultIssuer:     cfg.DefaultIssuer,
		DefaultExpiration: cfg.DefaultExpiration,
		AuthToken:         authToken,
		Authenticator:     authn,
		EnableTokenReview: cfg.EnableTokenReview,
		Issuer:            cfg.Issuer,
		CertFile:          cfg.CertFile,
		KeyFile:           cfg.KeyFile,
		Addr:              cfg.Addr,
		ReadTimeout:       cfg.ReadTimeout,
		WriteTimeout:      cfg.WriteTimeout,
		ShutdownTimeout:   cfg.ShutdownTimeout,
	})
	if err != nil {
		return err
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	return srv.Run(ctx)
}

// buildAuthenticator returns the configured Authenticator and the static AuthToken (if any).
//
// Static auth: returns (nil, cfg.AuthToken) so httpserver builds a StaticBearerAuthenticator.
// SA auth:     returns (k8sauth.New..., "") so httpserver uses the k8s authenticator.
// None:        returns (nil, "") for no auth.
func buildAuthenticator(cfg cli.Config) (httpserver.Authenticator, string, error) {
	switch cfg.AuthMode {
	case "", "static":
		return nil, cfg.AuthToken, nil
	case "none":
		return nil, "", nil
	case "sa":
		opts := []k8sauth.Opt{}
		if len(cfg.AllowedSAs) > 0 {
			opts = append(opts, k8sauth.WithAllowedSAs(cfg.AllowedSAs...))
		}
		if len(cfg.AuthAudiences) > 0 {
			opts = append(opts, k8sauth.WithAudiences(cfg.AuthAudiences...))
		}
		a, err := k8sauth.NewInCluster(opts...)
		if err != nil {
			return nil, "", fmt.Errorf("auth-mode=sa: %w", err)
		}
		return a, "", nil
	default:
		return nil, "", fmt.Errorf("unknown auth-mode %q", cfg.AuthMode)
	}
}

// loadAdditionalKeys reads each "kid=path" entry into a verification.KeyEntry tagged with method.
func loadAdditionalKeys(methodName string, method jwt.SigningMethod, entries []cli.KeyEntry) ([]verification.KeyEntry, error) {

	if len(entries) == 0 {
		return nil, nil
	}

	out := make([]verification.KeyEntry, 0, len(entries))
	for _, e := range entries {
		pemBytes, err := keys.ReadPEMFile(e.Path)
		if err != nil {
			return nil, fmt.Errorf("--additional-key %s: %w", e.Kid, err)
		}
		pub, err := loadPublicForMethod(methodName, pemBytes)
		if err != nil {
			return nil, fmt.Errorf("--additional-key %s: %w", e.Kid, err)
		}
		out = append(out, verification.KeyEntry{Kid: e.Kid, Method: method, PublicKey: pub})
	}
	return out, nil
}

// loadPublicForMethod parses pubPEM into the right Go public key type for the method family.
func loadPublicForMethod(methodName string, pubPEM []byte) (any, error) {
	switch methodName {
	case "ES256", "ES384", "ES512":
		return keys.LoadECDSAPublicFromPEM(pubPEM)
	case "RS256", "RS384", "RS512", "PS256", "PS384", "PS512":
		return keys.LoadRSAPublicFromPEM(pubPEM)
	case "EdDSA":
		return keys.LoadEd25519PublicFromPEM(pubPEM)
	default:
		return nil, fmt.Errorf("unsupported method %q", methodName)
	}
}

// loadKeyPairForMethod parses the PEM bytes into the right Go key types for method.
func loadKeyPairForMethod(method string, privPEM, pubPEM []byte) (priv, pub any, err error) {

	switch method {
	case "ES256", "ES384", "ES512":
		p, err := keys.LoadECDSAPrivateFromPEM(privPEM)
		if err != nil {
			return nil, nil, err
		}
		q, err := keys.LoadECDSAPublicFromPEM(pubPEM)
		return p, q, err
	case "RS256", "RS384", "RS512", "PS256", "PS384", "PS512":
		p, err := keys.LoadRSAPrivateFromPEM(privPEM)
		if err != nil {
			return nil, nil, err
		}
		q, err := keys.LoadRSAPublicFromPEM(pubPEM)
		return p, q, err
	case "EdDSA":
		p, err := keys.LoadEd25519PrivateFromPEM(privPEM)
		if err != nil {
			return nil, nil, err
		}
		q, err := keys.LoadEd25519PublicFromPEM(pubPEM)
		return p, q, err
	default:
		return nil, nil, fmt.Errorf("unsupported method %q", method)
	}
}

// newLogger returns a zap.Logger configured for stderr at the given level.
func newLogger(level string) (*zap.Logger, error) {

	cfg := zap.NewProductionConfig()
	cfg.OutputPaths = []string{"stderr"}
	cfg.ErrorOutputPaths = []string{"stderr"}
	cfg.EncoderConfig.TimeKey = "ts"
	cfg.EncoderConfig.EncodeTime = zapcore.RFC3339NanoTimeEncoder

	if level != "" {
		var lvl zap.AtomicLevel
		if err := lvl.UnmarshalText([]byte(level)); err != nil {
			return nil, fmt.Errorf("invalid log level %q: %w", level, err)
		}
		cfg.Level = lvl
	}
	return cfg.Build()
}
