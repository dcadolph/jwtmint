// Package httpserver exposes jwtsmith's library primitives as HTTP endpoints.
//
// Endpoints:
//   POST /sign                      sign a JWT with the server's private key
//   POST /verify                    verify a JWT with the server's public key
//   POST /refresh                   rotate a JWT, preserving its lifetime window
//   GET  /.well-known/jwks.json     publish the public key as a JWKS
//   GET  /healthz                   liveness probe
//
// Mutating endpoints (/sign and /refresh) require a bearer token when Config.AuthToken
// is set; verify and JWKS are public.
package httpserver

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"

	"github.com/dcadolph/jwtsmith/jwks"
	"github.com/dcadolph/jwtsmith/keys"
	"github.com/dcadolph/jwtsmith/pkgerr"
	"github.com/dcadolph/jwtsmith/refresh"
	"github.com/dcadolph/jwtsmith/signing"
	"github.com/dcadolph/jwtsmith/verification"
)

// Config holds everything needed to run the server.
//
// Method, PrivateKey, and PublicKey are required. Other fields have sensible defaults;
// see field comments. AuthToken protects /sign and /refresh — leave empty only when the
// server runs in a trusted network where any caller is allowed to mint tokens.
type Config struct {
	// Logger receives request logs and errors. Required.
	Logger *zap.Logger
	// Method is the JWT signing method (e.g. jwt.SigningMethodES256). Required.
	Method jwt.SigningMethod
	// PrivateKey signs new tokens. Type must match Method (e.g. *ecdsa.PrivateKey for ES*).
	PrivateKey any
	// PublicKey verifies tokens and is published via JWKS. Must pair with PrivateKey.
	PublicKey any

	// Kid is the key id published in JWKS and embedded as a token header. Optional.
	Kid string
	// DefaultIssuer is set as "iss" when /sign callers omit it.
	DefaultIssuer string
	// DefaultExpiration is the lifetime applied when /sign callers omit expires_in.
	DefaultExpiration time.Duration
	// AuthToken, when non-empty, must appear as "Authorization: Bearer <token>" on /sign and /refresh.
	AuthToken string `json:"-"`

	// Addr is the listen address (host:port). Defaults to ":8080".
	Addr string
	// ReadTimeout caps how long the server waits to receive a request. Defaults to 10s.
	ReadTimeout time.Duration
	// WriteTimeout caps how long the server takes to write a response. Defaults to 10s.
	WriteTimeout time.Duration
	// ShutdownTimeout caps graceful shutdown wait. Defaults to 15s.
	ShutdownTimeout time.Duration
}

// Server wraps an http.Server with the jwtsmith handler set.
type Server struct {
	cfg     Config
	signer  signing.Signer
	verify  verification.Verifier
	refresh refresh.Refresher
	jwksSet jwks.JWKS
	srv     *http.Server
}

// New constructs a Server from cfg, validating the keypair and pre-building the
// signer, verifier, refresher, and JWKS that handlers will reuse.
func New(cfg Config) (*Server, error) {

	if cfg.Logger == nil {
		return nil, fmt.Errorf("%w: Logger required", pkgerr.ErrInvalidValue)
	}
	if cfg.Method == nil {
		return nil, fmt.Errorf("%w: Method required", pkgerr.ErrInvalidValue)
	}
	if cfg.PrivateKey == nil {
		return nil, fmt.Errorf("%w: PrivateKey required", pkgerr.ErrInvalidValue)
	}
	if cfg.PublicKey == nil {
		return nil, fmt.Errorf("%w: PublicKey required", pkgerr.ErrInvalidValue)
	}
	if err := keys.ValidatePair(cfg.PublicKey, cfg.PrivateKey); err != nil {
		return nil, err
	}

	cfg = cfg.withDefaults()

	signerOpts := []signing.Opt{}
	if cfg.DefaultIssuer != "" {
		signerOpts = append(signerOpts, signing.WithDefaultIssuer(cfg.DefaultIssuer))
	}
	if cfg.DefaultExpiration > 0 {
		signerOpts = append(signerOpts, signing.WithDefaultExpiration(cfg.DefaultExpiration))
	}
	if cfg.Kid != "" {
		signerOpts = append(signerOpts, signing.WithStaticHeaders(map[string]any{"kid": cfg.Kid}))
	}

	s, err := signing.NewSigner(cfg.Method, cfg.PrivateKey, signerOpts...)
	if err != nil {
		return nil, err
	}

	v, err := verification.NewVerifier(cfg.Method, cfg.PublicKey)
	if err != nil {
		return nil, err
	}

	r, err := refresh.New(cfg.Method, cfg.PublicKey, cfg.PrivateKey, cfg.DefaultExpiration)
	if err != nil {
		return nil, err
	}

	jwk, err := jwks.JWKFromPublicKey(cfg.PublicKey, cfg.Kid)
	if err != nil {
		return nil, err
	}
	jwk.Alg = cfg.Method.Alg()

	srv := &Server{
		cfg:     cfg,
		signer:  s,
		verify:  v,
		refresh: r,
		jwksSet: jwks.JWKS{Keys: []jwks.JWK{jwk}},
	}
	srv.srv = &http.Server{
		Addr:         cfg.Addr,
		Handler:      srv.routes(),
		ReadTimeout:  cfg.ReadTimeout,
		WriteTimeout: cfg.WriteTimeout,
	}
	return srv, nil
}

// withDefaults fills in zero-value fields with their default values.
func (c Config) withDefaults() Config {
	if c.Addr == "" {
		c.Addr = ":8080"
	}
	if c.ReadTimeout == 0 {
		c.ReadTimeout = 10 * time.Second
	}
	if c.WriteTimeout == 0 {
		c.WriteTimeout = 10 * time.Second
	}
	if c.ShutdownTimeout == 0 {
		c.ShutdownTimeout = 15 * time.Second
	}
	if c.DefaultExpiration == 0 {
		c.DefaultExpiration = time.Hour
	}
	return c
}

// routes returns the http.Handler with all jwtsmith endpoints registered.
//
// Uses Go 1.22+ method-aware routing.
func (s *Server) routes() http.Handler {

	mux := http.NewServeMux()

	mux.HandleFunc("GET /healthz", handleHealth())
	mux.HandleFunc("GET /.well-known/jwks.json", handleJWKS(s.jwksSet))
	mux.HandleFunc("POST /verify", handleVerify(s.verify, s.cfg.Logger))
	mux.HandleFunc("POST /sign", requireAuth(s.cfg.AuthToken, handleSign(s.signer, s.cfg)))
	mux.HandleFunc("POST /refresh", requireAuth(s.cfg.AuthToken, handleRefresh(s.refresh)))

	return logRequests(s.cfg.Logger, mux)
}

// Run starts the server and blocks until ctx is canceled, then shuts down gracefully.
func (s *Server) Run(ctx context.Context) error {

	ln, err := net.Listen("tcp", s.cfg.Addr)
	if err != nil {
		return fmt.Errorf("%w: listening on %s: %w", pkgerr.ErrInvalidValue, s.cfg.Addr, err)
	}
	s.cfg.Logger.Info("jwtsmithd listening",
		zap.String("addr", ln.Addr().String()),
		zap.String("alg", s.cfg.Method.Alg()),
		zap.String("kid", s.cfg.Kid),
	)

	errCh := make(chan error, 1)
	go func() {
		if err := s.srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
			return
		}
		errCh <- nil
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), s.cfg.ShutdownTimeout)
		defer cancel()
		s.cfg.Logger.Info("jwtsmithd shutting down")
		if err := s.srv.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("shutdown: %w", err)
		}
		return nil
	case err := <-errCh:
		return err
	}
}

// Addr returns the configured listen address.
func (s *Server) Addr() string { return s.cfg.Addr }
