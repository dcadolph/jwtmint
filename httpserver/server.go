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
	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"

	"github.com/dcadolph/jwtsmith/jwks"
	"github.com/dcadolph/jwtsmith/k8s/tokenreview"
	"github.com/dcadolph/jwtsmith/keys"
	"github.com/dcadolph/jwtsmith/pkgerr"
	"github.com/dcadolph/jwtsmith/refresh"
	"github.com/dcadolph/jwtsmith/revocation"
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
	//
	// Mutually exclusive with Authenticator. Provided for ergonomic single-token setups.
	AuthToken string `json:"-"`

	// Authenticator authorizes /sign and /refresh requests. When set, AuthToken is ignored.
	//
	// Use to plug in alternate auth schemes (e.g. Kubernetes ServiceAccount token review).
	Authenticator Authenticator

	// RefreshMaxAge bounds how old (by original iat) a refreshable token can be.
	//
	// nil falls back to the refresh package default (24h). A non-nil pointer is honored
	// verbatim; in particular, &zero disables the cap entirely. Use the pointer form so
	// "disable" is distinguishable from "use default".
	RefreshMaxAge *time.Duration

	// RefreshClaimsResolver, when set, is called during refresh to rewrite or reject claims.
	// See refresh.ClaimsResolver. Use to drop revoked groups, deny refresh for deprovisioned
	// users, look up the latest entitlements, etc.
	RefreshClaimsResolver refresh.ClaimsResolver

	// Revoker, when set, is consulted on every /verify (and /k8s/token-review when enabled)
	// after signature and registered-claims validation succeed. Verify rejects revoked tokens
	// with pkgerr.ErrRevoked.
	//
	// Use revocation.NewMemRevoker for single-replica deployments; implement revocation.Revoker
	// against your shared store (Redis, etcd, database) for multi-replica fleets.
	Revoker revocation.Revoker

	// AdditionalKeys are verify-only keys published in JWKS alongside the primary signing key.
	//
	// Use during key rotation: rotate by adding the new keypair as primary and demoting the
	// previous keypair to AdditionalKeys until all tokens signed under it have expired.
	// Each entry needs a distinct Kid distinct from the primary's; tokens are dispatched to
	// the matching key by kid header.
	AdditionalKeys []verification.KeyEntry

	// EnableTokenReview opts into the /k8s/token-review endpoint that implements the
	// Kubernetes TokenReview webhook protocol. Off by default.
	EnableTokenReview bool

	// Issuer is the URL clients should use as the OIDC issuer for this jwtsmithd instance.
	// Used to populate /.well-known/openid-configuration. Should be the publicly-reachable
	// scheme://host[:port] of this server (no trailing slash). Optional; when empty the
	// discovery endpoint is not served.
	Issuer string

	// CertFile and KeyFile, when both are set, switch the server to HTTPS via http.ServeTLS.
	// Either both or neither must be set.
	CertFile string
	KeyFile  string

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
	metrics *metrics
	reg     *prometheus.Registry
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
	if (cfg.CertFile == "") != (cfg.KeyFile == "") {
		return nil, fmt.Errorf("%w: CertFile and KeyFile must be set together", pkgerr.ErrInvalidValue)
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

	v, err := buildVerifier(cfg)
	if err != nil {
		return nil, err
	}

	refresherOpts := []refresh.Opt{}
	if cfg.DefaultExpiration > 0 {
		refresherOpts = append(refresherOpts, refresh.WithDefaultExpiration(cfg.DefaultExpiration))
	}
	if cfg.RefreshMaxAge != nil {
		refresherOpts = append(refresherOpts, refresh.WithMaxAge(*cfg.RefreshMaxAge))
	}
	if cfg.RefreshClaimsResolver != nil {
		refresherOpts = append(refresherOpts, refresh.WithClaimsResolver(cfg.RefreshClaimsResolver))
	}
	r, err := refresh.NewRefresher(cfg.Method, cfg.PublicKey, cfg.PrivateKey, refresherOpts...)
	if err != nil {
		return nil, err
	}

	jwksSet, err := buildJWKS(cfg)
	if err != nil {
		return nil, err
	}

	reg := prometheus.NewRegistry()

	srv := &Server{
		cfg:     cfg,
		signer:  s,
		verify:  v,
		refresh: r,
		jwksSet: jwksSet,
		reg:     reg,
		metrics: newMetrics(reg),
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
	mux.Handle("GET /.well-known/jwks.json", withCORS(http.HandlerFunc(handleJWKS(s.jwksSet))))
	mux.Handle("OPTIONS /.well-known/jwks.json", withCORS(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})))
	mux.HandleFunc("POST /verify", handleVerify(s.verify, s.cfg.Logger))
	auth := s.authenticator()
	mux.HandleFunc("POST /sign", requireAuth(auth, handleSign(s.signer, s.cfg.Logger)))
	mux.HandleFunc("POST /refresh", requireAuth(auth, handleRefresh(s.refresh, s.cfg.Logger)))

	if s.cfg.EnableTokenReview {
		mux.Handle("POST /k8s/token-review", tokenreview.Handler(s.verify))
	}

	if s.cfg.Issuer != "" {
		mux.Handle("GET /.well-known/openid-configuration", withCORS(http.HandlerFunc(handleOIDCDiscovery(s.cfg.Issuer, s.supportedAlgs()))))
		mux.Handle("OPTIONS /.well-known/openid-configuration", withCORS(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})))
	}

	mux.Handle("GET /metrics", metricsHandler(s.reg))

	tlsEnabled := s.cfg.CertFile != ""
	return logRequests(s.cfg.Logger, instrument(s.metrics, withSecurityHeaders(tlsEnabled, mux)))
}

// authenticator returns the Authenticator to use for mutating endpoints.
//
// Config.Authenticator wins when set; otherwise Config.AuthToken builds a static
// bearer authenticator; otherwise nil (no auth).
func (s *Server) authenticator() Authenticator {
	if s.cfg.Authenticator != nil {
		return s.cfg.Authenticator
	}
	return StaticBearerAuthenticator(s.cfg.AuthToken)
}

// supportedAlgs returns the distinct alg strings the JWKS includes.
func (s *Server) supportedAlgs() []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, 1+len(s.cfg.AdditionalKeys))
	add := func(alg string) {
		if alg == "" {
			return
		}
		if _, ok := seen[alg]; ok {
			return
		}
		seen[alg] = struct{}{}
		out = append(out, alg)
	}
	add(s.cfg.Method.Alg())
	for _, e := range s.cfg.AdditionalKeys {
		add(e.Method.Alg())
	}
	return out
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
		zap.Bool("tls", s.cfg.CertFile != ""),
		zap.Int("additional_keys", len(s.cfg.AdditionalKeys)),
	)

	errCh := make(chan error, 1)
	go func() {
		var err error
		if s.cfg.CertFile != "" {
			err = s.srv.ServeTLS(ln, s.cfg.CertFile, s.cfg.KeyFile)
		} else {
			err = s.srv.Serve(ln)
		}
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
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
