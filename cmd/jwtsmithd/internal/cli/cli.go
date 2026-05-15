// Package cli parses command-line flags for jwtsmithd.
//
// Kept in an internal package so the daemon's flag surface can evolve without affecting
// importers of the httpserver package.
package cli

import (
	"flag"
	"fmt"
	"strings"
	"time"

	"github.com/dcadolph/jwtsmith/cmd/config"
)

// Config is the parsed daemon configuration.
type Config struct {
	// Addr is the listen address (host:port).
	Addr string
	// Method is the JWT signing method (ES256, RS256, EdDSA, ...).
	Method string
	// PrivPath is the path to the private key PEM.
	PrivPath string
	// PubPath is the path to the public key PEM.
	PubPath string
	// Kid is the key ID embedded in tokens and published in JWKS.
	Kid string
	// AdditionalKeys are additional verification-only public keys, one per "kid=path" entry.
	// Method matches the primary --method.
	AdditionalKeys []KeyEntry
	// DefaultIssuer is set as "iss" when /sign callers omit it.
	DefaultIssuer string
	// DefaultExpiration is the lifetime applied when /sign callers omit expires_in.
	DefaultExpiration time.Duration
	// AuthMode selects the authenticator for /sign and /refresh: "static" (default), "sa", or "none".
	AuthMode string
	// AuthToken is the static bearer token used when AuthMode == "static". Empty disables static auth.
	AuthToken string
	// AllowedSAs restricts SA auth (AuthMode=="sa") to these ServiceAccount usernames.
	// Format: "system:serviceaccount:<namespace>:<name>". Empty allows any authenticated SA token.
	AllowedSAs []string
	// AuthAudiences are required audiences for SA tokens (passed to TokenReview). Optional.
	AuthAudiences []string
	// EnableTokenReview opts into the /k8s/token-review endpoint.
	EnableTokenReview bool
	// Issuer is the publicly-reachable scheme://host[:port] of this server. Required for OIDC discovery.
	Issuer string
	// CertFile is the path to a TLS cert. When set with KeyFile, the server runs HTTPS.
	CertFile string
	// KeyFile is the path to the TLS private key matching CertFile.
	KeyFile string
	// LogLevel sets the zap level: debug, info, warn, error. Defaults to info.
	LogLevel string

	// ReadTimeout caps inbound request read time.
	ReadTimeout time.Duration
	// WriteTimeout caps response write time.
	WriteTimeout time.Duration
	// ShutdownTimeout caps graceful shutdown wait.
	ShutdownTimeout time.Duration
}

// KeyEntry is a parsed --additional-key flag value: kid plus path to the PEM public key.
type KeyEntry struct {
	// Kid is the key id matched against incoming tokens' kid header.
	Kid string
	// Path is the filesystem path to the PEM-encoded public key.
	Path string
}

// additionalKeyFlag implements flag.Value for repeatable --additional-key flags.
type additionalKeyFlag struct {
	dst *[]KeyEntry
}

// String renders the captured entries.
func (a *additionalKeyFlag) String() string {
	if a == nil || a.dst == nil {
		return ""
	}
	parts := make([]string, len(*a.dst))
	for i, e := range *a.dst {
		parts[i] = e.Kid + "=" + e.Path
	}
	return strings.Join(parts, ",")
}

// Set parses one --additional-key value of the form "kid=/path/to/pub.pem".
func (a *additionalKeyFlag) Set(s string) error {
	kid, path, ok := strings.Cut(s, "=")
	if !ok || kid == "" || path == "" {
		return fmt.Errorf("--additional-key must be kid=path, got %q", s)
	}
	*a.dst = append(*a.dst, KeyEntry{Kid: kid, Path: path})
	return nil
}

// stringSliceFlag implements flag.Value for repeatable string flags.
type stringSliceFlag struct {
	dst *[]string
}

// String renders the captured strings.
func (s *stringSliceFlag) String() string {
	if s == nil || s.dst == nil {
		return ""
	}
	return strings.Join(*s.dst, ",")
}

// Set appends the value.
func (s *stringSliceFlag) Set(v string) error {
	*s.dst = append(*s.dst, v)
	return nil
}

// Parse applies the daemon's flags to fs and parses args, returning the resolved Config.
//
// Each scalar flag falls back to a JWTSMITH_* environment variable; see config.EnvKey.
func Parse(fs *flag.FlagSet, args []string) (Config, error) {

	var c Config
	fs.StringVar(&c.Addr, "addr", "", "Listen address (default :8080).")
	fs.StringVar(&c.Method, "method", "", "Signing method: ES256/384/512, RS256/384/512, PS256/384/512, EdDSA. Required.")
	fs.StringVar(&c.PrivPath, "priv", "", "Path to private key PEM. Required.")
	fs.StringVar(&c.PubPath, "pub", "", "Path to public key PEM. Required.")
	fs.StringVar(&c.Kid, "kid", "", "Key ID published in JWKS and embedded as token header. Required when --additional-key is set.")
	fs.Var(&additionalKeyFlag{dst: &c.AdditionalKeys}, "additional-key", "Verify-only public key as kid=/path/to/pub.pem. Repeatable. Used for key rotation overlap.")
	fs.StringVar(&c.DefaultIssuer, "default-issuer", "", "Default value for the iss claim.")
	fs.DurationVar(&c.DefaultExpiration, "default-expires", 0, "Default token lifetime when expires_in is omitted (default 1h).")
	fs.StringVar(&c.AuthMode, "auth-mode", "", "Authenticator for /sign and /refresh: static, sa, none. Defaults to static.")
	fs.StringVar(&c.AuthToken, "auth-token", "", "Static bearer token (auth-mode=static). Empty disables static auth.")
	fs.Var(&stringSliceFlag{dst: &c.AllowedSAs}, "allowed-sa", "Allowed SA username for auth-mode=sa, e.g. system:serviceaccount:default:my-app. Repeatable.")
	fs.Var(&stringSliceFlag{dst: &c.AuthAudiences}, "auth-audience", "Required audience on caller SA tokens (auth-mode=sa). Repeatable.")
	fs.BoolVar(&c.EnableTokenReview, "enable-token-review", false, "Expose /k8s/token-review (Kubernetes TokenReview webhook). Off by default.")
	fs.StringVar(&c.Issuer, "issuer", "", "Publicly reachable scheme://host[:port] of this server. When set, exposes /.well-known/openid-configuration.")
	fs.StringVar(&c.CertFile, "cert", "", "Path to TLS certificate. Required with --key for HTTPS.")
	fs.StringVar(&c.KeyFile, "key", "", "Path to TLS private key. Required with --cert for HTTPS.")
	fs.StringVar(&c.LogLevel, "log-level", "", "zap log level: debug, info, warn, error.")
	fs.DurationVar(&c.ReadTimeout, "read-timeout", 0, "HTTP read timeout (default 10s).")
	fs.DurationVar(&c.WriteTimeout, "write-timeout", 0, "HTTP write timeout (default 10s).")
	fs.DurationVar(&c.ShutdownTimeout, "shutdown-timeout", 0, "Graceful shutdown timeout (default 15s).")

	if err := fs.Parse(args); err != nil {
		return Config{}, err
	}

	c.Addr = config.String("addr", c.Addr, ":8080")
	c.Method = config.String("method", c.Method, "")
	c.PrivPath = config.String("priv", c.PrivPath, "")
	c.PubPath = config.String("pub", c.PubPath, "")
	c.Kid = config.String("kid", c.Kid, "")
	c.DefaultIssuer = config.String("default-issuer", c.DefaultIssuer, "")
	c.AuthMode = config.String("auth-mode", c.AuthMode, "static")
	c.AuthToken = config.String("auth-token", c.AuthToken, "")
	c.Issuer = config.String("issuer", c.Issuer, "")
	c.CertFile = config.String("cert", c.CertFile, "")
	c.KeyFile = config.String("key", c.KeyFile, "")
	c.LogLevel = config.String("log-level", c.LogLevel, "info")

	d, err := config.Duration("default-expires", c.DefaultExpiration, time.Hour)
	if err != nil {
		return Config{}, err
	}
	c.DefaultExpiration = d

	if c.Method == "" {
		return Config{}, fmt.Errorf("--method is required (or env JWTSMITH_METHOD)")
	}
	if c.PrivPath == "" {
		return Config{}, fmt.Errorf("--priv is required (or env JWTSMITH_PRIV)")
	}
	if c.PubPath == "" {
		return Config{}, fmt.Errorf("--pub is required (or env JWTSMITH_PUB)")
	}
	if (c.CertFile == "") != (c.KeyFile == "") {
		return Config{}, fmt.Errorf("--cert and --key must be set together")
	}

	switch c.AuthMode {
	case "", "static", "sa", "none":
	default:
		return Config{}, fmt.Errorf("--auth-mode must be one of: static, sa, none (got %q)", c.AuthMode)
	}

	return c, nil
}
