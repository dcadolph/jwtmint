package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/spf13/cobra"

	"github.com/dcadolph/jwtmint/claims"
	"github.com/dcadolph/jwtmint/signing"
)

// signFlags holds every flag for the sign command. Grouped here so other helpers
// (like buildClaims) can be unit-tested without a *cobra.Command.
type signFlags struct {
	method      string
	privPath    string
	expiration  time.Duration
	claimsFile  string
	claimsJSON  string
	claimKV     []string
	headerKV    []string
	subject     string
	issuer      string
	audience    []string
	groups      []string
	roles       []string
	entitlements []string
	permissions []string
	scope       []string
	email       string
	name        string
	username    string
	tokenType   string
	jti         string
	notBefore   string
}

// newSignCmd builds the "sign" subcommand for issuing JWTs.
//
// Claim sources are merged in this order (later wins): static profile flags
// (--subject, --issuer, --audience, --groups, ...), --claims-file, --claims-json,
// then individual --claim key=value pairs. Headers are similarly merged from --header.
func newSignCmd() *cobra.Command {

	f := &signFlags{}

	c := &cobra.Command{
		Use:   "sign",
		Short: "Sign a JWT with the given private key. Outputs the signed token to stdout.",
		RunE: func(_ *cobra.Command, _ []string) error {
			return runSign(f)
		},
	}

	c.Flags().StringVar(&f.method, "method", "ES256", "Signing method (ES256, ES384, ES512, RS256, RS384, RS512, PS256, PS384, PS512, EdDSA).")
	c.Flags().StringVar(&f.privPath, "priv", "", "Path to PEM-encoded private key. Required.")
	c.Flags().DurationVar(&f.expiration, "expires", time.Hour, "Token lifetime (e.g. 1h, 30m, 24h).")

	c.Flags().StringVar(&f.claimsFile, "claims-file", "", "Path to JSON file with claims to merge.")
	c.Flags().StringVar(&f.claimsJSON, "claims-json", "", "JSON string of claims to merge.")
	c.Flags().StringArrayVar(&f.claimKV, "claim", nil, "Add a claim as key=value (repeatable). Value is treated as string.")
	c.Flags().StringArrayVar(&f.headerKV, "header", nil, "Add a header as key=value (repeatable). 'alg' and 'typ' are reserved.")

	c.Flags().StringVar(&f.subject, "subject", "", "Subject claim (sub).")
	c.Flags().StringVar(&f.issuer, "issuer", "", "Issuer claim (iss).")
	c.Flags().StringSliceVar(&f.audience, "audience", nil, "Audience claim (aud), repeatable or comma-separated.")
	c.Flags().StringSliceVar(&f.groups, "groups", nil, "Groups claim, repeatable or comma-separated.")
	c.Flags().StringSliceVar(&f.roles, "roles", nil, "Roles claim, repeatable or comma-separated.")
	c.Flags().StringSliceVar(&f.entitlements, "entitlements", nil, "Entitlements claim, repeatable or comma-separated.")
	c.Flags().StringSliceVar(&f.permissions, "permissions", nil, "Permissions claim, repeatable or comma-separated.")
	c.Flags().StringSliceVar(&f.scope, "scope", nil, "OAuth2 scope (joined with spaces), repeatable or comma-separated.")
	c.Flags().StringVar(&f.email, "email", "", "Email claim.")
	c.Flags().StringVar(&f.name, "name", "", "Name claim.")
	c.Flags().StringVar(&f.username, "username", "", "Username claim.")
	c.Flags().StringVar(&f.tokenType, "token-type", "", "Token type claim (token_type).")
	c.Flags().StringVar(&f.jti, "jti", "", "Token ID (jti). Random UUID if omitted.")
	c.Flags().StringVar(&f.notBefore, "not-before", "", "Not-before time as RFC3339 (default: now).")

	_ = c.MarkFlagRequired("priv")

	return c
}

// runSign loads the private key, builds the claim set, signs, and writes the token to stdout.
func runSign(f *signFlags) error {

	method, err := signing.SigningMethod(f.method)
	if err != nil {
		return err
	}
	priv, err := loadPrivateKeyForMethod(method, f.privPath)
	if err != nil {
		return err
	}

	mc, err := buildClaims(f)
	if err != nil {
		return err
	}

	headers, err := parseKVPairs(f.headerKV)
	if err != nil {
		return fmt.Errorf("%w: parsing --header: %w", ErrUsage, err)
	}

	signed, _, err := signing.SignedWithExpiration(f.expiration, method, priv, headers, mc)
	if err != nil {
		return err
	}
	fmt.Fprintln(cobraStdout(), signed)
	return nil
}

// buildClaims merges every claim source per the order documented on newSignCmd.
func buildClaims(f *signFlags) (jwt.MapClaims, error) {

	mc := jwt.MapClaims{}

	if f.subject != "" {
		claims.SetSubject(mc, f.subject)
	}
	if f.issuer != "" {
		claims.SetIssuer(mc, f.issuer)
	}
	if a := trimAll(f.audience); len(a) > 0 {
		claims.SetAudience(mc, a...)
	}
	if g := trimAll(f.groups); len(g) > 0 {
		claims.SetGroups(mc, g...)
	}
	if r := trimAll(f.roles); len(r) > 0 {
		claims.SetRoles(mc, r...)
	}
	if e := trimAll(f.entitlements); len(e) > 0 {
		claims.SetEntitlements(mc, e...)
	}
	if p := trimAll(f.permissions); len(p) > 0 {
		claims.SetPermissions(mc, p...)
	}
	if s := trimAll(f.scope); len(s) > 0 {
		claims.SetScope(mc, s...)
	}
	if f.email != "" {
		claims.SetEmail(mc, f.email)
	}
	if f.name != "" {
		claims.SetName(mc, f.name)
	}
	if f.username != "" {
		claims.SetUsername(mc, f.username)
	}
	if f.tokenType != "" {
		claims.SetTokenType(mc, f.tokenType)
	}
	if f.jti != "" {
		claims.SetID(mc, f.jti)
	}
	if f.notBefore != "" {
		t, err := time.Parse(time.RFC3339, f.notBefore)
		if err != nil {
			return nil, fmt.Errorf("%w: --not-before must be RFC3339: %w", ErrUsage, err)
		}
		claims.SetNotBefore(mc, t)
	}

	if f.claimsFile != "" {
		body, err := os.ReadFile(f.claimsFile)
		if err != nil {
			return nil, fmt.Errorf("reading --claims-file: %w", err)
		}
		if err := mergeJSON(mc, body); err != nil {
			return nil, fmt.Errorf("--claims-file: %w", err)
		}
	}

	if f.claimsJSON != "" {
		if err := mergeJSON(mc, []byte(f.claimsJSON)); err != nil {
			return nil, fmt.Errorf("--claims-json: %w", err)
		}
	}

	for _, kv := range f.claimKV {
		k, v, ok := strings.Cut(kv, "=")
		if !ok || k == "" {
			return nil, fmt.Errorf("%w: --claim must be key=value, got %q", ErrUsage, kv)
		}
		mc[k] = v
	}

	return mc, nil
}

// mergeJSON unmarshals body into a map and copies its entries into dst.
func mergeJSON(dst jwt.MapClaims, body []byte) error {
	parsed := map[string]any{}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return fmt.Errorf("unmarshal: %w", err)
	}
	for k, v := range parsed {
		dst[k] = v
	}
	return nil
}

// parseKVPairs converts ["a=b", "c=d"] to {"a":"b", "c":"d"}, rejecting malformed entries.
func parseKVPairs(pairs []string) (map[string]any, error) {
	if len(pairs) == 0 {
		return nil, nil
	}
	out := make(map[string]any, len(pairs))
	for _, kv := range pairs {
		k, v, ok := strings.Cut(kv, "=")
		if !ok || k == "" {
			return nil, fmt.Errorf("entry must be key=value, got %q", kv)
		}
		out[k] = v
	}
	return out, nil
}
