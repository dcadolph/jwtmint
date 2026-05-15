package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"github.com/spf13/cobra"

	"github.com/dcadolph/jwtsmith/claims"
	"github.com/dcadolph/jwtsmith/jwks"
	"github.com/dcadolph/jwtsmith/signing"
	"github.com/dcadolph/jwtsmith/verification"
)

// verifyFlags holds every flag for the verify command.
type verifyFlags struct {
	method       string
	pubPath      string
	jwksURL      string
	token        string
	issuer       []string
	audience     []string
	groups       []string
	roles        []string
	entitlements []string
	requireKeys  []string
	printClaims  bool
	pretty       bool
}

// newVerifyCmd builds the "verify" subcommand for verifying JWTs.
func newVerifyCmd() *cobra.Command {

	f := &verifyFlags{}

	c := &cobra.Command{
		Use:   "verify [token]",
		Short: "Verify a JWT signature and run optional claim checks. Exits non-zero on failure.",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			tok := f.token
			if tok == "" && len(args) == 1 {
				tok = args[0]
			}
			if tok == "" {
				body, err := io.ReadAll(os.Stdin)
				if err != nil {
					return fmt.Errorf("reading stdin: %w", err)
				}
				tok = strings.TrimSpace(string(body))
			}
			if tok == "" {
				return fmt.Errorf("%w: token required (positional arg, --token, or stdin)", ErrUsage)
			}
			f.token = tok
			return runVerify(cmd.Context(), f)
		},
	}

	c.Flags().StringVar(&f.method, "method", "ES256", "Expected signing method.")
	c.Flags().StringVar(&f.pubPath, "pub", "", "Path to PEM-encoded public key. Mutually exclusive with --jwks-url.")
	c.Flags().StringVar(&f.jwksURL, "jwks-url", "", "URL of a JWKS endpoint. Resolves the key by the token's kid header.")
	c.Flags().StringVar(&f.token, "token", "", "Token to verify. Defaults to positional arg or stdin.")
	c.Flags().StringSliceVar(&f.issuer, "issuer", nil, "Allowed issuers. Token's iss must match one.")
	c.Flags().StringSliceVar(&f.audience, "audience", nil, "Required audiences (any-of match).")
	c.Flags().StringSliceVar(&f.groups, "groups", nil, "Required groups (any-of match).")
	c.Flags().StringSliceVar(&f.roles, "roles", nil, "Required roles (any-of match).")
	c.Flags().StringSliceVar(&f.entitlements, "entitlements", nil, "Required entitlements (any-of match).")
	c.Flags().StringSliceVar(&f.requireKeys, "require-claim", nil, "Required claim keys (presence check).")
	c.Flags().BoolVar(&f.printClaims, "print", false, "Print verified claims to stdout on success.")
	c.Flags().BoolVar(&f.pretty, "pretty", false, "Indent the printed JSON output.")

	return c
}

// runVerify resolves the public key (PEM file or JWKS), builds the verifier, and verifies.
func runVerify(ctx context.Context, f *verifyFlags) error {

	method, err := signing.SigningMethod(f.method)
	if err != nil {
		return err
	}

	if f.pubPath == "" && f.jwksURL == "" {
		return fmt.Errorf("%w: one of --pub or --jwks-url is required", ErrUsage)
	}
	if f.pubPath != "" && f.jwksURL != "" {
		return fmt.Errorf("%w: --pub and --jwks-url are mutually exclusive", ErrUsage)
	}

	pub, err := resolvePublicKey(ctx, method, f)
	if err != nil {
		return err
	}

	v, err := verification.NewVerifier(method, pub, verification.WithStaticChecks(buildVerifyChecks(f)...))
	if err != nil {
		return err
	}

	tok, err := v.Verify(f.token)
	if err != nil {
		return err
	}

	fmt.Fprintln(cobraStderr(), "ok")

	if f.printClaims {
		mc, err := claims.ToMapClaims(tok.Claims)
		if err != nil {
			return err
		}
		enc := json.NewEncoder(cobraStdout())
		if f.pretty {
			enc.SetIndent("", "  ")
		}
		enc.SetEscapeHTML(false)
		if err := enc.Encode(mc); err != nil {
			return err
		}
	}
	return nil
}

// resolvePublicKey loads the verification key from --pub or --jwks-url.
func resolvePublicKey(ctx context.Context, method jwt.SigningMethod, f *verifyFlags) (any, error) {
	if f.pubPath != "" {
		return loadPublicKeyForMethod(method, f.pubPath)
	}
	remote, err := jwks.NewRemote(f.jwksURL)
	if err != nil {
		return nil, err
	}
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	parsed := jwt.MapClaims{}
	tok, _, err := parser.ParseUnverified(f.token, parsed)
	if err != nil {
		return nil, fmt.Errorf("%w: peeking kid: %w", ErrUsage, err)
	}
	kid, _ := tok.Header["kid"].(string)
	if kid == "" {
		return nil, fmt.Errorf("%w: token has no kid header; --jwks-url requires kid", ErrUsage)
	}
	return remote.PublicKey(ctx, kid)
}

// buildVerifyChecks turns the verify command's claim flags into TokenCheckFuncs.
func buildVerifyChecks(f *verifyFlags) []verification.TokenCheckFunc {

	var cs []claims.CheckFunc

	if iss := trimAll(f.issuer); len(iss) > 0 {
		cs = append(cs, claims.CheckIssuer(iss...))
	}
	if a := trimAll(f.audience); len(a) > 0 {
		cs = append(cs, claims.CheckAudience(a...))
	}
	if g := trimAll(f.groups); len(g) > 0 {
		cs = append(cs, claims.CheckHasGroups(g...))
	}
	if r := trimAll(f.roles); len(r) > 0 {
		cs = append(cs, claims.CheckHasRoles(r...))
	}
	if e := trimAll(f.entitlements); len(e) > 0 {
		cs = append(cs, checkHasEntitlements(e...))
	}
	if k := trimAll(f.requireKeys); len(k) > 0 {
		cs = append(cs, claims.CheckRequiredKeys(k...))
	}
	if len(cs) == 0 {
		return nil
	}
	return []verification.TokenCheckFunc{verification.CheckClaims(cs...)}
}

// checkHasEntitlements is a claims.CheckFunc factory for the entitlements claim.
func checkHasEntitlements(required ...string) claims.CheckFunc {
	return func(c jwt.MapClaims) error {
		_, err := claims.MatchingEntitlements(c, required...)
		return err
	}
}
