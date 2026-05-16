package cmd

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"github.com/spf13/cobra"

	"github.com/dcadolph/jwtmint/pkgerr"
)

// newInspectCmd builds the "inspect" subcommand for decoding tokens without verification.
//
// inspect does not verify signatures — it is for debugging and development. Use the
// verify subcommand for any security-relevant decision.
func newInspectCmd() *cobra.Command {

	var (
		token  string
		pretty bool
	)

	c := &cobra.Command{
		Use:   "inspect [token]",
		Short: "Decode and print a JWT's headers and claims (does not verify signature).",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			tok := token
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
			return runInspect(tok, pretty)
		},
	}

	c.Flags().StringVar(&token, "token", "", "Token to inspect. Defaults to positional arg or stdin.")
	c.Flags().BoolVar(&pretty, "pretty", false, "Indent the JSON output.")

	return c
}

// runInspect parses the token without verifying its signature and prints the headers and claims.
func runInspect(token string, pretty bool) error {

	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	parsed := jwt.MapClaims{}
	tok, _, err := parser.ParseUnverified(token, parsed)
	if err != nil {
		return fmt.Errorf("%w: %w", pkgerr.ErrParse, err)
	}

	out := struct {
		Header    map[string]any `json:"header"`
		Claims    jwt.MapClaims  `json:"claims"`
		Signature string         `json:"signature"`
	}{
		Header:    tok.Header,
		Claims:    parsed,
		Signature: base64.RawURLEncoding.EncodeToString(tok.Signature),
	}

	enc := json.NewEncoder(cobraStdout())
	if pretty {
		enc.SetIndent("", "  ")
	}
	enc.SetEscapeHTML(false)
	if err := enc.Encode(out); err != nil {
		return fmt.Errorf("%w: encoding output: %w", pkgerr.ErrEncode, err)
	}
	return nil
}
