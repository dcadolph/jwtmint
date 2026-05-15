package cmd

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/dcadolph/jwtsmith/refresh"
	"github.com/dcadolph/jwtsmith/signing"
)

// newRefreshCmd builds the "refresh" subcommand for rotating tokens.
func newRefreshCmd() *cobra.Command {

	var (
		method     string
		pubPath    string
		privPath   string
		token      string
		defaultExp time.Duration
	)

	c := &cobra.Command{
		Use:   "refresh [token]",
		Short: "Refresh a JWT, preserving its lifetime window. Outputs the refreshed token to stdout.",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
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
			ctx := cmd.Context()
			if ctx == nil {
				ctx = context.Background()
			}
			return runRefresh(ctx, method, pubPath, privPath, tok, defaultExp)
		},
	}

	c.Flags().StringVar(&method, "method", "ES256", "Signing method.")
	c.Flags().StringVar(&pubPath, "pub", "", "Path to PEM-encoded public key. Required.")
	c.Flags().StringVar(&privPath, "priv", "", "Path to PEM-encoded private key. Required.")
	c.Flags().StringVar(&token, "token", "", "Token to refresh. Defaults to positional arg or stdin.")
	c.Flags().DurationVar(&defaultExp, "default-expires", time.Hour, "Lifetime to use when the original token has no recoverable window.")

	_ = c.MarkFlagRequired("pub")
	_ = c.MarkFlagRequired("priv")

	return c
}

// runRefresh resolves the keypair, builds the refresher, and writes the rotated token.
func runRefresh(ctx context.Context, methodName, pubPath, privPath, token string, defaultExp time.Duration) error {

	method, err := signing.SigningMethod(methodName)
	if err != nil {
		return err
	}
	pub, err := loadPublicKeyForMethod(method, pubPath)
	if err != nil {
		return err
	}
	priv, err := loadPrivateKeyForMethod(method, privPath)
	if err != nil {
		return err
	}

	opts := []refresh.Opt{}
	if defaultExp > 0 {
		opts = append(opts, refresh.WithDefaultExpiration(defaultExp))
	}
	r, err := refresh.NewRefresher(method, pub, priv, opts...)
	if err != nil {
		return err
	}

	_, refreshed, err := r.Refresh(ctx, token)
	if err != nil {
		return err
	}
	fmt.Fprintln(cobraStdout(), refreshed)
	return nil
}
