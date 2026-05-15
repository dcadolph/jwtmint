package cmd

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/dcadolph/jwtsmith/jwks"
	"github.com/dcadolph/jwtsmith/keys"
	"github.com/dcadolph/jwtsmith/pkgerr"
)

// newJWKSCmd builds the "jwks" subcommand group.
//
// Subcommands:
//   - from-key: convert a PEM public key to a JWK or single-key JWKS.
//   - fetch:    fetch a remote JWKS and print it (or a specific kid).
func newJWKSCmd() *cobra.Command {

	c := &cobra.Command{
		Use:   "jwks",
		Short: "Work with JSON Web Key Sets: convert public keys to JWK and fetch remote sets.",
	}
	c.AddCommand(newJWKSFromKeyCmd(), newJWKSFetchCmd())
	return c
}

// newJWKSFromKeyCmd converts a PEM public key file to JWK / JWKS form.
func newJWKSFromKeyCmd() *cobra.Command {

	var (
		pubPath string
		kid     string
		set     bool
		pretty  bool
	)

	c := &cobra.Command{
		Use:   "from-key",
		Short: "Convert a PEM-encoded public key to a JWK (or single-key JWKS with --set).",
		RunE: func(_ *cobra.Command, _ []string) error {
			pubBytes, err := keys.ReadPEMFile(pubPath)
			if err != nil {
				return err
			}
			pub, err := loadAnyPublicKey(pubBytes)
			if err != nil {
				return err
			}
			j, err := jwks.JWKFromPublicKey(pub, kid)
			if err != nil {
				return err
			}
			enc := json.NewEncoder(cobraStdout())
			if pretty {
				enc.SetIndent("", "  ")
			}
			enc.SetEscapeHTML(false)
			if set {
				return enc.Encode(jwks.JWKS{Keys: []jwks.JWK{j}})
			}
			return enc.Encode(j)
		},
	}

	c.Flags().StringVar(&pubPath, "pub", "", "Path to PEM-encoded public key. Required.")
	c.Flags().StringVar(&kid, "kid", "", "Key ID to embed in the JWK (kid).")
	c.Flags().BoolVar(&set, "set", false, "Wrap output as a single-key JWKS.")
	c.Flags().BoolVar(&pretty, "pretty", false, "Indent JSON output.")
	_ = c.MarkFlagRequired("pub")

	return c
}

// newJWKSFetchCmd fetches a remote JWKS and prints it (optionally filtered to one kid).
func newJWKSFetchCmd() *cobra.Command {

	var (
		url    string
		kid    string
		pretty bool
	)

	c := &cobra.Command{
		Use:   "fetch",
		Short: "Fetch a remote JWKS over HTTPS and print it.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			r, err := jwks.NewRemote(url)
			if err != nil {
				return err
			}
			ks, err := r.KeySet(cmd.Context())
			if err != nil {
				return err
			}
			out := ks.JWKS()
			if kid != "" {
				j, err := ks.Lookup(kid)
				if err != nil {
					return err
				}
				out = jwks.JWKS{Keys: []jwks.JWK{j}}
			}
			enc := json.NewEncoder(cobraStdout())
			if pretty {
				enc.SetIndent("", "  ")
			}
			enc.SetEscapeHTML(false)
			return enc.Encode(out)
		},
	}

	c.Flags().StringVar(&url, "url", "", "JWKS URL to fetch. Required.")
	c.Flags().StringVar(&kid, "kid", "", "Filter to the JWK with this kid only.")
	c.Flags().BoolVar(&pretty, "pretty", false, "Indent JSON output.")
	_ = c.MarkFlagRequired("url")

	return c
}

// loadAnyPublicKey tries each public-key parser in turn, returning the first success.
func loadAnyPublicKey(pemBytes []byte) (any, error) {
	if k, err := keys.LoadECDSAPublicFromPEM(pemBytes); err == nil {
		return k, nil
	}
	if k, err := keys.LoadRSAPublicFromPEM(pemBytes); err == nil {
		return k, nil
	}
	if k, err := keys.LoadEd25519PublicFromPEM(pemBytes); err == nil {
		return k, nil
	}
	return nil, fmt.Errorf("%w: pem is not a recognized public key (tried ECDSA, RSA, Ed25519)", pkgerr.ErrParse)
}

// _ keeps the standard library imports referenced via key types we may switch on
// in future expansion.
var (
	_ = (*ecdsa.PublicKey)(nil)
	_ = (*rsa.PublicKey)(nil)
	_ = ed25519.PublicKey(nil)
)

// context is the cobra context passed through cmd.Context() for cancellation.
var _ context.Context = context.Background()
