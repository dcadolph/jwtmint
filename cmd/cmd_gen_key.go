package cmd

import (
	"crypto/elliptic"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/dcadolph/jwtsmith/keys"
)

// Supported algorithm names for the gen-key command.
const (
	algECDSA   = "ecdsa"
	algRSA     = "rsa"
	algEd25519 = "ed25519"
)

// newGenKeyCmd builds the "gen-key" subcommand for generating asymmetric key pairs.
func newGenKeyCmd() *cobra.Command {

	var (
		algorithm string
		curve     string
		bits      int
		privOut   string
		pubOut    string
		printPEM  bool
	)

	c := &cobra.Command{
		Use:   "gen-key",
		Short: "Generate an asymmetric key pair (ECDSA, RSA, or Ed25519) and write PEM files.",
		RunE: func(_ *cobra.Command, _ []string) error {
			return runGenKey(algorithm, curve, bits, privOut, pubOut, printPEM)
		},
	}

	c.Flags().StringVar(&algorithm, "algorithm", algECDSA, "Algorithm: ecdsa, rsa, or ed25519.")
	c.Flags().StringVar(&curve, "curve", "P-256", "ECDSA curve: P-256, P-384, or P-521.")
	c.Flags().IntVar(&bits, "bits", 2048, "RSA key size in bits (>= 2048).")
	c.Flags().StringVar(&privOut, "priv-out", "", "Path to write the private key PEM. Required unless --print is set.")
	c.Flags().StringVar(&pubOut, "pub-out", "", "Path to write the public key PEM. Required unless --print is set.")
	c.Flags().BoolVar(&printPEM, "print", false, "Print PEM to stdout instead of writing files (private then public).")

	return c
}

// runGenKey dispatches generation by algorithm and writes the resulting key pair.
func runGenKey(algorithm, curve string, bits int, privOut, pubOut string, printPEM bool) error {

	priv, pub, err := generatePair(algorithm, curve, bits)
	if err != nil {
		return err
	}

	if printPEM {
		privPEM, err := keys.EncodePrivateKeyPEM(priv)
		if err != nil {
			return err
		}
		pubPEM, err := keys.EncodePublicKeyPEM(pub)
		if err != nil {
			return err
		}
		fmt.Print(string(privPEM))
		fmt.Print(string(pubPEM))
		return nil
	}

	if privOut == "" || pubOut == "" {
		return fmt.Errorf("%w: --priv-out and --pub-out are required (or use --print)", ErrUsage)
	}

	if err := keys.SavePrivateKey(privOut, priv); err != nil {
		return err
	}
	if err := keys.SavePublicKey(pubOut, pub); err != nil {
		return err
	}
	fmt.Fprintf(cobraStderr(), "wrote %s and %s\n", privOut, pubOut)
	return nil
}

// generatePair dispatches to the correct keys.Generate* by algorithm name.
func generatePair(algorithm, curve string, bits int) (priv, pub any, err error) {
	switch strings.ToLower(algorithm) {
	case algECDSA:
		ec, err := curveFromName(curve)
		if err != nil {
			return nil, nil, err
		}
		p, q, err := keys.GenerateECDSA(ec)
		return p, q, err
	case algRSA:
		p, q, err := keys.GenerateRSA(bits)
		return p, q, err
	case algEd25519:
		p, q, err := keys.GenerateEd25519()
		return p, q, err
	default:
		return nil, nil, fmt.Errorf("%w: unknown algorithm %q (want ecdsa, rsa, or ed25519)", ErrUsage, algorithm)
	}
}

// curveFromName maps a JWK-style curve name to the elliptic.Curve.
func curveFromName(name string) (elliptic.Curve, error) {
	switch strings.ToUpper(name) {
	case "P-256", "P256":
		return elliptic.P256(), nil
	case "P-384", "P384":
		return elliptic.P384(), nil
	case "P-521", "P521":
		return elliptic.P521(), nil
	default:
		return nil, fmt.Errorf("%w: unknown ecdsa curve %q (want P-256, P-384, or P-521)", ErrUsage, name)
	}
}
