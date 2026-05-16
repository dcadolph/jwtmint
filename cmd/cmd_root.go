package cmd

import (
	"github.com/spf13/cobra"
)

// newRootCmd builds the root cobra command with all subcommands attached.
func newRootCmd() *cobra.Command {

	root := &cobra.Command{
		Use:           "jwtmint",
		Short:         "JWT toolkit: generate keys, sign, decode, verify, refresh, distribute via JWKS.",
		SilenceUsage:  true,
		SilenceErrors: true,
		Version:       Version,
	}

	root.AddCommand(
		newGenKeyCmd(),
		newSignCmd(),
		newInspectCmd(),
		newVerifyCmd(),
		newRefreshCmd(),
		newJWKSCmd(),
	)

	return root
}
