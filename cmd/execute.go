package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"
)

// Execute runs the root command with signal handling and exits with a process status code.
//
// Errors are written to stderr; QuietExitError suppresses the message and uses its code.
func Execute() {

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	root := newRootCmd()
	root.SetContext(ctx)

	if err := root.ExecuteContext(ctx); err != nil {
		os.Exit(exitCodeFor(err))
	}
	os.Exit(ExitOK)
}

// exitCodeFor maps an error to a process exit code, printing to stderr where appropriate.
func exitCodeFor(err error) int {
	if err == nil {
		return ExitOK
	}

	var quiet *QuietExitError
	if errors.As(err, &quiet) {
		return quiet.Code
	}

	fmt.Fprintf(os.Stderr, "jwtsmith: %s\n", err)

	switch {
	case errors.Is(err, ErrUsage):
		return ExitUsage
	case errors.Is(err, context.Canceled):
		return ExitInterrupted
	default:
		return ExitFailure
	}
}
