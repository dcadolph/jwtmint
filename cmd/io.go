package cmd

import (
	"io"
	"os"
)

// cobraStdout returns the writer to use for primary command output (signed token, JSON, etc.).
//
// Wrapped here so tests and library callers can override it later if needed.
func cobraStdout() io.Writer { return os.Stdout }

// cobraStderr returns the writer to use for human-readable status messages and errors.
func cobraStderr() io.Writer { return os.Stderr }
