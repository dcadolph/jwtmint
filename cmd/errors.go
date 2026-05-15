package cmd

import "errors"

var (
	// ErrUsage indicates a CLI usage problem (missing/invalid flags or args).
	ErrUsage = errors.New("usage error")

	// ErrAbort indicates the user aborted the operation.
	ErrAbort = errors.New("aborted")
)

// QuietExitError signals that the process should exit non-zero without printing the error.
//
// Use for user-initiated aborts (Ctrl+C, declined confirmations) where the user already
// knows what happened and an error message would be redundant.
type QuietExitError struct {
	Code int
}

// Error implements the error interface.
func (e *QuietExitError) Error() string { return "" }
