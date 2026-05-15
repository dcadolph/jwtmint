package cmd

// Process exit codes used by Execute.
const (
	// ExitOK indicates a successful run.
	ExitOK = 0
	// ExitUsage indicates a usage error (bad flag combination, missing required input).
	ExitUsage = 2
	// ExitFailure indicates a runtime failure (file not found, signature mismatch, etc.).
	ExitFailure = 1
	// ExitInterrupted indicates the process was interrupted (Ctrl+C).
	ExitInterrupted = 130
)
