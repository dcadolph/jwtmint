// Package config resolves CLI configuration from flags, environment variables, and defaults.
//
// Lookup order: explicit flag value > environment variable > default. The flag layer is
// owned by cobra/pflag — this package handles env resolution and default fallback for
// values that callers want to override outside the command line.
//
// Env naming convention: a flag named "default-issuer" maps to JWTSMITH_DEFAULT_ISSUER.
// See EnvKey for the exact transform.
package config

import (
	"strings"
)

// EnvPrefix is prepended to every environment variable jwtsmith reads.
const EnvPrefix = "JWTSMITH"

// EnvKey returns the environment variable name corresponding to a flag name.
//
// Hyphens become underscores; result is uppercased and prefixed with EnvPrefix.
// Example: "default-issuer" -> "JWTSMITH_DEFAULT_ISSUER".
func EnvKey(flagName string) string {
	upper := strings.ToUpper(strings.ReplaceAll(flagName, "-", "_"))
	return EnvPrefix + "_" + upper
}
