package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/dcadolph/jwtsmith/pkgerr"
)

// String returns flagValue when non-empty, otherwise the env value, otherwise def.
func String(flagName, flagValue, def string) string {
	if flagValue != "" {
		return flagValue
	}
	if v, ok := os.LookupEnv(EnvKey(flagName)); ok && v != "" {
		return v
	}
	return def
}

// Bool returns flagValue when explicitlySet, otherwise the env value parsed via strconv.ParseBool, otherwise def.
//
// Cobra/pflag does not expose "user explicitly set" cleanly without a *cobra.Command, so
// callers should pass true for explicitlySet only when the flag was actually provided.
func Bool(flagName string, flagValue, def, explicitlySet bool) (bool, error) {
	if explicitlySet {
		return flagValue, nil
	}
	if v, ok := os.LookupEnv(EnvKey(flagName)); ok && v != "" {
		parsed, err := strconv.ParseBool(v)
		if err != nil {
			return false, fmt.Errorf("%w: env %s: %w", pkgerr.ErrInvalidValue, EnvKey(flagName), err)
		}
		return parsed, nil
	}
	return def, nil
}

// Int returns flagValue when non-zero, otherwise the env value, otherwise def.
func Int(flagName string, flagValue, def int) (int, error) {
	if flagValue != 0 {
		return flagValue, nil
	}
	if v, ok := os.LookupEnv(EnvKey(flagName)); ok && v != "" {
		parsed, err := strconv.Atoi(v)
		if err != nil {
			return 0, fmt.Errorf("%w: env %s: %w", pkgerr.ErrInvalidValue, EnvKey(flagName), err)
		}
		return parsed, nil
	}
	return def, nil
}

// Duration returns flagValue when non-zero, otherwise the env value parsed via time.ParseDuration, otherwise def.
func Duration(flagName string, flagValue, def time.Duration) (time.Duration, error) {
	if flagValue != 0 {
		return flagValue, nil
	}
	if v, ok := os.LookupEnv(EnvKey(flagName)); ok && v != "" {
		parsed, err := time.ParseDuration(v)
		if err != nil {
			return 0, fmt.Errorf("%w: env %s: %w", pkgerr.ErrInvalidValue, EnvKey(flagName), err)
		}
		return parsed, nil
	}
	return def, nil
}

// StringSlice returns flagValue when non-empty, otherwise the env value (CSV split), otherwise def.
func StringSlice(flagName string, flagValue, def []string) []string {
	if len(flagValue) > 0 {
		return flagValue
	}
	if v, ok := os.LookupEnv(EnvKey(flagName)); ok && v != "" {
		return strings.Split(v, ",")
	}
	return def
}
