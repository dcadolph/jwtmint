package config

import (
	"testing"
)

// TestEnvKey covers the flag-name to env-var transformation.
func TestEnvKey(t *testing.T) {
	t.Parallel()

	tests := []struct {
		Flag string
		Want string
	}{
		{Flag: "default-issuer", Want: "JWTMINT_DEFAULT_ISSUER"},
		{Flag: "priv", Want: "JWTMINT_PRIV"},
		{Flag: "pub", Want: "JWTMINT_PUB"},
		{Flag: "jwks-url", Want: "JWTMINT_JWKS_URL"},
		{Flag: "expires", Want: "JWTMINT_EXPIRES"},
	}

	for testNum, test := range tests {
		t.Run(test.Flag, func(t *testing.T) {
			t.Parallel()
			if got := EnvKey(test.Flag); got != test.Want {
				t.Errorf("test %d: EnvKey(%q) = %q, want %q", testNum, test.Flag, got, test.Want)
			}
		})
	}
}
