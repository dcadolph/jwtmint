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
		{Flag: "default-issuer", Want: "JWTSMITH_DEFAULT_ISSUER"},
		{Flag: "priv", Want: "JWTSMITH_PRIV"},
		{Flag: "pub", Want: "JWTSMITH_PUB"},
		{Flag: "jwks-url", Want: "JWTSMITH_JWKS_URL"},
		{Flag: "expires", Want: "JWTSMITH_EXPIRES"},
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
