package jwks

import (
	"encoding/json"
	"testing"
)

// FuzzJWKSDecode exercises JWKS unmarshalling against arbitrary JSON inputs.
//
// Contract: must never panic, regardless of input. Errors are expected for non-JWKS-shaped
// input; what matters is the absence of crashes in the decode + key-construction path.
func FuzzJWKSDecode(f *testing.F) {

	seeds := [][]byte{
		[]byte(`{}`),
		[]byte(`{"keys":[]}`),
		[]byte(`{"keys":[{"kty":"EC","crv":"P-256","x":"AAAA","y":"AAAA","kid":"k"}]}`),
		[]byte(`{"keys":null}`),
		[]byte(`null`),
		[]byte(`[]`),
		[]byte(``),
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, in []byte) {
		var jwks JWKS
		if err := json.Unmarshal(in, &jwks); err != nil {
			return
		}
		_, _ = FromJWKS(jwks)
	})
}
