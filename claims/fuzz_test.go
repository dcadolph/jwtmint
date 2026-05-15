package claims

import (
	"encoding/json"
	"testing"
)

// FuzzToMapClaims exercises ToMapClaims against arbitrary JSON-decoded values.
//
// Contract: must never panic regardless of input. Errors are expected for inputs that
// don't shape into a JSON object; crashes are not.
func FuzzToMapClaims(f *testing.F) {

	seeds := [][]byte{
		[]byte(`{}`),
		[]byte(`{"sub":"u1"}`),
		[]byte(`{"exp":9999999999}`),
		[]byte(`null`),
		[]byte(`[]`),
		[]byte(`"string"`),
		[]byte(`42`),
		[]byte(``),
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, in []byte) {
		var v any
		if err := json.Unmarshal(in, &v); err != nil {
			return
		}
		_, _ = ToMapClaims(v)
	})
}
