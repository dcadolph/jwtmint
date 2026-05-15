// Package claims provides typed read, write, and check helpers for jwt.MapClaims.
//
// Helpers are forgiving on read (accepting strings, byte slices, []any, and CSV strings
// where appropriate) and strict on write (one canonical type per claim). Use the typed
// setters to keep claims consistent across services.
package claims

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/golang-jwt/jwt/v5"

	"github.com/dcadolph/jwtsmith/pkgerr"
)

// ToMapClaims converts an arbitrary value to jwt.MapClaims.
//
// If v is already a non-nil jwt.MapClaims, it is returned unchanged. Otherwise the
// value is round-tripped through JSON. Nil maps and unmarshalable values return an error.
func ToMapClaims(v any) (jwt.MapClaims, error) {

	if mc, ok := v.(jwt.MapClaims); ok {
		if mc == nil {
			return nil, fmt.Errorf("%w: claims nil", pkgerr.ErrInvalidValue)
		}
		return mc, nil
	}

	encoded, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("%w: encoding claims: %w", pkgerr.ErrEncode, err)
	}

	var mc jwt.MapClaims
	if err := json.Unmarshal(encoded, &mc); err != nil {
		return nil, fmt.Errorf("%w: decoding claims to jwt.MapClaims: %w", pkgerr.ErrDecode, err)
	}

	return mc, nil
}

// DeepCopy returns a deep copy of the claims via JSON round-trip.
//
// Use this when you need to mutate the returned map (including its slice/map values)
// without touching the caller's map. Returns an empty map if the input is nil.
//
// On the rare path where JSON marshaling fails (the input contains a value json/encoding
// rejects), DeepCopy degrades to ShallowCopy — guaranteeing a non-nil map at the cost of
// dropping deep-copy semantics for that one call. This trade favors caller simplicity:
// jwt.MapClaims is already a JSON-shaped value, so the failure mode is essentially
// unreachable in practice. Hot paths that only need top-level mutations can use
// ShallowCopy directly to avoid the JSON round-trip.
func DeepCopy(src jwt.MapClaims) jwt.MapClaims {
	if len(src) == 0 {
		return jwt.MapClaims{}
	}
	encoded, err := json.Marshal(src)
	if err != nil {
		return ShallowCopy(src)
	}
	var dst jwt.MapClaims
	if err := json.Unmarshal(encoded, &dst); err != nil {
		return ShallowCopy(src)
	}
	return dst
}

// ShallowCopy returns a copy of the top-level keys of src; values are aliased.
//
// Cheap (no JSON), but mutating slice/map values in the result will leak to the source.
// Prefer DeepCopy unless you know you only need top-level mutations.
func ShallowCopy(src jwt.MapClaims) jwt.MapClaims {
	dst := make(jwt.MapClaims, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

// RegisteredClaims returns the set of registered claim keys defined by RFC 7519.
func RegisteredClaims() map[string]struct{} {
	return map[string]struct{}{
		KeyExpiresAt: {},
		KeyIssuedAt:  {},
		KeyNotBefore: {},
		KeyID:        {},
		KeyIssuer:    {},
		KeyAudience:  {},
		KeySubject:   {},
	}
}

// IsRegisteredClaim reports whether the given key is a registered RFC 7519 claim.
func IsRegisteredClaim(key string) bool {
	switch key {
	case KeyExpiresAt, KeyIssuedAt, KeyNotBefore,
		KeyID, KeyIssuer, KeyAudience, KeySubject:
		return true
	}
	return false
}

// normalizeString trims whitespace and trailing slashes from s.
func normalizeString(s string) string {
	out := strings.TrimSpace(s)
	out = strings.TrimRight(out, "/")
	return strings.TrimSpace(out)
}

// normalizeStringSlice applies normalizeString to every element of s.
func normalizeStringSlice(s ...string) []string {
	out := make([]string, len(s))
	for i, v := range s {
		out[i] = normalizeString(v)
	}
	return out
}
