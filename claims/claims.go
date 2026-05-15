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

// DeepCopy returns a shallow-keyed copy of the claims.
//
// Values are copied by reference. Use this when you need to mutate exp/iat/nbf without
// touching the caller's map.
func DeepCopy(src jwt.MapClaims) jwt.MapClaims {
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
