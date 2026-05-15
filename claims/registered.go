package claims

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/dcadolph/jwtsmith/pkgerr"
)

// ID returns the "jti" claim as a string.
func ID(c jwt.MapClaims) (string, error) {
	return readString(c, KeyID, "id")
}

// SetID sets the "jti" claim. Accepts string, []byte, or uuid.UUID; other types are ignored.
func SetID(c jwt.MapClaims, id any) {
	switch v := id.(type) {
	case string:
		c[KeyID] = v
	case []byte:
		c[KeyID] = string(v)
	case uuid.UUID:
		c[KeyID] = v.String()
	}
}

// DeleteID removes the "jti" claim.
func DeleteID(c jwt.MapClaims) { delete(c, KeyID) }

// JTI is an alias for ID.
func JTI(c jwt.MapClaims) (string, error) { return ID(c) }

// SetJTI is an alias for SetID with a string value.
func SetJTI(c jwt.MapClaims, jti string) { SetID(c, jti) }

// DeleteJTI is an alias for DeleteID.
func DeleteJTI(c jwt.MapClaims) { DeleteID(c) }

// Issuer returns the "iss" claim as a string.
func Issuer(c jwt.MapClaims) (string, error) {
	return readString(c, KeyIssuer, "issuer")
}

// SetIssuer sets the "iss" claim.
func SetIssuer(c jwt.MapClaims, iss string) { c[KeyIssuer] = iss }

// DeleteIssuer removes the "iss" claim.
func DeleteIssuer(c jwt.MapClaims) { delete(c, KeyIssuer) }

// Subject returns the "sub" claim as a string.
func Subject(c jwt.MapClaims) (string, error) {
	return readString(c, KeySubject, "subject")
}

// SetSubject sets the "sub" claim.
func SetSubject(c jwt.MapClaims, sub string) { c[KeySubject] = sub }

// DeleteSubject removes the "sub" claim.
func DeleteSubject(c jwt.MapClaims) { delete(c, KeySubject) }

// Audience returns the "aud" claim as a slice of strings.
//
// Accepts []string, []any, and CSV string for compatibility with tokens issued elsewhere.
func Audience(c jwt.MapClaims) ([]string, error) {
	return readStringSlice(c, KeyAudience, "audience")
}

// SetAudience sets the "aud" claim as a slice of strings.
func SetAudience(c jwt.MapClaims, audience ...string) {
	c[KeyAudience] = audience
}

// DeleteAudience removes the "aud" claim.
func DeleteAudience(c jwt.MapClaims) { delete(c, KeyAudience) }

// MatchingAudience returns the subset of the token's audience that intersects with toMatch.
//
// Returns ErrNoAudience when there is no overlap.
func MatchingAudience(c jwt.MapClaims, toMatch ...string) ([]string, error) {

	have, err := Audience(c)
	if err != nil {
		return nil, err
	}

	if len(have) == 0 {
		return nil, errors.Join(pkgerr.ErrNotFound, ErrNoAudience)
	}

	set := make(map[string]bool, len(have))
	for _, a := range normalizeStringSlice(have...) {
		set[a] = true
	}

	var matched []string
	for _, want := range normalizeStringSlice(toMatch...) {
		if set[want] {
			matched = append(matched, want)
		}
	}

	if len(matched) == 0 {
		return nil, fmt.Errorf("%w: no overlap", ErrNoAudience)
	}
	return matched, nil
}

// IssuedAt returns the "iat" claim as a time.Time.
func IssuedAt(c jwt.MapClaims) (time.Time, error) {
	return readTime(c, KeyIssuedAt, "issued at")
}

// SetIssuedAt sets the "iat" claim.
func SetIssuedAt(c jwt.MapClaims, iat time.Time) {
	c[KeyIssuedAt] = jwt.NewNumericDate(iat)
}

// DeleteIssuedAt removes the "iat" claim.
func DeleteIssuedAt(c jwt.MapClaims) { delete(c, KeyIssuedAt) }

// IssuedAtBefore reports whether iat is before the given time.
func IssuedAtBefore(c jwt.MapClaims, t time.Time) (bool, error) {
	iat, err := IssuedAt(c)
	if err != nil {
		return false, err
	}
	return iat.Before(t), nil
}

// IssuedAtAfter reports whether iat is after the given time.
func IssuedAtAfter(c jwt.MapClaims, t time.Time) (bool, error) {
	iat, err := IssuedAt(c)
	if err != nil {
		return false, err
	}
	return iat.After(t), nil
}

// ExpiresAt returns the "exp" claim as a time.Time.
func ExpiresAt(c jwt.MapClaims) (time.Time, error) {
	return readTime(c, KeyExpiresAt, "expires at")
}

// SetExpiresAt sets the "exp" claim.
func SetExpiresAt(c jwt.MapClaims, exp time.Time) {
	c[KeyExpiresAt] = jwt.NewNumericDate(exp)
}

// DeleteExpiresAt removes the "exp" claim.
func DeleteExpiresAt(c jwt.MapClaims) { delete(c, KeyExpiresAt) }

// IsExpired reports whether the token has passed its expiration.
func IsExpired(c jwt.MapClaims) (expired bool, expiresAt time.Time, err error) {
	exp, err := ExpiresAt(c)
	if err != nil {
		return false, time.Time{}, err
	}
	return exp.Before(time.Now()), exp, nil
}

// ExpiresBefore reports whether exp is before the given time.
func ExpiresBefore(c jwt.MapClaims, t time.Time) (bool, error) {
	exp, err := ExpiresAt(c)
	if err != nil {
		return false, err
	}
	return exp.Before(t), nil
}

// ExpiresAfter reports whether exp is after the given time.
func ExpiresAfter(c jwt.MapClaims, t time.Time) (bool, error) {
	exp, err := ExpiresAt(c)
	if err != nil {
		return false, err
	}
	return exp.After(t), nil
}

// NotBefore returns the "nbf" claim as a time.Time.
func NotBefore(c jwt.MapClaims) (time.Time, error) {
	return readTime(c, KeyNotBefore, "not before")
}

// SetNotBefore sets the "nbf" claim.
func SetNotBefore(c jwt.MapClaims, nbf time.Time) {
	c[KeyNotBefore] = jwt.NewNumericDate(nbf)
}

// DeleteNotBefore removes the "nbf" claim.
func DeleteNotBefore(c jwt.MapClaims) { delete(c, KeyNotBefore) }

// IsNotBefore reports whether nbf is in the future (token not yet usable).
func IsNotBefore(c jwt.MapClaims) (notReady bool, nbf time.Time, err error) {
	nbf, err = NotBefore(c)
	if err != nil {
		return false, time.Time{}, err
	}
	return nbf.After(time.Now()), nbf, nil
}

// readString reads a string claim, handling string and []byte values.
func readString(c jwt.MapClaims, key, label string) (string, error) {
	v, ok := c[key]
	if !ok {
		return "", fmt.Errorf("%w: %s missing", pkgerr.ErrNotFound, label)
	}
	switch s := v.(type) {
	case string:
		if s == "" {
			return "", fmt.Errorf("%w: %s empty", pkgerr.ErrEmptyValue, label)
		}
		return s, nil
	case []byte:
		if len(s) == 0 {
			return "", fmt.Errorf("%w: %s empty", pkgerr.ErrEmptyValue, label)
		}
		return string(s), nil
	default:
		return "", fmt.Errorf("%w: %s must be string or []byte: got %T", pkgerr.ErrInvalidClaims, label, v)
	}
}

// readTime reads a time claim, normalizing through Timestamp.
func readTime(c jwt.MapClaims, key, label string) (time.Time, error) {
	v, ok := c[key]
	if !ok {
		return time.Time{}, fmt.Errorf("%w: %s missing", pkgerr.ErrNotFound, label)
	}
	if v == nil {
		return time.Time{}, fmt.Errorf("%w: %s nil", pkgerr.ErrEmptyValue, label)
	}
	nd, err := Timestamp(v)
	if err != nil {
		return time.Time{}, fmt.Errorf("normalizing %s: %w", label, err)
	}
	return nd.Time, nil
}
