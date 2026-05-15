package claims

import (
	"errors"
	"fmt"
	"strings"

	"github.com/golang-jwt/jwt/v5"

	"github.com/dcadolph/jwtsmith/pkgerr"
)

// Groups returns the "groups" claim as a slice of strings.
//
// Accepts []string, []any, and CSV string for compatibility with tokens issued elsewhere.
func Groups(c jwt.MapClaims) ([]string, error) {
	return readStringSlice(c, KeyGroups, "groups")
}

// SetGroups sets the "groups" claim.
func SetGroups(c jwt.MapClaims, groups ...string) {
	c[KeyGroups] = groups
}

// DeleteGroups removes the "groups" claim.
func DeleteGroups(c jwt.MapClaims) { delete(c, KeyGroups) }

// MatchingGroups returns the subset of the token's groups that intersects with toMatch.
func MatchingGroups(c jwt.MapClaims, toMatch ...string) ([]string, error) {

	have, err := Groups(c)
	if err != nil {
		return nil, err
	}

	if len(have) == 0 {
		return nil, errors.Join(pkgerr.ErrNotFound, ErrNoGroups)
	}

	set := make(map[string]bool, len(have))
	for _, g := range normalizeStringSlice(have...) {
		set[g] = true
	}

	var matched []string
	for _, want := range normalizeStringSlice(toMatch...) {
		if set[want] {
			matched = append(matched, want)
		}
	}

	if len(matched) == 0 {
		return nil, fmt.Errorf("%w: no overlap", ErrNoGroups)
	}
	return matched, nil
}

// Roles returns the "roles" claim as a slice of strings.
//
// Accepts []string, []any, and CSV string for compatibility with tokens issued elsewhere.
func Roles(c jwt.MapClaims) ([]string, error) {
	return readStringSlice(c, KeyRoles, "roles")
}

// SetRoles sets the "roles" claim.
func SetRoles(c jwt.MapClaims, roles ...string) {
	c[KeyRoles] = roles
}

// DeleteRoles removes the "roles" claim.
func DeleteRoles(c jwt.MapClaims) { delete(c, KeyRoles) }

// MatchingRoles returns the subset of the token's roles that intersects with toMatch.
func MatchingRoles(c jwt.MapClaims, toMatch ...string) ([]string, error) {

	have, err := Roles(c)
	if err != nil {
		return nil, err
	}

	if len(have) == 0 {
		return nil, errors.Join(pkgerr.ErrNotFound, ErrNoRoles)
	}

	set := make(map[string]bool, len(have))
	for _, r := range normalizeStringSlice(have...) {
		set[r] = true
	}

	var matched []string
	for _, want := range normalizeStringSlice(toMatch...) {
		if set[want] {
			matched = append(matched, want)
		}
	}

	if len(matched) == 0 {
		return nil, fmt.Errorf("%w: no overlap", ErrNoRoles)
	}
	return matched, nil
}

// Permissions returns the "permissions" claim as a slice of strings.
//
// Accepts []string, []any, and CSV string for compatibility with tokens issued elsewhere.
func Permissions(c jwt.MapClaims) ([]string, error) {
	return readStringSlice(c, KeyPermissions, "permissions")
}

// SetPermissions sets the "permissions" claim.
func SetPermissions(c jwt.MapClaims, permissions ...string) {
	c[KeyPermissions] = permissions
}

// DeletePermissions removes the "permissions" claim.
func DeletePermissions(c jwt.MapClaims) { delete(c, KeyPermissions) }

// Entitlements returns the "entitlements" claim as a slice of strings.
//
// Accepts []string, []any, and CSV string for compatibility with tokens issued elsewhere.
func Entitlements(c jwt.MapClaims) ([]string, error) {
	return readStringSlice(c, KeyEntitlements, "entitlements")
}

// SetEntitlements sets the "entitlements" claim.
func SetEntitlements(c jwt.MapClaims, entitlements ...string) {
	c[KeyEntitlements] = entitlements
}

// DeleteEntitlements removes the "entitlements" claim.
func DeleteEntitlements(c jwt.MapClaims) { delete(c, KeyEntitlements) }

// MatchingEntitlements returns the subset of the token's entitlements that intersects with toMatch.
func MatchingEntitlements(c jwt.MapClaims, toMatch ...string) ([]string, error) {

	have, err := Entitlements(c)
	if err != nil {
		return nil, err
	}

	if len(have) == 0 {
		return nil, fmt.Errorf("%w: entitlements empty", pkgerr.ErrEmptyValue)
	}

	set := make(map[string]bool, len(have))
	for _, e := range normalizeStringSlice(have...) {
		set[e] = true
	}

	var matched []string
	for _, want := range normalizeStringSlice(toMatch...) {
		if set[want] {
			matched = append(matched, want)
		}
	}

	if len(matched) == 0 {
		return nil, fmt.Errorf("%w: no entitlement overlap", pkgerr.ErrCheck)
	}
	return matched, nil
}

// Scope returns the "scope" claim as a slice of strings.
//
// OAuth2 conventionally encodes scope as a space-separated string. This helper accepts
// []string, []any, and either space-separated or CSV strings.
func Scope(c jwt.MapClaims) ([]string, error) {
	v, ok := c[KeyScope]
	if !ok {
		return nil, fmt.Errorf("%w: scope missing", pkgerr.ErrNotFound)
	}
	switch s := v.(type) {
	case string:
		if s == "" {
			return nil, fmt.Errorf("%w: scope empty", pkgerr.ErrEmptyValue)
		}
		if strings.Contains(s, " ") {
			return strings.Fields(s), nil
		}
		return strings.Split(s, ","), nil
	case []string:
		if len(s) == 0 {
			return nil, fmt.Errorf("%w: scope empty", pkgerr.ErrEmptyValue)
		}
		return s, nil
	case []any:
		if len(s) == 0 {
			return nil, fmt.Errorf("%w: scope empty", pkgerr.ErrEmptyValue)
		}
		out := make([]string, len(s))
		for i, item := range s {
			str, ok := item.(string)
			if !ok {
				return nil, fmt.Errorf("%w: scope element must be string: got %T", pkgerr.ErrInvalidClaims, item)
			}
			out[i] = str
		}
		return out, nil
	default:
		return nil, fmt.Errorf("%w: scope must be string, []string, or []any: got %T", pkgerr.ErrInvalidClaims, v)
	}
}

// SetScope sets the "scope" claim as a space-separated string per OAuth2 conventions.
func SetScope(c jwt.MapClaims, scope ...string) {
	c[KeyScope] = strings.Join(scope, " ")
}

// DeleteScope removes the "scope" claim.
func DeleteScope(c jwt.MapClaims) { delete(c, KeyScope) }

// Name returns the "name" claim as a string.
func Name(c jwt.MapClaims) (string, error) { return readString(c, KeyName, "name") }

// SetName sets the "name" claim, trimming surrounding whitespace.
func SetName(c jwt.MapClaims, name string) { c[KeyName] = strings.TrimSpace(name) }

// DeleteName removes the "name" claim.
func DeleteName(c jwt.MapClaims) { delete(c, KeyName) }

// FirstName returns the "first_name" claim as a string.
func FirstName(c jwt.MapClaims) (string, error) { return readString(c, KeyFirstName, "first name") }

// SetFirstName sets the "first_name" claim, trimming surrounding whitespace.
func SetFirstName(c jwt.MapClaims, name string) { c[KeyFirstName] = strings.TrimSpace(name) }

// DeleteFirstName removes the "first_name" claim.
func DeleteFirstName(c jwt.MapClaims) { delete(c, KeyFirstName) }

// LastName returns the "last_name" claim as a string.
func LastName(c jwt.MapClaims) (string, error) { return readString(c, KeyLastName, "last name") }

// SetLastName sets the "last_name" claim, trimming surrounding whitespace.
func SetLastName(c jwt.MapClaims, name string) { c[KeyLastName] = strings.TrimSpace(name) }

// DeleteLastName removes the "last_name" claim.
func DeleteLastName(c jwt.MapClaims) { delete(c, KeyLastName) }

// Username returns the "username" claim as a string.
func Username(c jwt.MapClaims) (string, error) { return readString(c, KeyUsername, "username") }

// SetUsername sets the "username" claim, trimming surrounding whitespace.
func SetUsername(c jwt.MapClaims, u string) { c[KeyUsername] = strings.TrimSpace(u) }

// DeleteUsername removes the "username" claim.
func DeleteUsername(c jwt.MapClaims) { delete(c, KeyUsername) }

// Email returns the "email" claim as a string.
func Email(c jwt.MapClaims) (string, error) { return readString(c, KeyEmail, "email") }

// SetEmail sets the "email" claim, trimming surrounding whitespace.
func SetEmail(c jwt.MapClaims, e string) { c[KeyEmail] = strings.TrimSpace(e) }

// DeleteEmail removes the "email" claim.
func DeleteEmail(c jwt.MapClaims) { delete(c, KeyEmail) }

// TokenType returns the "token_type" claim as a string.
func TokenType(c jwt.MapClaims) (string, error) { return readString(c, KeyTokenType, "token type") }

// SetTokenType sets the "token_type" claim, trimming surrounding whitespace.
func SetTokenType(c jwt.MapClaims, t string) { c[KeyTokenType] = strings.TrimSpace(t) }

// DeleteTokenType removes the "token_type" claim.
func DeleteTokenType(c jwt.MapClaims) { delete(c, KeyTokenType) }

// readStringSlice reads a string-slice claim, accepting []string, []any, and CSV string.
func readStringSlice(c jwt.MapClaims, key, label string) ([]string, error) {

	v, ok := c[key]
	if !ok {
		return nil, fmt.Errorf("%w: %s missing", pkgerr.ErrNotFound, label)
	}

	switch s := v.(type) {
	case []string:
		if len(s) == 0 {
			return nil, fmt.Errorf("%w: %s empty", pkgerr.ErrEmptyValue, label)
		}
		return s, nil
	case []any:
		if len(s) == 0 {
			return nil, fmt.Errorf("%w: %s empty", pkgerr.ErrEmptyValue, label)
		}
		out := make([]string, len(s))
		for i, item := range s {
			str, ok := item.(string)
			if !ok {
				return nil, fmt.Errorf("%w: %s element must be string: got %T", pkgerr.ErrInvalidClaims, label, item)
			}
			out[i] = str
		}
		return out, nil
	case string:
		if s == "" {
			return nil, fmt.Errorf("%w: %s empty", pkgerr.ErrEmptyValue, label)
		}
		return strings.Split(s, ","), nil
	default:
		return nil, fmt.Errorf(
			"%w: %s must be []string, []any, or string: got %T",
			pkgerr.ErrInvalidClaims, label, v,
		)
	}
}
