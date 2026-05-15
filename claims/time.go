package claims

import (
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/dcadolph/jwtsmith/pkgerr"
)

// Timestamp normalizes an arbitrary value to a *jwt.NumericDate.
//
// Standard registered claims like "exp" and "iat" are typically *jwt.NumericDate after
// parsing, but custom claims may use raw numbers, RFC3339 strings, or json.Number.
// Timestamp accepts all of those so callers can compare and inspect times consistently.
func Timestamp(v any) (*jwt.NumericDate, error) {

	switch t := v.(type) {

	case *jwt.NumericDate:
		if t == nil {
			return nil, fmt.Errorf("%w: nil *jwt.NumericDate", pkgerr.ErrInvalidValue)
		}
		if t.IsZero() {
			return nil, fmt.Errorf("%w: zero-value *jwt.NumericDate", pkgerr.ErrInvalidValue)
		}
		return jwt.NewNumericDate(t.Time), nil

	case jwt.NumericDate:
		if t.IsZero() {
			return nil, fmt.Errorf("%w: zero-value jwt.NumericDate", pkgerr.ErrInvalidValue)
		}
		return jwt.NewNumericDate(t.Time), nil

	case *time.Time:
		if t == nil {
			return nil, fmt.Errorf("%w: nil *time.Time", pkgerr.ErrInvalidValue)
		}
		if t.IsZero() {
			return nil, fmt.Errorf("%w: zero-value *time.Time", pkgerr.ErrInvalidValue)
		}
		return jwt.NewNumericDate(*t), nil

	case time.Time:
		if t.IsZero() {
			return nil, fmt.Errorf("%w: zero-value time.Time", pkgerr.ErrInvalidValue)
		}
		return jwt.NewNumericDate(t), nil

	case *float64:
		if t == nil {
			return nil, fmt.Errorf("%w: nil *float64", pkgerr.ErrInvalidValue)
		}
		return TimeFromFloat(*t)

	case float64:
		return TimeFromFloat(t)

	case json.Number:
		if i, err := t.Int64(); err == nil {
			return TimeFromFloat(float64(i))
		}
		f, err := t.Float64()
		if err != nil {
			return nil, fmt.Errorf("%w: invalid json.Number: %w", pkgerr.ErrInvalidValue, err)
		}
		return TimeFromFloat(f)

	case *string:
		if t == nil {
			return nil, fmt.Errorf("%w: nil *string", pkgerr.ErrInvalidValue)
		}
		return parseStringToNumericDate(*t)

	case string:
		return parseStringToNumericDate(t)

	case *int64:
		if t == nil {
			return nil, fmt.Errorf("%w: nil *int64", pkgerr.ErrInvalidValue)
		}
		return TimeFromFloat(float64(*t))

	case int64:
		return TimeFromFloat(float64(t))

	case *int:
		if t == nil {
			return nil, fmt.Errorf("%w: nil *int", pkgerr.ErrInvalidValue)
		}
		return TimeFromFloat(float64(*t))

	case int:
		return TimeFromFloat(float64(t))

	default:
		return nil, fmt.Errorf("%w: unsupported timestamp type %T", pkgerr.ErrInvalidType, v)
	}
}

// TimeFromFloat converts a unix-seconds float to a *jwt.NumericDate, preserving sub-second precision.
func TimeFromFloat(v float64) (*jwt.NumericDate, error) {
	if v < 1 {
		return nil, fmt.Errorf("%w: time value less than 1", pkgerr.ErrInvalidValue)
	}
	seconds := int64(v)
	frac := v - float64(seconds)
	return jwt.NewNumericDate(time.Unix(seconds, int64(frac*1e9))), nil
}

// parseStringToNumericDate parses an RFC3339 timestamp or unix-seconds numeric string.
func parseStringToNumericDate(s string) (*jwt.NumericDate, error) {

	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return jwt.NewNumericDate(t), nil
	}

	if f, err := strconv.ParseFloat(s, 64); err == nil {
		return TimeFromFloat(f)
	}

	return nil, fmt.Errorf("%w: invalid string timestamp: %s", pkgerr.ErrInvalidValue, s)
}
