package claims

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/go-cmp/cmp"

	"github.com/dcadolph/jwtmint/pkgerr"
)

// TestTimestamp tests Timestamp normalization across supported input types.
func TestTimestamp(t *testing.T) {
	t.Parallel()

	tests := []struct {
		WantND *jwt.NumericDate
		Want   error
		Input  any
	}{
		{ // Test 0: Valid jwt.NumericDate value.
			Input:  *jwt.NewNumericDate(time.Unix(1609459200, 0)),
			WantND: jwt.NewNumericDate(time.Unix(1609459200, 0)),
		},
		{ // Test 1: Nil *jwt.NumericDate.
			Input: (*jwt.NumericDate)(nil),
			Want:  pkgerr.ErrInvalidValue,
		},
		{ // Test 2: Valid *jwt.NumericDate.
			Input:  jwt.NewNumericDate(time.Unix(1609459200, 0)),
			WantND: jwt.NewNumericDate(time.Unix(1609459200, 0)),
		},
		{ // Test 3: Zero-value jwt.NumericDate.
			Input: jwt.NumericDate{},
			Want:  pkgerr.ErrInvalidValue,
		},
		{ // Test 4: Nil *float64.
			Input: (*float64)(nil),
			Want:  pkgerr.ErrInvalidValue,
		},
		{ // Test 5: Valid float64 with sub-second precision.
			Input:  1609459200.123456,
			WantND: jwt.NewNumericDate(time.Unix(1609459200, 123456000)),
		},
		{ // Test 6: float64 below 1.
			Input: 0.5,
			Want:  pkgerr.ErrInvalidValue,
		},
		{ // Test 7: Nil *time.Time.
			Input: (*time.Time)(nil),
			Want:  pkgerr.ErrInvalidValue,
		},
		{ // Test 8: Valid time.Time.
			Input:  time.Unix(1609459200, 0),
			WantND: jwt.NewNumericDate(time.Unix(1609459200, 0)),
		},
		{ // Test 9: Zero-value time.Time.
			Input: time.Time{},
			Want:  pkgerr.ErrInvalidValue,
		},
		{ // Test 10: Nil *int64.
			Input: (*int64)(nil),
			Want:  pkgerr.ErrInvalidValue,
		},
		{ // Test 11: Valid int64.
			Input:  int64(1609459200),
			WantND: jwt.NewNumericDate(time.Unix(1609459200, 0)),
		},
		{ // Test 12: Valid int.
			Input:  1609459200,
			WantND: jwt.NewNumericDate(time.Unix(1609459200, 0)),
		},
		{ // Test 13: Valid RFC3339 string.
			Input:  "2021-01-01T00:00:00Z",
			WantND: jwt.NewNumericDate(time.Unix(1609459200, 0).UTC()),
		},
		{ // Test 14: Valid numeric string.
			Input:  "1609459200",
			WantND: jwt.NewNumericDate(time.Unix(1609459200, 0)),
		},
		{ // Test 15: Unparseable string.
			Input: "tomorrow",
			Want:  pkgerr.ErrInvalidValue,
		},
		{ // Test 16: Unsupported type.
			Input: struct{}{},
			Want:  pkgerr.ErrInvalidType,
		},
	}

	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()

			got, err := Timestamp(test.Input)
			if !errors.Is(err, test.Want) {
				t.Fatalf("test %d: error mismatch\nwant: %v\ngot:  %v", testNum, test.Want, err)
			}
			if err != nil {
				return
			}
			if diff := cmp.Diff(test.WantND, got); diff != "" {
				t.Fatalf("test %d: mismatch (-want +got):\n%s", testNum, diff)
			}
		})
	}
}
