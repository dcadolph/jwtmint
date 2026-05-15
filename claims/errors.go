package claims

import "errors"

var (
	// ErrNoGroups is returned when a groups-related operation finds no matching groups.
	ErrNoGroups = errors.New("no groups")

	// ErrNoAudience is returned when an audience-related operation finds no matching audience.
	ErrNoAudience = errors.New("no audience")

	// ErrNoRoles is returned when a roles-related operation finds no matching roles.
	ErrNoRoles = errors.New("no roles")
)
