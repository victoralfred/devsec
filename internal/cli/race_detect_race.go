//go:build race

package cli

// isRaceEnabled returns true if the race detector is enabled.
// This file is for race-enabled builds.
func isRaceEnabled() bool {
	return true
}
