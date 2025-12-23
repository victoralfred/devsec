package metrics

import "errors"

// Sentinel errors for the metrics package.
var (
	// ErrServerAlreadyRunning is returned when trying to start an already running server.
	ErrServerAlreadyRunning = errors.New("metrics server is already running")

	// ErrServerNotRunning is returned when trying to stop a server that is not running.
	ErrServerNotRunning = errors.New("metrics server is not running")

	// ErrInvalidAddress is returned when the server address is invalid.
	ErrInvalidAddress = errors.New("invalid server address")

	// ErrInvalidPath is returned when the metrics path is invalid.
	ErrInvalidPath = errors.New("invalid metrics path")
)
