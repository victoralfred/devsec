// Package helm provides a Helm client for chart deployment and management.
package helm

import (
	"errors"
	"fmt"
)

// Sentinel errors for the helm package.
var (
	// Configuration errors.
	ErrNilContext       = errors.New("context cannot be nil")
	ErrInvalidConfig    = errors.New("invalid helm configuration")
	ErrEmptyReleaseName = errors.New("release name cannot be empty")
	ErrEmptyChartRef    = errors.New("chart reference cannot be empty")
	ErrEmptyNamespace   = errors.New("namespace cannot be empty")

	// Chart errors.
	ErrChartNotFound   = errors.New("chart not found")
	ErrChartInvalid    = errors.New("invalid chart")
	ErrChartLoadFailed = errors.New("failed to load chart")

	// Release errors.
	ErrReleaseNotFound  = errors.New("release not found")
	ErrReleaseExists    = errors.New("release already exists")
	ErrReleaseFailed    = errors.New("release failed")
	ErrRevisionNotFound = errors.New("revision not found")

	// Operation errors.
	ErrInstallFailed   = errors.New("installation failed")
	ErrUpgradeFailed   = errors.New("upgrade failed")
	ErrRollbackFailed  = errors.New("rollback failed")
	ErrUninstallFailed = errors.New("uninstall failed")
	ErrTimeout         = errors.New("operation timed out")

	// Values errors.
	ErrValuesLoadFailed  = errors.New("failed to load values")
	ErrValuesMergeFailed = errors.New("failed to merge values")
)

// HelmError represents a Helm operation error.
// Fields are ordered for optimal memory alignment.
//
//nolint:revive // HelmError is intentionally named for clarity.
type HelmError struct {
	Err       error
	Op        string
	Release   string
	Namespace string
}

// Error returns the error message.
func (e *HelmError) Error() string {
	if e.Namespace != "" && e.Release != "" {
		return fmt.Sprintf("%s %s/%s: %v", e.Op, e.Namespace, e.Release, e.Err)
	}
	if e.Release != "" {
		return fmt.Sprintf("%s %s: %v", e.Op, e.Release, e.Err)
	}
	return fmt.Sprintf("%s: %v", e.Op, e.Err)
}

// Unwrap returns the underlying error.
func (e *HelmError) Unwrap() error {
	return e.Err
}

// NewHelmError creates a new HelmError.
func NewHelmError(op, namespace, release string, err error) *HelmError {
	return &HelmError{
		Err:       err,
		Op:        op,
		Release:   release,
		Namespace: namespace,
	}
}

// IsNotFound returns true if the error indicates a resource was not found.
func IsNotFound(err error) bool {
	return errors.Is(err, ErrReleaseNotFound) ||
		errors.Is(err, ErrChartNotFound) ||
		errors.Is(err, ErrRevisionNotFound)
}

// IsTimeout returns true if the error indicates a timeout.
func IsTimeout(err error) bool {
	return errors.Is(err, ErrTimeout)
}

// IsChartError returns true if the error is chart-related.
func IsChartError(err error) bool {
	return errors.Is(err, ErrChartNotFound) ||
		errors.Is(err, ErrChartInvalid) ||
		errors.Is(err, ErrChartLoadFailed)
}

// IsReleaseError returns true if the error is release-related.
func IsReleaseError(err error) bool {
	return errors.Is(err, ErrReleaseNotFound) ||
		errors.Is(err, ErrReleaseExists) ||
		errors.Is(err, ErrReleaseFailed) ||
		errors.Is(err, ErrRevisionNotFound)
}

// IsOperationError returns true if the error is operation-related.
func IsOperationError(err error) bool {
	return errors.Is(err, ErrInstallFailed) ||
		errors.Is(err, ErrUpgradeFailed) ||
		errors.Is(err, ErrRollbackFailed) ||
		errors.Is(err, ErrUninstallFailed)
}
