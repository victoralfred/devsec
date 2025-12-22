package helm

import (
	"errors"
	"testing"
)

func TestHelmError_Error(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		err      *HelmError
		expected string
	}{
		{
			name: "full error with namespace and release",
			err: &HelmError{
				Op:        "install",
				Namespace: "default",
				Release:   "my-app",
				Err:       ErrInstallFailed,
			},
			expected: "install default/my-app: installation failed",
		},
		{
			name: "error with release only",
			err: &HelmError{
				Op:      "upgrade",
				Release: "my-app",
				Err:     ErrUpgradeFailed,
			},
			expected: "upgrade my-app: upgrade failed",
		},
		{
			name: "error with operation only",
			err: &HelmError{
				Op:  "load chart",
				Err: ErrChartLoadFailed,
			},
			expected: "load chart: failed to load chart",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.err.Error(); got != tt.expected {
				t.Errorf("HelmError.Error() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestHelmError_Unwrap(t *testing.T) {
	t.Parallel()

	underlyingErr := ErrReleaseNotFound
	err := &HelmError{
		Op:  "get",
		Err: underlyingErr,
	}

	if !errors.Is(err, underlyingErr) {
		t.Error("expected errors.Is to match underlying error")
	}
}

func TestNewHelmError(t *testing.T) {
	t.Parallel()

	err := NewHelmError("install", "default", "my-app", ErrInstallFailed)

	if err.Op != "install" {
		t.Errorf("Op = %v, want install", err.Op)
	}
	if err.Namespace != "default" {
		t.Errorf("Namespace = %v, want default", err.Namespace)
	}
	if err.Release != "my-app" {
		t.Errorf("Release = %v, want my-app", err.Release)
	}
	if !errors.Is(err, ErrInstallFailed) {
		t.Error("expected underlying error to be ErrInstallFailed")
	}
}

func TestIsNotFound(t *testing.T) {
	t.Parallel()

	tests := []struct {
		err      error
		name     string
		expected bool
	}{
		{ErrReleaseNotFound, "release not found", true},
		{ErrChartNotFound, "chart not found", true},
		{ErrRevisionNotFound, "revision not found", true},
		{NewHelmError("get", "ns", "rel", ErrReleaseNotFound), "wrapped release not found", true},
		{ErrTimeout, "timeout error", false},
		{nil, "nil error", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := IsNotFound(tt.err); got != tt.expected {
				t.Errorf("IsNotFound() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestIsTimeout(t *testing.T) {
	t.Parallel()

	tests := []struct {
		err      error
		name     string
		expected bool
	}{
		{ErrTimeout, "timeout error", true},
		{NewHelmError("install", "ns", "rel", ErrTimeout), "wrapped timeout", true},
		{ErrReleaseNotFound, "not found error", false},
		{nil, "nil error", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := IsTimeout(tt.err); got != tt.expected {
				t.Errorf("IsTimeout() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestIsChartError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		err      error
		name     string
		expected bool
	}{
		{ErrChartNotFound, "chart not found", true},
		{ErrChartInvalid, "chart invalid", true},
		{ErrChartLoadFailed, "chart load failed", true},
		{NewHelmError("load", "", "", ErrChartNotFound), "wrapped chart not found", true},
		{ErrReleaseNotFound, "release not found", false},
		{nil, "nil error", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := IsChartError(tt.err); got != tt.expected {
				t.Errorf("IsChartError() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestIsReleaseError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		err      error
		name     string
		expected bool
	}{
		{ErrReleaseNotFound, "release not found", true},
		{ErrReleaseExists, "release exists", true},
		{ErrReleaseFailed, "release failed", true},
		{ErrRevisionNotFound, "revision not found", true},
		{NewHelmError("get", "ns", "rel", ErrReleaseNotFound), "wrapped release error", true},
		{ErrChartNotFound, "chart not found", false},
		{nil, "nil error", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := IsReleaseError(tt.err); got != tt.expected {
				t.Errorf("IsReleaseError() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestIsOperationError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		err      error
		name     string
		expected bool
	}{
		{ErrInstallFailed, "install failed", true},
		{ErrUpgradeFailed, "upgrade failed", true},
		{ErrRollbackFailed, "rollback failed", true},
		{ErrUninstallFailed, "uninstall failed", true},
		{NewHelmError("install", "ns", "rel", ErrInstallFailed), "wrapped install error", true},
		{ErrTimeout, "timeout", false},
		{nil, "nil error", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := IsOperationError(tt.err); got != tt.expected {
				t.Errorf("IsOperationError() = %v, want %v", got, tt.expected)
			}
		})
	}
}
