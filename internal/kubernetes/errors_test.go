package kubernetes

import (
	"errors"
	"testing"
)

func TestClientError_Error(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		err      *ClientError
		expected string
	}{
		{
			name: "full error with namespace and resource",
			err: &ClientError{
				Op:        "get deployment",
				Namespace: "default",
				Resource:  "my-app",
				Err:       ErrDeploymentNotFound,
			},
			expected: "get deployment default/my-app: deployment not found",
		},
		{
			name: "error with resource only",
			err: &ClientError{
				Op:       "create",
				Resource: "my-app",
				Err:      errors.New("already exists"),
			},
			expected: "create my-app: already exists",
		},
		{
			name: "error with operation only",
			err: &ClientError{
				Op:  "connect",
				Err: ErrConnectionFailed,
			},
			expected: "connect: failed to connect to kubernetes API",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.err.Error(); got != tt.expected {
				t.Errorf("ClientError.Error() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestClientError_Unwrap(t *testing.T) {
	t.Parallel()

	underlyingErr := ErrDeploymentNotFound
	err := &ClientError{
		Op:  "get",
		Err: underlyingErr,
	}

	if !errors.Is(err, underlyingErr) {
		t.Error("expected errors.Is to match underlying error")
	}
}

func TestNewClientError(t *testing.T) {
	t.Parallel()

	err := NewClientError("get", "default", "my-app", ErrDeploymentNotFound)

	if err.Op != "get" {
		t.Errorf("Op = %v, want get", err.Op)
	}
	if err.Namespace != "default" {
		t.Errorf("Namespace = %v, want default", err.Namespace)
	}
	if err.Resource != "my-app" {
		t.Errorf("Resource = %v, want my-app", err.Resource)
	}
	if !errors.Is(err, ErrDeploymentNotFound) {
		t.Error("expected underlying error to be ErrDeploymentNotFound")
	}
}

func TestHealthError_Error(t *testing.T) {
	t.Parallel()

	err := &HealthError{
		TotalPods:     5,
		HealthyPods:   3,
		UnhealthyPods: []string{"pod-1", "pod-2"},
		Err:           ErrUnhealthyPods,
	}

	expected := "health check failed: 3/5 pods healthy: unhealthy pods detected"
	if got := err.Error(); got != expected {
		t.Errorf("HealthError.Error() = %v, want %v", got, expected)
	}
}

func TestHealthError_Unwrap(t *testing.T) {
	t.Parallel()

	err := &HealthError{
		Err: ErrUnhealthyPods,
	}

	if !errors.Is(err, ErrUnhealthyPods) {
		t.Error("expected errors.Is to match ErrUnhealthyPods")
	}
}

func TestIsNotFound(t *testing.T) {
	t.Parallel()

	tests := []struct {
		err      error
		name     string
		expected bool
	}{
		{ErrDeploymentNotFound, "deployment not found", true},
		{ErrPodNotFound, "pod not found", true},
		{ErrNamespaceNotFound, "namespace not found", true},
		{ErrResourceNotFound, "resource not found", true},
		{NewClientError("get", "ns", "res", ErrDeploymentNotFound), "wrapped deployment not found", true},
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
		{NewClientError("wait", "ns", "res", ErrTimeout), "wrapped timeout", true},
		{ErrDeploymentNotFound, "not found error", false},
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

func TestIsUnauthorized(t *testing.T) {
	t.Parallel()

	tests := []struct {
		err      error
		name     string
		expected bool
	}{
		{ErrUnauthorized, "unauthorized", true},
		{ErrForbidden, "forbidden", true},
		{NewClientError("get", "ns", "res", ErrUnauthorized), "wrapped unauthorized", true},
		{ErrDeploymentNotFound, "not found error", false},
		{nil, "nil error", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := IsUnauthorized(tt.err); got != tt.expected {
				t.Errorf("IsUnauthorized() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestIsConfigError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		err      error
		name     string
		expected bool
	}{
		{ErrInvalidConfig, "invalid config", true},
		{ErrKubeconfigNotFound, "kubeconfig not found", true},
		{ErrNotInCluster, "not in cluster", true},
		{ErrNoContextFound, "no context", true},
		{NewClientError("new", "", "", ErrInvalidConfig), "wrapped config error", true},
		{ErrTimeout, "timeout error", false},
		{nil, "nil error", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := IsConfigError(tt.err); got != tt.expected {
				t.Errorf("IsConfigError() = %v, want %v", got, tt.expected)
			}
		})
	}
}
