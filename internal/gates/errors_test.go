package gates

import (
	"errors"
	"testing"
)

func TestGateError_Error(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		err      *GateError
		expected string
	}{
		{
			name: "full error with gate name and resource",
			err: &GateError{
				Op:        "evaluate",
				GateName:  "policy",
				Namespace: "default",
				Resource:  "my-deployment",
				Err:       ErrPolicyViolation,
			},
			expected: "evaluate gate policy on default/my-deployment: policy violation detected",
		},
		{
			name: "error with gate name only",
			err: &GateError{
				Op:       "evaluate",
				GateName: "health",
				Err:      ErrHealthCheckFailed,
			},
			expected: "evaluate gate health: health check failed",
		},
		{
			name: "error with operation only",
			err: &GateError{
				Op:  "deploy",
				Err: ErrDeploymentFailed,
			},
			expected: "deploy: deployment failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.err.Error(); got != tt.expected {
				t.Errorf("GateError.Error() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestGateError_Unwrap(t *testing.T) {
	t.Parallel()

	underlyingErr := ErrPolicyViolation
	err := &GateError{
		Op:  "evaluate",
		Err: underlyingErr,
	}

	if !errors.Is(err, underlyingErr) {
		t.Error("expected errors.Is to match underlying error")
	}
}

func TestNewGateError(t *testing.T) {
	t.Parallel()

	err := NewGateError("evaluate", "policy", "default", "my-app", ErrPolicyViolation)

	if err.Op != "evaluate" {
		t.Errorf("Op = %v, want evaluate", err.Op)
	}
	if err.GateName != "policy" {
		t.Errorf("GateName = %v, want policy", err.GateName)
	}
	if err.Namespace != "default" {
		t.Errorf("Namespace = %v, want default", err.Namespace)
	}
	if err.Resource != "my-app" {
		t.Errorf("Resource = %v, want my-app", err.Resource)
	}
	if !errors.Is(err, ErrPolicyViolation) {
		t.Error("expected underlying error to be ErrPolicyViolation")
	}
}

func TestIsPreCheckFailure(t *testing.T) {
	t.Parallel()

	tests := []struct {
		err      error
		name     string
		expected bool
	}{
		{ErrPreCheckFailed, "pre-check failed", true},
		{ErrPolicyViolation, "policy violation", true},
		{NewGateError("evaluate", "policy", "", "", ErrPolicyViolation), "wrapped policy violation", true},
		{ErrPostCheckFailed, "post-check failed", false},
		{nil, "nil error", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := IsPreCheckFailure(tt.err); got != tt.expected {
				t.Errorf("IsPreCheckFailure() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestIsPostCheckFailure(t *testing.T) {
	t.Parallel()

	tests := []struct {
		err      error
		name     string
		expected bool
	}{
		{ErrPostCheckFailed, "post-check failed", true},
		{ErrHealthCheckFailed, "health check failed", true},
		{ErrUnhealthyPods, "unhealthy pods", true},
		{ErrReadinessTimeout, "readiness timeout", true},
		{NewGateError("check", "health", "", "", ErrHealthCheckFailed), "wrapped health error", true},
		{ErrPreCheckFailed, "pre-check failed", false},
		{nil, "nil error", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := IsPostCheckFailure(tt.err); got != tt.expected {
				t.Errorf("IsPostCheckFailure() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestIsRollbackFailure(t *testing.T) {
	t.Parallel()

	tests := []struct {
		err      error
		name     string
		expected bool
	}{
		{ErrRollbackFailed, "rollback failed", true},
		{NewGateError("rollback", "", "", "", ErrRollbackFailed), "wrapped rollback error", true},
		{ErrDeploymentFailed, "deployment failed", false},
		{nil, "nil error", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := IsRollbackFailure(tt.err); got != tt.expected {
				t.Errorf("IsRollbackFailure() = %v, want %v", got, tt.expected)
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
		{ErrGateTimeout, "gate timeout", true},
		{ErrReadinessTimeout, "readiness timeout", true},
		{NewGateError("evaluate", "health", "", "", ErrGateTimeout), "wrapped timeout", true},
		{ErrDeploymentFailed, "deployment failed", false},
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

func TestIsPolicyViolation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		err      error
		name     string
		expected bool
	}{
		{ErrPolicyViolation, "policy violation", true},
		{NewGateError("evaluate", "policy", "", "", ErrPolicyViolation), "wrapped violation", true},
		{ErrPreCheckFailed, "pre-check failed", false},
		{nil, "nil error", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := IsPolicyViolation(tt.err); got != tt.expected {
				t.Errorf("IsPolicyViolation() = %v, want %v", got, tt.expected)
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
		{ErrMissingKubeClient, "missing kube client", true},
		{ErrMissingHelmClient, "missing helm client", true},
		{ErrMissingPolicyEngine, "missing policy engine", true},
		{NewGateError("init", "", "", "", ErrInvalidConfig), "wrapped config error", true},
		{ErrDeploymentFailed, "deployment failed", false},
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

func TestIsValidationError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		err      error
		name     string
		expected bool
	}{
		{ErrEmptyReleaseName, "empty release name", true},
		{ErrEmptyChartRef, "empty chart ref", true},
		{ErrEmptyNamespace, "empty namespace", true},
		{ErrEmptyGateName, "empty gate name", true},
		{NewGateError("validate", "", "", "", ErrEmptyReleaseName), "wrapped validation error", true},
		{ErrDeploymentFailed, "deployment failed", false},
		{nil, "nil error", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := IsValidationError(tt.err); got != tt.expected {
				t.Errorf("IsValidationError() = %v, want %v", got, tt.expected)
			}
		})
	}
}
