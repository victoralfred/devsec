// Package gates provides deployment gates for pre/post deployment validation.
package gates

import (
	"errors"
	"fmt"
)

// Sentinel errors for the gates package.
var (
	// Configuration errors.
	ErrNilContext          = errors.New("context cannot be nil")
	ErrInvalidConfig       = errors.New("invalid gates configuration")
	ErrMissingKubeClient   = errors.New("kubernetes client is required")
	ErrMissingHelmClient   = errors.New("helm client is required")
	ErrMissingPolicyEngine = errors.New("policy engine is required for pre-checks")

	// Gate errors.
	ErrPreCheckFailed  = errors.New("pre-deployment check failed")
	ErrPostCheckFailed = errors.New("post-deployment verification failed")
	ErrGateTimeout     = errors.New("gate evaluation timed out")
	ErrPolicyViolation = errors.New("policy violation detected")

	// Deployment errors.
	ErrDeploymentFailed  = errors.New("deployment failed")
	ErrRollbackFailed    = errors.New("rollback failed")
	ErrHealthCheckFailed = errors.New("health check failed")
	ErrUnhealthyPods     = errors.New("unhealthy pods detected")
	ErrReadinessTimeout  = errors.New("readiness check timed out")

	// Validation errors.
	ErrEmptyReleaseName = errors.New("release name cannot be empty")
	ErrEmptyChartRef    = errors.New("chart reference cannot be empty")
	ErrEmptyNamespace   = errors.New("namespace cannot be empty")
	ErrEmptyGateName    = errors.New("gate name cannot be empty")
	ErrNoFindings       = errors.New("no findings to evaluate")
)

// GateError represents a gate operation error.
// Fields are ordered for optimal memory alignment.
type GateError struct {
	Err       error
	GateName  string
	Namespace string
	Resource  string
	Op        string
}

// Error returns the error message.
func (e *GateError) Error() string {
	if e.GateName != "" && e.Resource != "" {
		return fmt.Sprintf("%s gate %s on %s/%s: %v", e.Op, e.GateName, e.Namespace, e.Resource, e.Err)
	}
	if e.GateName != "" {
		return fmt.Sprintf("%s gate %s: %v", e.Op, e.GateName, e.Err)
	}
	return fmt.Sprintf("%s: %v", e.Op, e.Err)
}

// Unwrap returns the underlying error.
func (e *GateError) Unwrap() error {
	return e.Err
}

// NewGateError creates a new GateError.
func NewGateError(op, gateName, namespace, resource string, err error) *GateError {
	return &GateError{
		Err:       err,
		GateName:  gateName,
		Namespace: namespace,
		Resource:  resource,
		Op:        op,
	}
}

// IsPreCheckFailure returns true if the error indicates a pre-check failure.
func IsPreCheckFailure(err error) bool {
	return errors.Is(err, ErrPreCheckFailed) || errors.Is(err, ErrPolicyViolation)
}

// IsPostCheckFailure returns true if the error indicates a post-check failure.
func IsPostCheckFailure(err error) bool {
	return errors.Is(err, ErrPostCheckFailed) ||
		errors.Is(err, ErrHealthCheckFailed) ||
		errors.Is(err, ErrUnhealthyPods) ||
		errors.Is(err, ErrReadinessTimeout)
}

// IsRollbackFailure returns true if the error indicates a rollback failure.
func IsRollbackFailure(err error) bool {
	return errors.Is(err, ErrRollbackFailed)
}

// IsTimeout returns true if the error indicates a timeout.
func IsTimeout(err error) bool {
	return errors.Is(err, ErrGateTimeout) || errors.Is(err, ErrReadinessTimeout)
}

// IsPolicyViolation returns true if the error indicates a policy violation.
func IsPolicyViolation(err error) bool {
	return errors.Is(err, ErrPolicyViolation)
}

// IsConfigError returns true if the error indicates a configuration problem.
func IsConfigError(err error) bool {
	return errors.Is(err, ErrInvalidConfig) ||
		errors.Is(err, ErrMissingKubeClient) ||
		errors.Is(err, ErrMissingHelmClient) ||
		errors.Is(err, ErrMissingPolicyEngine)
}

// IsValidationError returns true if the error indicates a validation problem.
func IsValidationError(err error) bool {
	return errors.Is(err, ErrEmptyReleaseName) ||
		errors.Is(err, ErrEmptyChartRef) ||
		errors.Is(err, ErrEmptyNamespace) ||
		errors.Is(err, ErrEmptyGateName)
}
