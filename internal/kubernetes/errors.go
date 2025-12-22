// Package kubernetes provides a Kubernetes client for deployment integration.
package kubernetes

import (
	"errors"
	"fmt"
)

// Sentinel errors for the kubernetes package.
var (
	// Configuration errors.
	ErrNilContext         = errors.New("context cannot be nil")
	ErrInvalidConfig      = errors.New("invalid kubernetes configuration")
	ErrKubeconfigNotFound = errors.New("kubeconfig file not found")
	ErrNotInCluster       = errors.New("not running in kubernetes cluster")
	ErrNoContextFound     = errors.New("no context found in kubeconfig")

	// Connection errors.
	ErrConnectionFailed = errors.New("failed to connect to kubernetes API")
	ErrUnauthorized     = errors.New("unauthorized to access kubernetes API")
	ErrForbidden        = errors.New("forbidden access to kubernetes resource")

	// Resource errors.
	ErrDeploymentNotFound = errors.New("deployment not found")
	ErrPodNotFound        = errors.New("pod not found")
	ErrNamespaceNotFound  = errors.New("namespace not found")
	ErrResourceNotFound   = errors.New("resource not found")

	// Operation errors.
	ErrTimeout         = errors.New("operation timed out")
	ErrRolloutFailed   = errors.New("rollout failed")
	ErrUnhealthyPods   = errors.New("unhealthy pods detected")
	ErrWaitInterrupted = errors.New("wait operation interrupted")
	ErrInvalidSelector = errors.New("invalid label selector")

	// Validation errors.
	ErrEmptyName      = errors.New("name cannot be empty")
	ErrEmptyNamespace = errors.New("namespace cannot be empty")
)

// ClientError represents a Kubernetes operation error.
// Fields are ordered for optimal memory alignment.
type ClientError struct {
	Err       error
	Op        string
	Namespace string
	Resource  string
}

// Error returns the error message.
func (e *ClientError) Error() string {
	if e.Namespace != "" && e.Resource != "" {
		return fmt.Sprintf("%s %s/%s: %v", e.Op, e.Namespace, e.Resource, e.Err)
	}
	if e.Resource != "" {
		return fmt.Sprintf("%s %s: %v", e.Op, e.Resource, e.Err)
	}
	return fmt.Sprintf("%s: %v", e.Op, e.Err)
}

// Unwrap returns the underlying error.
func (e *ClientError) Unwrap() error {
	return e.Err
}

// NewClientError creates a new ClientError.
func NewClientError(op, namespace, resource string, err error) *ClientError {
	return &ClientError{
		Err:       err,
		Op:        op,
		Namespace: namespace,
		Resource:  resource,
	}
}

// HealthError represents a health check failure.
// Fields are ordered for optimal memory alignment.
type HealthError struct {
	Err           error
	UnhealthyPods []string
	TotalPods     int
	HealthyPods   int
}

// Error returns the error message.
func (e *HealthError) Error() string {
	return fmt.Sprintf("health check failed: %d/%d pods healthy: %v",
		e.HealthyPods, e.TotalPods, e.Err)
}

// Unwrap returns the underlying error.
func (e *HealthError) Unwrap() error {
	return e.Err
}

// IsNotFound returns true if the error indicates a resource was not found.
func IsNotFound(err error) bool {
	return errors.Is(err, ErrDeploymentNotFound) ||
		errors.Is(err, ErrPodNotFound) ||
		errors.Is(err, ErrNamespaceNotFound) ||
		errors.Is(err, ErrResourceNotFound)
}

// IsTimeout returns true if the error indicates a timeout.
func IsTimeout(err error) bool {
	return errors.Is(err, ErrTimeout)
}

// IsUnauthorized returns true if the error indicates an authorization failure.
func IsUnauthorized(err error) bool {
	return errors.Is(err, ErrUnauthorized) || errors.Is(err, ErrForbidden)
}

// IsConfigError returns true if the error indicates a configuration problem.
func IsConfigError(err error) bool {
	return errors.Is(err, ErrInvalidConfig) ||
		errors.Is(err, ErrKubeconfigNotFound) ||
		errors.Is(err, ErrNotInCluster) ||
		errors.Is(err, ErrNoContextFound)
}
