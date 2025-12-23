package gates

import (
	"context"
	"fmt"
)

// RollbackHandler manages automatic rollbacks.
// Fields are ordered for optimal memory alignment.
type RollbackHandler struct {
	helmClient HelmClient
	kubeClient KubeClient
}

// NewRollbackHandler creates a new rollback handler.
func NewRollbackHandler(helmClient HelmClient, kubeClient KubeClient) *RollbackHandler {
	return &RollbackHandler{
		helmClient: helmClient,
		kubeClient: kubeClient,
	}
}

// ShouldRollback determines if rollback is needed based on gate result.
func (h *RollbackHandler) ShouldRollback(result *GateResult) bool {
	if result == nil {
		return false
	}
	return !result.Passed
}

// Execute performs the rollback.
func (h *RollbackHandler) Execute(ctx context.Context, opts RollbackOptions) error {
	if ctx == nil {
		return ErrNilContext
	}
	if h.helmClient == nil {
		return ErrMissingHelmClient
	}

	if err := opts.Validate(); err != nil {
		return err
	}

	// Get previous revision if not specified.
	revision := opts.Revision
	if revision == 0 {
		prevRevision, err := h.GetPreviousRevision(ctx, opts.Namespace, opts.ReleaseName)
		if err != nil {
			return NewGateError("rollback", "", opts.Namespace, opts.ReleaseName, err)
		}
		revision = prevRevision
	}

	// Perform rollback.
	if err := h.helmClient.Rollback(ctx, opts.Namespace, opts.ReleaseName, revision); err != nil {
		return NewGateError("rollback", "", opts.Namespace, opts.ReleaseName,
			fmt.Errorf("%w: %v", ErrRollbackFailed, err))
	}

	return nil
}

// GetPreviousRevision gets the previous healthy revision.
func (h *RollbackHandler) GetPreviousRevision(ctx context.Context, namespace, release string) (int, error) {
	if ctx == nil {
		return 0, ErrNilContext
	}
	if h.helmClient == nil {
		return 0, ErrMissingHelmClient
	}
	if namespace == "" {
		return 0, ErrEmptyNamespace
	}
	if release == "" {
		return 0, ErrEmptyReleaseName
	}

	currentRevision, err := h.helmClient.GetCurrentRevision(ctx, namespace, release)
	if err != nil {
		return 0, NewGateError("get revision", "", namespace, release, err)
	}

	// Previous revision is current - 1.
	if currentRevision <= 1 {
		return 0, NewGateError("get revision", "", namespace, release,
			fmt.Errorf("no previous revision available (current: %d)", currentRevision))
	}

	return currentRevision - 1, nil
}

// RollbackResult contains the result of a rollback operation.
// Fields are ordered for optimal memory alignment.
type RollbackResult struct {
	Namespace    string `json:"namespace"`
	ReleaseName  string `json:"release_name"`
	ErrorMessage string `json:"error_message,omitempty"`
	FromRevision int    `json:"from_revision"`
	ToRevision   int    `json:"to_revision"`
	Success      bool   `json:"success"`
}

// ExecuteWithResult performs rollback and returns detailed result.
func (h *RollbackHandler) ExecuteWithResult(ctx context.Context, opts RollbackOptions) (*RollbackResult, error) {
	if ctx == nil {
		return nil, ErrNilContext
	}

	result := &RollbackResult{
		Namespace:   opts.Namespace,
		ReleaseName: opts.ReleaseName,
	}

	// Get current revision.
	currentRevision, err := h.helmClient.GetCurrentRevision(ctx, opts.Namespace, opts.ReleaseName)
	if err != nil {
		result.ErrorMessage = err.Error()
		return result, err
	}
	result.FromRevision = currentRevision

	// Determine target revision.
	targetRevision := opts.Revision
	if targetRevision == 0 {
		targetRevision = currentRevision - 1
	}
	if targetRevision < 1 {
		result.ErrorMessage = "no previous revision available"
		return result, fmt.Errorf("no previous revision available")
	}
	result.ToRevision = targetRevision

	// Perform rollback.
	opts.Revision = targetRevision
	if err := h.Execute(ctx, opts); err != nil {
		result.ErrorMessage = err.Error()
		return result, err
	}

	result.Success = true
	return result, nil
}

// AutoRollbackConfig configures automatic rollback behavior.
// Fields are ordered for optimal memory alignment.
type AutoRollbackConfig struct {
	MaxRetries    int  `json:"max_retries"`
	Enabled       bool `json:"enabled"`
	OnPreCheck    bool `json:"on_pre_check"`
	OnPostCheck   bool `json:"on_post_check"`
	OnDeployError bool `json:"on_deploy_error"`
}

// DefaultAutoRollbackConfig returns the default auto-rollback configuration.
func DefaultAutoRollbackConfig() AutoRollbackConfig {
	return AutoRollbackConfig{
		Enabled:       true,
		OnPreCheck:    false, // Don't rollback on pre-check (nothing deployed yet).
		OnPostCheck:   true,  // Rollback on post-check failure.
		OnDeployError: true,  // Rollback on deployment error.
		MaxRetries:    1,
	}
}

// ShouldRollbackOn determines if rollback should occur for a given failure type.
func (c *AutoRollbackConfig) ShouldRollbackOn(failureType string) bool {
	if !c.Enabled {
		return false
	}

	switch failureType {
	case "pre_check":
		return c.OnPreCheck
	case "post_check":
		return c.OnPostCheck
	case "deploy_error":
		return c.OnDeployError
	default:
		return false
	}
}
