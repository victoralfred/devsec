package gates

import (
	"context"
	"fmt"
	"time"
)

// DeploymentGates orchestrates deployment with gates.
type DeploymentGates interface {
	// PreCheck runs pre-deployment gates (policy checks).
	PreCheck(ctx context.Context, opts PreCheckOptions) (*GateResult, error)

	// PostCheck runs post-deployment verification gates.
	PostCheck(ctx context.Context, opts PostCheckOptions) (*GateResult, error)

	// Deploy performs deployment with all gates.
	Deploy(ctx context.Context, opts DeployOptions) (*DeploymentResult, error)

	// Rollback performs rollback to previous version.
	Rollback(ctx context.Context, opts RollbackOptions) error
}

// DefaultDeploymentGates implements DeploymentGates.
// Fields are ordered for optimal memory alignment.
type DefaultDeploymentGates struct {
	kubeClient      KubeClient
	helmClient      HelmClient
	policyEngine    PolicyEvaluator
	rollbackHandler *RollbackHandler
	preGates        []PreDeploymentGate
	postGates       []PostDeploymentGate
	cfg             Config
}

// NewDeploymentGates creates a new deployment gates orchestrator.
func NewDeploymentGates(opts ...Option) (*DefaultDeploymentGates, error) {
	cfg := DefaultConfig()
	for _, opt := range opts {
		opt(&cfg)
	}

	gates := &DefaultDeploymentGates{
		kubeClient:   cfg.KubeClient,
		helmClient:   cfg.HelmClient,
		policyEngine: cfg.PolicyEngine,
		cfg:          cfg,
		preGates:     make([]PreDeploymentGate, 0),
		postGates:    make([]PostDeploymentGate, 0),
	}

	// Initialize rollback handler if clients are available.
	if cfg.HelmClient != nil {
		gates.rollbackHandler = NewRollbackHandler(cfg.HelmClient, cfg.KubeClient)
	}

	// Add default gates if dependencies are available.
	if cfg.PolicyEngine != nil {
		gates.preGates = append(gates.preGates, NewPolicyGate(cfg.PolicyEngine))
	}

	// Add severity gate as a default pre-check.
	gates.preGates = append(gates.preGates, NewSeverityGate())

	if cfg.KubeClient != nil {
		gates.postGates = append(gates.postGates,
			NewHealthGate(cfg.KubeClient),
			NewReadinessGate(cfg.KubeClient),
		)
	}

	return gates, nil
}

// NewDeploymentGatesWithClients creates a deployment gates with injected clients.
// This is primarily useful for testing.
func NewDeploymentGatesWithClients(
	kubeClient KubeClient,
	helmClient HelmClient,
	policyEngine PolicyEvaluator,
	cfg Config,
) *DefaultDeploymentGates {
	gates := &DefaultDeploymentGates{
		kubeClient:   kubeClient,
		helmClient:   helmClient,
		policyEngine: policyEngine,
		cfg:          cfg,
		preGates:     make([]PreDeploymentGate, 0),
		postGates:    make([]PostDeploymentGate, 0),
	}

	if helmClient != nil {
		gates.rollbackHandler = NewRollbackHandler(helmClient, kubeClient)
	}

	return gates
}

// AddPreGate adds a pre-deployment gate.
func (g *DefaultDeploymentGates) AddPreGate(gate PreDeploymentGate) {
	g.preGates = append(g.preGates, gate)
}

// AddPostGate adds a post-deployment gate.
func (g *DefaultDeploymentGates) AddPostGate(gate PostDeploymentGate) {
	g.postGates = append(g.postGates, gate)
}

// PreCheck runs pre-deployment gates.
func (g *DefaultDeploymentGates) PreCheck(ctx context.Context, opts PreCheckOptions) (*GateResult, error) {
	if ctx == nil {
		return nil, ErrNilContext
	}

	if err := opts.Validate(); err != nil {
		return nil, err
	}

	runner := NewPreCheckRunner(g.preGates...)
	return runner.Run(ctx, opts)
}

// PostCheck runs post-deployment verification gates.
func (g *DefaultDeploymentGates) PostCheck(ctx context.Context, opts PostCheckOptions) (*GateResult, error) {
	if ctx == nil {
		return nil, ErrNilContext
	}

	if err := opts.Validate(); err != nil {
		return nil, err
	}

	runner := NewPostCheckRunner(g.postGates...)
	return runner.Run(ctx, opts)
}

// Deploy performs deployment with all gates.
func (g *DefaultDeploymentGates) Deploy(ctx context.Context, opts DeployOptions) (*DeploymentResult, error) {
	if ctx == nil {
		return nil, ErrNilContext
	}

	if err := opts.Validate(); err != nil {
		return nil, err
	}

	if g.helmClient == nil {
		return nil, ErrMissingHelmClient
	}

	result := &DeploymentResult{
		StartTime:   time.Now(),
		Namespace:   g.cfg.Namespace,
		ReleaseName: opts.ReleaseName,
		ChartRef:    opts.ChartRef,
	}

	// Get current revision before deployment.
	if g.rollbackHandler != nil {
		prevRevision, err := g.helmClient.GetCurrentRevision(ctx, g.cfg.Namespace, opts.ReleaseName)
		if err == nil {
			result.PreviousRevision = prevRevision
		}
	}

	// Run pre-check if configured.
	if opts.PreCheck != nil {
		preResult, err := g.PreCheck(ctx, *opts.PreCheck)
		if err != nil {
			result.EndTime = time.Now()
			result.Status = DeployStatusPreCheckFailed
			return result, NewGateError("pre-check", "", g.cfg.Namespace, opts.ReleaseName, err)
		}

		result.PreCheckResult = preResult

		if !preResult.Passed {
			result.EndTime = time.Now()
			result.Status = DeployStatusPreCheckFailed
			return result, NewGateError("pre-check", "", g.cfg.Namespace, opts.ReleaseName, ErrPreCheckFailed)
		}
	}

	// Check for dry-run mode.
	if g.cfg.DryRun {
		result.EndTime = time.Now()
		result.Status = DeployStatusSuccess
		return result, nil
	}

	// Perform deployment.
	releaseInfo, err := g.helmClient.Upgrade(ctx, g.cfg.Namespace, opts.ReleaseName, opts.ChartRef, opts.Values)
	if err != nil {
		result.EndTime = time.Now()
		result.Status = DeployStatusFailed

		// Auto-rollback on deployment error if enabled.
		if opts.AutoRollback && g.rollbackHandler != nil && result.PreviousRevision > 0 {
			rollbackOpts := RollbackOptions{
				Namespace:   g.cfg.Namespace,
				ReleaseName: opts.ReleaseName,
				Revision:    result.PreviousRevision,
			}
			if rollbackErr := g.rollbackHandler.Execute(ctx, rollbackOpts); rollbackErr == nil {
				result.RolledBack = true
				result.Status = DeployStatusRolledBack
			}
		}

		return result, NewGateError("deploy", "", g.cfg.Namespace, opts.ReleaseName, err)
	}

	result.Revision = releaseInfo.Revision

	// Run post-check if configured.
	if opts.PostCheck != nil {
		postOpts := *opts.PostCheck
		postOpts.Namespace = g.cfg.Namespace
		postOpts.ReleaseName = opts.ReleaseName

		postResult, err := g.PostCheck(ctx, postOpts)
		if err != nil {
			result.EndTime = time.Now()
			result.Status = DeployStatusPostCheckFailed

			// Auto-rollback on post-check failure if enabled.
			if opts.AutoRollback && g.rollbackHandler != nil && result.PreviousRevision > 0 {
				rollbackOpts := RollbackOptions{
					Namespace:   g.cfg.Namespace,
					ReleaseName: opts.ReleaseName,
					Revision:    result.PreviousRevision,
				}
				if rollbackErr := g.rollbackHandler.Execute(ctx, rollbackOpts); rollbackErr == nil {
					result.RolledBack = true
					result.Status = DeployStatusRolledBack
				}
			}

			return result, NewGateError("post-check", "", g.cfg.Namespace, opts.ReleaseName, err)
		}

		result.PostCheckResult = postResult

		if !postResult.Passed {
			result.EndTime = time.Now()
			result.Status = DeployStatusPostCheckFailed

			// Auto-rollback if enabled.
			if opts.AutoRollback && g.rollbackHandler != nil && result.PreviousRevision > 0 {
				rollbackOpts := RollbackOptions{
					Namespace:   g.cfg.Namespace,
					ReleaseName: opts.ReleaseName,
					Revision:    result.PreviousRevision,
				}
				if rollbackErr := g.rollbackHandler.Execute(ctx, rollbackOpts); rollbackErr == nil {
					result.RolledBack = true
					result.Status = DeployStatusRolledBack
				}
			}

			return result, NewGateError("post-check", "", g.cfg.Namespace, opts.ReleaseName, ErrPostCheckFailed)
		}
	}

	result.EndTime = time.Now()
	result.Status = DeployStatusSuccess

	return result, nil
}

// Rollback performs rollback to previous version.
func (g *DefaultDeploymentGates) Rollback(ctx context.Context, opts RollbackOptions) error {
	if ctx == nil {
		return ErrNilContext
	}

	if g.rollbackHandler == nil {
		return ErrMissingHelmClient
	}

	if opts.Namespace == "" {
		opts.Namespace = g.cfg.Namespace
	}

	return g.rollbackHandler.Execute(ctx, opts)
}

// Config returns the current configuration.
func (g *DefaultDeploymentGates) Config() Config {
	return g.cfg
}

// PreGateCount returns the number of pre-deployment gates.
func (g *DefaultDeploymentGates) PreGateCount() int {
	return len(g.preGates)
}

// PostGateCount returns the number of post-deployment gates.
func (g *DefaultDeploymentGates) PostGateCount() int {
	return len(g.postGates)
}

// Summary returns a summary of the deployment gates configuration.
func (g *DefaultDeploymentGates) Summary() string {
	return fmt.Sprintf("DeploymentGates: %d pre-gates, %d post-gates, namespace=%s, dry-run=%v",
		len(g.preGates), len(g.postGates), g.cfg.Namespace, g.cfg.DryRun)
}
