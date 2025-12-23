package gates

import (
	"context"
	"fmt"
	"time"
)

// PostDeploymentGate verifies deployment success.
type PostDeploymentGate interface {
	Gate

	// CheckHealth verifies deployment health.
	CheckHealth(ctx context.Context, namespace, deployment string) (*GateDecision, error)
}

// HealthGateOption configures a HealthGate.
type HealthGateOption func(*HealthGate)

// WithHealthThreshold sets the health threshold percentage.
func WithHealthThreshold(threshold float64) HealthGateOption {
	return func(g *HealthGate) {
		g.healthThreshold = threshold
	}
}

// WithMinReadySeconds sets the minimum ready seconds.
func WithMinReadySeconds(seconds int) HealthGateOption {
	return func(g *HealthGate) {
		g.minReadySeconds = seconds
	}
}

// HealthGate verifies deployment health via Kubernetes.
// Fields are ordered for optimal memory alignment.
type HealthGate struct {
	kubeClient      KubeClient
	healthThreshold float64
	minReadySeconds int
}

// NewHealthGate creates a new health gate.
func NewHealthGate(client KubeClient, opts ...HealthGateOption) *HealthGate {
	g := &HealthGate{
		kubeClient:      client,
		healthThreshold: DefaultHealthThreshold,
		minReadySeconds: DefaultMinReadySeconds,
	}

	for _, opt := range opts {
		opt(g)
	}

	return g
}

// Name returns the gate identifier.
func (g *HealthGate) Name() string {
	return "health"
}

// Evaluate runs the health gate check.
func (g *HealthGate) Evaluate(ctx context.Context, input GateInput) (*GateDecision, error) {
	if ctx == nil {
		return nil, ErrNilContext
	}
	if input.Namespace == "" {
		return nil, ErrEmptyNamespace
	}
	if input.Resource == "" {
		return nil, NewGateError("evaluate", g.Name(), input.Namespace, "", ErrEmptyGateName)
	}

	return g.CheckHealth(ctx, input.Namespace, input.Resource)
}

// CheckHealth verifies deployment health.
func (g *HealthGate) CheckHealth(ctx context.Context, namespace, deployment string) (*GateDecision, error) {
	if ctx == nil {
		return nil, ErrNilContext
	}
	if g.kubeClient == nil {
		return nil, ErrMissingKubeClient
	}
	if namespace == "" {
		return nil, ErrEmptyNamespace
	}
	if deployment == "" {
		return nil, NewGateError("check health", g.Name(), namespace, "", ErrEmptyGateName)
	}

	start := time.Now()

	// Check pod health.
	report, err := g.kubeClient.CheckPodHealth(ctx, namespace, deployment)
	if err != nil {
		return nil, NewGateError("check health", g.Name(), namespace, deployment, err)
	}

	decision := &GateDecision{
		Timestamp:  time.Now(),
		GateName:   g.Name(),
		EvalTimeMs: time.Since(start).Milliseconds(),
		Details: map[string]interface{}{
			"namespace":         namespace,
			"deployment":        deployment,
			"total_pods":        report.TotalPods,
			"healthy_pods":      report.HealthyPods,
			"health_percentage": report.HealthPercentage,
			"health_threshold":  g.healthThreshold,
			"min_ready_seconds": g.minReadySeconds,
		},
	}

	// Check if health meets threshold.
	if report.HealthPercentage >= g.healthThreshold {
		decision.Passed = true
		decision.Message = fmt.Sprintf("health check passed: %.0f%% healthy (threshold: %.0f%%)",
			report.HealthPercentage*100, g.healthThreshold*100)
	} else {
		decision.Passed = false
		decision.Message = fmt.Sprintf("health check failed: %.0f%% healthy (threshold: %.0f%%)",
			report.HealthPercentage*100, g.healthThreshold*100)
		if len(report.UnhealthyPods) > 0 {
			decision.Details["unhealthy_pods"] = report.UnhealthyPods
		}
	}

	return decision, nil
}

// ReadinessGateOption configures a ReadinessGate.
type ReadinessGateOption func(*ReadinessGate)

// WithReadinessTimeout sets the readiness timeout.
func WithReadinessTimeout(timeout time.Duration) ReadinessGateOption {
	return func(g *ReadinessGate) {
		g.timeout = timeout
	}
}

// ReadinessGate verifies pod readiness.
// Fields are ordered for optimal memory alignment.
type ReadinessGate struct {
	kubeClient KubeClient
	timeout    time.Duration
}

// NewReadinessGate creates a new readiness gate.
func NewReadinessGate(client KubeClient, opts ...ReadinessGateOption) *ReadinessGate {
	g := &ReadinessGate{
		kubeClient: client,
		timeout:    DefaultPostCheckTimeout,
	}

	for _, opt := range opts {
		opt(g)
	}

	return g
}

// Name returns the gate identifier.
func (g *ReadinessGate) Name() string {
	return "readiness"
}

// Evaluate runs the readiness gate check.
func (g *ReadinessGate) Evaluate(ctx context.Context, input GateInput) (*GateDecision, error) {
	if ctx == nil {
		return nil, ErrNilContext
	}
	if input.Namespace == "" {
		return nil, ErrEmptyNamespace
	}
	if input.Resource == "" {
		return nil, NewGateError("evaluate", g.Name(), input.Namespace, "", ErrEmptyGateName)
	}

	return g.CheckHealth(ctx, input.Namespace, input.Resource)
}

// CheckHealth verifies deployment readiness.
func (g *ReadinessGate) CheckHealth(ctx context.Context, namespace, deployment string) (*GateDecision, error) {
	if ctx == nil {
		return nil, ErrNilContext
	}
	if g.kubeClient == nil {
		return nil, ErrMissingKubeClient
	}
	if namespace == "" {
		return nil, ErrEmptyNamespace
	}
	if deployment == "" {
		return nil, NewGateError("check readiness", g.Name(), namespace, "", ErrEmptyGateName)
	}

	start := time.Now()

	// Wait for deployment to be ready.
	err := g.kubeClient.WaitForReady(ctx, namespace, deployment, g.timeout)

	decision := &GateDecision{
		Timestamp:  time.Now(),
		GateName:   g.Name(),
		EvalTimeMs: time.Since(start).Milliseconds(),
		Details: map[string]interface{}{
			"namespace":  namespace,
			"deployment": deployment,
			"timeout":    g.timeout.String(),
		},
	}

	if err != nil {
		decision.Passed = false
		decision.Message = fmt.Sprintf("readiness check failed: %v", err)
		decision.Details["error"] = err.Error()
	} else {
		decision.Passed = true
		decision.Message = fmt.Sprintf("deployment %s is ready", deployment)
	}

	return decision, nil
}

// PostCheckRunner executes post-deployment gates.
// Fields are ordered for optimal memory alignment.
type PostCheckRunner struct {
	gates []PostDeploymentGate
}

// NewPostCheckRunner creates a new post-check runner.
func NewPostCheckRunner(gates ...PostDeploymentGate) *PostCheckRunner {
	return &PostCheckRunner{
		gates: gates,
	}
}

// AddGate adds a gate to the runner.
func (r *PostCheckRunner) AddGate(gate PostDeploymentGate) {
	r.gates = append(r.gates, gate)
}

// Run executes all post-deployment gates.
func (r *PostCheckRunner) Run(ctx context.Context, opts PostCheckOptions) (*GateResult, error) {
	if ctx == nil {
		return nil, ErrNilContext
	}

	if err := opts.Validate(); err != nil {
		return nil, err
	}

	start := time.Now()

	result := &GateResult{
		Timestamp:  start,
		TotalGates: len(r.gates),
		Decisions:  make([]GateDecision, 0, len(r.gates)),
	}

	// Use deployment name if specified, otherwise use release name.
	deploymentName := opts.DeploymentName
	if deploymentName == "" {
		deploymentName = opts.ReleaseName
	}

	for _, gate := range r.gates {
		// Check for context cancellation.
		if err := ctx.Err(); err != nil {
			return nil, NewGateError("run", "post-check", opts.Namespace, deploymentName, err)
		}

		decision, err := gate.CheckHealth(ctx, opts.Namespace, deploymentName)
		if err != nil {
			return nil, NewGateError("run", gate.Name(), opts.Namespace, deploymentName, err)
		}

		result.Decisions = append(result.Decisions, *decision)

		if decision.Passed {
			result.PassedGates++
		} else {
			result.FailedGates++
		}
	}

	// Overall result passes only if all gates pass.
	result.Passed = result.FailedGates == 0
	result.Summary = fmt.Sprintf("%d/%d post-deployment gates passed", result.PassedGates, result.TotalGates)

	return result, nil
}

// CombinedHealthGate combines health and readiness checks.
// Fields are ordered for optimal memory alignment.
type CombinedHealthGate struct {
	healthGate    *HealthGate
	readinessGate *ReadinessGate
}

// NewCombinedHealthGate creates a combined health gate.
func NewCombinedHealthGate(client KubeClient, healthOpts []HealthGateOption, readinessOpts []ReadinessGateOption) *CombinedHealthGate {
	return &CombinedHealthGate{
		healthGate:    NewHealthGate(client, healthOpts...),
		readinessGate: NewReadinessGate(client, readinessOpts...),
	}
}

// Name returns the gate identifier.
func (g *CombinedHealthGate) Name() string {
	return "combined-health"
}

// Evaluate runs both health and readiness checks.
func (g *CombinedHealthGate) Evaluate(ctx context.Context, input GateInput) (*GateDecision, error) {
	return g.CheckHealth(ctx, input.Namespace, input.Resource)
}

// CheckHealth runs both health and readiness checks.
func (g *CombinedHealthGate) CheckHealth(ctx context.Context, namespace, deployment string) (*GateDecision, error) {
	if ctx == nil {
		return nil, ErrNilContext
	}

	start := time.Now()

	// Run readiness check first.
	readinessDecision, err := g.readinessGate.CheckHealth(ctx, namespace, deployment)
	if err != nil {
		return nil, err
	}

	// Run health check.
	healthDecision, err := g.healthGate.CheckHealth(ctx, namespace, deployment)
	if err != nil {
		return nil, err
	}

	// Combine results.
	decision := &GateDecision{
		Timestamp:  time.Now(),
		GateName:   g.Name(),
		EvalTimeMs: time.Since(start).Milliseconds(),
		Passed:     readinessDecision.Passed && healthDecision.Passed,
		Details: map[string]interface{}{
			"namespace":         namespace,
			"deployment":        deployment,
			"readiness_passed":  readinessDecision.Passed,
			"health_passed":     healthDecision.Passed,
			"readiness_message": readinessDecision.Message,
			"health_message":    healthDecision.Message,
		},
	}

	if decision.Passed {
		decision.Message = fmt.Sprintf("combined health check passed for %s", deployment)
	} else {
		if !readinessDecision.Passed {
			decision.Message = fmt.Sprintf("readiness check failed: %s", readinessDecision.Message)
		} else {
			decision.Message = fmt.Sprintf("health check failed: %s", healthDecision.Message)
		}
	}

	return decision, nil
}
