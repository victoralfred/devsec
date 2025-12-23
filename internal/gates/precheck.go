package gates

import (
	"context"
	"fmt"
	"time"

	"github.com/victoralfred/devsec/internal/model"
)

// Gate represents a single deployment gate.
type Gate interface {
	// Name returns the gate identifier.
	Name() string

	// Evaluate runs the gate check.
	Evaluate(ctx context.Context, input GateInput) (*GateDecision, error)
}

// PreDeploymentGate checks conditions before deployment.
type PreDeploymentGate interface {
	Gate

	// CheckFindings evaluates security findings against policy.
	CheckFindings(ctx context.Context, findings []model.Finding) (*GateDecision, error)
}

// PolicyGateOption configures a PolicyGate.
type PolicyGateOption func(*PolicyGate)

// WithPolicyPath sets a custom policy path.
func WithPolicyPath(path string) PolicyGateOption {
	return func(g *PolicyGate) {
		g.policyPath = path
	}
}

// WithStrictMode enables strict mode (fail on warnings).
func WithStrictMode(strict bool) PolicyGateOption {
	return func(g *PolicyGate) {
		g.strictMode = strict
	}
}

// PolicyGate evaluates security findings against policy.
// Fields are ordered for optimal memory alignment.
type PolicyGate struct {
	engine     PolicyEvaluator
	policyPath string
	strictMode bool
}

// NewPolicyGate creates a new policy gate.
func NewPolicyGate(engine PolicyEvaluator, opts ...PolicyGateOption) *PolicyGate {
	g := &PolicyGate{
		engine: engine,
	}

	for _, opt := range opts {
		opt(g)
	}

	return g
}

// Name returns the gate identifier.
func (g *PolicyGate) Name() string {
	return "policy"
}

// Evaluate runs the policy gate check.
func (g *PolicyGate) Evaluate(ctx context.Context, input GateInput) (*GateDecision, error) {
	if ctx == nil {
		return nil, ErrNilContext
	}
	if g.engine == nil {
		return nil, ErrMissingPolicyEngine
	}

	start := time.Now()

	// Create empty findings check (for general evaluation).
	decision := &GateDecision{
		Timestamp:  time.Now(),
		GateName:   g.Name(),
		EvalTimeMs: time.Since(start).Milliseconds(),
		Passed:     true,
		Message:    "policy gate passed (no findings to evaluate)",
		Details: map[string]interface{}{
			"namespace": input.Namespace,
			"resource":  input.Resource,
		},
	}

	return decision, nil
}

// CheckFindings evaluates security findings against policy.
func (g *PolicyGate) CheckFindings(ctx context.Context, findings []model.Finding) (*GateDecision, error) {
	if ctx == nil {
		return nil, ErrNilContext
	}
	if g.engine == nil {
		return nil, ErrMissingPolicyEngine
	}
	if len(findings) == 0 {
		return nil, ErrNoFindings
	}

	start := time.Now()

	// Evaluate policy.
	result, err := g.engine.Evaluate(ctx, findings)
	if err != nil {
		return nil, NewGateError("evaluate", g.Name(), "", "", err)
	}

	decision := &GateDecision{
		Timestamp:  time.Now(),
		GateName:   g.Name(),
		EvalTimeMs: time.Since(start).Milliseconds(),
		Details:    make(map[string]interface{}),
	}

	// Determine pass/fail based on policy result.
	decision.Passed = result.Allow && !result.Deny

	// In strict mode, warnings also cause failure.
	if g.strictMode && len(result.Warnings) > 0 {
		decision.Passed = false
	}

	// Build message.
	if decision.Passed {
		decision.Message = fmt.Sprintf("policy check passed (%d findings evaluated)", len(findings))
	} else {
		decision.Message = fmt.Sprintf("policy check failed: %d violations", len(result.Violations))
	}

	// Add details.
	decision.Details["findings_count"] = len(findings)
	decision.Details["violations_count"] = len(result.Violations)
	decision.Details["warnings_count"] = len(result.Warnings)
	decision.Details["strict_mode"] = g.strictMode

	if len(result.Violations) > 0 {
		decision.Details["violations"] = result.Violations
	}
	if len(result.Warnings) > 0 {
		decision.Details["warnings"] = result.Warnings
	}

	return decision, nil
}

// PreCheckRunner executes pre-deployment gates.
// Fields are ordered for optimal memory alignment.
type PreCheckRunner struct {
	gates []PreDeploymentGate
}

// NewPreCheckRunner creates a new pre-check runner.
func NewPreCheckRunner(gates ...PreDeploymentGate) *PreCheckRunner {
	return &PreCheckRunner{
		gates: gates,
	}
}

// AddGate adds a gate to the runner.
func (r *PreCheckRunner) AddGate(gate PreDeploymentGate) {
	r.gates = append(r.gates, gate)
}

// Run executes all pre-deployment gates.
func (r *PreCheckRunner) Run(ctx context.Context, opts PreCheckOptions) (*GateResult, error) {
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

	for _, gate := range r.gates {
		// Check for context cancellation.
		if err := ctx.Err(); err != nil {
			return nil, NewGateError("run", "pre-check", "", "", err)
		}

		decision, err := gate.CheckFindings(ctx, opts.Findings)
		if err != nil {
			return nil, NewGateError("run", gate.Name(), "", "", err)
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
	result.Summary = fmt.Sprintf("%d/%d pre-deployment gates passed", result.PassedGates, result.TotalGates)

	return result, nil
}

// SeverityGate is a simple gate that fails if findings exceed severity thresholds.
// Fields are ordered for optimal memory alignment.
type SeverityGate struct {
	maxCritical int
	maxHigh     int
}

// SeverityGateOption configures a SeverityGate.
type SeverityGateOption func(*SeverityGate)

// WithMaxCritical sets the maximum allowed critical findings.
func WithMaxCritical(maxCount int) SeverityGateOption {
	return func(g *SeverityGate) {
		g.maxCritical = maxCount
	}
}

// WithMaxHigh sets the maximum allowed high severity findings.
func WithMaxHigh(maxCount int) SeverityGateOption {
	return func(g *SeverityGate) {
		g.maxHigh = maxCount
	}
}

// NewSeverityGate creates a new severity gate.
func NewSeverityGate(opts ...SeverityGateOption) *SeverityGate {
	g := &SeverityGate{
		maxCritical: 0, // Default: no critical findings allowed.
		maxHigh:     5, // Default: up to 5 high findings allowed.
	}

	for _, opt := range opts {
		opt(g)
	}

	return g
}

// Name returns the gate identifier.
func (g *SeverityGate) Name() string {
	return "severity"
}

// Evaluate runs the severity gate check.
func (g *SeverityGate) Evaluate(ctx context.Context, input GateInput) (*GateDecision, error) {
	if ctx == nil {
		return nil, ErrNilContext
	}

	return &GateDecision{
		Timestamp:  time.Now(),
		GateName:   g.Name(),
		Passed:     true,
		Message:    "severity gate passed (no findings to evaluate)",
		EvalTimeMs: 0,
	}, nil
}

// CheckFindings evaluates findings against severity thresholds.
func (g *SeverityGate) CheckFindings(ctx context.Context, findings []model.Finding) (*GateDecision, error) {
	if ctx == nil {
		return nil, ErrNilContext
	}
	if len(findings) == 0 {
		return nil, ErrNoFindings
	}

	start := time.Now()

	// Count findings by severity.
	var criticalCount, highCount int
	for i := range findings {
		f := &findings[i]
		switch f.Severity {
		case model.SeverityCritical:
			criticalCount++
		case model.SeverityHigh:
			highCount++
		}
	}

	decision := &GateDecision{
		Timestamp:  time.Now(),
		GateName:   g.Name(),
		EvalTimeMs: time.Since(start).Milliseconds(),
		Details: map[string]interface{}{
			"critical_count": criticalCount,
			"high_count":     highCount,
			"max_critical":   g.maxCritical,
			"max_high":       g.maxHigh,
			"total_findings": len(findings),
		},
	}

	// Check thresholds.
	switch {
	case criticalCount > g.maxCritical:
		decision.Passed = false
		decision.Message = fmt.Sprintf("critical findings (%d) exceed threshold (%d)", criticalCount, g.maxCritical)
	case highCount > g.maxHigh:
		decision.Passed = false
		decision.Message = fmt.Sprintf("high severity findings (%d) exceed threshold (%d)", highCount, g.maxHigh)
	default:
		decision.Passed = true
		decision.Message = fmt.Sprintf("severity check passed: %d critical, %d high", criticalCount, highCount)
	}

	return decision, nil
}
