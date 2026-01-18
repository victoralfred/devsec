package gates

import (
	"context"
	"errors"
	"testing"

	"github.com/victoralfred/devsec/internal/model"
)

// mockPolicyEvaluator is a mock implementation for testing.
type mockPolicyEvaluator struct {
	err    error
	result PolicyResult
}

func (m *mockPolicyEvaluator) Evaluate(_ context.Context, _ []model.Finding) (PolicyResult, error) {
	if m.err != nil {
		return PolicyResult{}, m.err
	}
	return m.result, nil
}

func TestPolicyGate_Name(t *testing.T) {
	t.Parallel()

	gate := NewPolicyGate(nil)
	if gate.Name() != "policy" {
		t.Errorf("Name() = %v, want policy", gate.Name())
	}
}

func TestPolicyGate_Evaluate_NilContext(t *testing.T) {
	t.Parallel()

	gate := NewPolicyGate(&mockPolicyEvaluator{})
	var ctx context.Context = nil             //nolint:revive // explicit nil context for testing error handling
	_, err := gate.Evaluate(ctx, GateInput{}) //nolint:staticcheck // intentionally passing nil context for testing
	if err != ErrNilContext {
		t.Errorf("Evaluate(context.TODO()) error = %v, want ErrNilContext", err)
	}
}

func TestPolicyGate_Evaluate_MissingEngine(t *testing.T) {
	t.Parallel()

	gate := NewPolicyGate(nil)
	ctx := context.Background()
	_, err := gate.Evaluate(ctx, GateInput{})
	if err != ErrMissingPolicyEngine {
		t.Errorf("Evaluate() error = %v, want ErrMissingPolicyEngine", err)
	}
}

func TestPolicyGate_Evaluate_Success(t *testing.T) {
	t.Parallel()

	gate := NewPolicyGate(&mockPolicyEvaluator{})
	ctx := context.Background()
	decision, err := gate.Evaluate(ctx, GateInput{Namespace: "default", Resource: "my-app"})
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if !decision.Passed {
		t.Error("Evaluate() decision should pass")
	}
	if decision.GateName != "policy" {
		t.Errorf("GateName = %v, want policy", decision.GateName)
	}
}

func TestPolicyGate_CheckFindings_NilContext(t *testing.T) {
	t.Parallel()

	gate := NewPolicyGate(&mockPolicyEvaluator{})
	findings := []model.Finding{{ID: "1", Title: "Test"}}
	var ctx context.Context = nil               //nolint:revive // explicit nil context for testing error handling
	_, err := gate.CheckFindings(ctx, findings) //nolint:staticcheck // intentionally passing nil context for testing
	if err != ErrNilContext {
		t.Errorf("CheckFindings(nil) error = %v, want ErrNilContext", err)
	}
}

func TestPolicyGate_CheckFindings_MissingEngine(t *testing.T) {
	t.Parallel()

	gate := NewPolicyGate(nil)
	ctx := context.Background()
	findings := []model.Finding{{ID: "1", Title: "Test"}}
	_, err := gate.CheckFindings(ctx, findings)
	if err != ErrMissingPolicyEngine {
		t.Errorf("CheckFindings() error = %v, want ErrMissingPolicyEngine", err)
	}
}

func TestPolicyGate_CheckFindings_NoFindings(t *testing.T) {
	t.Parallel()

	gate := NewPolicyGate(&mockPolicyEvaluator{})
	ctx := context.Background()
	_, err := gate.CheckFindings(ctx, nil)
	if err != ErrNoFindings {
		t.Errorf("CheckFindings(context.TODO()) error = %v, want ErrNoFindings", err)
	}
}

func TestPolicyGate_CheckFindings_Pass(t *testing.T) {
	t.Parallel()

	evaluator := &mockPolicyEvaluator{
		result: PolicyResult{Allow: true, Deny: false},
	}
	gate := NewPolicyGate(evaluator)
	ctx := context.Background()
	findings := []model.Finding{{ID: "1", Title: "Test"}}

	decision, err := gate.CheckFindings(ctx, findings)
	if err != nil {
		t.Fatalf("CheckFindings() error = %v", err)
	}
	if !decision.Passed {
		t.Error("CheckFindings() decision should pass")
	}
}

func TestPolicyGate_CheckFindings_Fail(t *testing.T) {
	t.Parallel()

	evaluator := &mockPolicyEvaluator{
		result: PolicyResult{Allow: false, Deny: true, Violations: []string{"critical finding"}},
	}
	gate := NewPolicyGate(evaluator)
	ctx := context.Background()
	findings := []model.Finding{{ID: "1", Title: "Test"}}

	decision, err := gate.CheckFindings(ctx, findings)
	if err != nil {
		t.Fatalf("CheckFindings() error = %v", err)
	}
	if decision.Passed {
		t.Error("CheckFindings() decision should fail")
	}
}

func TestPolicyGate_CheckFindings_StrictMode(t *testing.T) {
	t.Parallel()

	evaluator := &mockPolicyEvaluator{
		result: PolicyResult{Allow: true, Deny: false, Warnings: []string{"warning"}},
	}
	gate := NewPolicyGate(evaluator, WithStrictMode(true))
	ctx := context.Background()
	findings := []model.Finding{{ID: "1", Title: "Test"}}

	decision, err := gate.CheckFindings(ctx, findings)
	if err != nil {
		t.Fatalf("CheckFindings() error = %v", err)
	}
	if decision.Passed {
		t.Error("CheckFindings() decision should fail in strict mode with warnings")
	}
}

func TestPolicyGate_CheckFindings_EvaluationError(t *testing.T) {
	t.Parallel()

	evaluator := &mockPolicyEvaluator{
		err: errors.New("evaluation failed"),
	}
	gate := NewPolicyGate(evaluator)
	ctx := context.Background()
	findings := []model.Finding{{ID: "1", Title: "Test"}}

	_, err := gate.CheckFindings(ctx, findings)
	if err == nil {
		t.Error("CheckFindings() should return error")
	}
}

func TestSeverityGate_Name(t *testing.T) {
	t.Parallel()

	gate := NewSeverityGate()
	if gate.Name() != "severity" {
		t.Errorf("Name() = %v, want severity", gate.Name())
	}
}

func TestSeverityGate_Evaluate_NilContext(t *testing.T) {
	t.Parallel()

	gate := NewSeverityGate()
	var ctx context.Context = nil             //nolint:revive // explicit nil context for testing error handling
	_, err := gate.Evaluate(ctx, GateInput{}) //nolint:staticcheck // intentionally passing nil context for testing
	if err != ErrNilContext {
		t.Errorf("Evaluate(context.TODO()) error = %v, want ErrNilContext", err)
	}
}

func TestSeverityGate_Evaluate_Success(t *testing.T) {
	t.Parallel()

	gate := NewSeverityGate()
	ctx := context.Background()
	decision, err := gate.Evaluate(ctx, GateInput{})
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if !decision.Passed {
		t.Error("Evaluate() decision should pass")
	}
}

func TestSeverityGate_CheckFindings_NilContext(t *testing.T) {
	t.Parallel()

	gate := NewSeverityGate()
	findings := []model.Finding{{ID: "1", Title: "Test"}}
	var ctx context.Context = nil               //nolint:revive // explicit nil context for testing error handling
	_, err := gate.CheckFindings(ctx, findings) //nolint:staticcheck // intentionally passing nil context for testing
	if err != ErrNilContext {
		t.Errorf("CheckFindings(context.TODO()) error = %v, want ErrNilContext", err)
	}
}

func TestSeverityGate_CheckFindings_NoFindings(t *testing.T) {
	t.Parallel()

	gate := NewSeverityGate()
	ctx := context.Background()
	_, err := gate.CheckFindings(ctx, nil)
	if err != ErrNoFindings {
		t.Errorf("CheckFindings(context.TODO()) error = %v, want ErrNoFindings", err)
	}
}

func TestSeverityGate_CheckFindings_Pass(t *testing.T) {
	t.Parallel()

	gate := NewSeverityGate(WithMaxCritical(1), WithMaxHigh(10))
	ctx := context.Background()
	findings := []model.Finding{
		{ID: "1", Title: "Test", Severity: model.SeverityMedium},
		{ID: "2", Title: "Test2", Severity: model.SeverityLow},
	}

	decision, err := gate.CheckFindings(ctx, findings)
	if err != nil {
		t.Fatalf("CheckFindings() error = %v", err)
	}
	if !decision.Passed {
		t.Error("CheckFindings() decision should pass")
	}
}

func TestSeverityGate_CheckFindings_FailCritical(t *testing.T) {
	t.Parallel()

	gate := NewSeverityGate(WithMaxCritical(0))
	ctx := context.Background()
	findings := []model.Finding{
		{ID: "1", Title: "Test", Severity: model.SeverityCritical},
	}

	decision, err := gate.CheckFindings(ctx, findings)
	if err != nil {
		t.Fatalf("CheckFindings() error = %v", err)
	}
	if decision.Passed {
		t.Error("CheckFindings() decision should fail for critical findings")
	}
}

func TestSeverityGate_CheckFindings_FailHigh(t *testing.T) {
	t.Parallel()

	gate := NewSeverityGate(WithMaxCritical(1), WithMaxHigh(2))
	ctx := context.Background()
	findings := []model.Finding{
		{ID: "1", Title: "Test", Severity: model.SeverityHigh},
		{ID: "2", Title: "Test2", Severity: model.SeverityHigh},
		{ID: "3", Title: "Test3", Severity: model.SeverityHigh},
	}

	decision, err := gate.CheckFindings(ctx, findings)
	if err != nil {
		t.Fatalf("CheckFindings() error = %v", err)
	}
	if decision.Passed {
		t.Error("CheckFindings() decision should fail for too many high findings")
	}
}

func TestPreCheckRunner_Run_NilContext(t *testing.T) {
	t.Parallel()

	runner := NewPreCheckRunner()
	opts := PreCheckOptions{Findings: []model.Finding{{ID: "1", Title: "Test"}}}
	var ctx context.Context = nil   //nolint:revive // explicit nil context for testing error handling
	_, err := runner.Run(ctx, opts) //nolint:staticcheck // intentionally passing nil context for testing
	if err != ErrNilContext {
		t.Errorf("Run(context.TODO()) error = %v, want ErrNilContext", err)
	}
}

func TestPreCheckRunner_Run_InvalidOptions(t *testing.T) {
	t.Parallel()

	runner := NewPreCheckRunner()
	ctx := context.Background()
	opts := PreCheckOptions{Findings: nil}

	_, err := runner.Run(ctx, opts)
	if err != ErrNoFindings {
		t.Errorf("Run() error = %v, want ErrNoFindings", err)
	}
}

func TestPreCheckRunner_Run_AllPass(t *testing.T) {
	t.Parallel()

	evaluator := &mockPolicyEvaluator{
		result: PolicyResult{Allow: true, Deny: false},
	}
	policyGate := NewPolicyGate(evaluator)
	severityGate := NewSeverityGate(WithMaxCritical(1), WithMaxHigh(10))

	runner := NewPreCheckRunner(policyGate, severityGate)
	ctx := context.Background()
	opts := PreCheckOptions{
		Findings: []model.Finding{{ID: "1", Title: "Test", Severity: model.SeverityMedium}},
	}

	result, err := runner.Run(ctx, opts)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if !result.Passed {
		t.Error("Run() result should pass")
	}
	if result.TotalGates != 2 {
		t.Errorf("TotalGates = %v, want 2", result.TotalGates)
	}
	if result.PassedGates != 2 {
		t.Errorf("PassedGates = %v, want 2", result.PassedGates)
	}
	if result.FailedGates != 0 {
		t.Errorf("FailedGates = %v, want 0", result.FailedGates)
	}
}

func TestPreCheckRunner_Run_OneFails(t *testing.T) {
	t.Parallel()

	evaluator := &mockPolicyEvaluator{
		result: PolicyResult{Allow: false, Deny: true, Violations: []string{"violation"}},
	}
	policyGate := NewPolicyGate(evaluator)
	severityGate := NewSeverityGate(WithMaxCritical(1), WithMaxHigh(10))

	runner := NewPreCheckRunner(policyGate, severityGate)
	ctx := context.Background()
	opts := PreCheckOptions{
		Findings: []model.Finding{{ID: "1", Title: "Test", Severity: model.SeverityMedium}},
	}

	result, err := runner.Run(ctx, opts)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if result.Passed {
		t.Error("Run() result should fail when any gate fails")
	}
	if result.PassedGates != 1 {
		t.Errorf("PassedGates = %v, want 1", result.PassedGates)
	}
	if result.FailedGates != 1 {
		t.Errorf("FailedGates = %v, want 1", result.FailedGates)
	}
}

func TestPreCheckRunner_AddGate(t *testing.T) {
	t.Parallel()

	runner := NewPreCheckRunner()
	gate := NewSeverityGate()
	runner.AddGate(gate)

	if len(runner.gates) != 1 {
		t.Errorf("gates length = %v, want 1", len(runner.gates))
	}
}

func TestPreCheckRunner_Run_ContextCancelled(t *testing.T) {
	t.Parallel()

	evaluator := &mockPolicyEvaluator{
		result: PolicyResult{Allow: true, Deny: false},
	}
	policyGate := NewPolicyGate(evaluator)

	runner := NewPreCheckRunner(policyGate)
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately.

	opts := PreCheckOptions{
		Findings: []model.Finding{{ID: "1", Title: "Test"}},
	}

	_, err := runner.Run(ctx, opts)
	if err == nil {
		t.Error("Run() should return error for canceled context")
	}
}

func TestWithPolicyPath(t *testing.T) {
	t.Parallel()

	gate := NewPolicyGate(nil, WithPolicyPath("/path/to/policy.rego"))
	if gate.policyPath != "/path/to/policy.rego" {
		t.Errorf("policyPath = %v, want /path/to/policy.rego", gate.policyPath)
	}
}
