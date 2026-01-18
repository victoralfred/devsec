package gates

import (
	"context"
	"errors"
	"testing"
	"time"
)

// mockKubeClient is a mock implementation for testing.
type mockKubeClient struct {
	healthReport       *HealthReport
	healthErr          error
	readinessErr       error
	waitForReadyCalled bool
}

func (m *mockKubeClient) CheckPodHealth(_ context.Context, _, _ string) (*HealthReport, error) {
	if m.healthErr != nil {
		return nil, m.healthErr
	}
	return m.healthReport, nil
}

func (m *mockKubeClient) WaitForReady(_ context.Context, _, _ string, _ time.Duration) error {
	m.waitForReadyCalled = true
	return m.readinessErr
}

func TestHealthGate_Name(t *testing.T) {
	t.Parallel()

	gate := NewHealthGate(&mockKubeClient{})
	if gate.Name() != "health" {
		t.Errorf("Name() = %v, want health", gate.Name())
	}
}

func TestHealthGate_Evaluate_NilContext(t *testing.T) {
	t.Parallel()

	gate := NewHealthGate(&mockKubeClient{})
	_, err := gate.Evaluate(nil, GateInput{Namespace: "default", Resource: "app"}) //nolint:staticcheck // intentionally passing nil context for testing
	if err != ErrNilContext {
		t.Errorf("Evaluate(context.TODO()) error = %v, want ErrNilContext", err)
	}
}

func TestHealthGate_Evaluate_EmptyNamespace(t *testing.T) {
	t.Parallel()

	gate := NewHealthGate(&mockKubeClient{})
	ctx := context.Background()
	_, err := gate.Evaluate(ctx, GateInput{Namespace: "", Resource: "app"})
	if err != ErrEmptyNamespace {
		t.Errorf("Evaluate() error = %v, want ErrEmptyNamespace", err)
	}
}

func TestHealthGate_Evaluate_EmptyResource(t *testing.T) {
	t.Parallel()

	gate := NewHealthGate(&mockKubeClient{})
	ctx := context.Background()
	_, err := gate.Evaluate(ctx, GateInput{Namespace: "default", Resource: ""})
	if err == nil {
		t.Error("Evaluate() should return error for empty resource")
	}
}

func TestHealthGate_CheckHealth_NilContext(t *testing.T) {
	t.Parallel()

	gate := NewHealthGate(&mockKubeClient{})
	_, err := gate.CheckHealth(nil, "default", "app") //nolint:staticcheck // intentionally passing nil context for testing
	if err != ErrNilContext {
		t.Errorf("CheckHealth(context.TODO()) error = %v, want ErrNilContext", err)
	}
}

func TestHealthGate_CheckHealth_MissingClient(t *testing.T) {
	t.Parallel()

	gate := NewHealthGate(nil)
	ctx := context.Background()
	_, err := gate.CheckHealth(ctx, "default", "app")
	if err != ErrMissingKubeClient {
		t.Errorf("CheckHealth() error = %v, want ErrMissingKubeClient", err)
	}
}

func TestHealthGate_CheckHealth_EmptyNamespace(t *testing.T) {
	t.Parallel()

	gate := NewHealthGate(&mockKubeClient{})
	ctx := context.Background()
	_, err := gate.CheckHealth(ctx, "", "app")
	if err != ErrEmptyNamespace {
		t.Errorf("CheckHealth() error = %v, want ErrEmptyNamespace", err)
	}
}

func TestHealthGate_CheckHealth_EmptyDeployment(t *testing.T) {
	t.Parallel()

	gate := NewHealthGate(&mockKubeClient{})
	ctx := context.Background()
	_, err := gate.CheckHealth(ctx, "default", "")
	if err == nil {
		t.Error("CheckHealth() should return error for empty deployment")
	}
}

func TestHealthGate_CheckHealth_Pass(t *testing.T) {
	t.Parallel()

	client := &mockKubeClient{
		healthReport: &HealthReport{
			Namespace:        "default",
			Deployment:       "app",
			TotalPods:        5,
			HealthyPods:      5,
			HealthPercentage: 1.0,
			Healthy:          true,
		},
	}
	gate := NewHealthGate(client, WithHealthThreshold(0.8))
	ctx := context.Background()

	decision, err := gate.CheckHealth(ctx, "default", "app")
	if err != nil {
		t.Fatalf("CheckHealth() error = %v", err)
	}
	if !decision.Passed {
		t.Error("CheckHealth() decision should pass")
	}
}

func TestHealthGate_CheckHealth_Fail(t *testing.T) {
	t.Parallel()

	client := &mockKubeClient{
		healthReport: &HealthReport{
			Namespace:        "default",
			Deployment:       "app",
			TotalPods:        5,
			HealthyPods:      2,
			HealthPercentage: 0.4,
			Healthy:          false,
			UnhealthyPods:    []string{"pod-1", "pod-2", "pod-3"},
		},
	}
	gate := NewHealthGate(client, WithHealthThreshold(0.8))
	ctx := context.Background()

	decision, err := gate.CheckHealth(ctx, "default", "app")
	if err != nil {
		t.Fatalf("CheckHealth() error = %v", err)
	}
	if decision.Passed {
		t.Error("CheckHealth() decision should fail")
	}
}

func TestHealthGate_CheckHealth_Error(t *testing.T) {
	t.Parallel()

	client := &mockKubeClient{
		healthErr: errors.New("connection failed"),
	}
	gate := NewHealthGate(client)
	ctx := context.Background()

	_, err := gate.CheckHealth(ctx, "default", "app")
	if err == nil {
		t.Error("CheckHealth() should return error")
	}
}

func TestReadinessGate_Name(t *testing.T) {
	t.Parallel()

	gate := NewReadinessGate(&mockKubeClient{})
	if gate.Name() != "readiness" {
		t.Errorf("Name() = %v, want readiness", gate.Name())
	}
}

func TestReadinessGate_Evaluate_NilContext(t *testing.T) {
	t.Parallel()

	gate := NewReadinessGate(&mockKubeClient{})
	_, err := gate.Evaluate(nil, GateInput{Namespace: "default", Resource: "app"}) //nolint:staticcheck // intentionally passing nil context for testing
	if err != ErrNilContext {
		t.Errorf("Evaluate(context.TODO()) error = %v, want ErrNilContext", err)
	}
}

func TestReadinessGate_CheckHealth_NilContext(t *testing.T) {
	t.Parallel()

	gate := NewReadinessGate(&mockKubeClient{})
	_, err := gate.CheckHealth(nil, "default", "app") //nolint:staticcheck // intentionally passing nil context for testing
	if err != ErrNilContext {
		t.Errorf("CheckHealth(context.TODO()) error = %v, want ErrNilContext", err)
	}
}

func TestReadinessGate_CheckHealth_MissingClient(t *testing.T) {
	t.Parallel()

	gate := NewReadinessGate(nil)
	ctx := context.Background()
	_, err := gate.CheckHealth(ctx, "default", "app")
	if err != ErrMissingKubeClient {
		t.Errorf("CheckHealth() error = %v, want ErrMissingKubeClient", err)
	}
}

func TestReadinessGate_CheckHealth_Pass(t *testing.T) {
	t.Parallel()

	client := &mockKubeClient{}
	gate := NewReadinessGate(client, WithReadinessTimeout(1*time.Minute))
	ctx := context.Background()

	decision, err := gate.CheckHealth(ctx, "default", "app")
	if err != nil {
		t.Fatalf("CheckHealth() error = %v", err)
	}
	if !decision.Passed {
		t.Error("CheckHealth() decision should pass")
	}
	if !client.waitForReadyCalled {
		t.Error("WaitForReady should be called")
	}
}

func TestReadinessGate_CheckHealth_Fail(t *testing.T) {
	t.Parallel()

	client := &mockKubeClient{
		readinessErr: errors.New("timeout waiting for readiness"),
	}
	gate := NewReadinessGate(client)
	ctx := context.Background()

	decision, err := gate.CheckHealth(ctx, "default", "app")
	if err != nil {
		t.Fatalf("CheckHealth() error = %v", err)
	}
	if decision.Passed {
		t.Error("CheckHealth() decision should fail")
	}
}

func TestPostCheckRunner_Run_NilContext(t *testing.T) {
	t.Parallel()

	runner := NewPostCheckRunner()
	opts := PostCheckOptions{Namespace: "default", ReleaseName: "app"}
	_, err := runner.Run(nil, opts) //nolint:staticcheck // intentionally passing nil context for testing
	if err != ErrNilContext {
		t.Errorf("Run(context.TODO()) error = %v, want ErrNilContext", err)
	}
}

func TestPostCheckRunner_Run_InvalidOptions(t *testing.T) {
	t.Parallel()

	runner := NewPostCheckRunner()
	ctx := context.Background()
	opts := PostCheckOptions{Namespace: "", ReleaseName: "app"}

	_, err := runner.Run(ctx, opts)
	if err != ErrEmptyNamespace {
		t.Errorf("Run() error = %v, want ErrEmptyNamespace", err)
	}
}

func TestPostCheckRunner_Run_AllPass(t *testing.T) {
	t.Parallel()

	client := &mockKubeClient{
		healthReport: &HealthReport{
			Namespace:        "default",
			Deployment:       "app",
			TotalPods:        5,
			HealthyPods:      5,
			HealthPercentage: 1.0,
			Healthy:          true,
		},
	}
	healthGate := NewHealthGate(client)
	readinessGate := NewReadinessGate(client)

	runner := NewPostCheckRunner(healthGate, readinessGate)
	ctx := context.Background()
	opts := PostCheckOptions{Namespace: "default", ReleaseName: "app"}

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
}

func TestPostCheckRunner_Run_OneFails(t *testing.T) {
	t.Parallel()

	client := &mockKubeClient{
		healthReport: &HealthReport{
			Namespace:        "default",
			Deployment:       "app",
			TotalPods:        5,
			HealthyPods:      2,
			HealthPercentage: 0.4,
			Healthy:          false,
		},
	}
	healthGate := NewHealthGate(client)
	readinessGate := NewReadinessGate(client)

	runner := NewPostCheckRunner(healthGate, readinessGate)
	ctx := context.Background()
	opts := PostCheckOptions{Namespace: "default", ReleaseName: "app"}

	result, err := runner.Run(ctx, opts)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if result.Passed {
		t.Error("Run() result should fail when any gate fails")
	}
	if result.FailedGates != 1 {
		t.Errorf("FailedGates = %v, want 1", result.FailedGates)
	}
}

func TestPostCheckRunner_Run_WithDeploymentName(t *testing.T) {
	t.Parallel()

	client := &mockKubeClient{
		healthReport: &HealthReport{
			TotalPods:        5,
			HealthyPods:      5,
			HealthPercentage: 1.0,
			Healthy:          true,
		},
	}
	healthGate := NewHealthGate(client)

	runner := NewPostCheckRunner(healthGate)
	ctx := context.Background()
	opts := PostCheckOptions{
		Namespace:      "default",
		ReleaseName:    "my-release",
		DeploymentName: "my-deployment",
	}

	result, err := runner.Run(ctx, opts)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if !result.Passed {
		t.Error("Run() result should pass")
	}
}

func TestPostCheckRunner_AddGate(t *testing.T) {
	t.Parallel()

	runner := NewPostCheckRunner()
	gate := NewHealthGate(&mockKubeClient{})
	runner.AddGate(gate)

	if len(runner.gates) != 1 {
		t.Errorf("gates length = %v, want 1", len(runner.gates))
	}
}

func TestCombinedHealthGate_Name(t *testing.T) {
	t.Parallel()

	gate := NewCombinedHealthGate(&mockKubeClient{}, nil, nil)
	if gate.Name() != "combined-health" {
		t.Errorf("Name() = %v, want combined-health", gate.Name())
	}
}

func TestCombinedHealthGate_CheckHealth_NilContext(t *testing.T) {
	t.Parallel()

	gate := NewCombinedHealthGate(&mockKubeClient{}, nil, nil)
	_, err := gate.CheckHealth(nil, "default", "app") //nolint:staticcheck // intentionally passing nil context for testing
	if err != ErrNilContext {
		t.Errorf("CheckHealthcontext.TODO()) error = %v, want ErrNilContext", err)
	}
}

func TestCombinedHealthGate_CheckHealth_AllPass(t *testing.T) {
	t.Parallel()

	client := &mockKubeClient{
		healthReport: &HealthReport{
			TotalPods:        5,
			HealthyPods:      5,
			HealthPercentage: 1.0,
			Healthy:          true,
		},
	}
	gate := NewCombinedHealthGate(client, nil, nil)
	ctx := context.Background()

	decision, err := gate.CheckHealth(ctx, "default", "app")
	if err != nil {
		t.Fatalf("CheckHealth() error = %v", err)
	}
	if !decision.Passed {
		t.Error("CheckHealth() decision should pass")
	}
}

func TestCombinedHealthGate_CheckHealth_ReadinessFails(t *testing.T) {
	t.Parallel()

	client := &mockKubeClient{
		readinessErr: errors.New("timeout"),
		healthReport: &HealthReport{
			TotalPods:        5,
			HealthyPods:      5,
			HealthPercentage: 1.0,
			Healthy:          true,
		},
	}
	gate := NewCombinedHealthGate(client, nil, nil)
	ctx := context.Background()

	decision, err := gate.CheckHealth(ctx, "default", "app")
	if err != nil {
		t.Fatalf("CheckHealth() error = %v", err)
	}
	if decision.Passed {
		t.Error("CheckHealth() decision should fail when readiness fails")
	}
}

func TestCombinedHealthGate_CheckHealth_HealthFails(t *testing.T) {
	t.Parallel()

	client := &mockKubeClient{
		healthReport: &HealthReport{
			TotalPods:        5,
			HealthyPods:      2,
			HealthPercentage: 0.4,
			Healthy:          false,
		},
	}
	gate := NewCombinedHealthGate(client, nil, nil)
	ctx := context.Background()

	decision, err := gate.CheckHealth(ctx, "default", "app")
	if err != nil {
		t.Fatalf("CheckHealth() error = %v", err)
	}
	if decision.Passed {
		t.Error("CheckHealth() decision should fail when health check fails")
	}
}

func TestWithHealthThreshold(t *testing.T) {
	t.Parallel()

	gate := NewHealthGate(nil, WithHealthThreshold(0.9))
	if gate.healthThreshold != 0.9 {
		t.Errorf("healthThreshold = %v, want 0.9", gate.healthThreshold)
	}
}

func TestWithMinReadySeconds(t *testing.T) {
	t.Parallel()

	gate := NewHealthGate(nil, WithMinReadySeconds(30))
	if gate.minReadySeconds != 30 {
		t.Errorf("minReadySeconds = %v, want 30", gate.minReadySeconds)
	}
}

func TestWithReadinessTimeout(t *testing.T) {
	t.Parallel()

	gate := NewReadinessGate(nil, WithReadinessTimeout(5*time.Minute))
	if gate.timeout != 5*time.Minute {
		t.Errorf("timeout = %v, want 5m", gate.timeout)
	}
}
