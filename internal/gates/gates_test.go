package gates

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/victoralfred/devsec/internal/model"
)

func TestNewDeploymentGates(t *testing.T) {
	t.Parallel()

	gates, err := NewDeploymentGates()
	if err != nil {
		t.Fatalf("NewDeploymentGates() error = %v", err)
	}
	if gates == nil {
		t.Fatal("NewDeploymentGates() returned nil")
	}

	// Should have severity gate by default.
	if gates.PreGateCount() < 1 {
		t.Errorf("PreGateCount() = %v, want >= 1", gates.PreGateCount())
	}
}

func TestNewDeploymentGates_WithClients(t *testing.T) {
	t.Parallel()

	kubeClient := &mockKubeClient{}
	helmClient := &mockHelmClient{}
	policyEngine := &mockPolicyEvaluator{}

	gates, err := NewDeploymentGates(
		WithKubeClient(kubeClient),
		WithHelmClient(helmClient),
		WithPolicyEngine(policyEngine),
		WithNamespace("test-ns"),
		WithTimeout(10*time.Minute),
		WithDryRun(true),
	)
	if err != nil {
		t.Fatalf("NewDeploymentGates() error = %v", err)
	}

	cfg := gates.Config()
	if cfg.Namespace != "test-ns" {
		t.Errorf("Namespace = %v, want test-ns", cfg.Namespace)
	}
	if cfg.Timeout != 10*time.Minute {
		t.Errorf("Timeout = %v, want 10m", cfg.Timeout)
	}
	if !cfg.DryRun {
		t.Error("DryRun should be true")
	}
}

func TestDefaultDeploymentGates_PreCheck_NilContext(t *testing.T) {
	t.Parallel()

	gates, _ := NewDeploymentGates()
	opts := PreCheckOptions{Findings: []model.Finding{{ID: "1", Title: "Test"}}}
	_, err := gates.PreCheck(nil, opts) //lint:ignore SA1012 intentionally passing nil context for testing
	if err != ErrNilContext {
		t.Errorf("PreCheck(nil) error = %v, want ErrNilContext", err)
	}
}

func TestDefaultDeploymentGates_PreCheck_InvalidOptions(t *testing.T) {
	t.Parallel()

	gates, _ := NewDeploymentGates()
	ctx := context.Background()
	opts := PreCheckOptions{Findings: nil}

	_, err := gates.PreCheck(ctx, opts)
	if err != ErrNoFindings {
		t.Errorf("PreCheck() error = %v, want ErrNoFindings", err)
	}
}

func TestDefaultDeploymentGates_PreCheck_Pass(t *testing.T) {
	t.Parallel()

	policyEngine := &mockPolicyEvaluator{
		result: PolicyResult{Allow: true, Deny: false},
	}
	gates, _ := NewDeploymentGates(WithPolicyEngine(policyEngine))
	ctx := context.Background()
	opts := PreCheckOptions{
		Findings: []model.Finding{{ID: "1", Title: "Test", Severity: model.SeverityLow}},
	}

	result, err := gates.PreCheck(ctx, opts)
	if err != nil {
		t.Fatalf("PreCheck() error = %v", err)
	}
	if !result.Passed {
		t.Error("PreCheck() result should pass")
	}
}

func TestDefaultDeploymentGates_PostCheck_NilContext(t *testing.T) {
	t.Parallel()

	gates, _ := NewDeploymentGates()
	opts := PostCheckOptions{Namespace: "default", ReleaseName: "app"}
	_, err := gates.PostCheck(nil, opts) //lint:ignore SA1012 intentionally passing nil context for testing
	if err != ErrNilContext {
		t.Errorf("PostCheck(nil) error = %v, want ErrNilContext", err)
	}
}

func TestDefaultDeploymentGates_PostCheck_InvalidOptions(t *testing.T) {
	t.Parallel()

	gates, _ := NewDeploymentGates()
	ctx := context.Background()
	opts := PostCheckOptions{Namespace: "", ReleaseName: "app"}

	_, err := gates.PostCheck(ctx, opts)
	if err != ErrEmptyNamespace {
		t.Errorf("PostCheck() error = %v, want ErrEmptyNamespace", err)
	}
}

func TestDefaultDeploymentGates_PostCheck_Pass(t *testing.T) {
	t.Parallel()

	kubeClient := &mockKubeClient{
		healthReport: &HealthReport{
			TotalPods:        5,
			HealthyPods:      5,
			HealthPercentage: 1.0,
			Healthy:          true,
		},
	}
	gates, _ := NewDeploymentGates(WithKubeClient(kubeClient))
	ctx := context.Background()
	opts := PostCheckOptions{Namespace: "default", ReleaseName: "app"}

	result, err := gates.PostCheck(ctx, opts)
	if err != nil {
		t.Fatalf("PostCheck() error = %v", err)
	}
	if !result.Passed {
		t.Error("PostCheck() result should pass")
	}
}

func TestDefaultDeploymentGates_Deploy_NilContext(t *testing.T) {
	t.Parallel()

	gates, _ := NewDeploymentGates()
	opts := DeployOptions{ReleaseName: "app", ChartRef: "nginx"}
	_, err := gates.Deploy(nil, opts) //lint:ignore SA1012 intentionally passing nil context for testing
	if err != ErrNilContext {
		t.Errorf("Deploy(nil) error = %v, want ErrNilContext", err)
	}
}

func TestDefaultDeploymentGates_Deploy_InvalidOptions(t *testing.T) {
	t.Parallel()

	gates, _ := NewDeploymentGates()
	ctx := context.Background()
	opts := DeployOptions{ReleaseName: "", ChartRef: "nginx"}

	_, err := gates.Deploy(ctx, opts)
	if err != ErrEmptyReleaseName {
		t.Errorf("Deploy() error = %v, want ErrEmptyReleaseName", err)
	}
}

func TestDefaultDeploymentGates_Deploy_MissingHelmClient(t *testing.T) {
	t.Parallel()

	gates, _ := NewDeploymentGates()
	ctx := context.Background()
	opts := DeployOptions{ReleaseName: "app", ChartRef: "nginx"}

	_, err := gates.Deploy(ctx, opts)
	if err != ErrMissingHelmClient {
		t.Errorf("Deploy() error = %v, want ErrMissingHelmClient", err)
	}
}

func TestDefaultDeploymentGates_Deploy_DryRun(t *testing.T) {
	t.Parallel()

	helmClient := &mockHelmClient{
		releaseInfo:     &ReleaseInfo{Name: "app", Revision: 1},
		currentRevision: 0,
	}
	gates, _ := NewDeploymentGates(
		WithHelmClient(helmClient),
		WithDryRun(true),
	)
	ctx := context.Background()
	opts := DeployOptions{ReleaseName: "app", ChartRef: "nginx"}

	result, err := gates.Deploy(ctx, opts)
	if err != nil {
		t.Fatalf("Deploy() error = %v", err)
	}
	if result.Status != DeployStatusSuccess {
		t.Errorf("Status = %v, want success", result.Status)
	}
}

func TestDefaultDeploymentGates_Deploy_Success(t *testing.T) {
	t.Parallel()

	helmClient := &mockHelmClient{
		releaseInfo:     &ReleaseInfo{Name: "app", Revision: 2},
		currentRevision: 1,
	}
	kubeClient := &mockKubeClient{
		healthReport: &HealthReport{
			TotalPods:        5,
			HealthyPods:      5,
			HealthPercentage: 1.0,
			Healthy:          true,
		},
	}
	gates, _ := NewDeploymentGates(
		WithHelmClient(helmClient),
		WithKubeClient(kubeClient),
	)
	ctx := context.Background()
	opts := DeployOptions{
		ReleaseName: "app",
		ChartRef:    "nginx",
		PostCheck: &PostCheckOptions{
			Namespace:   "default",
			ReleaseName: "app",
		},
	}

	result, err := gates.Deploy(ctx, opts)
	if err != nil {
		t.Fatalf("Deploy() error = %v", err)
	}
	if result.Status != DeployStatusSuccess {
		t.Errorf("Status = %v, want success", result.Status)
	}
	if result.Revision != 2 {
		t.Errorf("Revision = %v, want 2", result.Revision)
	}
	if result.PreviousRevision != 1 {
		t.Errorf("PreviousRevision = %v, want 1", result.PreviousRevision)
	}
}

func TestDefaultDeploymentGates_Deploy_PreCheckFails(t *testing.T) {
	t.Parallel()

	helmClient := &mockHelmClient{
		releaseInfo:     &ReleaseInfo{Name: "app", Revision: 2},
		currentRevision: 1,
	}
	policyEngine := &mockPolicyEvaluator{
		result: PolicyResult{Allow: false, Deny: true, Violations: []string{"violation"}},
	}
	gates, _ := NewDeploymentGates(
		WithHelmClient(helmClient),
		WithPolicyEngine(policyEngine),
	)
	ctx := context.Background()
	opts := DeployOptions{
		ReleaseName: "app",
		ChartRef:    "nginx",
		PreCheck: &PreCheckOptions{
			Findings: []model.Finding{{ID: "1", Title: "Test", Severity: model.SeverityCritical}},
		},
	}

	result, err := gates.Deploy(ctx, opts)
	if err == nil {
		t.Error("Deploy() should return error")
	}
	if result.Status != DeployStatusPreCheckFailed {
		t.Errorf("Status = %v, want pre_check_failed", result.Status)
	}
}

func TestDefaultDeploymentGates_Deploy_PostCheckFails_AutoRollback(t *testing.T) {
	t.Parallel()

	helmClient := &mockHelmClient{
		releaseInfo:     &ReleaseInfo{Name: "app", Revision: 2},
		currentRevision: 1,
	}
	kubeClient := &mockKubeClient{
		healthReport: &HealthReport{
			TotalPods:        5,
			HealthyPods:      1,
			HealthPercentage: 0.2,
			Healthy:          false,
		},
	}
	gates, _ := NewDeploymentGates(
		WithHelmClient(helmClient),
		WithKubeClient(kubeClient),
	)
	ctx := context.Background()
	opts := DeployOptions{
		ReleaseName:  "app",
		ChartRef:     "nginx",
		AutoRollback: true,
		PostCheck: &PostCheckOptions{
			Namespace:   "default",
			ReleaseName: "app",
		},
	}

	result, err := gates.Deploy(ctx, opts)
	if err == nil {
		t.Error("Deploy() should return error")
	}
	if !result.RolledBack {
		t.Error("RolledBack should be true")
	}
	if result.Status != DeployStatusRolledBack {
		t.Errorf("Status = %v, want rolled_back", result.Status)
	}
	if !helmClient.rollbackCalled {
		t.Error("Rollback should be called")
	}
}

func TestDefaultDeploymentGates_Deploy_DeployError_AutoRollback(t *testing.T) {
	t.Parallel()

	helmClient := &mockHelmClient{
		currentRevision: 1,
		upgradeErr:      errors.New("upgrade failed"),
	}
	gates, _ := NewDeploymentGates(WithHelmClient(helmClient))
	ctx := context.Background()
	opts := DeployOptions{
		ReleaseName:  "app",
		ChartRef:     "nginx",
		AutoRollback: true,
	}

	result, err := gates.Deploy(ctx, opts)
	if err == nil {
		t.Error("Deploy() should return error")
	}
	if !result.RolledBack {
		t.Error("RolledBack should be true")
	}
	if result.Status != DeployStatusRolledBack {
		t.Errorf("Status = %v, want rolled_back", result.Status)
	}
}

func TestDefaultDeploymentGates_Rollback_NilContext(t *testing.T) {
	t.Parallel()

	gates, _ := NewDeploymentGates(WithHelmClient(&mockHelmClient{currentRevision: 2}))
	opts := RollbackOptions{ReleaseName: "app"}
	err := gates.Rollback(nil, opts) //lint:ignore SA1012 intentionally passing nil context for testing
	if err != ErrNilContext {
		t.Errorf("Rollback(nil) error = %v, want ErrNilContext", err)
	}
}

func TestDefaultDeploymentGates_Rollback_MissingClient(t *testing.T) {
	t.Parallel()

	gates, _ := NewDeploymentGates()
	ctx := context.Background()
	opts := RollbackOptions{ReleaseName: "app"}

	err := gates.Rollback(ctx, opts)
	if err != ErrMissingHelmClient {
		t.Errorf("Rollback() error = %v, want ErrMissingHelmClient", err)
	}
}

func TestDefaultDeploymentGates_Rollback_Success(t *testing.T) {
	t.Parallel()

	helmClient := &mockHelmClient{currentRevision: 3}
	gates, _ := NewDeploymentGates(WithHelmClient(helmClient))
	ctx := context.Background()
	opts := RollbackOptions{ReleaseName: "app", Namespace: "default"}

	err := gates.Rollback(ctx, opts)
	if err != nil {
		t.Fatalf("Rollback() error = %v", err)
	}
	if !helmClient.rollbackCalled {
		t.Error("Rollback should be called")
	}
}

func TestDefaultDeploymentGates_AddGates(t *testing.T) {
	t.Parallel()

	gates, _ := NewDeploymentGates()
	initialPreCount := gates.PreGateCount()
	initialPostCount := gates.PostGateCount()

	gates.AddPreGate(NewSeverityGate())
	gates.AddPostGate(NewHealthGate(nil))

	if gates.PreGateCount() != initialPreCount+1 {
		t.Errorf("PreGateCount() = %v, want %v", gates.PreGateCount(), initialPreCount+1)
	}
	if gates.PostGateCount() != initialPostCount+1 {
		t.Errorf("PostGateCount() = %v, want %v", gates.PostGateCount(), initialPostCount+1)
	}
}

func TestDefaultDeploymentGates_Summary(t *testing.T) {
	t.Parallel()

	gates, _ := NewDeploymentGates(WithNamespace("test-ns"))
	summary := gates.Summary()

	if summary == "" {
		t.Error("Summary() should not be empty")
	}
}

func TestNewDeploymentGatesWithClients(t *testing.T) {
	t.Parallel()

	kubeClient := &mockKubeClient{}
	helmClient := &mockHelmClient{}
	policyEngine := &mockPolicyEvaluator{}
	cfg := Config{Namespace: "test-ns"}

	gates := NewDeploymentGatesWithClients(kubeClient, helmClient, policyEngine, cfg)

	if gates.kubeClient != kubeClient {
		t.Error("kubeClient not set correctly")
	}
	if gates.helmClient != helmClient {
		t.Error("helmClient not set correctly")
	}
	if gates.policyEngine != policyEngine {
		t.Error("policyEngine not set correctly")
	}
	if gates.cfg.Namespace != "test-ns" {
		t.Errorf("Namespace = %v, want test-ns", gates.cfg.Namespace)
	}
}

func TestDefaultDeploymentGates_Deploy_WithPreAndPostCheck(t *testing.T) {
	t.Parallel()

	helmClient := &mockHelmClient{
		releaseInfo:     &ReleaseInfo{Name: "app", Revision: 2},
		currentRevision: 1,
	}
	kubeClient := &mockKubeClient{
		healthReport: &HealthReport{
			TotalPods:        5,
			HealthyPods:      5,
			HealthPercentage: 1.0,
			Healthy:          true,
		},
	}
	policyEngine := &mockPolicyEvaluator{
		result: PolicyResult{Allow: true, Deny: false},
	}
	gates, _ := NewDeploymentGates(
		WithHelmClient(helmClient),
		WithKubeClient(kubeClient),
		WithPolicyEngine(policyEngine),
	)
	ctx := context.Background()
	opts := DeployOptions{
		ReleaseName: "app",
		ChartRef:    "nginx",
		PreCheck: &PreCheckOptions{
			Findings: []model.Finding{{ID: "1", Title: "Test", Severity: model.SeverityLow}},
		},
		PostCheck: &PostCheckOptions{
			Namespace:   "default",
			ReleaseName: "app",
		},
	}

	result, err := gates.Deploy(ctx, opts)
	if err != nil {
		t.Fatalf("Deploy() error = %v", err)
	}
	if result.Status != DeployStatusSuccess {
		t.Errorf("Status = %v, want success", result.Status)
	}
	if result.PreCheckResult == nil {
		t.Error("PreCheckResult should not be nil")
	}
	if result.PostCheckResult == nil {
		t.Error("PostCheckResult should not be nil")
	}
}
