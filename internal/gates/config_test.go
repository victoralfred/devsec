package gates

import (
	"testing"
	"time"

	"github.com/victoralfred/devsec/internal/model"
)

func TestDeployStatus_IsValid(t *testing.T) {
	t.Parallel()

	tests := []struct {
		status   DeployStatus
		name     string
		expected bool
	}{
		{DeployStatusSuccess, "success", true},
		{DeployStatusFailed, "failed", true},
		{DeployStatusRolledBack, "rolled_back", true},
		{DeployStatusPreCheckFailed, "pre_check_failed", true},
		{DeployStatusPostCheckFailed, "post_check_failed", true},
		{DeployStatus("invalid"), "invalid", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.status.IsValid(); got != tt.expected {
				t.Errorf("DeployStatus.IsValid() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestDeployStatus_IsSuccess(t *testing.T) {
	t.Parallel()

	tests := []struct {
		status   DeployStatus
		name     string
		expected bool
	}{
		{DeployStatusSuccess, "success", true},
		{DeployStatusFailed, "failed", false},
		{DeployStatusRolledBack, "rolled_back", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.status.IsSuccess(); got != tt.expected {
				t.Errorf("DeployStatus.IsSuccess() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestDeployStatus_IsFailure(t *testing.T) {
	t.Parallel()

	tests := []struct {
		status   DeployStatus
		name     string
		expected bool
	}{
		{DeployStatusSuccess, "success", false},
		{DeployStatusFailed, "failed", true},
		{DeployStatusPreCheckFailed, "pre_check_failed", true},
		{DeployStatusPostCheckFailed, "post_check_failed", true},
		{DeployStatusRolledBack, "rolled_back", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.status.IsFailure(); got != tt.expected {
				t.Errorf("DeployStatus.IsFailure() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestDefaultConfig(t *testing.T) {
	t.Parallel()

	cfg := DefaultConfig()

	if cfg.Namespace != DefaultNamespace {
		t.Errorf("Namespace = %v, want %v", cfg.Namespace, DefaultNamespace)
	}
	if cfg.Timeout != DefaultTimeout {
		t.Errorf("Timeout = %v, want %v", cfg.Timeout, DefaultTimeout)
	}
	if cfg.DryRun {
		t.Error("DryRun should be false by default")
	}
}

func TestWithNamespace(t *testing.T) {
	t.Parallel()

	cfg := DefaultConfig()
	WithNamespace("kube-system")(&cfg)

	if cfg.Namespace != "kube-system" {
		t.Errorf("Namespace = %v, want kube-system", cfg.Namespace)
	}
}

func TestWithTimeout(t *testing.T) {
	t.Parallel()

	cfg := DefaultConfig()
	WithTimeout(10 * time.Minute)(&cfg)

	if cfg.Timeout != 10*time.Minute {
		t.Errorf("Timeout = %v, want 10m", cfg.Timeout)
	}
}

func TestWithDryRun(t *testing.T) {
	t.Parallel()

	cfg := DefaultConfig()
	WithDryRun(true)(&cfg)

	if !cfg.DryRun {
		t.Error("DryRun should be true")
	}
}

func TestDefaultPostCheckOptions(t *testing.T) {
	t.Parallel()

	opts := DefaultPostCheckOptions()

	if opts.Timeout != DefaultPostCheckTimeout {
		t.Errorf("Timeout = %v, want %v", opts.Timeout, DefaultPostCheckTimeout)
	}
	if opts.MinReadySeconds != DefaultMinReadySeconds {
		t.Errorf("MinReadySeconds = %v, want %v", opts.MinReadySeconds, DefaultMinReadySeconds)
	}
	if opts.HealthThreshold != DefaultHealthThreshold {
		t.Errorf("HealthThreshold = %v, want %v", opts.HealthThreshold, DefaultHealthThreshold)
	}
}

func TestDeployOptions_Validate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		expected error
		name     string
		opts     DeployOptions
	}{
		{
			name:     "valid options",
			opts:     DeployOptions{ReleaseName: "my-app", ChartRef: "nginx"},
			expected: nil,
		},
		{
			name:     "empty release name",
			opts:     DeployOptions{ReleaseName: "", ChartRef: "nginx"},
			expected: ErrEmptyReleaseName,
		},
		{
			name:     "empty chart ref",
			opts:     DeployOptions{ReleaseName: "my-app", ChartRef: ""},
			expected: ErrEmptyChartRef,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.opts.Validate(); got != tt.expected {
				t.Errorf("DeployOptions.Validate() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestRollbackOptions_Validate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		expected error
		name     string
		opts     RollbackOptions
	}{
		{
			name:     "valid options",
			opts:     RollbackOptions{ReleaseName: "my-app", Revision: 1},
			expected: nil,
		},
		{
			name:     "empty release name",
			opts:     RollbackOptions{ReleaseName: "", Revision: 1},
			expected: ErrEmptyReleaseName,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.opts.Validate(); got != tt.expected {
				t.Errorf("RollbackOptions.Validate() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestPreCheckOptions_Validate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		expected error
		name     string
		opts     PreCheckOptions
	}{
		{
			name: "valid options",
			opts: PreCheckOptions{
				Findings: []model.Finding{{ID: "1", Title: "Test"}},
			},
			expected: nil,
		},
		{
			name:     "empty findings",
			opts:     PreCheckOptions{Findings: nil},
			expected: ErrNoFindings,
		},
		{
			name:     "empty findings slice",
			opts:     PreCheckOptions{Findings: []model.Finding{}},
			expected: ErrNoFindings,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.opts.Validate(); got != tt.expected {
				t.Errorf("PreCheckOptions.Validate() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestPostCheckOptions_Validate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		expected error
		name     string
		opts     PostCheckOptions
	}{
		{
			name: "valid options",
			opts: PostCheckOptions{
				Namespace:   "default",
				ReleaseName: "my-app",
			},
			expected: nil,
		},
		{
			name: "empty namespace",
			opts: PostCheckOptions{
				Namespace:   "",
				ReleaseName: "my-app",
			},
			expected: ErrEmptyNamespace,
		},
		{
			name: "empty release name",
			opts: PostCheckOptions{
				Namespace:   "default",
				ReleaseName: "",
			},
			expected: ErrEmptyReleaseName,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.opts.Validate(); got != tt.expected {
				t.Errorf("PostCheckOptions.Validate() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestGateDecision(t *testing.T) {
	t.Parallel()

	now := time.Now()
	decision := GateDecision{
		Timestamp:  now,
		GateName:   "policy",
		Message:    "passed",
		EvalTimeMs: 100,
		Passed:     true,
		Details:    map[string]interface{}{"key": "value"},
	}

	if decision.Timestamp != now {
		t.Errorf("Timestamp = %v, want %v", decision.Timestamp, now)
	}
	if decision.GateName != "policy" {
		t.Errorf("GateName = %v, want policy", decision.GateName)
	}
	if decision.Message != "passed" {
		t.Errorf("Message = %v, want passed", decision.Message)
	}
	if decision.EvalTimeMs != 100 {
		t.Errorf("EvalTimeMs = %v, want 100", decision.EvalTimeMs)
	}
	if !decision.Passed {
		t.Error("Passed should be true")
	}
	if decision.Details["key"] != "value" {
		t.Errorf("Details[key] = %v, want value", decision.Details["key"])
	}
}

func TestGateResult(t *testing.T) {
	t.Parallel()

	now := time.Now()
	result := GateResult{
		Timestamp:   now,
		TotalGates:  3,
		PassedGates: 2,
		FailedGates: 1,
		Passed:      false,
		Summary:     "2/3 gates passed",
		Decisions:   []GateDecision{{GateName: "policy", Passed: true}},
	}

	if result.Timestamp != now {
		t.Errorf("Timestamp = %v, want %v", result.Timestamp, now)
	}
	if result.TotalGates != 3 {
		t.Errorf("TotalGates = %v, want 3", result.TotalGates)
	}
	if result.PassedGates != 2 {
		t.Errorf("PassedGates = %v, want 2", result.PassedGates)
	}
	if result.FailedGates != 1 {
		t.Errorf("FailedGates = %v, want 1", result.FailedGates)
	}
	if result.Passed {
		t.Error("Passed should be false")
	}
	if result.Summary != "2/3 gates passed" {
		t.Errorf("Summary = %v, want '2/3 gates passed'", result.Summary)
	}
	if len(result.Decisions) != 1 {
		t.Errorf("Decisions length = %v, want 1", len(result.Decisions))
	}
}

func TestDeploymentResult(t *testing.T) {
	t.Parallel()

	startTime := time.Now()
	endTime := startTime.Add(time.Minute)
	result := DeploymentResult{
		StartTime:        startTime,
		EndTime:          endTime,
		Namespace:        "default",
		ReleaseName:      "my-app",
		ChartRef:         "nginx",
		Revision:         2,
		PreviousRevision: 1,
		Status:           DeployStatusSuccess,
		RolledBack:       false,
	}

	if result.StartTime != startTime {
		t.Errorf("StartTime = %v, want %v", result.StartTime, startTime)
	}
	if result.EndTime != endTime {
		t.Errorf("EndTime = %v, want %v", result.EndTime, endTime)
	}
	if result.Namespace != "default" {
		t.Errorf("Namespace = %v, want default", result.Namespace)
	}
	if result.ReleaseName != "my-app" {
		t.Errorf("ReleaseName = %v, want my-app", result.ReleaseName)
	}
	if result.ChartRef != "nginx" {
		t.Errorf("ChartRef = %v, want nginx", result.ChartRef)
	}
	if result.Revision != 2 {
		t.Errorf("Revision = %v, want 2", result.Revision)
	}
	if result.PreviousRevision != 1 {
		t.Errorf("PreviousRevision = %v, want 1", result.PreviousRevision)
	}
	if result.Status != DeployStatusSuccess {
		t.Errorf("Status = %v, want success", result.Status)
	}
	if result.RolledBack {
		t.Error("RolledBack should be false")
	}
}

func TestHealthReport(t *testing.T) {
	t.Parallel()

	report := HealthReport{
		Namespace:        "default",
		Deployment:       "my-app",
		TotalPods:        5,
		HealthyPods:      4,
		HealthPercentage: 0.8,
		Healthy:          true,
		UnhealthyPods:    []string{"pod-1"},
	}

	if report.Namespace != "default" {
		t.Errorf("Namespace = %v, want default", report.Namespace)
	}
	if report.Deployment != "my-app" {
		t.Errorf("Deployment = %v, want my-app", report.Deployment)
	}
	if report.TotalPods != 5 {
		t.Errorf("TotalPods = %v, want 5", report.TotalPods)
	}
	if report.HealthyPods != 4 {
		t.Errorf("HealthyPods = %v, want 4", report.HealthyPods)
	}
	if report.HealthPercentage != 0.8 {
		t.Errorf("HealthPercentage = %v, want 0.8", report.HealthPercentage)
	}
	if !report.Healthy {
		t.Error("Healthy should be true")
	}
	if len(report.UnhealthyPods) != 1 {
		t.Errorf("UnhealthyPods length = %v, want 1", len(report.UnhealthyPods))
	}
}

func TestReleaseInfo(t *testing.T) {
	t.Parallel()

	info := ReleaseInfo{
		Name:      "my-app",
		Namespace: "default",
		Chart:     "nginx",
		Version:   "1.0.0",
		Status:    "deployed",
		Revision:  1,
	}

	if info.Name != "my-app" {
		t.Errorf("Name = %v, want my-app", info.Name)
	}
	if info.Namespace != "default" {
		t.Errorf("Namespace = %v, want default", info.Namespace)
	}
	if info.Chart != "nginx" {
		t.Errorf("Chart = %v, want nginx", info.Chart)
	}
	if info.Version != "1.0.0" {
		t.Errorf("Version = %v, want 1.0.0", info.Version)
	}
	if info.Status != "deployed" {
		t.Errorf("Status = %v, want deployed", info.Status)
	}
	if info.Revision != 1 {
		t.Errorf("Revision = %v, want 1", info.Revision)
	}
}

func TestPolicyResult(t *testing.T) {
	t.Parallel()

	result := PolicyResult{
		Allow:      true,
		Deny:       false,
		Violations: nil,
		Warnings:   []string{"warning1"},
	}

	if !result.Allow {
		t.Error("Allow should be true")
	}
	if result.Deny {
		t.Error("Deny should be false")
	}
	if result.Violations != nil {
		t.Errorf("Violations = %v, want nil", result.Violations)
	}
	if len(result.Warnings) != 1 {
		t.Errorf("Warnings length = %v, want 1", len(result.Warnings))
	}
}

func TestGateInput(t *testing.T) {
	t.Parallel()

	input := GateInput{
		Namespace: "default",
		Resource:  "my-deployment",
		Metadata:  map[string]interface{}{"key": "value"},
	}

	if input.Namespace != "default" {
		t.Errorf("Namespace = %v, want default", input.Namespace)
	}
	if input.Resource != "my-deployment" {
		t.Errorf("Resource = %v, want my-deployment", input.Resource)
	}
	if input.Metadata["key"] != "value" {
		t.Errorf("Metadata[key] = %v, want value", input.Metadata["key"])
	}
}
