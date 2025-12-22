package pipeline

import (
	"context"
	"time"

	"github.com/victoralfred/devsec/internal/compliance"
	"github.com/victoralfred/devsec/internal/model"
	"github.com/victoralfred/devsec/internal/policy"
)

// RunnerInput provides input data to stage runners.
// Fields are ordered for optimal memory alignment.
type RunnerInput struct {
	PreviousResults map[string]StageResult
	Assessments     map[compliance.FrameworkID][]compliance.ControlAssessment
	WorkDir         string
	Findings        []model.Finding
	PolicyResults   []policy.EvaluationResult
}

// StageRunner interface for executing stages.
type StageRunner interface {
	Kind() StageKind
	Run(ctx context.Context, stage Stage, input RunnerInput) (StageResult, error)
}

// RunnerRegistry manages stage runners.
type RunnerRegistry struct {
	runners map[StageKind]StageRunner
}

// NewRunnerRegistry creates a new runner registry.
func NewRunnerRegistry() *RunnerRegistry {
	return &RunnerRegistry{
		runners: make(map[StageKind]StageRunner),
	}
}

// Register registers a runner for a stage kind.
func (r *RunnerRegistry) Register(runner StageRunner) {
	if runner != nil {
		r.runners[runner.Kind()] = runner
	}
}

// Get returns the runner for a stage kind.
func (r *RunnerRegistry) Get(kind StageKind) (StageRunner, bool) {
	runner, ok := r.runners[kind]
	return runner, ok
}

// Has checks if a runner is registered for a stage kind.
func (r *RunnerRegistry) Has(kind StageKind) bool {
	_, ok := r.runners[kind]
	return ok
}

// Kinds returns all registered stage kinds.
func (r *RunnerRegistry) Kinds() []StageKind {
	kinds := make([]StageKind, 0, len(r.runners))
	for k := range r.runners {
		kinds = append(kinds, k)
	}
	return kinds
}

// BaseRunner provides common functionality for stage runners.
type BaseRunner struct {
	kind StageKind
}

// Kind returns the stage kind this runner handles.
func (r *BaseRunner) Kind() StageKind {
	return r.kind
}

// createResult creates a stage result with common fields.
func createResult(name string, status StageStatus, startTime time.Time, err error) StageResult {
	endTime := time.Now()
	result := StageResult{
		Name:      name,
		Status:    status,
		StartTime: startTime,
		EndTime:   endTime,
		Duration:  endTime.Sub(startTime),
	}
	if err != nil {
		result.Error = err.Error()
	}
	return result
}

// ScanRunner executes scan stages.
type ScanRunner struct {
	BaseRunner
}

// NewScanRunner creates a new scan runner.
func NewScanRunner() *ScanRunner {
	return &ScanRunner{
		BaseRunner: BaseRunner{kind: StageKindScan},
	}
}

// Run executes a scan stage.
func (r *ScanRunner) Run(ctx context.Context, stage Stage, input RunnerInput) (StageResult, error) {
	startTime := time.Now()

	// Check context cancellation.
	select {
	case <-ctx.Done():
		return createResult(stage.Name, StageStatusCanceled, startTime, ctx.Err()), ctx.Err()
	default:
	}

	// Get scanner type from config.
	scannerType := stage.Config["scanner"]
	if scannerType == "" {
		err := NewStageError(stage.Name, "scanner type not specified", nil)
		return createResult(stage.Name, StageStatusFailed, startTime, err), err
	}

	// Get target path.
	targetPath := stage.Config["path"]
	if targetPath == "" {
		targetPath = input.WorkDir
	}

	// Execute scan (placeholder - actual implementation would use scanner.MultiScanner).
	// This is a stub that will be connected to the real scanner infrastructure.
	result := createResult(stage.Name, StageStatusSuccess, startTime, nil)
	result.Artifacts = map[string]any{
		"scanner": scannerType,
		"path":    targetPath,
	}

	return result, nil
}

// PolicyRunner executes policy stages.
type PolicyRunner struct {
	BaseRunner
}

// NewPolicyRunner creates a new policy runner.
func NewPolicyRunner() *PolicyRunner {
	return &PolicyRunner{
		BaseRunner: BaseRunner{kind: StageKindPolicy},
	}
}

// Run executes a policy stage.
func (r *PolicyRunner) Run(ctx context.Context, stage Stage, input RunnerInput) (StageResult, error) {
	startTime := time.Now()

	// Check context cancellation.
	select {
	case <-ctx.Done():
		return createResult(stage.Name, StageStatusCanceled, startTime, ctx.Err()), ctx.Err()
	default:
	}

	// Get policy directory from config.
	policyDir := stage.Config["policy_dir"]
	if policyDir == "" {
		policyDir = "policies"
	}

	// Get fail threshold.
	failOn := stage.Config["fail_on"]
	if failOn == "" {
		failOn = "high"
	}

	// Execute policy evaluation (placeholder).
	result := createResult(stage.Name, StageStatusSuccess, startTime, nil)
	result.Artifacts = map[string]any{
		"policy_dir": policyDir,
		"fail_on":    failOn,
	}

	return result, nil
}

// ReportRunner executes report stages.
type ReportRunner struct {
	BaseRunner
}

// NewReportRunner creates a new report runner.
func NewReportRunner() *ReportRunner {
	return &ReportRunner{
		BaseRunner: BaseRunner{kind: StageKindReport},
	}
}

// Run executes a report stage.
func (r *ReportRunner) Run(ctx context.Context, stage Stage, input RunnerInput) (StageResult, error) {
	startTime := time.Now()

	// Check context cancellation.
	select {
	case <-ctx.Done():
		return createResult(stage.Name, StageStatusCanceled, startTime, ctx.Err()), ctx.Err()
	default:
	}

	// Get output format.
	format := stage.Config["format"]
	if format == "" {
		format = "json"
	}

	// Get output file.
	output := stage.Config["output"]

	// Execute report generation (placeholder).
	result := createResult(stage.Name, StageStatusSuccess, startTime, nil)
	result.Artifacts = map[string]any{
		"format": format,
		"output": output,
	}

	return result, nil
}

// ComplianceRunner executes compliance stages.
type ComplianceRunner struct {
	BaseRunner
}

// NewComplianceRunner creates a new compliance runner.
func NewComplianceRunner() *ComplianceRunner {
	return &ComplianceRunner{
		BaseRunner: BaseRunner{kind: StageKindCompliance},
	}
}

// Run executes a compliance stage.
func (r *ComplianceRunner) Run(ctx context.Context, stage Stage, input RunnerInput) (StageResult, error) {
	startTime := time.Now()

	// Check context cancellation.
	select {
	case <-ctx.Done():
		return createResult(stage.Name, StageStatusCanceled, startTime, ctx.Err()), ctx.Err()
	default:
	}

	// Get frameworks from config.
	frameworks := stage.Config["frameworks"]
	if frameworks == "" {
		frameworks = "soc2,iso27001,gdpr"
	}

	// Execute compliance assessment (placeholder).
	result := createResult(stage.Name, StageStatusSuccess, startTime, nil)
	result.Artifacts = map[string]any{
		"frameworks": frameworks,
	}

	return result, nil
}

// CustomRunner executes custom shell command stages.
type CustomRunner struct {
	BaseRunner
}

// NewCustomRunner creates a new custom runner.
func NewCustomRunner() *CustomRunner {
	return &CustomRunner{
		BaseRunner: BaseRunner{kind: StageKindCustom},
	}
}

// Run executes a custom stage.
func (r *CustomRunner) Run(ctx context.Context, stage Stage, input RunnerInput) (StageResult, error) {
	startTime := time.Now()

	// Check context cancellation.
	select {
	case <-ctx.Done():
		return createResult(stage.Name, StageStatusCanceled, startTime, ctx.Err()), ctx.Err()
	default:
	}

	// Get command from config.
	command := stage.Config["command"]
	if command == "" {
		err := NewStageError(stage.Name, "command not specified", nil)
		return createResult(stage.Name, StageStatusFailed, startTime, err), err
	}

	// Execute command (placeholder - would use goexec in production).
	result := createResult(stage.Name, StageStatusSuccess, startTime, nil)
	result.Artifacts = map[string]any{
		"command": command,
	}

	return result, nil
}

// DefaultRegistry returns a registry with all default runners.
func DefaultRegistry() *RunnerRegistry {
	registry := NewRunnerRegistry()
	registry.Register(NewScanRunner())
	registry.Register(NewPolicyRunner())
	registry.Register(NewReportRunner())
	registry.Register(NewComplianceRunner())
	registry.Register(NewCustomRunner())
	return registry
}
