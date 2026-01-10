package pipeline

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/victoralfred/devsec/internal/compliance"
	"github.com/victoralfred/devsec/internal/model"
	"github.com/victoralfred/devsec/internal/policy"
	"github.com/victoralfred/devsec/internal/progress"
	"github.com/victoralfred/devsec/internal/report"
	"github.com/victoralfred/devsec/internal/scanner"
	"github.com/victoralfred/goexec"
	"github.com/victoralfred/gowritter/safepath"
)

// RunnerInput provides input data to stage runners.
// Fields are ordered for optimal memory alignment.
type RunnerInput struct {
	PreviousResults  map[string]StageResult
	Assessments      map[compliance.FrameworkID][]compliance.ControlAssessment
	ProgressReporter progress.Reporter
	WorkDir          string
	Findings         []model.Finding
	PolicyResults    []policy.EvaluationResult
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
	registry *scanner.Registry
	BaseRunner
}

// ScanRunnerOption configures a ScanRunner.
type ScanRunnerOption func(*ScanRunner)

// WithScannerRegistry sets the scanner registry for the ScanRunner.
func WithScannerRegistry(registry *scanner.Registry) ScanRunnerOption {
	return func(r *ScanRunner) {
		r.registry = registry
	}
}

// NewScanRunner creates a new scan runner.
// If no registry is provided via options, the default registry is used.
func NewScanRunner(opts ...ScanRunnerOption) *ScanRunner {
	r := &ScanRunner{
		BaseRunner: BaseRunner{kind: StageKindScan},
	}

	for _, opt := range opts {
		opt(r)
	}

	// Use default registry if none provided.
	if r.registry == nil {
		r.registry = scanner.DefaultRegistry()
	}

	return r
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

	// Resolve absolute path.
	absPath, err := filepath.Abs(targetPath)
	if err != nil {
		err = NewStageError(stage.Name, fmt.Sprintf("failed to resolve path: %v", err), nil)
		return createResult(stage.Name, StageStatusFailed, startTime, err), err
	}

	// Get timeout from config or use stage timeout.
	timeout := stage.GetTimeout()

	// Create scanner based on type.
	findings, scanErr := r.runScanner(ctx, scannerType, absPath, timeout)
	if scanErr != nil {
		err := NewStageError(stage.Name, fmt.Sprintf("scanner %s failed: %v", scannerType, scanErr), nil)
		return createResult(stage.Name, StageStatusFailed, startTime, err), err
	}

	// Report findings to progress reporter.
	if input.ProgressReporter != nil && len(findings) > 0 {
		count := countFindingsBySeverity(findings)
		input.ProgressReporter.ReportFindingCount(count)
	}

	result := createResult(stage.Name, StageStatusSuccess, startTime, nil)
	result.Artifacts = map[string]any{
		"scanner":       scannerType,
		"path":          absPath,
		"findings":      findings,
		"finding_count": len(findings),
	}

	return result, nil
}

// countFindingsBySeverity counts findings by severity level.
func countFindingsBySeverity(findings []model.Finding) progress.FindingCount {
	var count progress.FindingCount
	for i := range findings {
		switch findings[i].Severity {
		case model.SeverityCritical:
			count.Critical++
		case model.SeverityHigh:
			count.High++
		case model.SeverityMedium:
			count.Medium++
		case model.SeverityLow:
			count.Low++
		default:
			count.Info++
		}
	}
	return count
}

// runScanner creates and executes the appropriate scanner using the registry.
func (r *ScanRunner) runScanner(ctx context.Context, scannerType, path string, timeout time.Duration) ([]model.Finding, error) {
	return r.registry.RunScanner(ctx, scannerType, path, timeout)
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

	// Resolve to absolute path relative to work dir.
	if !filepath.IsAbs(policyDir) {
		policyDir = filepath.Join(input.WorkDir, policyDir)
	}

	// Get fail threshold.
	failOn := stage.Config["fail_on"]
	if failOn == "" {
		failOn = "high"
	}

	// Create policy engine.
	engine := policy.New()
	defer func() { _ = engine.Close(ctx) }()

	// Load policies from directory.
	if loadErr := r.loadPolicies(ctx, engine, policyDir); loadErr != nil {
		err := NewStageError(stage.Name, fmt.Sprintf("failed to load policies: %v", loadErr), nil)
		return createResult(stage.Name, StageStatusFailed, startTime, err), err
	}

	// Check if any policies were loaded.
	if engine.PolicyCount() == 0 {
		err := NewStageError(stage.Name, "no policies found in directory", nil)
		return createResult(stage.Name, StageStatusFailed, startTime, err), err
	}

	// Evaluate policies against findings.
	evalResults, evalErr := engine.Evaluate(ctx, input.Findings)
	if evalErr != nil {
		err := NewStageError(stage.Name, fmt.Sprintf("policy evaluation failed: %v", evalErr), nil)
		return createResult(stage.Name, StageStatusFailed, startTime, err), err
	}

	// Check if any policy failed based on fail_on threshold.
	failed, failedCount := r.checkThreshold(evalResults, failOn, input.Findings)

	status := StageStatusSuccess
	var stageErr error
	if failed {
		status = StageStatusFailed
		stageErr = NewStageError(stage.Name, fmt.Sprintf("policy check failed: %d findings exceed threshold", failedCount), nil)
	}

	result := createResult(stage.Name, status, startTime, stageErr)
	result.Artifacts = map[string]any{
		"policy_dir":     policyDir,
		"fail_on":        failOn,
		"policy_count":   engine.PolicyCount(),
		"eval_results":   evalResults,
		"findings_count": len(input.Findings),
		"failed_count":   failedCount,
	}

	if stageErr != nil {
		return result, stageErr
	}
	return result, nil
}

// loadPolicies loads all .rego files from the policy directory.
func (r *PolicyRunner) loadPolicies(ctx context.Context, engine *policy.Engine, policyDir string) error {
	sp, err := safepath.New(policyDir)
	if err != nil {
		return fmt.Errorf("policy directory not accessible: %w", err)
	}

	entries, err := sp.ReadDir(".")
	if err != nil {
		return fmt.Errorf("failed to read policy directory: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if !strings.HasSuffix(entry.Name(), ".rego") {
			continue
		}

		policyPath := filepath.Join(policyDir, entry.Name())
		if loadErr := engine.LoadPolicy(ctx, policyPath); loadErr != nil {
			return fmt.Errorf("failed to load policy %s: %w", entry.Name(), loadErr)
		}
	}

	return nil
}

// checkThreshold checks if findings exceed the fail_on threshold.
func (r *PolicyRunner) checkThreshold(_ []policy.EvaluationResult, failOn string, findings []model.Finding) (failed bool, count int) {
	// Count findings by severity.
	var critical, high, medium, low int
	for i := range findings {
		switch findings[i].Severity {
		case model.SeverityCritical:
			critical++
		case model.SeverityHigh:
			high++
		case model.SeverityMedium:
			medium++
		case model.SeverityLow:
			low++
		}
	}

	// Determine failure based on threshold.
	switch strings.ToLower(failOn) {
	case "critical":
		return critical > 0, critical
	case "high":
		total := critical + high
		return total > 0, total
	case "medium":
		total := critical + high + medium
		return total > 0, total
	case "low":
		total := critical + high + medium + low
		return total > 0, total
	default:
		// Default to high threshold.
		total := critical + high
		return total > 0, total
	}
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

	// Get output file path.
	output := stage.Config["output"]

	// Create aggregator with deduplication.
	agg := report.New(report.WithDeduplication(true))

	// Add findings from input.
	if len(input.Findings) > 0 {
		if addErr := agg.AddFindings("pipeline", input.Findings); addErr != nil {
			err := NewStageError(stage.Name, fmt.Sprintf("failed to add findings: %v", addErr), nil)
			return createResult(stage.Name, StageStatusFailed, startTime, err), err
		}
	}

	// Aggregate findings into report.
	rpt, aggErr := agg.Aggregate(ctx)
	if aggErr != nil {
		err := NewStageError(stage.Name, fmt.Sprintf("failed to aggregate report: %v", aggErr), nil)
		return createResult(stage.Name, StageStatusFailed, startTime, err), err
	}

	// Format report based on requested format.
	reportData, formatErr := r.formatReport(rpt, format)
	if formatErr != nil {
		err := NewStageError(stage.Name, fmt.Sprintf("failed to format report: %v", formatErr), nil)
		return createResult(stage.Name, StageStatusFailed, startTime, err), err
	}

	// Write to file if output path specified.
	if output != "" {
		if !filepath.IsAbs(output) {
			output = filepath.Join(input.WorkDir, output)
		}

		dir := filepath.Dir(output)
		sp, spErr := safepath.New(dir)
		if spErr != nil {
			err := NewStageError(stage.Name, fmt.Sprintf("output directory not accessible: %v", spErr), nil)
			return createResult(stage.Name, StageStatusFailed, startTime, err), err
		}

		filename := filepath.Base(output)
		if writeErr := sp.WriteFile(filename, reportData, 0o644); writeErr != nil {
			err := NewStageError(stage.Name, fmt.Sprintf("failed to write report: %v", writeErr), nil)
			return createResult(stage.Name, StageStatusFailed, startTime, err), err
		}
	}

	result := createResult(stage.Name, StageStatusSuccess, startTime, nil)
	result.Artifacts = map[string]any{
		"format":        format,
		"output":        output,
		"finding_count": len(rpt.Findings),
		"summary":       rpt.Summary,
		"report_data":   string(reportData),
	}

	return result, nil
}

// formatReport formats the report based on the specified format.
func (r *ReportRunner) formatReport(rpt *model.Report, format string) ([]byte, error) {
	switch strings.ToLower(format) {
	case "json":
		return json.MarshalIndent(rpt, "", "  ")
	case "sarif":
		return r.formatSARIF(rpt)
	case "markdown", "md":
		return r.formatMarkdown(rpt), nil
	default:
		return json.MarshalIndent(rpt, "", "  ")
	}
}

// formatSARIF formats the report as SARIF.
func (r *ReportRunner) formatSARIF(rpt *model.Report) ([]byte, error) {
	sarif := map[string]any{
		"$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		"version": "2.1.0",
		"runs": []map[string]any{
			{
				"tool": map[string]any{
					"driver": map[string]any{
						"name":    "devsec",
						"version": "1.0.0",
					},
				},
				"results": r.findingsToSARIFResults(rpt.Findings),
			},
		},
	}
	return json.MarshalIndent(sarif, "", "  ")
}

// findingsToSARIFResults converts findings to SARIF results.
func (r *ReportRunner) findingsToSARIFResults(findings []model.Finding) []map[string]any {
	results := make([]map[string]any, 0, len(findings))
	for i := range findings {
		f := &findings[i]
		result := map[string]any{
			"ruleId":  f.Rule,
			"level":   r.severityToSARIFLevel(f.Severity),
			"message": map[string]string{"text": f.Description},
			"locations": []map[string]any{
				{
					"physicalLocation": map[string]any{
						"artifactLocation": map[string]string{"uri": f.Location.File},
						"region": map[string]int{
							"startLine": f.Location.StartLine,
							"endLine":   f.Location.EndLine,
						},
					},
				},
			},
		}
		results = append(results, result)
	}
	return results
}

// severityToSARIFLevel converts severity to SARIF level.
func (r *ReportRunner) severityToSARIFLevel(severity model.Severity) string {
	switch severity {
	case model.SeverityCritical, model.SeverityHigh:
		return "error"
	case model.SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}

// formatMarkdown formats the report as Markdown.
func (r *ReportRunner) formatMarkdown(rpt *model.Report) []byte {
	var builder strings.Builder
	builder.Grow(4096)

	builder.WriteString("# Security Report\n\n")
	builder.WriteString(fmt.Sprintf("Generated: %s\n\n", rpt.Timestamp))

	builder.WriteString("## Summary\n\n")
	builder.WriteString(fmt.Sprintf("- Total: %d\n", rpt.Summary.Total))
	builder.WriteString(fmt.Sprintf("- Critical: %d\n", rpt.Summary.Critical))
	builder.WriteString(fmt.Sprintf("- High: %d\n", rpt.Summary.High))
	builder.WriteString(fmt.Sprintf("- Medium: %d\n", rpt.Summary.Medium))
	builder.WriteString(fmt.Sprintf("- Low: %d\n", rpt.Summary.Low))
	builder.WriteString(fmt.Sprintf("- Info: %d\n\n", rpt.Summary.Info))

	if len(rpt.Findings) > 0 {
		builder.WriteString("## Findings\n\n")
		for i := range rpt.Findings {
			f := &rpt.Findings[i]
			builder.WriteString(fmt.Sprintf("### %s\n\n", f.Title))
			builder.WriteString(fmt.Sprintf("- **Severity**: %s\n", f.Severity))
			builder.WriteString(fmt.Sprintf("- **Rule**: %s\n", f.Rule))
			builder.WriteString(fmt.Sprintf("- **File**: %s:%d\n", f.Location.File, f.Location.StartLine))
			builder.WriteString(fmt.Sprintf("- **Description**: %s\n\n", f.Description))
		}
	}

	return []byte(builder.String())
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
	frameworksConfig := stage.Config["frameworks"]
	if frameworksConfig == "" {
		frameworksConfig = "soc2,iso27001,gdpr"
	}

	// Parse framework IDs.
	frameworkIDs := r.parseFrameworks(frameworksConfig)
	if len(frameworkIDs) == 0 {
		err := NewStageError(stage.Name, "no valid frameworks specified", nil)
		return createResult(stage.Name, StageStatusFailed, startTime, err), err
	}

	// Create compliance mapper.
	mapper := compliance.NewMapper()

	// Enrich findings with compliance metadata.
	enriched, enrichErr := mapper.Enrich(ctx, input.Findings)
	if enrichErr != nil {
		err := NewStageError(stage.Name, fmt.Sprintf("failed to enrich findings: %v", enrichErr), nil)
		return createResult(stage.Name, StageStatusFailed, startTime, err), err
	}

	// Map to controls for each framework.
	assessments, mapErr := mapper.MapToControls(ctx, enriched, frameworkIDs)
	if mapErr != nil {
		err := NewStageError(stage.Name, fmt.Sprintf("failed to map to controls: %v", mapErr), nil)
		return createResult(stage.Name, StageStatusFailed, startTime, err), err
	}

	// Calculate summary statistics.
	summary := r.calculateComplianceSummary(assessments)

	result := createResult(stage.Name, StageStatusSuccess, startTime, nil)
	result.Artifacts = map[string]any{
		"frameworks":        frameworksConfig,
		"framework_ids":     frameworkIDs,
		"assessments":       assessments,
		"enriched_findings": len(enriched),
		"summary":           summary,
	}

	return result, nil
}

// parseFrameworks parses a comma-separated list of framework names to IDs.
func (r *ComplianceRunner) parseFrameworks(config string) []compliance.FrameworkID {
	parts := strings.Split(config, ",")
	frameworks := make([]compliance.FrameworkID, 0, len(parts))

	for _, part := range parts {
		part = strings.TrimSpace(strings.ToLower(part))
		switch part {
		case "soc2":
			frameworks = append(frameworks, compliance.FrameworkSOC2)
		case "iso27001":
			frameworks = append(frameworks, compliance.FrameworkISO27001)
		case "gdpr":
			frameworks = append(frameworks, compliance.FrameworkGDPR)
		}
	}

	return frameworks
}

// calculateComplianceSummary calculates summary statistics from assessments.
func (r *ComplianceRunner) calculateComplianceSummary(assessments map[compliance.FrameworkID][]compliance.ControlAssessment) map[string]any {
	summary := make(map[string]any)

	for fwID, fwAssessments := range assessments {
		var compliant, nonCompliant, partial, notAssessed int
		var totalFindings int

		for i := range fwAssessments {
			a := &fwAssessments[i]
			totalFindings += a.FindingCount

			switch a.Status {
			case compliance.StatusCompliant:
				compliant++
			case compliance.StatusNonCompliant:
				nonCompliant++
			case compliance.StatusPartial:
				partial++
			case compliance.StatusNotAssessed:
				notAssessed++
			}
		}

		summary[string(fwID)] = map[string]int{
			"total_controls": len(fwAssessments),
			"compliant":      compliant,
			"non_compliant":  nonCompliant,
			"partial":        partial,
			"not_assessed":   notAssessed,
			"total_findings": totalFindings,
		}
	}

	return summary
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

	// Get working directory from config or use input.WorkDir.
	workDir := stage.Config["working_dir"]
	if workDir == "" {
		workDir = input.WorkDir
	}
	if !filepath.IsAbs(workDir) {
		workDir = filepath.Join(input.WorkDir, workDir)
	}

	// Get timeout from stage config.
	timeout := stage.GetTimeout()

	// Create executor.
	executor, execErr := goexec.New()
	if execErr != nil {
		err := NewStageError(stage.Name, fmt.Sprintf("failed to create executor: %v", execErr), nil)
		return createResult(stage.Name, StageStatusFailed, startTime, err), err
	}
	defer func() { _ = executor.Shutdown(ctx) }()

	// Parse command into parts (simple split by space, doesn't handle quotes).
	parts := r.parseCommand(command)
	if len(parts) == 0 {
		err := NewStageError(stage.Name, "invalid command", nil)
		return createResult(stage.Name, StageStatusFailed, startTime, err), err
	}

	// Build command.
	cmdBuilder := goexec.Cmd(parts[0], parts[1:]...).
		WithTimeout(timeout).
		WithWorkingDir(workDir)

	cmd, buildErr := cmdBuilder.Build()
	if buildErr != nil {
		err := NewStageError(stage.Name, fmt.Sprintf("failed to build command: %v", buildErr), nil)
		return createResult(stage.Name, StageStatusFailed, startTime, err), err
	}

	// Execute command.
	execResult, runErr := executor.Execute(ctx, cmd)
	if runErr != nil {
		err := NewStageError(stage.Name, fmt.Sprintf("failed to execute command: %v", runErr), nil)
		return createResult(stage.Name, StageStatusFailed, startTime, err), err
	}

	// Determine status based on exit code.
	status := StageStatusSuccess
	var stageErr error
	if !execResult.Success() {
		status = StageStatusFailed
		stageErr = NewStageError(stage.Name, fmt.Sprintf("command failed with exit code %d", execResult.ExitCode), nil)
	}

	result := createResult(stage.Name, status, startTime, stageErr)
	result.Artifacts = map[string]any{
		"command":   command,
		"work_dir":  workDir,
		"exit_code": execResult.ExitCode,
		"stdout":    execResult.StdoutString(),
		"stderr":    execResult.StderrString(),
	}

	if stageErr != nil {
		return result, stageErr
	}
	return result, nil
}

// parseCommand parses a command string into parts.
// Handles simple quoted strings (single and double quotes).
func (r *CustomRunner) parseCommand(command string) []string {
	var parts []string
	var current strings.Builder
	inSingleQuote := false
	inDoubleQuote := false

	for i := 0; i < len(command); i++ {
		c := command[i]

		switch {
		case c == '\'' && !inDoubleQuote:
			inSingleQuote = !inSingleQuote
		case c == '"' && !inSingleQuote:
			inDoubleQuote = !inDoubleQuote
		case c == ' ' && !inSingleQuote && !inDoubleQuote:
			if current.Len() > 0 {
				parts = append(parts, current.String())
				current.Reset()
			}
		default:
			current.WriteByte(c)
		}
	}

	if current.Len() > 0 {
		parts = append(parts, current.String())
	}

	return parts
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
