package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"
	"github.com/victoralfred/devsec/internal/compliance"
	"github.com/victoralfred/devsec/internal/model"
	"github.com/victoralfred/devsec/internal/progress"
	"github.com/victoralfred/devsec/internal/scanner/gitleaks"
	"github.com/victoralfred/devsec/internal/scanner/osv"
	"github.com/victoralfred/devsec/internal/scanner/semgrep"
	"github.com/victoralfred/devsec/internal/scanner/trivy"
	"github.com/victoralfred/devsec/internal/tui"
	"github.com/victoralfred/gowritter/safepath"
)

// coverageResult holds coverage statistics for JSON output.
// Fields ordered for optimal memory alignment.
type coverageResult struct {
	Frameworks []compliance.CoverageStats `json:"frameworks"`
	Overall    compliance.CoverageStats   `json:"overall"`
}

// gapsResult holds gap analysis results for JSON output.
// Fields ordered for optimal memory alignment.
type gapsResult struct {
	Gaps    []compliance.Gap      `json:"gaps"`
	Summary compliance.GapSummary `json:"summary"`
}

var (
	complianceAssessOutput    string
	complianceAssessFormat    string
	complianceAssessFramework string
	complianceAssessTimeout   time.Duration
	complianceAssessScanFile  string

	complianceReportOutput  string
	complianceReportFormat  string
	complianceReportTimeout time.Duration

	complianceCoverageOutput  string
	complianceCoverageFormat  string
	complianceCoverageTimeout time.Duration

	complianceGapsOutput  string
	complianceGapsFormat  string
	complianceGapsTimeout time.Duration
)

// NewComplianceCmd creates the compliance command.
func NewComplianceCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "compliance",
		Short: "Compliance assessment and reporting",
		Long: `Compliance assessment and reporting tools.

Provides:
  - Compliance assessment against SOC 2, ISO 27001, GDPR
  - Compliance report generation
  - Coverage statistics
  - Gap analysis

Supported frameworks:
  - soc2: SOC 2 Trust Services Criteria
  - iso27001: ISO/IEC 27001:2022
  - gdpr: EU General Data Protection Regulation`,
	}

	cmd.AddCommand(NewComplianceAssessCmd())
	cmd.AddCommand(NewComplianceReportCmd())
	cmd.AddCommand(NewComplianceCoverageCmd())
	cmd.AddCommand(NewComplianceGapsCmd())
	cmd.AddCommand(NewComplianceControlsCmd())

	return cmd
}

// NewComplianceAssessCmd creates the compliance assess subcommand.
func NewComplianceAssessCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "assess [path]",
		Short: "Run compliance assessment",
		Long: `Run compliance assessment against specified frameworks.

Maps security findings to compliance controls and calculates
compliance status for each control.

The assessment determines if controls are:
  - compliant: No violations detected
  - non_compliant: Critical or high severity violations
  - partial: Low or medium severity issues
  - not_assessed: Not enough data to assess`,
		Args: cobra.MaximumNArgs(1),
		RunE: runComplianceAssess,
	}

	cmd.Flags().StringVarP(&complianceAssessOutput, "output", "o", "", "output file (default: stdout)")
	cmd.Flags().StringVarP(&complianceAssessFormat, "format", "f", "json", "output format (json, markdown)")
	cmd.Flags().StringVarP(&complianceAssessFramework, "frameworks", "F", "", "frameworks (comma-separated: soc2,iso27001,gdpr)")
	cmd.Flags().DurationVarP(&complianceAssessTimeout, "timeout", "t", 5*time.Minute, "assessment timeout")
	cmd.Flags().StringVarP(&complianceAssessScanFile, "scan-file", "s", "", "use existing scan results file")

	return cmd
}

func runComplianceAssess(cmd *cobra.Command, args []string) error {
	path := "."
	if len(args) > 0 {
		path = args[0]
	}

	absPath, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("resolve path: %w", err)
	}

	// Use TUI if enabled and scanning is needed (no scan-file provided).
	if IsProgressEnabled() && complianceAssessScanFile == "" {
		return runComplianceAssessWithTUI(cmd, absPath)
	}

	ctx, cancel := context.WithTimeout(context.Background(), complianceAssessTimeout)
	defer cancel()

	// Get findings.
	var findings []model.Finding
	if complianceAssessScanFile != "" {
		findings, err = loadFindingsFromFile(complianceAssessScanFile)
		if err != nil {
			return fmt.Errorf("load scan file: %w", err)
		}
	} else {
		cmd.Printf("Scanning %s for security findings...\n", absPath)
		findings, err = runQuickScan(ctx, absPath)
		if err != nil {
			return fmt.Errorf("scan: %w", err)
		}
	}

	// Parse frameworks.
	frameworks := parseFrameworks(complianceAssessFramework)

	// Create mapper and generator.
	mapper := compliance.NewMapper()
	generator := compliance.NewReportGenerator(mapper)

	opts := compliance.GenerateOptions{
		Frameworks:  frameworks,
		IncludeGaps: true,
	}

	report, err := generator.Generate(ctx, findings, opts)
	if err != nil {
		return fmt.Errorf("generate report: %w", err)
	}

	// Format output.
	formatter := compliance.GetFormatter(complianceAssessFormat)
	output, err := formatter.Format(report)
	if err != nil {
		return fmt.Errorf("format report: %w", err)
	}

	return writeComplianceOutput(cmd, output, complianceAssessOutput)
}

// complianceResult holds the result of a compliance assessment.
type complianceResult struct {
	err    error
	report *compliance.Report
	output []byte
}

// runComplianceAssessWithTUI runs compliance assessment with TUI progress display.
func runComplianceAssessWithTUI(cmd *cobra.Command, absPath string) error {
	reporter, events := progress.NewChannelReporter(100)

	tuiModel := tui.NewModel(tui.Config{
		CommandName: "compliance-assess",
		CommandType: tui.CommandTypeCompliance,
		Events:      events,
	})

	// Result channel for capturing the final result.
	resultChan := make(chan complianceResult, 1)

	// Run assessment in goroutine.
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), complianceAssessTimeout)
		defer cancel()

		// Run scans with progress reporting.
		reporter.ReportLog("info", fmt.Sprintf("Scanning %s for security findings...", absPath))
		findings, err := runQuickScanWithProgress(ctx, absPath, reporter)
		if err != nil {
			reporter.ReportCompleted(context.TODO(), fmt.Errorf("scan: %w", err))
			reporter.Close()
			resultChan <- complianceResult{err: fmt.Errorf("scan: %w", err)}
			return
		}

		// Parse frameworks.
		reporter.ReportStageStarted("compliance-mapping")
		reporter.ReportLog("info", "Mapping findings to compliance controls...")
		frameworks := parseFrameworks(complianceAssessFramework)

		// Create mapper and generator.
		mapper := compliance.NewMapper()
		generator := compliance.NewReportGenerator(mapper)

		opts := compliance.GenerateOptions{
			Frameworks:  frameworks,
			IncludeGaps: true,
		}

		report, err := generator.Generate(ctx, findings, opts)
		if err != nil {
			reporter.ReportStageCompleted("compliance-mapping", progress.StatusFailed, 0)
			reporter.ReportCompleted(context.TODO(), fmt.Errorf("generate report: %w", err))
			reporter.Close()
			resultChan <- complianceResult{err: fmt.Errorf("generate report: %w", err)}
			return
		}
		reporter.ReportStageCompleted("compliance-mapping", progress.StatusSuccess, 0)

		// Format output.
		formatter := compliance.GetFormatter(complianceAssessFormat)
		output, err := formatter.Format(report)
		if err != nil {
			reporter.ReportCompleted(context.TODO(), fmt.Errorf("format report: %w", err))
			reporter.Close()
			resultChan <- complianceResult{err: fmt.Errorf("format report: %w", err)}
			return
		}

		// Write output.
		if complianceAssessOutput != "" {
			absOutput, err := filepath.Abs(complianceAssessOutput)
			if err != nil {
				reporter.ReportCompleted(context.TODO(), fmt.Errorf("resolve output path: %w", err))
				reporter.Close()
				resultChan <- complianceResult{err: fmt.Errorf("resolve output path: %w", err)}
				return
			}

			dir := filepath.Dir(absOutput)
			filename := filepath.Base(absOutput)

			sp, err := safepath.New(dir)
			if err != nil {
				reporter.ReportCompleted(context.TODO(), fmt.Errorf("create safepath: %w", err))
				reporter.Close()
				resultChan <- complianceResult{err: fmt.Errorf("create safepath: %w", err)}
				return
			}

			if err := sp.WriteFile(filename, output, 0o644); err != nil {
				reporter.ReportCompleted(context.TODO(), fmt.Errorf("write output: %w", err))
				reporter.Close()
				resultChan <- complianceResult{err: fmt.Errorf("write output: %w", err)}
				return
			}

			reporter.ReportLog("info", fmt.Sprintf("Results written to: %s", absOutput))
		}

		reporter.ReportCompleted(report, nil)
		reporter.Close()
		resultChan <- complianceResult{report: report, output: output}
	}()

	// Run TUI.
	if tuiErr := tui.Run(tuiModel); tuiErr != nil {
		res := <-resultChan
		if res.err != nil {
			return fmt.Errorf("compliance assessment failed: %w", res.err)
		}
		return fmt.Errorf("TUI error: %w", tuiErr)
	}

	// Get the result.
	res := <-resultChan
	if res.err != nil {
		return res.err
	}

	// Print output to stdout if no output file was specified.
	if complianceAssessOutput == "" && len(res.output) > 0 {
		cmd.Println(string(res.output))
	}

	return nil
}

// runQuickScanWithProgress runs security scanners with progress reporting.
func runQuickScanWithProgress(ctx context.Context, path string, reporter progress.Reporter) ([]model.Finding, error) {
	// Check context cancellation early.
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	scanners := []string{"gitleaks", "osv", "semgrep", "trivy"}
	var wg sync.WaitGroup
	results := make(chan scannerResult, 4)

	// Report all scanner stages.
	for _, name := range scanners {
		reporter.ReportStageStarted(name)
	}

	// Run gitleaks for secret detection.
	wg.Add(1)
	go func() {
		defer wg.Done()
		startTime := time.Now()
		scanner, err := gitleaks.New()
		if err != nil {
			reporter.ReportStageCompleted("gitleaks", progress.StatusFailed, time.Since(startTime))
			results <- scannerResult{name: "gitleaks", err: err}
			return
		}
		defer func() { _ = scanner.Close(ctx) }()

		findings, err := scanner.Scan(ctx, path)
		if err != nil {
			reporter.ReportStageCompleted("gitleaks", progress.StatusFailed, time.Since(startTime))
		} else {
			reporter.ReportStageCompleted("gitleaks", progress.StatusSuccess, time.Since(startTime))
		}
		results <- scannerResult{name: "gitleaks", findings: findings, err: err}
	}()

	// Run OSV for dependency vulnerabilities.
	wg.Add(1)
	go func() {
		defer wg.Done()
		startTime := time.Now()
		scanner := osv.New()
		defer func() { _ = scanner.Close(ctx) }()

		findings, err := scanner.Scan(ctx, path)
		if err != nil {
			reporter.ReportStageCompleted("osv", progress.StatusFailed, time.Since(startTime))
		} else {
			reporter.ReportStageCompleted("osv", progress.StatusSuccess, time.Since(startTime))
		}
		results <- scannerResult{name: "osv", findings: findings, err: err}
	}()

	// Run Semgrep for SAST (if available).
	wg.Add(1)
	go func() {
		defer wg.Done()
		startTime := time.Now()
		scanner := semgrep.New()
		defer func() { _ = scanner.Close(ctx) }()

		findings, err := scanner.Scan(ctx, path)
		if err != nil {
			reporter.ReportStageCompleted("semgrep", progress.StatusFailed, time.Since(startTime))
		} else {
			reporter.ReportStageCompleted("semgrep", progress.StatusSuccess, time.Since(startTime))
		}
		results <- scannerResult{name: "semgrep", findings: findings, err: err}
	}()

	// Run Trivy for container/filesystem vulnerabilities.
	wg.Add(1)
	go func() {
		defer wg.Done()
		startTime := time.Now()
		scanner := trivy.New()
		defer func() { _ = scanner.Close(ctx) }()

		findings, err := scanner.Scan(ctx, path)
		if err != nil {
			reporter.ReportStageCompleted("trivy", progress.StatusFailed, time.Since(startTime))
		} else {
			reporter.ReportStageCompleted("trivy", progress.StatusSuccess, time.Since(startTime))
		}
		results <- scannerResult{name: "trivy", findings: findings, err: err}
	}()

	// Wait for all scanners to complete.
	go func() {
		wg.Wait()
		close(results)
	}()

	// Aggregate findings from all scanners.
	var allFindings []model.Finding
	var scanErrors []string

	for result := range results {
		if result.err != nil {
			// Log scanner errors but continue with other scanners.
			scanErrors = append(scanErrors, fmt.Sprintf("%s: %v", result.name, result.err))
			reporter.ReportLog("warn", fmt.Sprintf("Scanner %s failed: %v", result.name, result.err))
			continue
		}
		allFindings = append(allFindings, result.findings...)

		// Report findings count.
		if len(result.findings) > 0 {
			reporter.ReportLog("info", fmt.Sprintf("%s found %d findings", result.name, len(result.findings)))
			for i := range result.findings {
				reporter.ReportFinding(result.findings[i])
			}
		}
	}

	// Update overall finding count.
	reporter.ReportFindingCount(countComplianceFindings(allFindings))

	// If all scanners failed, return an error.
	if len(allFindings) == 0 && len(scanErrors) == len(scanners) {
		return nil, fmt.Errorf("all scanners failed: %s", strings.Join(scanErrors, "; "))
	}

	return allFindings, nil
}

// countComplianceFindings counts findings by severity.
func countComplianceFindings(findings []model.Finding) progress.FindingCount {
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
		case model.SeverityInfo:
			count.Info++
		}
	}
	return count
}

// NewComplianceReportCmd creates the compliance report subcommand.
func NewComplianceReportCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "report [scan-file]",
		Short: "Generate compliance report from scan results",
		Long: `Generate a compliance report from existing scan results.

Creates an auditor-ready report with:
  - Executive summary
  - Per-framework compliance status
  - Control assessments with evidence
  - Gap analysis and remediation guidance`,
		Args: cobra.ExactArgs(1),
		RunE: runComplianceReport,
	}

	cmd.Flags().StringVarP(&complianceReportOutput, "output", "o", "", "output file (required)")
	cmd.Flags().StringVarP(&complianceReportFormat, "format", "f", "markdown", "output format (json, markdown)")
	cmd.Flags().DurationVarP(&complianceReportTimeout, "timeout", "t", 2*time.Minute, "report generation timeout")

	_ = cmd.MarkFlagRequired("output")

	return cmd
}

func runComplianceReport(cmd *cobra.Command, args []string) error {
	scanFile := args[0]

	findings, err := loadFindingsFromFile(scanFile)
	if err != nil {
		return fmt.Errorf("load scan file: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), complianceReportTimeout)
	defer cancel()

	// Create mapper and generator.
	mapper := compliance.NewMapper()
	generator := compliance.NewReportGenerator(mapper)

	opts := compliance.GenerateOptions{
		Frameworks:      nil, // All frameworks.
		IncludeEvidence: true,
		IncludeGaps:     true,
	}

	report, err := generator.Generate(ctx, findings, opts)
	if err != nil {
		return fmt.Errorf("generate report: %w", err)
	}

	// Create enhanced report with metadata.
	enhanced := compliance.NewEnhancedReport(report)

	// Format output.
	var output []byte
	switch complianceReportFormat {
	case "markdown", "md":
		formatter := compliance.NewMarkdownFormatter(true)
		output, err = formatter.Format(report)
	default:
		output, err = json.MarshalIndent(enhanced, "", "  ")
	}
	if err != nil {
		return fmt.Errorf("format report: %w", err)
	}

	return writeComplianceOutput(cmd, output, complianceReportOutput)
}

// NewComplianceCoverageCmd creates the compliance coverage subcommand.
func NewComplianceCoverageCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "coverage [scan-file]",
		Short: "Show compliance coverage statistics",
		Long: `Show compliance coverage statistics from scan results.

Displays:
  - Per-framework coverage percentage
  - Total vs assessed controls
  - Compliant vs non-compliant counts
  - Overall compliance score`,
		Args: cobra.ExactArgs(1),
		RunE: runComplianceCoverage,
	}

	cmd.Flags().StringVarP(&complianceCoverageOutput, "output", "o", "", "output file (default: stdout)")
	cmd.Flags().StringVarP(&complianceCoverageFormat, "format", "f", "text", "output format (text, json)")
	cmd.Flags().DurationVarP(&complianceCoverageTimeout, "timeout", "t", 1*time.Minute, "coverage calculation timeout")

	return cmd
}

func runComplianceCoverage(cmd *cobra.Command, args []string) error {
	scanFile := args[0]

	findings, err := loadFindingsFromFile(scanFile)
	if err != nil {
		return fmt.Errorf("load scan file: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), complianceCoverageTimeout)
	defer cancel()

	// Create mapper and generator.
	mapper := compliance.NewMapper()
	generator := compliance.NewReportGenerator(mapper)

	opts := compliance.GenerateOptions{
		Frameworks:  nil,
		IncludeGaps: false,
	}

	report, err := generator.Generate(ctx, findings, opts)
	if err != nil {
		return fmt.Errorf("generate report: %w", err)
	}

	// Get coverage stats.
	stats, err := generator.GetCoverageStats(ctx, report)
	if err != nil {
		return fmt.Errorf("calculate coverage: %w", err)
	}

	overall, err := generator.GetOverallCoverage(ctx, report)
	if err != nil {
		return fmt.Errorf("calculate overall coverage: %w", err)
	}

	// Format output.
	var output []byte
	switch complianceCoverageFormat {
	case "json":
		result := coverageResult{
			Overall:    overall,
			Frameworks: stats,
		}
		output, err = json.MarshalIndent(result, "", "  ")
		if err != nil {
			return fmt.Errorf("marshal JSON: %w", err)
		}
	default:
		output = []byte(formatCoverageStats(overall, stats))
	}

	return writeComplianceOutput(cmd, output, complianceCoverageOutput)
}

func formatCoverageStats(overall compliance.CoverageStats, stats []compliance.CoverageStats) string {
	var sb strings.Builder

	sb.WriteString("Compliance Coverage Summary\n")
	sb.WriteString("===========================\n\n")

	fmt.Fprintf(&sb, "Overall Compliance: %.1f%%\n", overall.CoveragePercent)
	fmt.Fprintf(&sb, "Total Controls: %d\n", overall.TotalControls)
	fmt.Fprintf(&sb, "Compliant: %d\n", overall.CompliantControls)
	fmt.Fprintf(&sb, "Gaps: %d\n\n", overall.GapCount)

	sb.WriteString("By Framework:\n")
	sb.WriteString("-------------\n")

	for i := range stats {
		s := &stats[i]
		fmt.Fprintf(&sb, "\n%s:\n", strings.ToUpper(string(s.Framework)))
		fmt.Fprintf(&sb, "  Coverage: %.1f%%\n", s.CoveragePercent)
		fmt.Fprintf(&sb, "  Compliant: %d/%d\n", s.CompliantControls, s.TotalControls)
		fmt.Fprintf(&sb, "  Gaps: %d\n", s.GapCount)
	}

	return sb.String()
}

// NewComplianceGapsCmd creates the compliance gaps subcommand.
func NewComplianceGapsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "gaps [scan-file]",
		Short: "Show compliance gaps",
		Long: `Show compliance gaps from scan results.

Lists gaps by severity with:
  - Control ID and framework
  - Severity level
  - Description
  - Remediation guidance
  - Related findings`,
		Args: cobra.ExactArgs(1),
		RunE: runComplianceGaps,
	}

	cmd.Flags().StringVarP(&complianceGapsOutput, "output", "o", "", "output file (default: stdout)")
	cmd.Flags().StringVarP(&complianceGapsFormat, "format", "f", "text", "output format (text, json, markdown)")
	cmd.Flags().DurationVarP(&complianceGapsTimeout, "timeout", "t", 1*time.Minute, "gap analysis timeout")

	return cmd
}

func runComplianceGaps(cmd *cobra.Command, args []string) error {
	scanFile := args[0]

	findings, err := loadFindingsFromFile(scanFile)
	if err != nil {
		return fmt.Errorf("load scan file: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), complianceGapsTimeout)
	defer cancel()

	// Create mapper and generator.
	mapper := compliance.NewMapper()
	generator := compliance.NewReportGenerator(mapper)

	opts := compliance.GenerateOptions{
		Frameworks:  nil,
		IncludeGaps: true,
	}

	report, err := generator.Generate(ctx, findings, opts)
	if err != nil {
		return fmt.Errorf("generate report: %w", err)
	}

	gapSummary := generator.GetGapSummary(report)

	// Format output.
	var output []byte
	switch complianceGapsFormat {
	case "json":
		result := gapsResult{
			Summary: gapSummary,
			Gaps:    report.Gaps,
		}
		output, err = json.MarshalIndent(result, "", "  ")
		if err != nil {
			return fmt.Errorf("marshal JSON: %w", err)
		}
	case "markdown", "md":
		output = []byte(formatGapsMarkdown(gapSummary, report.Gaps))
	default:
		output = []byte(formatGapsText(gapSummary, report.Gaps))
	}

	return writeComplianceOutput(cmd, output, complianceGapsOutput)
}

func formatGapsText(summary compliance.GapSummary, gaps []compliance.Gap) string {
	var sb strings.Builder

	sb.WriteString("Compliance Gaps\n")
	sb.WriteString("===============\n\n")

	fmt.Fprintf(&sb, "Total Gaps: %d\n", summary.TotalGaps)
	fmt.Fprintf(&sb, "Critical: %d\n", summary.CriticalCount)
	fmt.Fprintf(&sb, "High: %d\n", summary.HighCount)
	fmt.Fprintf(&sb, "Medium: %d\n", summary.MediumCount)
	fmt.Fprintf(&sb, "Low: %d\n\n", summary.LowCount)

	for i := range gaps {
		gap := &gaps[i]
		fmt.Fprintf(&sb, "[%s] %s (%s)\n", strings.ToUpper(gap.Severity), gap.Control.ID, gap.Control.Framework)
		fmt.Fprintf(&sb, "  %s\n", gap.Description)
		if gap.Remediation != "" {
			fmt.Fprintf(&sb, "  Remediation: %s\n", gap.Remediation)
		}
		if gap.FindingCount > 0 {
			fmt.Fprintf(&sb, "  Findings: %d\n", gap.FindingCount)
		}
		sb.WriteString("\n")
	}

	return sb.String()
}

func formatGapsMarkdown(summary compliance.GapSummary, gaps []compliance.Gap) string {
	var sb strings.Builder

	sb.WriteString("# Compliance Gaps\n\n")
	sb.WriteString("## Summary\n\n")

	fmt.Fprintf(&sb, "| Severity | Count |\n")
	fmt.Fprintf(&sb, "|----------|-------|\n")
	fmt.Fprintf(&sb, "| Critical | %d |\n", summary.CriticalCount)
	fmt.Fprintf(&sb, "| High | %d |\n", summary.HighCount)
	fmt.Fprintf(&sb, "| Medium | %d |\n", summary.MediumCount)
	fmt.Fprintf(&sb, "| Low | %d |\n", summary.LowCount)
	fmt.Fprintf(&sb, "| **Total** | **%d** |\n\n", summary.TotalGaps)

	sb.WriteString("## Gap Details\n\n")

	for i := range gaps {
		gap := &gaps[i]
		fmt.Fprintf(&sb, "### %s (%s) - %s\n\n", gap.Control.ID, gap.Control.Framework, strings.ToUpper(gap.Severity))
		fmt.Fprintf(&sb, "%s\n\n", gap.Description)
		if gap.Remediation != "" {
			fmt.Fprintf(&sb, "**Remediation**: %s\n\n", gap.Remediation)
		}
		if gap.FindingCount > 0 {
			fmt.Fprintf(&sb, "**Related Findings**: %d\n\n", gap.FindingCount)
		}
	}

	return sb.String()
}

// NewComplianceControlsCmd creates the compliance controls subcommand.
func NewComplianceControlsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "controls",
		Short: "List compliance controls",
		Long: `List all compliance controls for specified frameworks.

Shows control IDs, titles, and categories for:
  - SOC 2 Trust Services Criteria
  - ISO 27001 Annex A Controls
  - GDPR Articles`,
	}

	cmd.AddCommand(NewComplianceControlsListCmd())

	return cmd
}

// NewComplianceControlsListCmd creates the compliance controls list subcommand.
func NewComplianceControlsListCmd() *cobra.Command {
	var framework string
	var output string
	var format string

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List controls for a framework",
		Long:  `List all controls for the specified compliance framework.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			mapper := compliance.NewMapper()
			fwID := compliance.FrameworkID(framework)

			controls := mapper.ListControls(fwID)
			if len(controls) == 0 {
				return fmt.Errorf("no controls found for framework: %s", framework)
			}

			var outputBytes []byte
			var err error

			switch format {
			case "json":
				outputBytes, err = json.MarshalIndent(controls, "", "  ")
				if err != nil {
					return fmt.Errorf("marshal JSON: %w", err)
				}
			default:
				var sb strings.Builder
				fmt.Fprintf(&sb, "%s Controls\n", strings.ToUpper(framework))
				sb.WriteString(strings.Repeat("=", len(framework)+9) + "\n\n")

				for i := range controls {
					c := &controls[i]
					fmt.Fprintf(&sb, "%s: %s\n", c.ID, c.Title)
					fmt.Fprintf(&sb, "  Category: %s\n", c.Category)
					if c.Description != "" {
						fmt.Fprintf(&sb, "  %s\n", c.Description)
					}
					sb.WriteString("\n")
				}
				outputBytes = []byte(sb.String())
			}

			return writeComplianceOutput(cmd, outputBytes, output)
		},
	}

	cmd.Flags().StringVarP(&framework, "framework", "F", "soc2", "framework (soc2, iso27001, gdpr)")
	cmd.Flags().StringVarP(&output, "output", "o", "", "output file (default: stdout)")
	cmd.Flags().StringVarP(&format, "format", "f", "text", "output format (text, json)")

	return cmd
}

// Helper functions.

func parseFrameworks(frameworksStr string) []compliance.FrameworkID {
	if frameworksStr == "" {
		return nil // All frameworks.
	}

	parts := strings.Split(frameworksStr, ",")
	frameworks := make([]compliance.FrameworkID, 0, len(parts))

	for _, p := range parts {
		p = strings.TrimSpace(strings.ToLower(p))
		switch p {
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

func loadFindingsFromFile(path string) ([]model.Finding, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve path: %w", err)
	}

	dir := filepath.Dir(absPath)
	file := filepath.Base(absPath)

	sp, err := safepath.New(dir)
	if err != nil {
		return nil, fmt.Errorf("create safepath: %w", err)
	}

	data, err := sp.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("read file: %w", err)
	}

	var findings []model.Finding
	if err := json.Unmarshal(data, &findings); err != nil {
		return nil, fmt.Errorf("parse JSON: %w", err)
	}

	return findings, nil
}

// scannerResult holds the result from a single scanner.
// Fields are ordered for optimal memory alignment.
type scannerResult struct {
	err      error
	name     string
	findings []model.Finding
}

// runQuickScan runs security scanners concurrently and aggregates findings.
func runQuickScan(ctx context.Context, path string) ([]model.Finding, error) {
	// Check context cancellation early.
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	var wg sync.WaitGroup
	results := make(chan scannerResult, 4)

	// Run gitleaks for secret detection.
	wg.Add(1)
	go func() {
		defer wg.Done()
		scanner, err := gitleaks.New()
		if err != nil {
			results <- scannerResult{name: "gitleaks", err: err}
			return
		}
		defer func() { _ = scanner.Close(ctx) }()

		findings, err := scanner.Scan(ctx, path)
		results <- scannerResult{name: "gitleaks", findings: findings, err: err}
	}()

	// Run OSV for dependency vulnerabilities.
	wg.Add(1)
	go func() {
		defer wg.Done()
		scanner := osv.New()
		defer func() { _ = scanner.Close(ctx) }()

		findings, err := scanner.Scan(ctx, path)
		results <- scannerResult{name: "osv", findings: findings, err: err}
	}()

	// Run Semgrep for SAST (if available).
	wg.Add(1)
	go func() {
		defer wg.Done()
		scanner := semgrep.New()
		defer func() { _ = scanner.Close(ctx) }()

		findings, err := scanner.Scan(ctx, path)
		results <- scannerResult{name: "semgrep", findings: findings, err: err}
	}()

	// Run Trivy for container/filesystem vulnerabilities.
	wg.Add(1)
	go func() {
		defer wg.Done()
		scanner := trivy.New()
		defer func() { _ = scanner.Close(ctx) }()

		findings, err := scanner.Scan(ctx, path)
		results <- scannerResult{name: "trivy", findings: findings, err: err}
	}()

	// Wait for all scanners to complete.
	go func() {
		wg.Wait()
		close(results)
	}()

	// Aggregate findings from all scanners.
	var allFindings []model.Finding
	var scanErrors []string

	for result := range results {
		if result.err != nil {
			// Log scanner errors but continue with other scanners.
			scanErrors = append(scanErrors, fmt.Sprintf("%s: %v", result.name, result.err))
			continue
		}
		allFindings = append(allFindings, result.findings...)
	}

	// If all scanners failed, return an error.
	if len(allFindings) == 0 && len(scanErrors) == len([]string{"gitleaks", "osv", "semgrep", "trivy"}) {
		return nil, fmt.Errorf("all scanners failed: %s", strings.Join(scanErrors, "; "))
	}

	return allFindings, nil
}

func writeComplianceOutput(cmd *cobra.Command, output []byte, outputPath string) error {
	if outputPath != "" {
		absOutput, err := filepath.Abs(outputPath)
		if err != nil {
			return fmt.Errorf("resolve output path: %w", err)
		}

		dir := filepath.Dir(absOutput)
		filename := filepath.Base(absOutput)

		sp, err := safepath.New(dir)
		if err != nil {
			return fmt.Errorf("create safepath: %w", err)
		}

		if err := sp.WriteFile(filename, output, 0o644); err != nil {
			return fmt.Errorf("write output: %w", err)
		}

		cmd.Printf("Results written to: %s\n", absOutput)
	} else {
		cmd.Println(string(output))
	}

	return nil
}
