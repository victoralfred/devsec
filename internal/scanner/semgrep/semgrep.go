// Package semgrep provides a scanner implementation for Semgrep SAST.
package semgrep

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"time"

	"github.com/google/uuid"
	"github.com/victoralfred/devsec/internal/model"
	"github.com/victoralfred/goexec"
	"github.com/victoralfred/gowritter/safepath"
)

// DefaultBinaryPath is the default path to the semgrep binary.
const DefaultBinaryPath = "/usr/bin/semgrep"

// DefaultTimeout is the default timeout for semgrep execution.
const DefaultTimeout = 10 * time.Minute

// Scanner implements the scanner.Scanner interface for Semgrep.
type Scanner struct {
	executor   goexec.Executor
	binaryPath string
	configFile string
	timeout    time.Duration
}

// Option configures a Scanner.
type Option func(*Scanner)

// WithBinaryPath sets a custom path to the semgrep binary.
func WithBinaryPath(path string) Option {
	return func(s *Scanner) {
		s.binaryPath = path
	}
}

// WithTimeout sets a custom timeout for semgrep execution.
func WithTimeout(timeout time.Duration) Option {
	return func(s *Scanner) {
		s.timeout = timeout
	}
}

// WithConfigFile sets a custom semgrep config/ruleset.
func WithConfigFile(path string) Option {
	return func(s *Scanner) {
		s.configFile = path
	}
}

// WithExecutor sets a custom executor for command execution.
func WithExecutor(exec goexec.Executor) Option {
	return func(s *Scanner) {
		s.executor = exec
	}
}

// New creates a new Semgrep scanner.
func New(opts ...Option) *Scanner {
	s := &Scanner{
		binaryPath: DefaultBinaryPath,
		timeout:    DefaultTimeout,
	}

	for _, opt := range opts {
		opt(s)
	}

	if s.executor == nil {
		exec, err := goexec.New()
		if err != nil {
			// In case of error, create a minimal scanner.
			// The Scan method will fail appropriately.
			return s
		}
		s.executor = exec
	}

	return s
}

// Name returns the scanner name.
func (s *Scanner) Name() string {
	return "semgrep"
}

// Scan executes semgrep and returns findings.
func (s *Scanner) Scan(ctx context.Context, path string) ([]model.Finding, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve absolute path: %w", err)
	}

	reportFile := s.generateReportPath()

	execErr := s.executeSemgrep(ctx, absPath, reportFile)
	if execErr != nil {
		// Cleanup is best-effort, don't fail on error.
		cleanupErr := s.cleanupReport(reportFile)
		_ = cleanupErr
		return nil, fmt.Errorf("failed to execute semgrep: %w", execErr)
	}

	findings, err := s.parseReport(reportFile)
	if err != nil {
		// Cleanup is best-effort, don't fail on error.
		cleanupErr := s.cleanupReport(reportFile)
		_ = cleanupErr
		return nil, fmt.Errorf("failed to parse semgrep report: %w", err)
	}

	// Cleanup is best-effort, don't fail on error.
	cleanupErr := s.cleanupReport(reportFile)
	_ = cleanupErr

	return findings, nil
}

// generateReportPath generates a unique temporary file path for the SARIF report.
func (s *Scanner) generateReportPath() string {
	tmpDir := "/tmp"
	reportID := uuid.New().String()
	return filepath.Join(tmpDir, fmt.Sprintf("semgrep-report-%s.sarif", reportID))
}

// executeSemgrep runs the semgrep command.
func (s *Scanner) executeSemgrep(ctx context.Context, path, reportFile string) error {
	args := []string{
		"scan",
		"--sarif",
		"--output", reportFile,
	}

	// Add config if specified, otherwise use auto mode.
	if s.configFile != "" {
		args = append(args, "--config", s.configFile)
	} else {
		args = append(args, "--config", "auto")
	}

	args = append(args, path)

	cmd, err := goexec.Cmd(s.binaryPath, args...).
		WithTimeout(s.timeout).
		Build()
	if err != nil {
		return fmt.Errorf("failed to build command: %w", err)
	}

	result, err := s.executor.Execute(ctx, cmd)
	if err != nil {
		return fmt.Errorf("failed to execute semgrep: %w", err)
	}

	// Semgrep returns non-zero if findings are found, which is expected.
	if !result.Success() && result.ExitCode != 1 {
		return fmt.Errorf("semgrep failed with exit code %d: %s", result.ExitCode, result.StderrString())
	}

	return nil
}

// parseReport reads and parses the SARIF report.
func (s *Scanner) parseReport(reportFile string) ([]model.Finding, error) {
	dir := filepath.Dir(reportFile)
	filename := filepath.Base(reportFile)

	sp, err := safepath.New(dir)
	if err != nil {
		return nil, fmt.Errorf("failed to create safe path: %w", err)
	}

	data, err := sp.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read report file: %w", err)
	}

	if len(data) == 0 {
		return []model.Finding{}, nil
	}

	var sarif SARIFReport
	if err := json.Unmarshal(data, &sarif); err != nil {
		return nil, fmt.Errorf("failed to unmarshal SARIF: %w", err)
	}

	return s.mapFindings(sarif), nil
}

// cleanupReport removes the temporary report file.
func (s *Scanner) cleanupReport(reportFile string) error {
	dir := filepath.Dir(reportFile)
	filename := filepath.Base(reportFile)

	sp, err := safepath.New(dir)
	if err != nil {
		return err
	}

	return sp.Remove(filename)
}

// mapFindings converts SARIF results to model.Finding.
func (s *Scanner) mapFindings(sarif SARIFReport) []model.Finding {
	var findings []model.Finding

	for i := range sarif.Runs {
		run := &sarif.Runs[i]
		for j := range run.Results {
			result := &run.Results[j]
			findings = append(findings, s.mapResult(result, run))
		}
	}

	return findings
}

// mapResult converts a single SARIF result to model.Finding.
func (s *Scanner) mapResult(result *SARIFResult, run *SARIFRun) model.Finding {
	severity := s.mapSeverity(result.Level)
	location := s.extractLocation(result)
	description := s.buildDescription(result, run)

	return model.Finding{
		Scanner:     "semgrep",
		Rule:        result.RuleID,
		Title:       s.getRuleMessage(result, run),
		Description: description,
		Severity:    severity,
		Location:    location,
	}
}

// mapSeverity converts SARIF severity level to model.Severity.
func (s *Scanner) mapSeverity(level string) model.Severity {
	switch level {
	case "error":
		return model.SeverityHigh
	case "warning":
		return model.SeverityMedium
	case "note":
		return model.SeverityLow
	default:
		return model.SeverityInfo
	}
}

// extractLocation extracts location information from SARIF result.
func (s *Scanner) extractLocation(result *SARIFResult) model.Location {
	if len(result.Locations) == 0 {
		return model.Location{}
	}

	loc := result.Locations[0]
	region := loc.PhysicalLocation.Region

	return model.Location{
		File:      loc.PhysicalLocation.ArtifactLocation.URI,
		StartLine: region.StartLine,
		EndLine:   region.EndLine,
	}
}

// getRuleMessage gets the rule message from result or rule definition.
func (s *Scanner) getRuleMessage(result *SARIFResult, run *SARIFRun) string {
	if result.Message.Text != "" {
		return result.Message.Text
	}

	// Look up rule definition.
	for i := range run.Tool.Driver.Rules {
		rule := &run.Tool.Driver.Rules[i]
		if rule.ID == result.RuleID {
			if rule.ShortDescription.Text != "" {
				return rule.ShortDescription.Text
			}
			return rule.ID
		}
	}

	return result.RuleID
}

// buildDescription builds a detailed description from SARIF data.
func (s *Scanner) buildDescription(result *SARIFResult, run *SARIFRun) string {
	desc := result.Message.Text

	// Look up rule for additional details.
	for i := range run.Tool.Driver.Rules {
		rule := &run.Tool.Driver.Rules[i]
		if rule.ID == result.RuleID {
			if rule.FullDescription.Text != "" {
				if desc != "" {
					desc += "\n\n"
				}
				desc += rule.FullDescription.Text
			}
			break
		}
	}

	return desc
}

// Close shuts down the scanner and releases resources.
func (s *Scanner) Close(ctx context.Context) error {
	if s.executor != nil {
		return s.executor.Shutdown(ctx)
	}
	return nil
}
