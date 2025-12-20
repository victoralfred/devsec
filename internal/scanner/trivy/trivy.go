// Package trivy provides a scanner implementation for Trivy vulnerability detection.
package trivy

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

// DefaultBinaryPath is the default path to the trivy binary.
const DefaultBinaryPath = "/usr/bin/trivy"

// DefaultTimeout is the default timeout for trivy execution.
const DefaultTimeout = 10 * time.Minute

// DefaultTempDir is the default temporary directory for report files.
const DefaultTempDir = "/tmp"

// MaxReportSize is the maximum size of a report file in bytes (100MB).
const MaxReportSize = 100 * 1024 * 1024

// Scanner implements the scanner.Scanner interface for Trivy.
type Scanner struct {
	executor   goexec.Executor
	binaryPath string
	scanType   string
	timeout    time.Duration
}

// Option configures a Scanner.
type Option func(*Scanner)

// WithBinaryPath sets a custom path to the trivy binary.
func WithBinaryPath(path string) Option {
	return func(s *Scanner) {
		s.binaryPath = path
	}
}

// WithTimeout sets a custom timeout for trivy execution.
func WithTimeout(timeout time.Duration) Option {
	return func(s *Scanner) {
		s.timeout = timeout
	}
}

// WithScanType sets the scan type (fs, image, repo).
func WithScanType(scanType string) Option {
	return func(s *Scanner) {
		s.scanType = scanType
	}
}

// WithExecutor sets a custom executor for command execution.
func WithExecutor(exec goexec.Executor) Option {
	return func(s *Scanner) {
		s.executor = exec
	}
}

// New creates a new Trivy scanner.
func New(opts ...Option) *Scanner {
	s := &Scanner{
		binaryPath: DefaultBinaryPath,
		timeout:    DefaultTimeout,
		scanType:   "fs", // Default to filesystem scan.
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
	return "trivy"
}

// Scan executes trivy and returns findings.
func (s *Scanner) Scan(ctx context.Context, path string) ([]model.Finding, error) {
	// Validate input path.
	if path == "" {
		return nil, fmt.Errorf("path cannot be empty")
	}

	absPath, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve absolute path: %w", err)
	}

	// Check if path exists using safepath.
	sp, err := safepath.New(absPath)
	if err != nil {
		return nil, fmt.Errorf("path does not exist or is not accessible: %w", err)
	}
	_, err = sp.Stat(".")
	if err != nil {
		return nil, fmt.Errorf("failed to stat path: %w", err)
	}

	reportFile, cleanup := s.generateReportPath()
	defer func() {
		// Use context with short timeout for cleanup.
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cleanupCancel()
		if cleanupErr := cleanup(cleanupCtx); cleanupErr != nil {
			// Best-effort cleanup, log but don't fail.
			_ = cleanupErr
		}
	}()

	// Check for context cancellation before execution.
	if ctxErr := ctx.Err(); ctxErr != nil {
		return nil, fmt.Errorf("context canceled: %w", ctxErr)
	}

	execErr := s.executeTrivy(ctx, absPath, reportFile)
	if execErr != nil {
		return nil, fmt.Errorf("failed to execute trivy: %w", execErr)
	}

	// Check for context cancellation before parsing.
	if ctxErr := ctx.Err(); ctxErr != nil {
		return nil, fmt.Errorf("context canceled: %w", ctxErr)
	}

	findings, err := s.parseReport(ctx, reportFile)
	if err != nil {
		return nil, fmt.Errorf("failed to parse trivy report: %w", err)
	}

	return findings, nil
}

// generateReportPath generates a unique temporary file path for the JSON report.
func (s *Scanner) generateReportPath() (reportPath string, cleanupFn func(context.Context) error) {
	reportID := uuid.New().String()
	reportPath = filepath.Join(DefaultTempDir, fmt.Sprintf("trivy-report-%s.json", reportID))

	cleanupFn = func(ctx context.Context) error {
		return s.cleanupReport(reportPath)
	}

	return reportPath, cleanupFn
}

// executeTrivy runs the trivy command.
func (s *Scanner) executeTrivy(ctx context.Context, path, reportFile string) error {
	args := []string{
		s.scanType,
		"--format", "json",
		"--output", reportFile,
		"--quiet",
		path,
	}

	cmd, err := goexec.Cmd(s.binaryPath, args...).
		WithTimeout(s.timeout).
		Build()
	if err != nil {
		return fmt.Errorf("failed to build command: %w", err)
	}

	result, err := s.executor.Execute(ctx, cmd)
	if err != nil {
		return fmt.Errorf("failed to execute trivy: %w", err)
	}

	// Trivy returns exit code 0 even with vulnerabilities found.
	if !result.Success() {
		return fmt.Errorf("trivy failed with exit code %d: %s", result.ExitCode, result.StderrString())
	}

	return nil
}

// parseReport reads and parses the Trivy JSON report.
func (s *Scanner) parseReport(ctx context.Context, reportFile string) ([]model.Finding, error) {
	dir := filepath.Dir(reportFile)
	filename := filepath.Base(reportFile)

	sp, err := safepath.New(dir)
	if err != nil {
		return nil, fmt.Errorf("failed to create safe path: %w", err)
	}

	// Check file size before reading.
	info, err := sp.Stat(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to stat report file: %w", err)
	}
	if info.Size() > MaxReportSize {
		return nil, fmt.Errorf("report file too large: %d bytes (max %d)", info.Size(), MaxReportSize)
	}

	data, err := sp.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read report file: %w", err)
	}

	// Check for context cancellation.
	if ctxErr := ctx.Err(); ctxErr != nil {
		return nil, fmt.Errorf("context canceled: %w", ctxErr)
	}

	if len(data) == 0 {
		return []model.Finding{}, nil
	}

	var report Report
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JSON: %w", err)
	}

	return s.mapFindings(report), nil
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

// mapFindings converts Trivy results to model.Finding.
func (s *Scanner) mapFindings(report Report) []model.Finding {
	// Pre-allocate slice with estimated capacity.
	totalResults := 0
	for i := range report.Results {
		totalResults += len(report.Results[i].Vulnerabilities)
	}

	findings := make([]model.Finding, 0, totalResults)

	for i := range report.Results {
		result := &report.Results[i]
		for j := range result.Vulnerabilities {
			vuln := &result.Vulnerabilities[j]
			findings = append(findings, s.mapVulnerability(vuln, result.Target))
		}
	}

	return findings
}

// mapVulnerability converts a single Trivy vulnerability to model.Finding.
func (s *Scanner) mapVulnerability(vuln *Vulnerability, target string) model.Finding {
	severity := s.mapSeverity(vuln.Severity)
	description := s.buildDescription(vuln)
	findingID := s.generateFindingID(vuln, target)

	return model.Finding{
		ID:          findingID,
		Scanner:     "trivy",
		Rule:        vuln.VulnerabilityID,
		Title:       vuln.Title,
		Description: description,
		Severity:    severity,
		Location: model.Location{
			File: target,
		},
	}
}

// generateFindingID generates a unique ID for a finding.
func (s *Scanner) generateFindingID(vuln *Vulnerability, target string) string {
	// Use vulnerability ID, package name, and target to create a deterministic ID.
	id := fmt.Sprintf("%s:%s:%s", vuln.VulnerabilityID, vuln.PkgName, target)
	// Add UUID suffix for uniqueness.
	return fmt.Sprintf("%s-%s", id, uuid.New().String()[:8])
}

// mapSeverity converts Trivy severity to model.Severity.
func (s *Scanner) mapSeverity(severity string) model.Severity {
	switch severity {
	case "CRITICAL":
		return model.SeverityCritical
	case "HIGH":
		return model.SeverityHigh
	case "MEDIUM":
		return model.SeverityMedium
	case "LOW":
		return model.SeverityLow
	default:
		return model.SeverityInfo
	}
}

// buildDescription builds a detailed description from vulnerability data.
func (s *Scanner) buildDescription(vuln *Vulnerability) string {
	desc := vuln.Description

	if vuln.PkgName != "" {
		desc = fmt.Sprintf("Package: %s\nInstalled: %s\nFixed: %s\n\n%s",
			vuln.PkgName, vuln.InstalledVersion, vuln.FixedVersion, desc)
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
