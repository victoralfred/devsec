// Package gitleaks provides a scanner implementation for Gitleaks secret detection.
package gitleaks

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/victoralfred/devsec/internal/model"
	"github.com/victoralfred/goexec"
	"github.com/victoralfred/gowritter/safepath"
)

// DefaultBinaryPath is the default path to the gitleaks binary.
const DefaultBinaryPath = "/usr/bin/gitleaks"

// DefaultTimeout is the default timeout for gitleaks execution.
const DefaultTimeout = 5 * time.Minute

// Finding represents a single finding from Gitleaks JSON output.
type Finding struct {
	Date        string   `json:"Date"`
	Message     string   `json:"Message"`
	Secret      string   `json:"Secret"`
	Match       string   `json:"Match"`
	File        string   `json:"File"`
	Commit      string   `json:"Commit"`
	Author      string   `json:"Author"`
	Email       string   `json:"Email"`
	RuleID      string   `json:"RuleID"`
	Fingerprint string   `json:"Fingerprint"`
	Description string   `json:"Description"`
	Tags        []string `json:"Tags"`
	StartLine   int      `json:"StartLine"`
	EndLine     int      `json:"EndLine"`
	StartColumn int      `json:"StartColumn"`
	EndColumn   int      `json:"EndColumn"`
	Entropy     float64
}

// Scanner implements the scanner.Scanner interface for Gitleaks.
type Scanner struct {
	executor   goexec.Executor
	binaryPath string
	configFile string
	timeout    time.Duration
}

// Option configures a Scanner.
type Option func(*Scanner)

// WithBinaryPath sets a custom path to the gitleaks binary.
func WithBinaryPath(path string) Option {
	return func(s *Scanner) {
		s.binaryPath = path
	}
}

// WithTimeout sets a custom timeout for gitleaks execution.
func WithTimeout(timeout time.Duration) Option {
	return func(s *Scanner) {
		s.timeout = timeout
	}
}

// WithConfigFile sets a custom gitleaks config file.
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

// New creates a new Gitleaks scanner with the given options.
func New(opts ...Option) (*Scanner, error) {
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
			return nil, fmt.Errorf("failed to create executor: %w", err)
		}
		s.executor = exec
	}

	return s, nil
}

// Name returns the name of the scanner.
func (s *Scanner) Name() string {
	return "gitleaks"
}

// Scan performs a secret detection scan on the given path.
func (s *Scanner) Scan(ctx context.Context, targetPath string) ([]model.Finding, error) {
	// Validate input path
	if targetPath == "" {
		return nil, fmt.Errorf("target path cannot be empty")
	}

	absPath, err := filepath.Abs(targetPath)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve path: %w", err)
	}

	// Check if path exists and is a directory
	info, err := os.Stat(absPath)
	if err != nil {
		return nil, fmt.Errorf("path does not exist: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("path must be a directory: %s", absPath)
	}

	// Use temp directory instead of targetPath for report file
	tmpDir := os.TempDir()
	reportFile := filepath.Join(tmpDir, fmt.Sprintf("gitleaks-report-%s.json", uuid.New().String()))

	args := []string{
		"detect",
		"--source", absPath,
		"--report-format", "json",
		"--report-path", reportFile,
		"--exit-code", "0",
	}

	if s.configFile != "" {
		args = append(args, "--config", s.configFile)
	}

	cmd, err := goexec.Cmd(s.binaryPath, args...).
		WithTimeout(s.timeout).
		Build()
	if err != nil {
		return nil, fmt.Errorf("failed to build command: %w", err)
	}

	// Check for context cancellation before execution
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context cancelled: %w", err)
	}

	result, err := s.executor.Execute(ctx, cmd)
	if err != nil {
		// Cleanup on error
		_ = s.cleanupReport(reportFile)
		return nil, fmt.Errorf("failed to execute gitleaks: %w", err)
	}

	if !result.Success() && result.ExitCode != 1 {
		// Cleanup on error
		_ = s.cleanupReport(reportFile)
		return nil, fmt.Errorf("gitleaks failed with exit code %d: %s", result.ExitCode, result.StderrString())
	}

	// Check for context cancellation before parsing
	if err := ctx.Err(); err != nil {
		_ = s.cleanupReport(reportFile)
		return nil, fmt.Errorf("context cancelled: %w", err)
	}

	findings, err := s.parseReport(ctx, reportFile)
	if err != nil {
		// Cleanup on error
		_ = s.cleanupReport(reportFile)
		return nil, fmt.Errorf("failed to parse report: %w", err)
	}

	// Cleanup is best-effort, don't fail on error.
	_ = s.cleanupReport(reportFile)

	return findings, nil
}

// parseReport reads and parses the Gitleaks JSON report.
func (s *Scanner) parseReport(ctx context.Context, reportPath string) ([]model.Finding, error) {
	dir := filepath.Dir(reportPath)
	filename := filepath.Base(reportPath)

	sp, err := safepath.New(dir)
	if err != nil {
		return nil, fmt.Errorf("failed to create safe path: %w", err)
	}

	// Check file size before reading
	info, err := sp.Stat(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to stat report file: %w", err)
	}
	const MaxReportSize = 100 * 1024 * 1024 // 100MB
	if info.Size() > MaxReportSize {
		return nil, fmt.Errorf("report file too large: %d bytes (max %d)", info.Size(), MaxReportSize)
	}

	data, err := sp.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read report file: %w", err)
	}

	// Check for context cancellation
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context cancelled: %w", err)
	}

	if len(data) == 0 {
		return []model.Finding{}, nil
	}

	var gitleaksFindings []Finding
	if err := json.Unmarshal(data, &gitleaksFindings); err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %w", err)
	}

	return s.mapFindings(gitleaksFindings), nil
}

// mapFindings converts Gitleaks findings to model.Finding.
func (s *Scanner) mapFindings(gitleaksFindings []Finding) []model.Finding {
	findings := make([]model.Finding, 0, len(gitleaksFindings))

	for i := range gitleaksFindings {
		gf := &gitleaksFindings[i]
		finding := model.Finding{
			ID:          gf.Fingerprint,
			Title:       gf.Description,
			Description: buildDescription(gf),
			Severity:    model.SeverityHigh,
			Rule:        gf.RuleID,
			Scanner:     s.Name(),
			Location: model.Location{
				File:      gf.File,
				StartLine: gf.StartLine,
				EndLine:   gf.EndLine,
				Column:    gf.StartColumn,
			},
		}
		findings = append(findings, finding)
	}

	return findings
}

// buildDescription creates a detailed description for the finding.
func buildDescription(gf *Finding) string {
	var builder strings.Builder
	builder.Grow(200) // Pre-allocate estimated capacity

	builder.WriteString("Secret detected by rule '")
	builder.WriteString(gf.RuleID)
	builder.WriteString("'")

	if gf.Commit != "" {
		commitLen := minInt(8, len(gf.Commit))
		builder.WriteString(" in commit ")
		builder.WriteString(gf.Commit[:commitLen])
	}

	if gf.Author != "" {
		builder.WriteString(" by ")
		builder.WriteString(gf.Author)
	}

	return builder.String()
}

// cleanupReport removes the temporary report file.
func (s *Scanner) cleanupReport(reportPath string) error {
	dir := filepath.Dir(reportPath)
	filename := filepath.Base(reportPath)

	sp, err := safepath.New(dir)
	if err != nil {
		return err
	}

	return sp.Remove(filename)
}

// minInt returns the minimum of two integers.
func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// Close shuts down the scanner's executor.
func (s *Scanner) Close(ctx context.Context) error {
	if s.executor != nil {
		return s.executor.Shutdown(ctx)
	}
	return nil
}
