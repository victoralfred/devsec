package report

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/victoralfred/devsec/internal/model"
	"github.com/victoralfred/gowritter/safepath"
)

func createTestReport() *model.Report {
	return &model.Report{
		Timestamp: "2025-01-01T00:00:00Z",
		Findings: []model.Finding{
			{
				ID:          "finding-1",
				Title:       "Critical Finding",
				Description: "A critical security issue",
				Rule:        "SEC001",
				Scanner:     "gitleaks",
				Severity:    model.SeverityCritical,
				Location: model.Location{
					File:      "config.go",
					StartLine: 10,
					EndLine:   12,
				},
			},
			{
				ID:          "finding-2",
				Title:       "High Finding",
				Description: "A high severity issue",
				Rule:        "SEC002",
				Scanner:     "semgrep",
				Severity:    model.SeverityHigh,
				Location: model.Location{
					File:      "main.go",
					StartLine: 25,
					EndLine:   25,
				},
			},
		},
		Summary: model.Summary{
			Total:    2,
			Critical: 1,
			High:     1,
		},
		Metadata: map[string]string{
			"scanners": "gitleaks,semgrep",
		},
	}
}

// TestJSONFormatterFormat tests JSON formatting.
func TestJSONFormatterFormat(t *testing.T) {
	formatter := NewJSONFormatter(true)
	report := createTestReport()

	ctx := context.Background()
	data, err := formatter.Format(ctx, report)
	if err != nil {
		t.Fatalf("Format() error = %v", err)
	}

	// Verify it's valid JSON
	var parsed model.Report
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("invalid JSON output: %v", err)
	}

	if parsed.Summary.Total != 2 {
		t.Errorf("expected total 2, got %d", parsed.Summary.Total)
	}
}

// TestJSONFormatterNoIndent tests JSON formatting without indentation.
func TestJSONFormatterNoIndent(t *testing.T) {
	formatter := NewJSONFormatter(false)
	report := createTestReport()

	ctx := context.Background()
	data, err := formatter.Format(ctx, report)
	if err != nil {
		t.Fatalf("Format() error = %v", err)
	}

	// Compact JSON should not have newlines
	if strings.Contains(string(data), "\n") {
		t.Error("expected compact JSON without newlines")
	}
}

// TestJSONFormatterExtension tests JSON formatter extension.
func TestJSONFormatterExtension(t *testing.T) {
	formatter := NewJSONFormatter(true)
	if formatter.Extension() != ".json" {
		t.Errorf("expected .json extension, got %s", formatter.Extension())
	}
}

// TestJSONFormatterContextCancellation tests context cancellation.
func TestJSONFormatterContextCancellation(t *testing.T) {
	formatter := NewJSONFormatter(true)
	report := createTestReport()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := formatter.Format(ctx, report)
	if err == nil {
		t.Error("expected error for canceled context")
	}
}

// TestSARIFFormatterFormat tests SARIF formatting.
func TestSARIFFormatterFormat(t *testing.T) {
	formatter := NewSARIFFormatter()
	report := createTestReport()

	ctx := context.Background()
	data, err := formatter.Format(ctx, report)
	if err != nil {
		t.Fatalf("Format() error = %v", err)
	}

	// Verify it's valid JSON
	var sarif SARIFReport
	if err := json.Unmarshal(data, &sarif); err != nil {
		t.Fatalf("invalid SARIF output: %v", err)
	}

	if sarif.Version != "2.1.0" {
		t.Errorf("expected SARIF version 2.1.0, got %s", sarif.Version)
	}

	if len(sarif.Runs) == 0 {
		t.Error("expected at least one run")
	}
}

// TestSARIFFormatterExtension tests SARIF formatter extension.
func TestSARIFFormatterExtension(t *testing.T) {
	formatter := NewSARIFFormatter()
	if formatter.Extension() != ".sarif.json" {
		t.Errorf("expected .sarif.json extension, got %s", formatter.Extension())
	}
}

// TestSARIFFormatterContextCancellation tests context cancellation.
func TestSARIFFormatterContextCancellation(t *testing.T) {
	formatter := NewSARIFFormatter()
	report := createTestReport()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := formatter.Format(ctx, report)
	if err == nil {
		t.Error("expected error for canceled context")
	}
}

// TestSARIFFormatterSeverityMapping tests severity to SARIF level mapping.
func TestSARIFFormatterSeverityMapping(t *testing.T) {
	tests := []struct {
		severity model.Severity
		expected string
	}{
		{model.SeverityCritical, "error"},
		{model.SeverityHigh, "error"},
		{model.SeverityMedium, "warning"},
		{model.SeverityLow, "note"},
		{model.SeverityInfo, "note"},
		{model.Severity("unknown"), "none"},
	}

	for _, tt := range tests {
		t.Run(string(tt.severity), func(t *testing.T) {
			result := severityToSARIFLevel(tt.severity)
			if result != tt.expected {
				t.Errorf("severityToSARIFLevel(%s) = %s, want %s", tt.severity, result, tt.expected)
			}
		})
	}
}

// TestMarkdownFormatterFormat tests Markdown formatting.
func TestMarkdownFormatterFormat(t *testing.T) {
	formatter := NewMarkdownFormatter()
	report := createTestReport()

	ctx := context.Background()
	data, err := formatter.Format(ctx, report)
	if err != nil {
		t.Fatalf("Format() error = %v", err)
	}

	output := string(data)

	// Check for expected sections
	if !strings.Contains(output, "# Security Scan Report") {
		t.Error("expected header in markdown output")
	}
	if !strings.Contains(output, "## Summary") {
		t.Error("expected summary section in markdown output")
	}
	if !strings.Contains(output, "## Findings") {
		t.Error("expected findings section in markdown output")
	}
	if !strings.Contains(output, "Critical Finding") {
		t.Error("expected finding title in markdown output")
	}
}

// TestMarkdownFormatterEmptyFindings tests Markdown formatting with no findings.
func TestMarkdownFormatterEmptyFindings(t *testing.T) {
	formatter := NewMarkdownFormatter()
	report := &model.Report{
		Timestamp: "2025-01-01T00:00:00Z",
		Findings:  []model.Finding{},
		Summary:   model.Summary{},
	}

	ctx := context.Background()
	data, err := formatter.Format(ctx, report)
	if err != nil {
		t.Fatalf("Format() error = %v", err)
	}

	output := string(data)
	if !strings.Contains(output, "No findings detected") {
		t.Error("expected 'No findings detected' message")
	}
}

// TestMarkdownFormatterExtension tests Markdown formatter extension.
func TestMarkdownFormatterExtension(t *testing.T) {
	formatter := NewMarkdownFormatter()
	if formatter.Extension() != ".md" {
		t.Errorf("expected .md extension, got %s", formatter.Extension())
	}
}

// TestMarkdownFormatterContextCancellation tests context cancellation.
func TestMarkdownFormatterContextCancellation(t *testing.T) {
	formatter := NewMarkdownFormatter()
	report := createTestReport()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := formatter.Format(ctx, report)
	if err == nil {
		t.Error("expected error for canceled context")
	}
}

// TestFormatReport tests the FormatReport helper function.
func TestFormatReport(t *testing.T) {
	report := createTestReport()
	ctx := context.Background()

	tests := []struct {
		format      string
		expectError bool
	}{
		{"json", false},
		{"sarif", false},
		{"markdown", false},
		{"md", false},
		{"invalid", true},
	}

	for _, tt := range tests {
		t.Run(tt.format, func(t *testing.T) {
			_, err := FormatReport(ctx, report, tt.format)
			if (err != nil) != tt.expectError {
				t.Errorf("FormatReport() error = %v, wantErr %v", err, tt.expectError)
			}
		})
	}
}

// TestWriteReport tests writing a report to a file.
func TestWriteReport(t *testing.T) {
	tmpDir := t.TempDir()
	sp, err := safepath.New(tmpDir)
	if err != nil {
		t.Fatalf("failed to create safepath: %v", err)
	}

	report := createTestReport()
	formatter := NewJSONFormatter(true)
	ctx := context.Background()

	outputPath := filepath.Join(tmpDir, "report.json")
	err = WriteReport(ctx, outputPath, report, formatter)
	if err != nil {
		t.Fatalf("WriteReport() error = %v", err)
	}

	// Verify file was written
	data, err := sp.ReadFile("report.json")
	if err != nil {
		t.Fatalf("failed to read report: %v", err)
	}

	var parsed model.Report
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("invalid JSON in written file: %v", err)
	}
}

// TestWriteReportContextCancellation tests context cancellation for WriteReport.
func TestWriteReportContextCancellation(t *testing.T) {
	report := createTestReport()
	formatter := NewJSONFormatter(true)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := WriteReport(ctx, "/tmp/report.json", report, formatter)
	if err == nil {
		t.Error("expected error for canceled context")
	}
}

// TestGenerateReport tests report generation.
func TestGenerateReport(t *testing.T) {
	findings := []model.Finding{
		{ID: "f1", Severity: model.SeverityCritical},
		{ID: "f2", Severity: model.SeverityHigh},
		{ID: "f3", Severity: model.SeverityMedium},
	}

	report := GenerateReport(findings)

	if report.Timestamp == "" {
		t.Error("expected non-empty timestamp")
	}
	if len(report.Findings) != 3 {
		t.Errorf("expected 3 findings, got %d", len(report.Findings))
	}
	if report.Summary.Total != 3 {
		t.Errorf("expected total 3, got %d", report.Summary.Total)
	}
	if report.Summary.Critical != 1 {
		t.Errorf("expected critical 1, got %d", report.Summary.Critical)
	}
}

// TestFilterBySeverity tests filtering findings by severity.
func TestFilterBySeverity(t *testing.T) {
	findings := []model.Finding{
		{ID: "f1", Severity: model.SeverityCritical},
		{ID: "f2", Severity: model.SeverityHigh},
		{ID: "f3", Severity: model.SeverityCritical},
		{ID: "f4", Severity: model.SeverityMedium},
	}

	critical := filterBySeverity(findings, model.SeverityCritical)
	if len(critical) != 2 {
		t.Errorf("expected 2 critical findings, got %d", len(critical))
	}

	high := filterBySeverity(findings, model.SeverityHigh)
	if len(high) != 1 {
		t.Errorf("expected 1 high finding, got %d", len(high))
	}

	low := filterBySeverity(findings, model.SeverityLow)
	if len(low) != 0 {
		t.Errorf("expected 0 low findings, got %d", len(low))
	}
}
