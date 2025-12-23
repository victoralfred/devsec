package gitleaks

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/victoralfred/devsec/internal/model"
	"github.com/victoralfred/gowritter/safepath"
)

// closeScanner is a helper to close scanner in tests without lint errors.
func closeScanner(t *testing.T, s *Scanner) {
	t.Helper()
	if err := s.Close(context.Background()); err != nil {
		t.Logf("warning: failed to close scanner: %v", err)
	}
}

func TestNew(t *testing.T) {
	scanner, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer closeScanner(t, scanner)

	// binaryPath should be set (either found in PATH or fallback to name).
	if scanner.binaryPath == "" {
		t.Error("expected binaryPath to be set")
	}

	if scanner.timeout != DefaultTimeout {
		t.Errorf("expected timeout %v, got %v", DefaultTimeout, scanner.timeout)
	}
}

func TestNewWithOptions(t *testing.T) {
	customPath := "/custom/path/gitleaks"
	customTimeout := 10 * time.Minute
	customConfig := "/path/to/config.toml"

	scanner, err := New(
		WithBinaryPath(customPath),
		WithTimeout(customTimeout),
		WithConfigFile(customConfig),
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer closeScanner(t, scanner)

	if scanner.binaryPath != customPath {
		t.Errorf("expected binaryPath %s, got %s", customPath, scanner.binaryPath)
	}

	if scanner.timeout != customTimeout {
		t.Errorf("expected timeout %v, got %v", customTimeout, scanner.timeout)
	}

	if scanner.configFile != customConfig {
		t.Errorf("expected configFile %s, got %s", customConfig, scanner.configFile)
	}
}

func TestScannerName(t *testing.T) {
	scanner, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer closeScanner(t, scanner)

	if scanner.Name() != "gitleaks" {
		t.Errorf("expected name 'gitleaks', got '%s'", scanner.Name())
	}
}

func TestMapFindings(t *testing.T) {
	scanner, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer closeScanner(t, scanner)

	gitleaksFindings := []Finding{
		{
			Description: "AWS Access Key",
			RuleID:      "aws-access-key",
			Secret:      "AKIAIOSFODNN7EXAMPLE",
			File:        "config/secrets.go",
			Commit:      "abc123def456",
			Author:      "John Doe",
			Fingerprint: "fingerprint-123",
			StartLine:   10,
			EndLine:     10,
			StartColumn: 5,
			EndColumn:   25,
		},
		{
			Description: "GitHub Token",
			RuleID:      "github-token",
			Secret:      "ghp_xxxxxxxxxxxx",
			File:        ".env",
			Commit:      "def456abc789",
			Author:      "Jane Doe",
			Fingerprint: "fingerprint-456",
			StartLine:   5,
			EndLine:     5,
			StartColumn: 1,
			EndColumn:   50,
		},
	}

	findings := scanner.mapFindings(gitleaksFindings)

	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}

	first := findings[0]
	if first.ID != "fingerprint-123" {
		t.Errorf("expected ID 'fingerprint-123', got '%s'", first.ID)
	}
	if first.Title != "AWS Access Key" {
		t.Errorf("expected title 'AWS Access Key', got '%s'", first.Title)
	}
	if first.Rule != "aws-access-key" {
		t.Errorf("expected rule 'aws-access-key', got '%s'", first.Rule)
	}
	if first.Scanner != "gitleaks" {
		t.Errorf("expected scanner 'gitleaks', got '%s'", first.Scanner)
	}
	if first.Severity != model.SeverityHigh {
		t.Errorf("expected severity high, got '%s'", first.Severity)
	}
	if first.Location.File != "config/secrets.go" {
		t.Errorf("expected file 'config/secrets.go', got '%s'", first.Location.File)
	}
	if first.Location.StartLine != 10 {
		t.Errorf("expected start line 10, got %d", first.Location.StartLine)
	}
}

func TestParseReport(t *testing.T) {
	tmpDir := t.TempDir()

	sp, err := safepath.New(tmpDir)
	if err != nil {
		t.Fatalf("failed to create safe path: %v", err)
	}

	gitleaksFindings := []Finding{
		{
			Description: "Generic API Key",
			RuleID:      "generic-api-key",
			Secret:      "api_key_12345",
			File:        "main.go",
			Fingerprint: "fp-001",
			StartLine:   20,
			EndLine:     20,
			StartColumn: 10,
			EndColumn:   30,
		},
	}

	data, err := json.Marshal(gitleaksFindings)
	if err != nil {
		t.Fatalf("failed to marshal findings: %v", err)
	}

	reportFile := "test-report.json"
	err = sp.WriteFile(reportFile, data, 0o644)
	if err != nil {
		t.Fatalf("failed to write report: %v", err)
	}

	scanner, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer closeScanner(t, scanner)

	reportPath := filepath.Join(tmpDir, reportFile)
	ctx := context.Background()
	findings, err := scanner.parseReport(ctx, reportPath)
	if err != nil {
		t.Fatalf("parseReport() error = %v", err)
	}

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	if findings[0].ID != "fp-001" {
		t.Errorf("expected ID 'fp-001', got '%s'", findings[0].ID)
	}
}

func TestParseReportEmpty(t *testing.T) {
	tmpDir := t.TempDir()

	sp, err := safepath.New(tmpDir)
	if err != nil {
		t.Fatalf("failed to create safe path: %v", err)
	}

	reportFile := "empty-report.json"
	err = sp.WriteFile(reportFile, []byte{}, 0o644)
	if err != nil {
		t.Fatalf("failed to write report: %v", err)
	}

	scanner, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer closeScanner(t, scanner)

	reportPath := filepath.Join(tmpDir, reportFile)
	ctx := context.Background()
	findings, err := scanner.parseReport(ctx, reportPath)
	if err != nil {
		t.Fatalf("parseReport() error = %v", err)
	}

	if len(findings) != 0 {
		t.Errorf("expected 0 findings for empty report, got %d", len(findings))
	}
}

func TestParseReportEmptyArray(t *testing.T) {
	tmpDir := t.TempDir()

	sp, err := safepath.New(tmpDir)
	if err != nil {
		t.Fatalf("failed to create safe path: %v", err)
	}

	reportFile := "empty-array-report.json"
	err = sp.WriteFile(reportFile, []byte("[]"), 0o644)
	if err != nil {
		t.Fatalf("failed to write report: %v", err)
	}

	scanner, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer closeScanner(t, scanner)

	reportPath := filepath.Join(tmpDir, reportFile)
	ctx := context.Background()
	findings, err := scanner.parseReport(ctx, reportPath)
	if err != nil {
		t.Fatalf("parseReport() error = %v", err)
	}

	if len(findings) != 0 {
		t.Errorf("expected 0 findings for empty array, got %d", len(findings))
	}
}

func TestParseReportInvalidJSON(t *testing.T) {
	tmpDir := t.TempDir()

	sp, err := safepath.New(tmpDir)
	if err != nil {
		t.Fatalf("failed to create safe path: %v", err)
	}

	reportFile := "invalid-report.json"
	err = sp.WriteFile(reportFile, []byte("not valid json"), 0o644)
	if err != nil {
		t.Fatalf("failed to write report: %v", err)
	}

	scanner, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer closeScanner(t, scanner)

	reportPath := filepath.Join(tmpDir, reportFile)
	ctx := context.Background()
	_, err = scanner.parseReport(ctx, reportPath)
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestParseReportFileNotFound(t *testing.T) {
	scanner, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer closeScanner(t, scanner)

	ctx := context.Background()
	_, err = scanner.parseReport(ctx, "/nonexistent/path/report.json")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestBuildDescription(t *testing.T) {
	//nolint:govet // test struct field order for readability
	tests := []struct {
		name     string
		finding  Finding
		contains []string
	}{
		{
			name: "with commit and author",
			finding: Finding{
				RuleID: "aws-key",
				Commit: "abc123def456",
				Author: "John Doe",
			},
			contains: []string{"aws-key", "abc123de", "John Doe"},
		},
		{
			name: "without commit",
			finding: Finding{
				RuleID: "github-token",
				Author: "Jane Doe",
			},
			contains: []string{"github-token", "Jane Doe"},
		},
		{
			name: "rule only",
			finding: Finding{
				RuleID: "generic-secret",
			},
			contains: []string{"generic-secret"},
		},
		{
			name: "short commit",
			finding: Finding{
				RuleID: "api-key",
				Commit: "abc",
			},
			contains: []string{"api-key", "abc"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			desc := buildDescription(&tt.finding)
			for _, substr := range tt.contains {
				if !containsSubstring(desc, substr) {
					t.Errorf("expected description to contain '%s', got '%s'", substr, desc)
				}
			}
		})
	}
}

func TestMinInt(t *testing.T) {
	tests := []struct {
		a, b, expected int
	}{
		{5, 10, 5},
		{10, 5, 5},
		{5, 5, 5},
		{0, 5, 0},
		{-1, 5, -1},
	}

	for _, tt := range tests {
		result := minInt(tt.a, tt.b)
		if result != tt.expected {
			t.Errorf("minInt(%d, %d) = %d, expected %d", tt.a, tt.b, result, tt.expected)
		}
	}
}

func containsSubstring(s, substr string) bool {
	return len(s) >= len(substr) && findSubstring(s, substr)
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
