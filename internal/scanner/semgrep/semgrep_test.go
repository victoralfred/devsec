package semgrep

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
	scanner := New()
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
	customPath := "/custom/path/semgrep"
	customTimeout := 15 * time.Minute
	customConfig := "/path/to/rules.yaml"

	scanner := New(
		WithBinaryPath(customPath),
		WithTimeout(customTimeout),
		WithConfigFile(customConfig),
	)
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
	scanner := New()
	defer closeScanner(t, scanner)

	if scanner.Name() != "semgrep" {
		t.Errorf("expected name 'semgrep', got '%s'", scanner.Name())
	}
}

func TestMapFindings(t *testing.T) {
	scanner := New()
	defer closeScanner(t, scanner)

	sarif := SARIFReport{
		Version: "2.1.0",
		Runs: []SARIFRun{
			{
				Tool: SARIFTool{
					Driver: SARIFDriver{
						Name:    "Semgrep",
						Version: "1.0.0",
						Rules: []SARIFRule{
							{
								ID:   "javascript.lang.security.audit.xss.reflected.reflected-xss",
								Name: "Reflected XSS",
								ShortDescription: SARIFMessage{
									Text: "Potential XSS vulnerability",
								},
								FullDescription: SARIFMessage{
									Text: "User input is used in HTML context without proper escaping",
								},
							},
							{
								ID:   "go.lang.security.audit.sqli.pg-sqli",
								Name: "SQL Injection",
								ShortDescription: SARIFMessage{
									Text: "Potential SQL injection",
								},
								FullDescription: SARIFMessage{
									Text: "User input is used in SQL query without parameterization",
								},
							},
						},
					},
				},
				Results: []SARIFResult{
					{
						RuleID: "javascript.lang.security.audit.xss.reflected.reflected-xss",
						Level:  "error",
						Message: SARIFMessage{
							Text: "User input in HTML context",
						},
						Locations: []SARIFLocation{
							{
								PhysicalLocation: SARIFPhysicalLocation{
									ArtifactLocation: SARIFArtifactLocation{
										URI: "app/views/index.js",
									},
									Region: SARIFRegion{
										StartLine:   42,
										EndLine:     42,
										StartColumn: 10,
										EndColumn:   30,
									},
								},
							},
						},
					},
					{
						RuleID: "go.lang.security.audit.sqli.pg-sqli",
						Level:  "warning",
						Message: SARIFMessage{
							Text: "Possible SQL injection vector",
						},
						Locations: []SARIFLocation{
							{
								PhysicalLocation: SARIFPhysicalLocation{
									ArtifactLocation: SARIFArtifactLocation{
										URI: "internal/db/queries.go",
									},
									Region: SARIFRegion{
										StartLine:   100,
										EndLine:     102,
										StartColumn: 5,
										EndColumn:   20,
									},
								},
							},
						},
					},
				},
			},
		},
	}

	findings := scanner.mapFindings(sarif)

	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}

	// Check first finding (XSS).
	f1 := findings[0]
	if f1.Scanner != "semgrep" {
		t.Errorf("expected scanner 'semgrep', got '%s'", f1.Scanner)
	}
	if f1.Rule != "javascript.lang.security.audit.xss.reflected.reflected-xss" {
		t.Errorf("unexpected rule: %s", f1.Rule)
	}
	if f1.Severity != model.SeverityHigh {
		t.Errorf("expected severity High, got %s", f1.Severity)
	}
	if f1.Location.File != "app/views/index.js" {
		t.Errorf("expected file 'app/views/index.js', got '%s'", f1.Location.File)
	}
	if f1.Location.StartLine != 42 {
		t.Errorf("expected startLine 42, got %d", f1.Location.StartLine)
	}
	if f1.Location.EndLine != 42 {
		t.Errorf("expected endLine 42, got %d", f1.Location.EndLine)
	}

	// Check second finding (SQL injection).
	f2 := findings[1]
	if f2.Severity != model.SeverityMedium {
		t.Errorf("expected severity Medium, got %s", f2.Severity)
	}
	if f2.Location.File != "internal/db/queries.go" {
		t.Errorf("expected file 'internal/db/queries.go', got '%s'", f2.Location.File)
	}
	if f2.Location.StartLine != 100 {
		t.Errorf("expected startLine 100, got %d", f2.Location.StartLine)
	}
	if f2.Location.EndLine != 102 {
		t.Errorf("expected endLine 102, got %d", f2.Location.EndLine)
	}
}

func TestParseReport(t *testing.T) {
	scanner := New()
	defer closeScanner(t, scanner)

	sarif := SARIFReport{
		Version: "2.1.0",
		Runs: []SARIFRun{
			{
				Tool: SARIFTool{
					Driver: SARIFDriver{
						Name:    "Semgrep",
						Version: "1.0.0",
						Rules: []SARIFRule{
							{
								ID: "test-rule",
								ShortDescription: SARIFMessage{
									Text: "Test rule",
								},
							},
						},
					},
				},
				Results: []SARIFResult{
					{
						RuleID: "test-rule",
						Level:  "error",
						Message: SARIFMessage{
							Text: "Test finding",
						},
						Locations: []SARIFLocation{
							{
								PhysicalLocation: SARIFPhysicalLocation{
									ArtifactLocation: SARIFArtifactLocation{
										URI: "test.go",
									},
									Region: SARIFRegion{
										StartLine: 10,
										EndLine:   10,
									},
								},
							},
						},
					},
				},
			},
		},
	}

	data, err := json.Marshal(sarif)
	if err != nil {
		t.Fatalf("failed to marshal SARIF: %v", err)
	}

	tmpDir := "/tmp"
	tmpFile := "test-semgrep-report.sarif"

	sp, err := safepath.New(tmpDir)
	if err != nil {
		t.Fatalf("failed to create safe path: %v", err)
	}

	writeErr := sp.WriteFile(tmpFile, data, 0o600)
	if writeErr != nil {
		t.Fatalf("failed to write test file: %v", writeErr)
	}
	defer func() {
		removeErr := sp.Remove(tmpFile)
		_ = removeErr
	}()

	fullPath := filepath.Join(tmpDir, tmpFile)
	ctx := context.Background()
	findings, err := scanner.parseReport(ctx, fullPath)
	if err != nil {
		t.Fatalf("parseReport() error = %v", err)
	}

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	if findings[0].Rule != "test-rule" {
		t.Errorf("expected rule 'test-rule', got '%s'", findings[0].Rule)
	}
}

func TestParseReportEmpty(t *testing.T) {
	scanner := New()
	defer closeScanner(t, scanner)

	tmpDir := "/tmp"
	tmpFile := "test-semgrep-empty.sarif"

	sp, err := safepath.New(tmpDir)
	if err != nil {
		t.Fatalf("failed to create safe path: %v", err)
	}

	writeErr := sp.WriteFile(tmpFile, []byte(""), 0o600)
	if writeErr != nil {
		t.Fatalf("failed to write test file: %v", writeErr)
	}
	defer func() {
		removeErr := sp.Remove(tmpFile)
		_ = removeErr
	}()

	fullPath := filepath.Join(tmpDir, tmpFile)
	ctx := context.Background()
	findings, err := scanner.parseReport(ctx, fullPath)
	if err != nil {
		t.Fatalf("parseReport() error = %v", err)
	}

	if len(findings) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(findings))
	}
}

func TestParseReportEmptyResults(t *testing.T) {
	scanner := New()
	defer closeScanner(t, scanner)

	sarif := SARIFReport{
		Version: "2.1.0",
		Runs: []SARIFRun{
			{
				Tool: SARIFTool{
					Driver: SARIFDriver{
						Name:    "Semgrep",
						Version: "1.0.0",
					},
				},
				Results: []SARIFResult{},
			},
		},
	}

	data, err := json.Marshal(sarif)
	if err != nil {
		t.Fatalf("failed to marshal SARIF: %v", err)
	}

	tmpDir := "/tmp"
	tmpFile := "test-semgrep-empty-results.sarif"

	sp, err := safepath.New(tmpDir)
	if err != nil {
		t.Fatalf("failed to create safe path: %v", err)
	}

	writeErr := sp.WriteFile(tmpFile, data, 0o600)
	if writeErr != nil {
		t.Fatalf("failed to write test file: %v", writeErr)
	}
	defer func() {
		removeErr := sp.Remove(tmpFile)
		_ = removeErr
	}()

	fullPath := filepath.Join(tmpDir, tmpFile)
	ctx := context.Background()
	findings, err := scanner.parseReport(ctx, fullPath)
	if err != nil {
		t.Fatalf("parseReport() error = %v", err)
	}

	if len(findings) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(findings))
	}
}

func TestParseReportInvalidJSON(t *testing.T) {
	scanner := New()
	defer closeScanner(t, scanner)

	tmpDir := "/tmp"
	tmpFile := "test-semgrep-invalid.sarif"

	sp, err := safepath.New(tmpDir)
	if err != nil {
		t.Fatalf("failed to create safe path: %v", err)
	}

	writeErr := sp.WriteFile(tmpFile, []byte("invalid json {{{"), 0o600)
	if writeErr != nil {
		t.Fatalf("failed to write test file: %v", writeErr)
	}
	defer func() {
		removeErr := sp.Remove(tmpFile)
		_ = removeErr
	}()

	fullPath := filepath.Join(tmpDir, tmpFile)
	ctx := context.Background()
	_, err = scanner.parseReport(ctx, fullPath)
	if err == nil {
		t.Fatal("expected error for invalid JSON, got nil")
	}
}

func TestParseReportFileNotFound(t *testing.T) {
	scanner := New()
	defer closeScanner(t, scanner)

	ctx := context.Background()
	_, err := scanner.parseReport(ctx, "/nonexistent/path/report.sarif")
	if err == nil {
		t.Fatal("expected error for nonexistent file, got nil")
	}
}

func TestMapSeverity(t *testing.T) {
	scanner := New()
	defer closeScanner(t, scanner)

	tests := []struct {
		name     string
		level    string
		expected model.Severity
	}{
		{"error level", "error", model.SeverityHigh},
		{"warning level", "warning", model.SeverityMedium},
		{"note level", "note", model.SeverityLow},
		{"unknown level", "unknown", model.SeverityInfo},
		{"empty level", "", model.SeverityInfo},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := scanner.mapSeverity(tt.level)
			if result != tt.expected {
				t.Errorf("mapSeverity(%q) = %v, want %v", tt.level, result, tt.expected)
			}
		})
	}
}
