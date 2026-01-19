package trivy

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

	if scanner.scanType != "fs" {
		t.Errorf("expected scanType 'fs', got '%s'", scanner.scanType)
	}
}

func TestNewWithOptions(t *testing.T) {
	customPath := "/custom/path/trivy"
	customTimeout := 15 * time.Minute
	customScanType := "image"

	scanner := New(
		WithBinaryPath(customPath),
		WithTimeout(customTimeout),
		WithScanType(customScanType),
	)
	defer closeScanner(t, scanner)

	if scanner.binaryPath != customPath {
		t.Errorf("expected binaryPath %s, got %s", customPath, scanner.binaryPath)
	}

	if scanner.timeout != customTimeout {
		t.Errorf("expected timeout %v, got %v", customTimeout, scanner.timeout)
	}

	if scanner.scanType != customScanType {
		t.Errorf("expected scanType %s, got %s", customScanType, scanner.scanType)
	}
}

func TestScannerName(t *testing.T) {
	scanner := New()
	defer closeScanner(t, scanner)

	if scanner.Name() != "trivy" {
		t.Errorf("expected name 'trivy', got '%s'", scanner.Name())
	}
}

func TestMapFindings(t *testing.T) {
	scanner := New()
	defer closeScanner(t, scanner)

	report := Report{
		SchemaVersion: 2,
		ArtifactName:  "test-project",
		ArtifactType:  "filesystem",
		Results: []Result{
			{
				Target: "package-lock.json",
				Class:  "lang-pkgs",
				Type:   "npm",
				Vulnerabilities: []Vulnerability{
					{
						VulnerabilityID:  "CVE-2021-44228",
						PkgName:          "log4j-core",
						InstalledVersion: "2.14.0",
						FixedVersion:     "2.17.0",
						Title:            "Log4Shell RCE Vulnerability",
						Description:      "Apache Log4j2 allows remote code execution",
						Severity:         "CRITICAL",
					},
					{
						VulnerabilityID:  "CVE-2022-12345",
						PkgName:          "lodash",
						InstalledVersion: "4.17.19",
						FixedVersion:     "4.17.21",
						Title:            "Prototype Pollution",
						Description:      "Prototype pollution vulnerability in lodash",
						Severity:         "HIGH",
					},
				},
			},
			{
				Target: "requirements.txt",
				Class:  "lang-pkgs",
				Type:   "pip",
				Vulnerabilities: []Vulnerability{
					{
						VulnerabilityID:  "CVE-2022-67890",
						PkgName:          "requests",
						InstalledVersion: "2.25.0",
						FixedVersion:     "2.28.0",
						Title:            "HTTP Request Smuggling",
						Description:      "HTTP request smuggling vulnerability",
						Severity:         "MEDIUM",
					},
				},
			},
		},
	}

	findings := scanner.mapFindings(report)

	if len(findings) != 3 {
		t.Fatalf("expected 3 findings, got %d", len(findings))
	}

	// Check first finding (Log4Shell).
	f1 := findings[0]
	if f1.Scanner != "trivy" {
		t.Errorf("expected scanner 'trivy', got '%s'", f1.Scanner)
	}
	if f1.Rule != "CVE-2021-44228" {
		t.Errorf("unexpected rule: %s", f1.Rule)
	}
	if f1.Severity != model.SeverityCritical {
		t.Errorf("expected severity Critical, got %s", f1.Severity)
	}
	if f1.Title != "Log4Shell RCE Vulnerability" {
		t.Errorf("unexpected title: %s", f1.Title)
	}
	if f1.Location.File != "package-lock.json" {
		t.Errorf("expected file 'package-lock.json', got '%s'", f1.Location.File)
	}

	// Check second finding (lodash).
	f2 := findings[1]
	if f2.Severity != model.SeverityHigh {
		t.Errorf("expected severity High, got %s", f2.Severity)
	}
	if f2.Rule != "CVE-2022-12345" {
		t.Errorf("unexpected rule: %s", f2.Rule)
	}

	// Check third finding (requests).
	f3 := findings[2]
	if f3.Severity != model.SeverityMedium {
		t.Errorf("expected severity Medium, got %s", f3.Severity)
	}
	if f3.Location.File != "requirements.txt" {
		t.Errorf("expected file 'requirements.txt', got '%s'", f3.Location.File)
	}
}

func TestParseReport(t *testing.T) {
	scanner := New()
	defer closeScanner(t, scanner)

	report := Report{
		SchemaVersion: 2,
		ArtifactName:  "test",
		Results: []Result{
			{
				Target: "go.mod",
				Class:  "lang-pkgs",
				Type:   "gomod",
				Vulnerabilities: []Vulnerability{
					{
						VulnerabilityID:  "CVE-2023-12345",
						PkgName:          "golang.org/x/crypto",
						InstalledVersion: "0.1.0",
						FixedVersion:     "0.5.0",
						Title:            "Test Vulnerability",
						Description:      "Test description",
						Severity:         "HIGH",
					},
				},
			},
		},
	}

	data, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("failed to marshal report: %v", err)
	}

	tmpDir := t.TempDir()
	tmpFile := "test-trivy-report.json"

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

	if findings[0].Rule != "CVE-2023-12345" {
		t.Errorf("expected rule 'CVE-2023-12345', got '%s'", findings[0].Rule)
	}
}

func TestParseReportEmpty(t *testing.T) {
	scanner := New()
	defer closeScanner(t, scanner)

	tmpDir := t.TempDir()
	tmpFile := "test-trivy-empty.json"

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

func TestParseReportNoVulnerabilities(t *testing.T) {
	scanner := New()
	defer closeScanner(t, scanner)

	report := Report{
		SchemaVersion: 2,
		ArtifactName:  "clean-project",
		Results: []Result{
			{
				Target:          "package.json",
				Class:           "lang-pkgs",
				Type:            "npm",
				Vulnerabilities: []Vulnerability{},
			},
		},
	}

	data, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("failed to marshal report: %v", err)
	}

	tmpDir := t.TempDir()
	tmpFile := "test-trivy-no-vulns.json"

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

	tmpDir := t.TempDir()
	tmpFile := "test-trivy-invalid.json"

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
	_, err := scanner.parseReport(ctx, "/nonexistent/path/report.json")
	if err == nil {
		t.Fatal("expected error for nonexistent file, got nil")
	}
}

func TestMapSeverity(t *testing.T) {
	scanner := New()
	defer closeScanner(t, scanner)

	tests := []struct {
		name     string
		severity string
		expected model.Severity
	}{
		{"critical", "CRITICAL", model.SeverityCritical},
		{"high", "HIGH", model.SeverityHigh},
		{"medium", "MEDIUM", model.SeverityMedium},
		{"low", "LOW", model.SeverityLow},
		{"unknown", "UNKNOWN", model.SeverityInfo},
		{"empty", "", model.SeverityInfo},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := scanner.mapSeverity(tt.severity)
			if result != tt.expected {
				t.Errorf("mapSeverity(%q) = %v, want %v", tt.severity, result, tt.expected)
			}
		})
	}
}

func TestBuildDescription(t *testing.T) {
	scanner := New()
	defer closeScanner(t, scanner)

	vuln := &Vulnerability{
		PkgName:          "test-package",
		InstalledVersion: "1.0.0",
		FixedVersion:     "2.0.0",
		Description:      "This is a test vulnerability",
	}

	desc := scanner.buildDescription(vuln)

	if desc == "" {
		t.Error("expected non-empty description")
	}

	// Should contain package info.
	expectedSubstrings := []string{"test-package", "1.0.0", "2.0.0", "This is a test vulnerability"}
	for _, substr := range expectedSubstrings {
		if !containsString(desc, substr) {
			t.Errorf("description should contain '%s', got: %s", substr, desc)
		}
	}
}

// containsString checks if a string contains a substring.
func containsString(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || s != "" && containsSubstring(s, substr))
}

func containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
