package osv

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/victoralfred/devsec/internal/model"
	"github.com/victoralfred/gowritter/safepath"
)

func TestNew(t *testing.T) {
	scanner := New()

	if scanner.apiURL != DefaultAPIURL {
		t.Errorf("expected apiURL %s, got %s", DefaultAPIURL, scanner.apiURL)
	}

	if scanner.timeout != DefaultTimeout {
		t.Errorf("expected timeout %v, got %v", DefaultTimeout, scanner.timeout)
	}

	if scanner.batchSize != DefaultBatchSize {
		t.Errorf("expected batchSize %d, got %d", DefaultBatchSize, scanner.batchSize)
	}
}

func TestNewWithOptions(t *testing.T) {
	customURL := "https://custom.osv.dev/v1"
	customTimeout := 5 * time.Minute
	customBatchSize := 50

	scanner := New(
		WithAPIURL(customURL),
		WithTimeout(customTimeout),
		WithBatchSize(customBatchSize),
	)

	if scanner.apiURL != customURL {
		t.Errorf("expected apiURL %s, got %s", customURL, scanner.apiURL)
	}

	if scanner.timeout != customTimeout {
		t.Errorf("expected timeout %v, got %v", customTimeout, scanner.timeout)
	}

	if scanner.batchSize != customBatchSize {
		t.Errorf("expected batchSize %d, got %d", customBatchSize, scanner.batchSize)
	}
}

func TestScannerName(t *testing.T) {
	scanner := New()
	if scanner.Name() != "osv" {
		t.Errorf("expected name 'osv', got '%s'", scanner.Name())
	}
}

func TestParseGoModContent(t *testing.T) {
	content := []byte(`module github.com/example/project

go 1.21

require (
	github.com/google/uuid v1.3.0
	github.com/spf13/cobra v1.7.0
	golang.org/x/crypto v0.14.0 // indirect
)

require github.com/single/dep v1.0.0
`)

	deps := parseGoModContent(content, "go.mod")

	// Should have 3 deps (excluding indirect).
	if len(deps) != 3 {
		t.Fatalf("expected 3 dependencies, got %d", len(deps))
	}

	// Check first dep.
	if deps[0].Name != "github.com/google/uuid" {
		t.Errorf("expected name 'github.com/google/uuid', got '%s'", deps[0].Name)
	}
	if deps[0].Version != "1.3.0" {
		t.Errorf("expected version '1.3.0', got '%s'", deps[0].Version)
	}
	if deps[0].Ecosystem != "Go" {
		t.Errorf("expected ecosystem 'Go', got '%s'", deps[0].Ecosystem)
	}
}

func TestParsePackageJSONContent(t *testing.T) {
	content := []byte(`{
		"name": "test-project",
		"version": "1.0.0",
		"dependencies": {
			"lodash": "^4.17.21",
			"express": "~4.18.0"
		},
		"devDependencies": {
			"jest": ">=29.0.0"
		}
	}`)

	deps := parsePackageJSONContent(content, "package.json")

	if len(deps) != 3 {
		t.Fatalf("expected 3 dependencies, got %d", len(deps))
	}

	// Check that versions are cleaned.
	found := make(map[string]string)
	for _, dep := range deps {
		found[dep.Name] = dep.Version
		if dep.Ecosystem != "npm" {
			t.Errorf("expected ecosystem 'npm', got '%s'", dep.Ecosystem)
		}
	}

	if found["lodash"] != "4.17.21" {
		t.Errorf("expected lodash version '4.17.21', got '%s'", found["lodash"])
	}
	if found["express"] != "4.18.0" {
		t.Errorf("expected express version '4.18.0', got '%s'", found["express"])
	}
	if found["jest"] != "29.0.0" {
		t.Errorf("expected jest version '29.0.0', got '%s'", found["jest"])
	}
}

func TestParseRequirementsTxtContent(t *testing.T) {
	content := []byte(`# This is a comment
requests==2.28.0
flask>=2.0.0
django~=4.2
numpy==1.24.0

# Another comment
-r base.txt
`)

	deps := parseRequirementsTxtContent(content, "requirements.txt")

	if len(deps) != 4 {
		t.Fatalf("expected 4 dependencies, got %d", len(deps))
	}

	found := make(map[string]string)
	for _, dep := range deps {
		found[dep.Name] = dep.Version
		if dep.Ecosystem != "PyPI" {
			t.Errorf("expected ecosystem 'PyPI', got '%s'", dep.Ecosystem)
		}
	}

	if found["requests"] != "2.28.0" {
		t.Errorf("expected requests version '2.28.0', got '%s'", found["requests"])
	}
	if found["flask"] != "2.0.0" {
		t.Errorf("expected flask version '2.0.0', got '%s'", found["flask"])
	}
}

func TestCleanVersion(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"^1.0.0", "1.0.0"},
		{"~1.0.0", "1.0.0"},
		{">=1.0.0", "1.0.0"},
		{"<=1.0.0", "1.0.0"},
		{">1.0.0", "1.0.0"},
		{"<1.0.0", "1.0.0"},
		{"=1.0.0", "1.0.0"},
		{"1.0.0", "1.0.0"},
	}

	for _, tt := range tests {
		result := cleanVersion(tt.input)
		if result != tt.expected {
			t.Errorf("cleanVersion(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestMapVulnerability(t *testing.T) {
	scanner := New()

	vuln := &Vulnerability{
		ID:      "GHSA-1234-5678-abcd",
		Summary: "Test vulnerability",
		Details: "This is a test vulnerability description.",
		Aliases: []string{"CVE-2023-12345"},
		Severity: []Severity{
			{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"},
		},
	}

	dep := &Dependency{
		Name:      "test-package",
		Version:   "1.0.0",
		Ecosystem: "npm",
		File:      "package.json",
	}

	finding := scanner.mapVulnerability(vuln, dep)

	if finding.Scanner != "osv" {
		t.Errorf("expected scanner 'osv', got '%s'", finding.Scanner)
	}
	if finding.Rule != "GHSA-1234-5678-abcd" {
		t.Errorf("expected rule 'GHSA-1234-5678-abcd', got '%s'", finding.Rule)
	}
	if finding.Title != "Test vulnerability" {
		t.Errorf("expected title 'Test vulnerability', got '%s'", finding.Title)
	}
	if finding.Location.File != "package.json" {
		t.Errorf("expected file 'package.json', got '%s'", finding.Location.File)
	}
}

func TestDetermineSeverity(t *testing.T) {
	scanner := New()

	tests := []struct {
		name     string
		vuln     *Vulnerability
		expected model.Severity
	}{
		{
			name: "cvss_high",
			vuln: &Vulnerability{
				Severity: []Severity{
					{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
				},
			},
			expected: model.SeverityHigh,
		},
		{
			name: "ghsa_default",
			vuln: &Vulnerability{
				ID: "GHSA-xxxx-yyyy-zzzz",
			},
			expected: model.SeverityMedium,
		},
		{
			name: "unknown",
			vuln: &Vulnerability{
				ID: "OSV-2023-1234",
			},
			expected: model.SeverityInfo,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := scanner.determineSeverity(tt.vuln)
			if result != tt.expected {
				t.Errorf("determineSeverity() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestQueryBatchWithMockServer(t *testing.T) {
	// Create mock server.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/querybatch" {
			t.Errorf("unexpected path: %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}

		if r.Method != http.MethodPost {
			t.Errorf("unexpected method: %s", r.Method)
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		// Return mock response.
		resp := BatchQueryResponse{
			Results: []QueryResponse{
				{
					Vulns: []Vulnerability{
						{
							ID:      "GHSA-test-1234",
							Summary: "Test vulnerability in lodash",
							Aliases: []string{"CVE-2023-99999"},
						},
					},
				},
				{
					Vulns: []Vulnerability{},
				},
			},
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	scanner := New(WithAPIURL(server.URL))

	deps := []Dependency{
		{Name: "lodash", Version: "4.17.20", Ecosystem: "npm", File: "package.json"},
		{Name: "express", Version: "4.18.0", Ecosystem: "npm", File: "package.json"},
	}

	ctx := context.Background()
	findings, err := scanner.queryBatch(ctx, deps)
	if err != nil {
		t.Fatalf("queryBatch() error = %v", err)
	}

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	if findings[0].Rule != "GHSA-test-1234" {
		t.Errorf("expected rule 'GHSA-test-1234', got '%s'", findings[0].Rule)
	}
}

func TestScanWithMockServer(t *testing.T) {
	// Create mock server.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := BatchQueryResponse{
			Results: []QueryResponse{
				{
					Vulns: []Vulnerability{
						{
							ID:      "GHSA-scan-test",
							Summary: "Vulnerability found during scan",
						},
					},
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	// Create temp directory with go.mod.
	tmpDir := "/tmp"
	tmpFile := "test-go.mod"

	sp, err := safepath.New(tmpDir)
	if err != nil {
		t.Fatalf("failed to create safe path: %v", err)
	}

	goModContent := []byte(`module test

go 1.21

require github.com/vulnerable/pkg v1.0.0
`)
	writeErr := sp.WriteFile(tmpFile, goModContent, 0o600)
	if writeErr != nil {
		t.Fatalf("failed to write go.mod: %v", writeErr)
	}
	defer func() {
		_ = sp.Remove(tmpFile)
	}()

	// Create a subdirectory for scanning.
	testDir := filepath.Join(tmpDir, "osv-test-scan")
	testSp, spErr := safepath.New(tmpDir)
	if spErr != nil {
		t.Fatalf("failed to create safe path: %v", spErr)
	}
	mkdirErr := testSp.MkdirAll("osv-test-scan", 0o755)
	if mkdirErr != nil {
		t.Fatalf("failed to create test dir: %v", mkdirErr)
	}
	defer func() {
		_ = testSp.RemoveAll("osv-test-scan")
	}()

	// Write go.mod to test directory.
	testDirSp, dirSpErr := safepath.New(testDir)
	if dirSpErr != nil {
		t.Fatalf("failed to create safe path for test dir: %v", dirSpErr)
	}
	testWriteErr := testDirSp.WriteFile("go.mod", goModContent, 0o600)
	if testWriteErr != nil {
		t.Fatalf("failed to write go.mod to test dir: %v", testWriteErr)
	}

	scanner := New(WithAPIURL(server.URL))
	ctx := context.Background()

	findings, err := scanner.Scan(ctx, testDir)
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	if findings[0].Rule != "GHSA-scan-test" {
		t.Errorf("expected rule 'GHSA-scan-test', got '%s'", findings[0].Rule)
	}
}

func TestScanEmptyPath(t *testing.T) {
	scanner := New()
	ctx := context.Background()

	_, err := scanner.Scan(ctx, "")
	if err == nil {
		t.Fatal("expected error for empty path")
	}
}

func TestScanNonExistentPath(t *testing.T) {
	scanner := New()
	ctx := context.Background()

	_, err := scanner.Scan(ctx, "/nonexistent/path/12345")
	if err == nil {
		t.Fatal("expected error for nonexistent path")
	}
}

func TestScanContextCanceled(t *testing.T) {
	scanner := New()
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately.

	_, err := scanner.Scan(ctx, "/tmp")
	if err == nil {
		t.Fatal("expected error for canceled context")
	}
}

func TestClose(t *testing.T) {
	scanner := New()
	ctx := context.Background()

	err := scanner.Close(ctx)
	if err != nil {
		t.Errorf("Close() error = %v", err)
	}
}

func TestBuildDescription(t *testing.T) {
	scanner := New()

	vuln := &Vulnerability{
		ID:      "GHSA-test",
		Details: "This is the vulnerability details.",
		Aliases: []string{"CVE-2023-1111", "CVE-2023-2222"},
		Affected: []Affected{
			{
				Package: &Package{
					Name:      "test-pkg",
					Ecosystem: "npm",
				},
				Ranges: []Range{
					{
						Type: "SEMVER",
						Events: []Event{
							{Introduced: "0"},
							{Fixed: "2.0.0"},
						},
					},
				},
			},
		},
	}

	dep := &Dependency{
		Name:      "test-pkg",
		Version:   "1.5.0",
		Ecosystem: "npm",
		File:      "package.json",
	}

	desc := scanner.buildDescription(vuln, dep)

	if desc == "" {
		t.Error("expected non-empty description")
	}

	// Check for expected substrings.
	expectedSubstrings := []string{
		"test-pkg",
		"1.5.0",
		"npm",
		"CVE-2023-1111",
		"2.0.0",
		"This is the vulnerability details.",
	}

	for _, substr := range expectedSubstrings {
		if !containsString(desc, substr) {
			t.Errorf("description should contain '%s', got: %s", substr, desc)
		}
	}
}

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
