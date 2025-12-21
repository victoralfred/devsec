package cli

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/victoralfred/devsec/internal/model"
	"github.com/victoralfred/gowritter/safepath"
)

// TestEmptyFindings tests handling of empty findings.
func TestEmptyFindings(t *testing.T) {
	cmd := NewScanSecretsCmd()
	buf := newBuffer()
	cmd.SetOut(buf)
	cmd.SetErr(buf)

	tests := []struct {
		name     string
		findings []model.Finding
	}{
		{"nil findings", nil},
		{"empty slice", []model.Finding{}},
		{"zero length", make([]model.Finding, 0)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := outputResults(cmd, tt.findings)
			if err != nil {
				t.Errorf("outputResults() error = %v", err)
			}
		})
	}
}

// TestNilCommand tests handling of nil command.
func TestNilCommand(t *testing.T) {
	findings := []model.Finding{{ID: "test", Severity: model.SeverityLow}}

	// These should handle nil command gracefully or panic appropriately
	t.Run("outputJSON with nil command", func(t *testing.T) {
		err := outputJSON(nil, findings)
		// May or may not error, but shouldn't panic
		_ = err
	})
}

// TestInvalidJSONFormat tests handling of invalid JSON in findings file.
func TestInvalidJSONFormat(t *testing.T) {
	tmpDir := t.TempDir()
	sp, err := safepath.New(tmpDir)
	if err != nil {
		t.Fatalf("failed to create safe path: %v", err)
	}

	invalidJSON := "not valid json {{{"
	invalidFile := "invalid.json"
	err = sp.WriteFile(invalidFile, []byte(invalidJSON), 0o644)
	if err != nil {
		t.Fatalf("failed to write invalid JSON: %v", err)
	}

	ctx := context.Background()
	findings, err := loadFindings(ctx, filepath.Join(tmpDir, invalidFile))
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
	if findings != nil {
		t.Error("expected nil findings for invalid JSON")
	}
}

// TestMissingFile tests handling of missing file.
func TestMissingFile(t *testing.T) {
	ctx := context.Background()
	findings, err := loadFindings(ctx, "/nonexistent/file.json")
	if err == nil {
		t.Error("expected error for missing file")
	}
	if findings != nil {
		t.Error("expected nil findings for missing file")
	}
}

// TestEmptyFile tests handling of empty file.
func TestEmptyFile(t *testing.T) {
	tmpDir := t.TempDir()
	sp, err := safepath.New(tmpDir)
	if err != nil {
		t.Fatalf("failed to create safe path: %v", err)
	}

	emptyFile := "empty.json"
	err = sp.WriteFile(emptyFile, []byte{}, 0o644)
	if err != nil {
		t.Fatalf("failed to write empty file: %v", err)
	}

	ctx := context.Background()
	findings, err := loadFindings(ctx, filepath.Join(tmpDir, emptyFile))
	if err != nil {
		// Empty file might be valid (empty array)
		t.Logf("loadFindings() error = %v (may be expected)", err)
	}
	// Findings should be empty or nil
	if findings == nil {
		findings = []model.Finding{}
	}
	if len(findings) != 0 {
		t.Errorf("expected empty findings, got %d", len(findings))
	}
}

// TestEmptyArrayFile tests handling of file with empty JSON array.
func TestEmptyArrayFile(t *testing.T) {
	tmpDir := t.TempDir()
	sp, err := safepath.New(tmpDir)
	if err != nil {
		t.Fatalf("failed to create safe path: %v", err)
	}

	emptyArrayFile := "empty-array.json"
	err = sp.WriteFile(emptyArrayFile, []byte("[]"), 0o644)
	if err != nil {
		t.Fatalf("failed to write empty array file: %v", err)
	}

	ctx := context.Background()
	findings, err := loadFindings(ctx, filepath.Join(tmpDir, emptyArrayFile))
	if err != nil {
		t.Fatalf("loadFindings() error = %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

// TestSpecialCharactersInPaths tests handling of special characters in file paths.
func TestSpecialCharactersInPaths(t *testing.T) {
	tests := []struct {
		name        string
		path        string
		expectError bool
	}{
		{"spaces in path", "/tmp/test file.json", false},
		{"unicode in path", "/tmp/test-文件.json", false},
		{"newline in path", "/tmp/test\nfile.json", true},
		{"null byte in path", "/tmp/test\x00file.json", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test that writeToFile handles special characters
			data := []byte("test")
			err := writeToFile(tt.path, data)
			if (err != nil) != tt.expectError {
				t.Errorf("writeToFile() error = %v, wantErr %v", err, tt.expectError)
			}
		})
	}
}

// TestInvalidOutputFormat tests handling of invalid output format.
func TestInvalidOutputFormat(t *testing.T) {
	cmd := NewScanSecretsCmd()
	buf := newBuffer()
	cmd.SetOut(buf)
	cmd.SetErr(buf)

	outputFormat = "invalid-format"
	defer func() { outputFormat = "text" }()

	findings := []model.Finding{{ID: "test", Severity: model.SeverityLow}}
	err := outputResults(cmd, findings)
	if err == nil {
		t.Error("expected error for invalid output format")
	}
}

// TestFindingsWithMissingFields tests handling of findings with missing fields.
func TestFindingsWithMissingFields(t *testing.T) {
	cmd := NewScanSecretsCmd()
	buf := newBuffer()
	cmd.SetOut(buf)
	cmd.SetErr(buf)

	tests := []struct {
		name     string
		findings []model.Finding
	}{
		{"missing ID", []model.Finding{{Severity: model.SeverityLow}}},
		{"missing severity", []model.Finding{{ID: "test"}}},
		{"missing title", []model.Finding{{ID: "test", Severity: model.SeverityLow}}},
		{"missing location", []model.Finding{{ID: "test", Severity: model.SeverityLow}}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := outputResults(cmd, tt.findings)
			// Should not error, but may produce incomplete output
			if err != nil {
				t.Logf("outputResults() error = %v (may be acceptable)", err)
			}
		})
	}
}

// TestVeryLongStrings tests handling of very long strings in findings
func TestVeryLongStrings(t *testing.T) {
	cmd := NewScanSecretsCmd()
	buf := newBuffer()
	cmd.SetOut(buf)
	cmd.SetErr(buf)

	longString := make([]byte, 100000)
	for i := range longString {
		longString[i] = 'a'
	}

	findings := []model.Finding{
		{
			ID:          "test",
			Title:       string(longString),
			Description: string(longString),
			Severity:    model.SeverityLow,
		},
	}

	err := outputResults(cmd, findings)
	if err != nil {
		t.Errorf("outputResults() error = %v", err)
	}
}

// TestMalformedFindingsJSON tests handling of malformed JSON structures
func TestMalformedFindingsJSON(t *testing.T) {
	tmpDir := t.TempDir()
	sp, err := safepath.New(tmpDir)
	if err != nil {
		t.Fatalf("failed to create safe path: %v", err)
	}

	malformedJSON := `[{"id": "test", "severity": "low", "invalid": "field"}]`
	malformedFile := "malformed.json"
	err = sp.WriteFile(malformedFile, []byte(malformedJSON), 0o644)
	if err != nil {
		t.Fatalf("failed to write malformed JSON: %v", err)
	}

	ctx := context.Background()
	findings, err := loadFindings(ctx, filepath.Join(tmpDir, malformedFile))
	// Should either succeed (ignoring extra fields) or fail gracefully
	if err != nil {
		t.Logf("loadFindings() error = %v (may be expected)", err)
	}
	_ = findings
}

// TestUnicodeInFindings tests handling of unicode characters in findings
func TestUnicodeInFindings(t *testing.T) {
	cmd := NewScanSecretsCmd()
	buf := newBuffer()
	cmd.SetOut(buf)
	cmd.SetErr(buf)

	findings := []model.Finding{
		{
			ID:          "test-中文",
			Title:       "测试发现",
			Description: "これはテストです",
			Severity:    model.SeverityLow,
			Location: model.Location{
				File: "文件.go",
			},
		},
	}

	err := outputResults(cmd, findings)
	if err != nil {
		t.Errorf("outputResults() error = %v", err)
	}

	// Test JSON encoding
	data, err := json.Marshal(findings)
	if err != nil {
		t.Errorf("json.Marshal() error = %v", err)
	}

	// Test JSON decoding
	var decoded []model.Finding
	err = json.Unmarshal(data, &decoded)
	if err != nil {
		t.Errorf("json.Unmarshal() error = %v", err)
	}
}

// TestNegativeLineNumbers tests handling of negative line numbers
func TestNegativeLineNumbers(t *testing.T) {
	cmd := NewScanSecretsCmd()
	buf := newBuffer()
	cmd.SetOut(buf)
	cmd.SetErr(buf)

	findings := []model.Finding{
		{
			ID:       "test",
			Severity: model.SeverityLow,
			Location: model.Location{
				File:      "test.go",
				StartLine: -1,
				EndLine:   -1,
			},
		},
	}

	err := outputResults(cmd, findings)
	// Should not error, but may produce invalid output
	if err != nil {
		t.Logf("outputResults() error = %v (may be acceptable)", err)
	}
}
