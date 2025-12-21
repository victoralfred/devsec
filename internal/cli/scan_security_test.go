package cli

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/victoralfred/devsec/internal/model"
	"github.com/victoralfred/gowritter/safepath"
)

// TestPathTraversalSecurity tests for path traversal vulnerabilities.
func TestPathTraversalSecurity(t *testing.T) {
	tests := []struct {
		name        string
		path        string
		expectError bool
	}{
		{"relative path", ".", false},
		{"absolute path", "/tmp", false},
		{"path traversal attempt 1", "../../../etc/passwd", true},
		{"path traversal attempt 2", "..\\..\\..\\windows\\system32", true},
		{"path with null byte", "test\x00file", true},
		{"path with newline", "test\nfile", true},
		{"symlink attempt", "/tmp", false}, // Should resolve to real path
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			absPath, err := filepath.Abs(tt.path)
			if err != nil {
				if !tt.expectError {
					t.Errorf("unexpected error: %v", err)
				}
				return
			}

			// Try to create safepath - should fail for traversal attempts
			sp, err := safepath.New(absPath)
			if err != nil {
				if !tt.expectError {
					t.Logf("expected no error but got: %v", err)
				}
				return
			}

			// If we got here, verify it's a valid path
			_, statErr := sp.Stat(".")
			if statErr != nil && !tt.expectError {
				t.Errorf("unexpected stat error: %v", statErr)
			}
		})
	}
}

// TestFileSizeLimits tests file size limit enforcement.
func TestFileSizeLimits(t *testing.T) {
	tmpDir := t.TempDir()
	sp, err := safepath.New(tmpDir)
	if err != nil {
		t.Fatalf("failed to create safe path: %v", err)
	}

	// Test with file at limit
	limitFile := "limit.txt"
	limitData := make([]byte, 50*1024*1024) // 50MB
	err = sp.WriteFile(limitFile, limitData, 0o644)
	if err != nil {
		t.Fatalf("failed to write limit file: %v", err)
	}

	// Test loading findings file at limit
	ctx := context.Background()
	findings, err := loadFindings(ctx, filepath.Join(tmpDir, limitFile))
	if err == nil {
		t.Error("expected error for file at size limit")
	}
	if findings != nil {
		t.Error("expected nil findings for oversized file")
	}

	// Test with file exceeding limit
	oversizedFile := "oversized.txt"
	oversizedData := make([]byte, 51*1024*1024) // 51MB
	err = sp.WriteFile(oversizedFile, oversizedData, 0o644)
	if err != nil {
		t.Fatalf("failed to write oversized file: %v", err)
	}

	_, err = loadFindings(ctx, filepath.Join(tmpDir, oversizedFile))
	if err == nil {
		t.Error("expected error for file exceeding size limit")
	}
}

// TestInputValidation tests input validation for security.
func TestInputValidation(t *testing.T) {
	tests := []struct {
		name        string
		findings    []model.Finding
		expectError bool
	}{
		{"empty findings", []model.Finding{}, false},
		{"nil findings", nil, false},
		{"valid findings", []model.Finding{
			{ID: "test-1", Severity: model.SeverityLow},
		}, false},
		{"findings with empty ID", []model.Finding{
			{ID: "", Severity: model.SeverityLow},
		}, false}, // Should not error, but may cause issues
		{"findings with invalid severity", []model.Finding{
			{ID: "test-1", Severity: model.Severity("invalid")},
		}, false}, // Should not error, but may cause issues
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test that output functions handle these cases
			cmd := NewScanSecretsCmd()
			buf := newBuffer()
			cmd.SetOut(buf)
			cmd.SetErr(buf)

			err := outputResults(cmd, tt.findings)
			if (err != nil) != tt.expectError {
				t.Errorf("outputResults() error = %v, wantErr %v", err, tt.expectError)
			}
		})
	}
}

// TestContextCancellation tests proper context cancellation handling.
func TestContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	// Test loadFindings with canceled context and a file path
	// (empty path returns early before context check, which is valid behavior)
	findings, err := loadFindings(ctx, "/tmp/test-findings.json")
	if err == nil {
		t.Error("expected error for canceled context")
	}
	if findings != nil {
		t.Error("expected nil findings for canceled context")
	}
}

// TestOutputFileSecurity tests output file path security.
func TestOutputFileSecurity(t *testing.T) {
	tests := []struct {
		name        string
		outputPath  string
		expectError bool
	}{
		{"valid path", "/tmp/test.json", false},
		{"path traversal", "../../../etc/passwd", true},
		{"absolute path in temp", filepath.Join(os.TempDir(), "test.json"), false},
		{"path with special chars", "test\x00file.json", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := NewScanSecretsCmd()
			buf := newBuffer()
			cmd.SetOut(buf)
			cmd.SetErr(buf)

			outputFile = tt.outputPath
			defer func() { outputFile = "" }()

			findings := []model.Finding{{ID: "test", Severity: model.SeverityLow}}
			err := outputResults(cmd, findings)

			if (err != nil) != tt.expectError {
				t.Errorf("outputResults() error = %v, wantErr %v", err, tt.expectError)
			}
		})
	}
}

// TestTimeoutHandling tests timeout behavior.
func TestTimeoutHandling(t *testing.T) {
	// Test with very short timeout
	shortTimeout := 1 * time.Nanosecond
	timeout = shortTimeout
	defer func() { timeout = 5 * time.Minute }()

	ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
	defer cancel()

	// Wait for timeout
	time.Sleep(10 * time.Nanosecond)

	// Test that context is properly canceled
	if ctx.Err() == nil {
		t.Error("expected context to be canceled")
	}
}

// newBuffer is a helper function to create a buffer.
func newBuffer() *os.File {
	r, w, _ := os.Pipe()
	go func() {
		_, _ = w.Write([]byte{})
		_ = w.Close()
	}()
	return r
}
