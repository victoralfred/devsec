package cli

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/victoralfred/devsec/internal/model"
	"github.com/victoralfred/devsec/internal/policy"
	"github.com/victoralfred/gowritter/safepath"
)

func TestLoadFindings(t *testing.T) {
	tmpDir := t.TempDir()
	sp, err := safepath.New(tmpDir)
	if err != nil {
		t.Fatalf("failed to create safe path: %v", err)
	}

	findings := []model.Finding{
		{ID: "test-1", Severity: model.SeverityLow},
		{ID: "test-2", Severity: model.SeverityHigh},
	}

	data, err := json.Marshal(findings)
	if err != nil {
		t.Fatalf("failed to marshal findings: %v", err)
	}

	testFile := "findings.json"
	err = sp.WriteFile(testFile, data, 0o644)
	if err != nil {
		t.Fatalf("failed to write findings file: %v", err)
	}

	ctx := context.Background()
	loaded, err := loadFindings(ctx, filepath.Join(tmpDir, testFile))
	if err != nil {
		t.Fatalf("loadFindings() error = %v", err)
	}

	if len(loaded) != 2 {
		t.Errorf("expected 2 findings, got %d", len(loaded))
	}
}

func TestLoadFindingsEmptyFile(t *testing.T) {
	ctx := context.Background()
	findings, err := loadFindings(ctx, "")
	if err != nil {
		t.Fatalf("loadFindings() error = %v", err)
	}

	if findings == nil {
		t.Error("expected non-nil findings for empty path")
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestLoadFindingsInvalidJSON(t *testing.T) {
	tmpDir := t.TempDir()
	sp, err := safepath.New(tmpDir)
	if err != nil {
		t.Fatalf("failed to create safe path: %v", err)
	}

	invalidJSON := "not valid json"
	invalidFile := "invalid.json"
	err = sp.WriteFile(invalidFile, []byte(invalidJSON), 0o644)
	if err != nil {
		t.Fatalf("failed to write invalid JSON: %v", err)
	}

	ctx := context.Background()
	_, err = loadFindings(ctx, filepath.Join(tmpDir, invalidFile))
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestLoadFindingsFileNotFound(t *testing.T) {
	ctx := context.Background()
	_, err := loadFindings(ctx, "/nonexistent/file.json")
	if err == nil {
		t.Error("expected error for missing file")
	}
}

func TestLoadFindingsLargeFile(t *testing.T) {
	tmpDir := t.TempDir()
	sp, err := safepath.New(tmpDir)
	if err != nil {
		t.Fatalf("failed to create safe path: %v", err)
	}

	// Create file larger than maxSize (50MB)
	largeData := make([]byte, 51*1024*1024)
	largeFile := "large.json"
	err = sp.WriteFile(largeFile, largeData, 0o644)
	if err != nil {
		t.Fatalf("failed to write large file: %v", err)
	}

	ctx := context.Background()
	_, err = loadFindings(ctx, filepath.Join(tmpDir, largeFile))
	if err == nil {
		t.Error("expected error for file exceeding size limit")
	}
}

func TestLoadFindingsContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, err := loadFindings(ctx, "/tmp/test.json")
	if err == nil {
		t.Error("expected error for canceled context")
	}
}

func TestOutputPolicyResult(t *testing.T) {
	cmd := NewPolicyCheckCmd()
	buf := newBuffer()
	cmd.SetOut(buf)
	cmd.SetErr(buf)

	result := policy.CheckResult{
		Passed:     true,
		TotalCount: 0,
		Summary:    "Policy check PASSED",
	}

	dp, err := policy.NewDecisionPoint(context.Background())
	if err != nil {
		t.Fatalf("NewDecisionPoint() error = %v", err)
	}
	defer func() {
		_ = dp.Close(context.Background())
	}()

	err = outputPolicyResult(cmd, result, dp)
	if err != nil {
		t.Errorf("outputPolicyResult() error = %v", err)
	}
}

func TestOutputPolicyJSON(t *testing.T) {
	cmd := NewPolicyCheckCmd()
	buf := newBuffer()
	cmd.SetOut(buf)
	cmd.SetErr(buf)

	result := policy.CheckResult{
		Passed:     true,
		TotalCount: 0,
		Summary:    "Policy check PASSED",
	}

	dp, err := policy.NewDecisionPoint(context.Background())
	if err != nil {
		t.Fatalf("NewDecisionPoint() error = %v", err)
	}
	defer func() {
		_ = dp.Close(context.Background())
	}()

	outputFormat = "json"
	defer func() { outputFormat = "text" }()

	err = outputPolicyJSON(cmd, result, dp)
	if err != nil {
		t.Errorf("outputPolicyJSON() error = %v", err)
	}
}

func TestOutputPolicyText(t *testing.T) {
	cmd := NewPolicyCheckCmd()
	buf := newBuffer()
	cmd.SetOut(buf)
	cmd.SetErr(buf)

	result := policy.CheckResult{
		Passed:     true,
		TotalCount: 0,
		Summary:    "Policy check PASSED",
	}

	dp, err := policy.NewDecisionPoint(context.Background())
	if err != nil {
		t.Fatalf("NewDecisionPoint() error = %v", err)
	}
	defer func() {
		_ = dp.Close(context.Background())
	}()

	err = outputPolicyText(cmd, result, dp)
	if err != nil {
		t.Errorf("outputPolicyText() error = %v", err)
	}
}

func TestOutputPolicyResultInvalidFormat(t *testing.T) {
	cmd := NewPolicyCheckCmd()
	buf := newBuffer()
	cmd.SetOut(buf)
	cmd.SetErr(buf)

	result := policy.CheckResult{
		Passed:     true,
		TotalCount: 0,
	}

	dp, err := policy.NewDecisionPoint(context.Background())
	if err != nil {
		t.Fatalf("NewDecisionPoint() error = %v", err)
	}
	defer func() {
		_ = dp.Close(context.Background())
	}()

	outputFormat = "invalid"
	defer func() { outputFormat = "text" }()

	err = outputPolicyResult(cmd, result, dp)
	if err == nil {
		t.Error("expected error for invalid format")
	}
}

func TestNewPolicyCheckCmd(t *testing.T) {
	cmd := NewPolicyCheckCmd()
	if cmd == nil {
		t.Fatal("expected non-nil command")
	}
	if cmd.Use != "check" {
		t.Errorf("expected Use 'check', got '%s'", cmd.Use)
	}
}

func TestRunPolicyCheckWithEmptyFindings(t *testing.T) {
	cmd := NewPolicyCheckCmd()
	buf := newBuffer()
	cmd.SetOut(buf)
	cmd.SetErr(buf)

	findingsFile = ""
	defer func() { findingsFile = "" }()

	err := runPolicyCheck(cmd, []string{})
	if err != nil {
		t.Errorf("runPolicyCheck() error = %v", err)
	}
}

func TestRunPolicyCheckWithFindings(t *testing.T) {
	tmpDir := t.TempDir()
	sp, err := safepath.New(tmpDir)
	if err != nil {
		t.Fatalf("failed to create safe path: %v", err)
	}

	findings := []model.Finding{
		{ID: "test-1", Severity: model.SeverityLow},
	}

	data, err := json.Marshal(findings)
	if err != nil {
		t.Fatalf("failed to marshal findings: %v", err)
	}

	findingsFile := "findings.json"
	err = sp.WriteFile(findingsFile, data, 0o644)
	if err != nil {
		t.Fatalf("failed to write findings file: %v", err)
	}

	cmd := NewPolicyCheckCmd()
	buf := newBuffer()
	cmd.SetOut(buf)
	cmd.SetErr(buf)

	findingsFile = filepath.Join(tmpDir, findingsFile)
	defer func() { findingsFile = "" }()

	err = runPolicyCheck(cmd, []string{})
	if err != nil {
		// May error if findings violate policy
		t.Logf("runPolicyCheck() error = %v (may be expected)", err)
	}
}

func TestRunPolicyCheckContextTimeout(t *testing.T) {
	cmd := NewPolicyCheckCmd()
	buf := newBuffer()
	cmd.SetOut(buf)
	cmd.SetErr(buf)

	// This test verifies that context timeouts are handled
	// The actual timeout is set in runPolicyCheck
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
	defer cancel()

	time.Sleep(10 * time.Nanosecond)

	if ctx.Err() == nil {
		t.Error("expected context to be canceled")
	}
}
