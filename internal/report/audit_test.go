package report

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/victoralfred/gowritter/safepath"
)

// TestNewAuditTrail tests audit trail creation.
func TestNewAuditTrail(t *testing.T) {
	trail := NewAuditTrail("/path/to/target")
	if trail == nil {
		t.Fatal("expected non-nil audit trail")
	}
	if trail.targetPath != "/path/to/target" {
		t.Errorf("expected target path /path/to/target, got %s", trail.targetPath)
	}
	if trail.startTime.IsZero() {
		t.Error("expected non-zero start time")
	}
}

// TestRecordOperation tests operation recording.
func TestRecordOperation(t *testing.T) {
	trail := NewAuditTrail("/test")
	trail.RecordOperation("scan", "success", "completed without errors")

	ops := trail.GetOperations()
	if len(ops) != 1 {
		t.Fatalf("expected 1 operation, got %d", len(ops))
	}
	if ops[0].Name != "scan" {
		t.Errorf("expected operation name 'scan', got %s", ops[0].Name)
	}
	if ops[0].Status != "success" {
		t.Errorf("expected status 'success', got %s", ops[0].Status)
	}
}

// TestStartOperation tests operation timing.
func TestStartOperation(t *testing.T) {
	trail := NewAuditTrail("/test")
	complete := trail.StartOperation("long-operation")

	time.Sleep(10 * time.Millisecond)
	complete("success", "completed")

	ops := trail.GetOperations()
	if len(ops) != 1 {
		t.Fatalf("expected 1 operation, got %d", len(ops))
	}
	if ops[0].Duration < 10*time.Millisecond {
		t.Errorf("expected duration >= 10ms, got %s", ops[0].Duration)
	}
}

// TestRecordScanner tests scanner information recording.
func TestRecordScanner(t *testing.T) {
	trail := NewAuditTrail("/test")
	info := ScannerInfo{
		Name:      "gitleaks",
		Version:   "8.18.0",
		StartTime: time.Now(),
		EndTime:   time.Now(),
		Status:    "success",
	}
	trail.RecordScanner(info)

	scanners := trail.GetScannerInfo()
	if len(scanners) != 1 {
		t.Fatalf("expected 1 scanner, got %d", len(scanners))
	}
	if scanners["gitleaks"].Version != "8.18.0" {
		t.Errorf("expected version 8.18.0, got %s", scanners["gitleaks"].Version)
	}
}

// TestStartScanner tests scanner timing.
func TestStartScanner(t *testing.T) {
	trail := NewAuditTrail("/test")
	complete := trail.StartScanner("semgrep", "1.0.0")

	time.Sleep(10 * time.Millisecond)
	complete("success")

	scanners := trail.GetScannerInfo()
	if len(scanners) != 1 {
		t.Fatalf("expected 1 scanner, got %d", len(scanners))
	}
	info := scanners["semgrep"]
	if info.EndTime.Sub(info.StartTime) < 10*time.Millisecond {
		t.Error("expected duration >= 10ms")
	}
}

// TestHashContent tests content hashing.
func TestHashContent(t *testing.T) {
	trail := NewAuditTrail("/test")
	content := []byte("test content")

	hash := trail.HashContent("test-file", content)
	if hash == "" {
		t.Error("expected non-empty hash")
	}

	hashes := trail.GetContentHashes()
	if len(hashes) != 1 {
		t.Fatalf("expected 1 hash, got %d", len(hashes))
	}
	if hashes["test-file"] != hash {
		t.Error("hash mismatch in stored hashes")
	}
}

// TestHashFile tests file hashing.
func TestHashFile(t *testing.T) {
	tmpDir := t.TempDir()
	sp, err := safepath.New(tmpDir)
	if err != nil {
		t.Fatalf("failed to create safepath: %v", err)
	}

	testContent := []byte("test file content for hashing")
	writeErr := sp.WriteFile("test.txt", testContent, 0o644)
	if writeErr != nil {
		t.Fatalf("failed to write test file: %v", writeErr)
	}

	trail := NewAuditTrail(tmpDir)
	ctx := context.Background()

	hash, err := trail.HashFile(ctx, filepath.Join(tmpDir, "test.txt"))
	if err != nil {
		t.Fatalf("HashFile() error = %v", err)
	}
	if hash == "" {
		t.Error("expected non-empty hash")
	}

	// Hash should be stored
	hashes := trail.GetContentHashes()
	storedPath := filepath.Join(tmpDir, "test.txt")
	if _, ok := hashes[storedPath]; !ok {
		t.Error("hash not stored for file path")
	}
}

// TestHashFileContextCancellation tests context cancellation.
func TestHashFileContextCancellation(t *testing.T) {
	trail := NewAuditTrail("/test")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := trail.HashFile(ctx, "/some/file.txt")
	if err == nil {
		t.Error("expected error for canceled context")
	}
}

// TestHashReader tests reader hashing.
func TestHashReader(t *testing.T) {
	content := bytes.NewReader([]byte("test content"))
	hash, err := HashReader(content)
	if err != nil {
		t.Fatalf("HashReader() error = %v", err)
	}
	if hash == "" {
		t.Error("expected non-empty hash")
	}

	// Same content should produce same hash
	content2 := bytes.NewReader([]byte("test content"))
	hash2, err := HashReader(content2)
	if err != nil {
		t.Fatalf("HashReader() error = %v", err)
	}
	if hash != hash2 {
		t.Error("expected same hash for same content")
	}
}

// TestComplete tests audit trail completion.
func TestComplete(t *testing.T) {
	trail := NewAuditTrail("/test")
	if !trail.endTime.IsZero() {
		t.Error("expected zero end time before completion")
	}

	time.Sleep(10 * time.Millisecond)
	trail.Complete()

	if trail.endTime.IsZero() {
		t.Error("expected non-zero end time after completion")
	}
}

// TestGenerateAuditReport tests audit report generation.
func TestGenerateAuditReport(t *testing.T) {
	trail := NewAuditTrail("/test/path")
	trail.RecordOperation("init", "success", "")
	trail.RecordScanner(ScannerInfo{Name: "test-scanner", Version: "1.0.0"})
	trail.HashContent("config", []byte("test"))
	trail.Complete()

	report := trail.GenerateReport("1.0.0")
	if report == nil {
		t.Fatal("expected non-nil report")
	}
	if report.TargetPath != "/test/path" {
		t.Errorf("expected target path /test/path, got %s", report.TargetPath)
	}
	if report.Version != "1.0.0" {
		t.Errorf("expected version 1.0.0, got %s", report.Version)
	}
	if len(report.Operations) != 1 {
		t.Errorf("expected 1 operation, got %d", len(report.Operations))
	}
	if len(report.Scanners) != 1 {
		t.Errorf("expected 1 scanner, got %d", len(report.Scanners))
	}
	if len(report.ContentHashes) != 1 {
		t.Errorf("expected 1 content hash, got %d", len(report.ContentHashes))
	}
}

// TestGetDuration tests duration calculation.
func TestGetDuration(t *testing.T) {
	trail := NewAuditTrail("/test")
	time.Sleep(10 * time.Millisecond)

	// Before completion, duration should be calculated from now
	duration := trail.GetDuration()
	if duration < 10*time.Millisecond {
		t.Errorf("expected duration >= 10ms, got %s", duration)
	}

	trail.Complete()

	// After completion, duration should be fixed
	duration2 := trail.GetDuration()
	time.Sleep(10 * time.Millisecond)
	duration3 := trail.GetDuration()

	if duration2 != duration3 {
		t.Error("expected fixed duration after completion")
	}
}

// TestFormatAuditSummary tests summary formatting.
func TestFormatAuditSummary(t *testing.T) {
	trail := NewAuditTrail("/test/path")
	trail.RecordOperation("scan", "success", "completed")
	trail.RecordScanner(ScannerInfo{Name: "gitleaks", Version: "8.18.0", Status: "success"})
	trail.HashContent("config.yaml", []byte("test"))
	trail.Complete()

	summary := trail.FormatAuditSummary()

	if !strings.Contains(summary, "Audit Trail Summary") {
		t.Error("expected header in summary")
	}
	if !strings.Contains(summary, "/test/path") {
		t.Error("expected target path in summary")
	}
	if !strings.Contains(summary, "gitleaks") {
		t.Error("expected scanner name in summary")
	}
	if !strings.Contains(summary, "8.18.0") {
		t.Error("expected scanner version in summary")
	}
	if !strings.Contains(summary, "scan") {
		t.Error("expected operation name in summary")
	}
	if !strings.Contains(summary, "config.yaml") {
		t.Error("expected content hash file in summary")
	}
}

// TestGetHostInfo tests host info collection.
func TestGetHostInfo(t *testing.T) {
	info := getHostInfo()
	if info.OS == "" {
		t.Error("expected non-empty OS")
	}
	if info.Arch == "" {
		t.Error("expected non-empty Arch")
	}
	if info.NumCPU <= 0 {
		t.Error("expected positive NumCPU")
	}
}

// TestMultipleScanners tests recording multiple scanners.
func TestMultipleScanners(t *testing.T) {
	trail := NewAuditTrail("/test")

	scanners := []string{"gitleaks", "semgrep", "trivy", "osv"}
	for _, name := range scanners {
		complete := trail.StartScanner(name, "1.0.0")
		complete("success")
	}

	info := trail.GetScannerInfo()
	if len(info) != 4 {
		t.Errorf("expected 4 scanners, got %d", len(info))
	}
}

// TestMultipleOperations tests recording multiple operations.
func TestMultipleOperations(t *testing.T) {
	trail := NewAuditTrail("/test")

	operations := []string{"init", "scan", "aggregate", "format", "write"}
	for _, name := range operations {
		trail.RecordOperation(name, "success", "")
	}

	ops := trail.GetOperations()
	if len(ops) != 5 {
		t.Errorf("expected 5 operations, got %d", len(ops))
	}
}
