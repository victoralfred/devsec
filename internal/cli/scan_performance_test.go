package cli

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/victoralfred/devsec/internal/model"
	"github.com/victoralfred/gowritter/safepath"
)

// TestLargeFindingsList tests performance with large findings lists.
func TestLargeFindingsList(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping performance test in short mode")
	}

	cmd := NewScanSecretsCmd()
	buf := newBuffer()
	cmd.SetOut(buf)
	cmd.SetErr(buf)

	// Create large findings list
	largeFindings := make([]model.Finding, 10000)
	for i := range largeFindings {
		largeFindings[i] = model.Finding{
			ID:          "finding-" + string(rune(i)),
			Title:       "Test Finding " + string(rune(i)),
			Description: "This is a test finding with some description text",
			Severity:    model.SeverityLow,
			Rule:        "test-rule",
			Scanner:     "test-scanner",
			Location: model.Location{
				File:      "test.go",
				StartLine: i,
				EndLine:   i + 1,
			},
		}
	}

	start := time.Now()
	err := outputResults(cmd, largeFindings)
	duration := time.Since(start)

	if err != nil {
		t.Fatalf("outputResults() error = %v", err)
	}

	if duration > 5*time.Second {
		t.Errorf("outputResults() took too long: %v", duration)
	}
}

// TestMemoryUsageWithLargeFindings tests memory usage with large findings.
func TestMemoryUsageWithLargeFindings(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping memory test in short mode")
	}

	// Create very large findings list
	largeFindings := make([]model.Finding, 100000)
	for i := range largeFindings {
		largeFindings[i] = model.Finding{
			ID:          "finding-" + string(rune(i)),
			Title:       "Test Finding",
			Description: "Description",
			Severity:    model.SeverityLow,
		}
	}

	// Test JSON marshaling
	start := time.Now()
	err := outputJSON(nil, largeFindings)
	duration := time.Since(start)

	if err != nil {
		t.Fatalf("outputJSON() error = %v", err)
	}

	if duration > 10*time.Second {
		t.Errorf("outputJSON() took too long: %v", duration)
	}
}

// TestLargeFileHandling tests handling of large files.
func TestLargeFileHandling(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping large file test in short mode")
	}

	tmpDir := t.TempDir()
	sp, err := safepath.New(tmpDir)
	if err != nil {
		t.Fatalf("failed to create safe path: %v", err)
	}

	// Create a file just under the limit
	largeFile := "large.json"
	largeData := make([]byte, 49*1024*1024) // 49MB
	for i := range largeData {
		largeData[i] = byte(i % 256)
	}

	err = sp.WriteFile(largeFile, largeData, 0o644)
	if err != nil {
		t.Fatalf("failed to write large file: %v", err)
	}

	ctx := context.Background()
	start := time.Now()
	findings, err := loadFindings(ctx, filepath.Join(tmpDir, largeFile))
	duration := time.Since(start)

	if err == nil {
		t.Error("expected error for large file")
	}
	if findings != nil {
		t.Error("expected nil findings for large file")
	}

	if duration > 5*time.Second {
		t.Errorf("loadFindings() took too long: %v", duration)
	}
}

// TestTimeoutPerformance tests timeout handling performance.
func TestTimeoutPerformance(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	start := time.Now()
	<-ctx.Done()
	duration := time.Since(start)

	if duration > 200*time.Millisecond {
		t.Errorf("context cancellation took too long: %v", duration)
	}
}

// BenchmarkOutputResults benchmarks outputResults performance.
func BenchmarkOutputResults(b *testing.B) {
	cmd := NewScanSecretsCmd()
	buf := newBuffer()
	cmd.SetOut(buf)
	cmd.SetErr(buf)

	findings := make([]model.Finding, 100)
	for i := range findings {
		findings[i] = model.Finding{
			ID:       "test-" + string(rune(i)),
			Severity: model.SeverityLow,
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = outputResults(cmd, findings)
	}
}

// BenchmarkOutputJSON benchmarks JSON output performance.
func BenchmarkOutputJSON(b *testing.B) {
	findings := make([]model.Finding, 1000)
	for i := range findings {
		findings[i] = model.Finding{
			ID:       "test-" + string(rune(i)),
			Severity: model.SeverityLow,
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = outputJSON(nil, findings)
	}
}

// BenchmarkOutputText benchmarks text output performance.
func BenchmarkOutputText(b *testing.B) {
	cmd := NewScanSecretsCmd()
	buf := newBuffer()
	cmd.SetOut(buf)

	findings := make([]model.Finding, 1000)
	for i := range findings {
		findings[i] = model.Finding{
			ID:       "test-" + string(rune(i)),
			Severity: model.SeverityLow,
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = outputText(cmd, findings)
	}
}
