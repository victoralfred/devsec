package cli

import (
	"context"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/victoralfred/devsec/internal/model"
	"github.com/victoralfred/devsec/internal/scanner/gitleaks"
)

// TestConcurrentOutputResults tests concurrent access to outputResults.
func TestConcurrentOutputResults(t *testing.T) {
	cmd := NewScanSecretsCmd()
	buf := newBuffer()
	cmd.SetOut(buf)
	cmd.SetErr(buf)

	findings := []model.Finding{
		{ID: "test-1", Severity: model.SeverityLow},
		{ID: "test-2", Severity: model.SeverityMedium},
	}

	var wg sync.WaitGroup
	concurrency := 10
	wg.Add(concurrency)

	for i := 0; i < concurrency; i++ {
		go func() {
			defer wg.Done()
			err := outputResults(cmd, findings)
			if err != nil {
				t.Errorf("outputResults() error = %v", err)
			}
		}()
	}

	wg.Wait()
}

// TestConcurrentLoadFindings tests concurrent access to loadFindings.
func TestConcurrentLoadFindings(t *testing.T) {
	ctx := context.Background()
	var wg sync.WaitGroup
	concurrency := 10
	wg.Add(concurrency)

	for i := 0; i < concurrency; i++ {
		go func() {
			defer wg.Done()
			findings, err := loadFindings(ctx, "")
			if err != nil {
				t.Errorf("loadFindings() error = %v", err)
			}
			if findings == nil {
				t.Error("expected non-nil findings")
			}
		}()
	}

	wg.Wait()
}

// TestConcurrentWriteToFile tests concurrent file writes.
func TestConcurrentWriteToFile(t *testing.T) {
	tmpDir := t.TempDir()
	data := []byte("test data")

	var wg sync.WaitGroup
	concurrency := 5
	wg.Add(concurrency)

	for i := 0; i < concurrency; i++ {
		go func(id int) {
			defer wg.Done()
			// Use valid file paths with numeric IDs
			filePath := tmpDir + "/concurrent-test-" + strconv.Itoa(id) + ".txt"
			err := writeToFile(filePath, data)
			if err != nil {
				t.Errorf("writeToFile() error = %v", err)
			}
		}(i)
	}

	wg.Wait()
}

// TestConcurrentScannerOperations tests concurrent scanner operations.
func TestConcurrentScannerOperations(t *testing.T) {
	ctx := context.Background()
	var wg sync.WaitGroup
	concurrency := 5
	wg.Add(concurrency)

	for i := 0; i < concurrency; i++ {
		go func() {
			defer wg.Done()
			// Test that we can create multiple scanners concurrently
			scanner, err := gitleaks.New()
			if err != nil {
				t.Errorf("New() error = %v", err)
				return
			}
			defer func() {
				_ = scanner.Close(ctx)
			}()

			// Small delay to simulate concurrent operations
			time.Sleep(10 * time.Millisecond)
		}()
	}

	wg.Wait()
}
