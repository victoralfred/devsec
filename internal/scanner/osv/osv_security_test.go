package osv

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestOSVScannerSecurity tests security aspects of OSV scanner.
func TestOSVScannerSecurity(t *testing.T) {
	tests := []struct {
		name        string
		path        string
		expectError bool
	}{
		{"valid path", "/tmp", false},
		{"path traversal", "../../../etc/passwd", true},
		{"empty path", "", true},
		{"relative path", ".", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scanner := New()
			ctx := context.Background()

			_, err := scanner.Scan(ctx, tt.path)
			if (err != nil) != tt.expectError {
				t.Errorf("Scan() error = %v, wantErr %v", err, tt.expectError)
			}
		})
	}
}

// TestOSVAPISecurity tests API security.
func TestOSVAPISecurity(t *testing.T) {
	// Test with malicious server response
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Return extremely large response
		largeData := make([]byte, 100*1024*1024) // 100MB
		_, _ = w.Write(largeData)
	}))
	defer server.Close()

	scanner := New(WithAPIURL(server.URL))
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	deps := []Dependency{
		{Name: "test", Version: "1.0.0", Ecosystem: "npm"},
	}

	_, err := scanner.queryBatch(ctx, deps)
	// Should handle large response or timeout
	if err == nil {
		t.Log("queryBatch handled large response")
	}
}

// TestOSVInputValidation tests input validation.
func TestOSVInputValidation(t *testing.T) {
	scanner := New()
	ctx := context.Background()

	// Test with empty dependencies
	findings, err := scanner.queryVulnerabilities(ctx, []Dependency{})
	if err != nil {
		t.Errorf("queryVulnerabilities() error = %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

// TestOSVContextCancellation tests context cancellation.
func TestOSVContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Delay response to test cancellation
		time.Sleep(2 * time.Second)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	scanner := New(WithAPIURL(server.URL))
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	deps := []Dependency{
		{Name: "test", Version: "1.0.0", Ecosystem: "npm"},
	}

	_, err := scanner.queryBatch(ctx, deps)
	if err == nil {
		t.Error("expected error for canceled context")
	}
}

// TestOSVTimeoutHandling tests timeout handling.
func TestOSVTimeoutHandling(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	scanner := New(
		WithAPIURL(server.URL),
		WithTimeout(100*time.Millisecond),
	)

	ctx := context.Background()
	deps := []Dependency{
		{Name: "test", Version: "1.0.0", Ecosystem: "npm"},
	}

	_, err := scanner.queryBatch(ctx, deps)
	if err == nil {
		t.Error("expected error for timeout")
	}
}
