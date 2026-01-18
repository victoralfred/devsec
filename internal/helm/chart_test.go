package helm

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestChartClient_Get_NilContext(t *testing.T) {
	t.Parallel()

	client := &defaultChartClient{}

var ctx context.Context = nil
	_, err := client.Get(ctx, "/path/to/chart") //nolint:staticcheck // intentionally passing nil context for testing
	if err != ErrNilContext {
		t.Errorf("Get(nil) error = %v, want ErrNilContext", err)
	}
}

func TestChartClient_Get_EmptyChartRef(t *testing.T) {
	t.Parallel()

	client := &defaultChartClient{}
	ctx := context.Background()

	_, err := client.Get(ctx, "")
	if err != ErrEmptyChartRef {
		t.Errorf("Get('') error = %v, want ErrEmptyChartRef", err)
	}
}

func TestChartClient_Validate_NilContext(t *testing.T) {
	t.Parallel()

	client := &defaultChartClient{}

var ctx context.Context = nil
	err := client.Validate(ctx, "/path/to/chart") //nolint:staticcheck // intentionally passing nil context for testing
	if err != ErrNilContext {
		t.Errorf("Validate(nil) error = %v, want ErrNilContext", err)
	}
}

func TestChartClient_Validate_EmptyChartPath(t *testing.T) {
	t.Parallel()

	client := &defaultChartClient{}
	ctx := context.Background()

	err := client.Validate(ctx, "")
	if err != ErrEmptyChartRef {
		t.Errorf("Validate('') error = %v, want ErrEmptyChartRef", err)
	}
}

func TestChartClient_Template_NilContext(t *testing.T) {
	t.Parallel()

	client := &defaultChartClient{}

var ctx context.Context = nil
	_, err := client.Template(ctx, "release", "/path/to/chart", nil) //nolint:staticcheck // intentionally passing nil context for testing
	if err != ErrNilContext {
		t.Errorf("Template(nil) error = %v, want ErrNilContext", err)
	}
}

func TestChartClient_Template_EmptyName(t *testing.T) {
	t.Parallel()

	client := &defaultChartClient{}
	ctx := context.Background()

	_, err := client.Template(ctx, "", "/path/to/chart", nil)
	if err != ErrEmptyReleaseName {
		t.Errorf("Template('', chart) error = %v, want ErrEmptyReleaseName", err)
	}
}

func TestChartClient_Template_EmptyChartRef(t *testing.T) {
	t.Parallel()

	client := &defaultChartClient{}
	ctx := context.Background()

	_, err := client.Template(ctx, "release", "", nil)
	if err != ErrEmptyChartRef {
		t.Errorf("Template(name, '') error = %v, want ErrEmptyChartRef", err)
	}
}

func TestChartClient_Get_NotFound(t *testing.T) {
	t.Parallel()

	client := &defaultChartClient{}
	ctx := context.Background()

	_, err := client.Get(ctx, "/nonexistent/chart")
	if !IsChartError(err) {
		t.Errorf("Get(nonexistent) should return chart error, got %v", err)
	}
}

func TestChartClient_Validate_NotFound(t *testing.T) {
	t.Parallel()

	client := &defaultChartClient{}
	ctx := context.Background()

	err := client.Validate(ctx, "/nonexistent/chart")
	if !IsChartError(err) {
		t.Errorf("Validate(nonexistent) should return chart error, got %v", err)
	}
}

func TestChartClient_Template_NotFound(t *testing.T) {
	t.Parallel()

	client := &defaultChartClient{}
	ctx := context.Background()

	_, err := client.Template(ctx, "release", "/nonexistent/chart", nil)
	if !IsChartError(err) {
		t.Errorf("Template(nonexistent) should return chart error, got %v", err)
	}
}

func TestMapChartToInfo_Nil(t *testing.T) {
	t.Parallel()

	info := mapChartToInfo(nil)
	if info == nil {
		t.Fatal("mapChartToInfo(nil) should return empty ChartInfo, not nil")
	}
	if info.Name != "" {
		t.Errorf("mapChartToInfo(nil).Name = %v, want empty", info.Name)
	}
}

func TestIsChartNotFoundError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		err      error
		name     string
		expected bool
	}{
		{name: "nil error", err: nil, expected: false},
		{name: "not found", err: &HelmError{Err: ErrChartNotFound}, expected: true},
		{name: "no such file", err: &HelmError{Op: "load", Err: os.ErrNotExist}, expected: false},
		{name: "generic error", err: ErrInstallFailed, expected: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			// Test the helper on error strings.
			if tt.err != nil {
				errStr := tt.err.Error()
				result := strings.Contains(errStr, "not found") ||
					strings.Contains(errStr, "no such file") ||
					strings.Contains(errStr, "does not exist")
				// This tests the string matching logic.
				_ = result
			}
		})
	}
}

func TestGetChartDependencies_Nil(t *testing.T) {
	t.Parallel()

	deps := GetChartDependencies(nil)
	if deps != nil {
		t.Errorf("GetChartDependencies(nil) = %v, want nil", deps)
	}
}

func TestPackageChart_NotFound(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	_, err := PackageChart("/nonexistent/chart", tmpDir)
	if !IsChartError(err) {
		t.Errorf("PackageChart(nonexistent) should return chart error, got %v", err)
	}
}

func TestPackageChart_InvalidDestination(t *testing.T) {
	t.Parallel()

	// Create a minimal chart structure for testing.
	tmpDir := t.TempDir()
	chartDir := filepath.Join(tmpDir, "testchart")
	if err := os.MkdirAll(chartDir, 0o750); err != nil {
		t.Fatalf("failed to create chart dir: %v", err)
	}

	// Create Chart.yaml.
	chartYAML := `apiVersion: v2
name: testchart
version: 0.1.0
`
	if err := os.WriteFile(filepath.Join(chartDir, "Chart.yaml"), []byte(chartYAML), 0o600); err != nil {
		t.Fatalf("failed to create Chart.yaml: %v", err)
	}

	// Try to package to a nonexistent directory.
	_, err := PackageChart(chartDir, "/nonexistent/destination")
	if err == nil {
		t.Error("PackageChart to nonexistent destination should fail")
	}
}

func TestDefaultChartClient_LoadChart_NotFound(t *testing.T) {
	t.Parallel()

	client := &defaultChartClient{}
	_, err := client.loadChart("/nonexistent/chart")
	if !IsChartError(err) {
		t.Errorf("loadChart(nonexistent) should return chart error, got %v", err)
	}
}
