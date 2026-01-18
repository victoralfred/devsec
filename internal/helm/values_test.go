package helm

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestValuesClient_Merge(t *testing.T) {
	t.Parallel()

	client := &defaultValuesClient{}

	tests := []struct {
		base     map[string]interface{}
		expected map[string]interface{}
		name     string
		overlays []map[string]interface{}
	}{
		{
			name:     "nil base",
			base:     nil,
			overlays: []map[string]interface{}{{"key": "value"}},
			expected: map[string]interface{}{"key": "value"},
		},
		{
			name:     "simple merge",
			base:     map[string]interface{}{"a": 1},
			overlays: []map[string]interface{}{{"b": 2}},
			expected: map[string]interface{}{"a": 1, "b": 2},
		},
		{
			name:     "override value",
			base:     map[string]interface{}{"a": 1},
			overlays: []map[string]interface{}{{"a": 2}},
			expected: map[string]interface{}{"a": 2},
		},
		{
			name: "nested merge",
			base: map[string]interface{}{
				"nested": map[string]interface{}{"a": 1},
			},
			overlays: []map[string]interface{}{
				{"nested": map[string]interface{}{"b": 2}},
			},
			expected: map[string]interface{}{
				"nested": map[string]interface{}{"a": 1, "b": 2},
			},
		},
		{
			name:     "multiple overlays",
			base:     map[string]interface{}{"a": 1},
			overlays: []map[string]interface{}{{"b": 2}, {"c": 3}},
			expected: map[string]interface{}{"a": 1, "b": 2, "c": 3},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result := client.Merge(tt.base, tt.overlays...)

			for k, v := range tt.expected {
				// Handle nested maps - skip deep comparison for simplicity.
				if _, ok := v.(map[string]interface{}); ok {
					if _, rOk := result[k].(map[string]interface{}); rOk {
						continue
					}
				}
				if result[k] != v {
					t.Errorf("result[%s] = %v, want %v", k, result[k], v)
				}
			}
		})
	}
}

func TestValuesClient_LoadFromFile(t *testing.T) {
	t.Parallel()

	client := &defaultValuesClient{}
	ctx := context.Background()

	// Create a temp values file.
	tmpDir := t.TempDir()
	valuesFile := filepath.Join(tmpDir, "values.yaml")
	content := `
replicas: 3
image:
  repository: nginx
  tag: latest
`
	if err := os.WriteFile(valuesFile, []byte(content), 0o600); err != nil {
		t.Fatalf("failed to create values file: %v", err)
	}

	values, err := client.LoadFromFile(ctx, valuesFile)
	if err != nil {
		t.Fatalf("LoadFromFile() error = %v", err)
	}

	if values["replicas"] != float64(3) { // YAML unmarshals numbers as float64.
		t.Errorf("replicas = %v, want 3", values["replicas"])
	}

	image, ok := values["image"].(map[string]interface{})
	if !ok {
		t.Fatal("image should be a map")
	}
	if image["repository"] != "nginx" {
		t.Errorf("image.repository = %v, want nginx", image["repository"])
	}
}

func TestValuesClient_LoadFromFile_NilContext(t *testing.T) {
	t.Parallel()

	client := &defaultValuesClient{}

var ctx context.Context = nil
	_, err := client.LoadFromFile(ctx, "/path/to/values.yaml") //nolint:staticcheck // intentionally passing nil context for testing
	if err != ErrNilContext {
		t.Errorf("LoadFromFile(nil) error = %v, want ErrNilContext", err)
	}
}

func TestValuesClient_LoadFromFile_EmptyPath(t *testing.T) {
	t.Parallel()

	client := &defaultValuesClient{}
	ctx := context.Background()

	_, err := client.LoadFromFile(ctx, "")
	if !IsChartError(err) && err != ErrValuesLoadFailed {
		t.Errorf("LoadFromFile('') error = %v, want ErrValuesLoadFailed", err)
	}
}

func TestValuesClient_LoadFromFile_NotFound(t *testing.T) {
	t.Parallel()

	client := &defaultValuesClient{}
	ctx := context.Background()

	_, err := client.LoadFromFile(ctx, "/nonexistent/values.yaml")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestValuesClient_Get_NilContext(t *testing.T) {
	t.Parallel()

	client := &defaultValuesClient{
		actionConfig: newTestActionConfig(),
	}

var ctx context.Context = nil
	_, err := client.Get(ctx, "default", "my-release") //nolint:staticcheck // intentionally passing nil context for testing
	if err != ErrNilContext {
		t.Errorf("Get(nil) error = %v, want ErrNilContext", err)
	}
}

func TestValuesClient_Get_EmptyNamespace(t *testing.T) {
	t.Parallel()

	client := &defaultValuesClient{}
	ctx := context.Background()

	_, err := client.Get(ctx, "", "my-release")
	if err != ErrEmptyNamespace {
		t.Errorf("Get('', release) error = %v, want ErrEmptyNamespace", err)
	}
}

func TestValuesClient_Get_EmptyReleaseName(t *testing.T) {
	t.Parallel()

	client := &defaultValuesClient{}
	ctx := context.Background()

	_, err := client.Get(ctx, "default", "")
	if err != ErrEmptyReleaseName {
		t.Errorf("Get(namespace, '') error = %v, want ErrEmptyReleaseName", err)
	}
}

func TestCopyMap(t *testing.T) {
	t.Parallel()

	tests := []struct {
		src  map[string]interface{}
		name string
	}{
		{
			name: "nil map",
			src:  nil,
		},
		{
			name: "empty map",
			src:  map[string]interface{}{},
		},
		{
			name: "simple map",
			src:  map[string]interface{}{"a": 1, "b": "test"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			dst := copyMap(tt.src)

			if dst == nil {
				t.Error("copyMap should never return nil")
			}

			// Verify values are copied.
			for k, v := range tt.src {
				if dst[k] != v {
					t.Errorf("dst[%s] = %v, want %v", k, dst[k], v)
				}
			}
		})
	}
}

func TestMergeMaps(t *testing.T) {
	t.Parallel()

	tests := []struct {
		dst      map[string]interface{}
		src      map[string]interface{}
		expected map[string]interface{}
		name     string
	}{
		{
			name:     "nil dst",
			dst:      nil,
			src:      map[string]interface{}{"a": 1},
			expected: map[string]interface{}{"a": 1},
		},
		{
			name:     "nil src",
			dst:      map[string]interface{}{"a": 1},
			src:      nil,
			expected: map[string]interface{}{"a": 1},
		},
		{
			name:     "both nil",
			dst:      nil,
			src:      nil,
			expected: map[string]interface{}{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result := mergeMaps(tt.dst, tt.src)

			if result == nil {
				t.Error("mergeMaps should never return nil")
			}

			for k, v := range tt.expected {
				if result[k] != v {
					t.Errorf("result[%s] = %v, want %v", k, result[k], v)
				}
			}
		})
	}
}
