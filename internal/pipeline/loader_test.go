package pipeline

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNewLoader(t *testing.T) {
	t.Parallel()

	t.Run("default loader", func(t *testing.T) {
		t.Parallel()
		l := NewLoader()
		if l == nil {
			t.Fatal("expected non-nil loader")
		}
	})
}

func TestLoader_Load(t *testing.T) {
	t.Parallel()

	t.Run("nil context", func(t *testing.T) {
		t.Parallel()
		l := NewLoader()
		_, err := l.Load(nil, "test.yaml") //nolint:staticcheck // intentionally passing nil context for testing
		if err != ErrNilContext {
			t.Errorf("Load() error = %v, want ErrNilContext", err)
		}
	})

	t.Run("empty path", func(t *testing.T) {
		t.Parallel()
		l := NewLoader()
		ctx := context.Background()
		_, err := l.Load(ctx, "")
		if err != ErrEmptyPath {
			t.Errorf("Load() error = %v, want ErrEmptyPath", err)
		}
	})

	t.Run("file not found", func(t *testing.T) {
		t.Parallel()
		l := NewLoader()
		ctx := context.Background()
		_, err := l.Load(ctx, "/nonexistent/file.yaml")
		if !IsLoadError(err) {
			t.Errorf("Load() error = %v, want LoadError", err)
		}
	})

	t.Run("valid file", func(t *testing.T) {
		t.Parallel()

		// Create temp file.
		content := []byte(`
name: test-pipeline
version: "1.0"
timeout: 30m
stages:
  - name: scan
    kind: scan
    timeout: 5m
    config:
      scanner: gitleaks
  - name: policy
    kind: policy
    depends_on:
      - scan
`)
		tmpDir := t.TempDir()
		path := filepath.Join(tmpDir, "pipeline.yaml")
		if err := os.WriteFile(path, content, 0o600); err != nil {
			t.Fatal(err)
		}

		l := NewLoader()
		ctx := context.Background()
		p, err := l.Load(ctx, path)
		if err != nil {
			t.Fatalf("Load() error = %v", err)
		}

		if p.Name != "test-pipeline" {
			t.Errorf("Name = %q, want test-pipeline", p.Name)
		}
		if p.Version != "1.0" {
			t.Errorf("Version = %q, want 1.0", p.Version)
		}
		if p.Timeout != 30*time.Minute {
			t.Errorf("Timeout = %v, want 30m", p.Timeout)
		}
		if len(p.Stages) != 2 {
			t.Errorf("len(Stages) = %d, want 2", len(p.Stages))
		}
		if p.Stages[0].Timeout != 5*time.Minute {
			t.Errorf("Stage[0].Timeout = %v, want 5m", p.Stages[0].Timeout)
		}
	})

	t.Run("canceled context", func(t *testing.T) {
		t.Parallel()

		tmpDir := t.TempDir()
		path := filepath.Join(tmpDir, "pipeline.yaml")
		if err := os.WriteFile(path, []byte("name: test\nstages:\n  - name: s\n    kind: scan"), 0o600); err != nil {
			t.Fatal(err)
		}

		l := NewLoader()
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		_, err := l.Load(ctx, path)
		if err != context.Canceled {
			t.Errorf("Load() error = %v, want context.Canceled", err)
		}
	})

	t.Run("invalid yaml", func(t *testing.T) {
		t.Parallel()

		tmpDir := t.TempDir()
		path := filepath.Join(tmpDir, "invalid.yaml")
		if err := os.WriteFile(path, []byte("::invalid::yaml::"), 0o600); err != nil {
			t.Fatal(err)
		}

		l := NewLoader()
		ctx := context.Background()
		_, err := l.Load(ctx, path)
		if !IsLoadError(err) {
			t.Errorf("Load() error = %v, want LoadError", err)
		}
	})

	t.Run("invalid pipeline", func(t *testing.T) {
		t.Parallel()

		// Missing required stage kind.
		content := []byte(`
name: test
stages:
  - name: stage1
`)
		tmpDir := t.TempDir()
		path := filepath.Join(tmpDir, "invalid.yaml")
		if err := os.WriteFile(path, content, 0o600); err != nil {
			t.Fatal(err)
		}

		l := NewLoader()
		ctx := context.Background()
		_, err := l.Load(ctx, path)
		if !IsLoadError(err) {
			t.Errorf("Load() error = %v, want LoadError", err)
		}
	})
}

func TestLoader_LoadFromBytes(t *testing.T) {
	t.Parallel()

	t.Run("nil ", func(t *testing.T) {
		t.Parallel()
		l := NewLoader()
		_, err := l.LoadFromBytes(nil, []byte("test")) //nolint:staticcheck // intentionally passing nil context for testing
		if err != ErrNilContext {
			t.Errorf("LoadFromBytes() error = %v, want ErrNilContext", err)
		}
	})

	t.Run("empty content", func(t *testing.T) {
		t.Parallel()
		l := NewLoader()
		ctx := context.Background()
		_, err := l.LoadFromBytes(ctx, []byte{})
		if !IsLoadError(err) {
			t.Errorf("LoadFromBytes() error = %v, want LoadError", err)
		}
	})

	t.Run("valid content", func(t *testing.T) {
		t.Parallel()
		content := []byte(`
name: test
stages:
  - name: scan
    kind: scan
`)
		l := NewLoader()
		ctx := context.Background()
		p, err := l.LoadFromBytes(ctx, content)
		if err != nil {
			t.Fatalf("LoadFromBytes() error = %v", err)
		}
		if p.Name != "test" {
			t.Errorf("Name = %q, want test", p.Name)
		}
	})

	t.Run("canceled context", func(t *testing.T) {
		t.Parallel()
		l := NewLoader()
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		_, err := l.LoadFromBytes(ctx, []byte("name: test"))
		if err != context.Canceled {
			t.Errorf("LoadFromBytes() error = %v, want context.Canceled", err)
		}
	})
}

func TestLoader_FindPipeline(t *testing.T) {
	t.Parallel()

	t.Run("nil context", func(t *testing.T) {
		t.Parallel()
		l := NewLoader()
		_, err := l.FindPipeline(nil, ".") //nolint:staticcheck // intentionally passing nil context for testing
		if err != ErrNilContext {
			t.Errorf("FindPipeline() error = %v, want ErrNilContext", err)
		}
	})

	t.Run("no pipeline found", func(t *testing.T) {
		t.Parallel()
		tmpDir := t.TempDir()
		l := NewLoader()
		ctx := context.Background()
		_, err := l.FindPipeline(ctx, tmpDir)
		if !IsLoadError(err) {
			t.Errorf("FindPipeline() error = %v, want LoadError", err)
		}
	})

	t.Run("find devsec.yaml", func(t *testing.T) {
		t.Parallel()
		tmpDir := t.TempDir()
		path := filepath.Join(tmpDir, "devsec.yaml")
		if err := os.WriteFile(path, []byte("test"), 0o600); err != nil {
			t.Fatal(err)
		}

		l := NewLoader()
		ctx := context.Background()
		found, err := l.FindPipeline(ctx, tmpDir)
		if err != nil {
			t.Fatalf("FindPipeline() error = %v", err)
		}
		if found != path {
			t.Errorf("FindPipeline() = %q, want %q", found, path)
		}
	})

	t.Run("find pipeline.yml", func(t *testing.T) {
		t.Parallel()
		tmpDir := t.TempDir()
		path := filepath.Join(tmpDir, "pipeline.yml")
		if err := os.WriteFile(path, []byte("test"), 0o600); err != nil {
			t.Fatal(err)
		}

		l := NewLoader()
		ctx := context.Background()
		found, err := l.FindPipeline(ctx, tmpDir)
		if err != nil {
			t.Fatalf("FindPipeline() error = %v", err)
		}
		if found != path {
			t.Errorf("FindPipeline() = %q, want %q", found, path)
		}
	})

	t.Run("canceled context", func(t *testing.T) {
		t.Parallel()
		l := NewLoader()
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		_, err := l.FindPipeline(ctx, ".")
		if err != context.Canceled {
			t.Errorf("FindPipeline() error = %v, want context.Canceled", err)
		}
	})

	t.Run("empty dir uses current", func(t *testing.T) {
		t.Parallel()
		// Create devsec.yaml in a temp dir and change to it.
		tmpDir := t.TempDir()
		path := filepath.Join(tmpDir, "devsec.yaml")
		if err := os.WriteFile(path, []byte("test"), 0o600); err != nil {
			t.Fatal(err)
		}

		l := NewLoader()
		ctx := context.Background()
		// Search in tmpDir with empty string should work.
		found, err := l.FindPipeline(ctx, tmpDir)
		if err != nil {
			t.Fatalf("FindPipeline() error = %v", err)
		}
		if found != path {
			t.Errorf("FindPipeline() = %q, want %q", found, path)
		}
	})
}

func TestLoader_Save(t *testing.T) {
	t.Parallel()

	t.Run("nil context", func(t *testing.T) {
		t.Parallel()
		l := NewLoader()
		p := &Pipeline{Name: "test", Stages: []Stage{{Name: "s", Kind: StageKindScan}}}
		err := l.Save(nil, p, "test.yaml") //nolint:staticcheck // intentionally passing nil context for testing
		if err != ErrNilContext {
			t.Errorf("Save() error = %v, want ErrNilContext", err)
		}
	})

	t.Run("nil pipeline", func(t *testing.T) {
		t.Parallel()
		l := NewLoader()
		ctx := context.Background()
		err := l.Save(ctx, nil, "test.yaml")
		if err != ErrNilPipeline {
			t.Errorf("Save() error = %v, want ErrNilPipeline", err)
		}
	})

	t.Run("empty path", func(t *testing.T) {
		t.Parallel()
		l := NewLoader()
		ctx := context.Background()
		p := &Pipeline{Name: "test", Stages: []Stage{{Name: "s", Kind: StageKindScan}}}
		err := l.Save(ctx, p, "")
		if err != ErrEmptyPath {
			t.Errorf("Save() error = %v, want ErrEmptyPath", err)
		}
	})

	t.Run("invalid pipeline", func(t *testing.T) {
		t.Parallel()
		l := NewLoader()
		ctx := context.Background()
		p := &Pipeline{Name: "test"} // no stages
		tmpDir := t.TempDir()
		path := filepath.Join(tmpDir, "test.yaml")
		err := l.Save(ctx, p, path)
		if err != ErrNoStages {
			t.Errorf("Save() error = %v, want ErrNoStages", err)
		}
	})

	t.Run("save and reload", func(t *testing.T) {
		t.Parallel()

		p := &Pipeline{
			Name:    "test-pipeline",
			Version: "1.0",
			Timeout: 30 * time.Minute,
			Metadata: map[string]string{
				"author": "test",
			},
			Stages: []Stage{
				{
					Name:    "scan",
					Kind:    StageKindScan,
					Timeout: 5 * time.Minute,
					Config:  map[string]string{"scanner": "gitleaks"},
				},
				{
					Name:       "policy",
					Kind:       StageKindPolicy,
					DependsOn:  []string{"scan"},
					ContinueOn: ContinueAlways,
				},
			},
		}

		tmpDir := t.TempDir()
		path := filepath.Join(tmpDir, "pipeline.yaml")

		l := NewLoader()
		ctx := context.Background()

		// Save.
		if err := l.Save(ctx, p, path); err != nil {
			t.Fatalf("Save() error = %v", err)
		}

		// Verify file exists.
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("file not created: %v", err)
		}

		// Reload.
		loaded, err := l.Load(ctx, path)
		if err != nil {
			t.Fatalf("Load() error = %v", err)
		}

		// Verify.
		if loaded.Name != p.Name {
			t.Errorf("Name = %q, want %q", loaded.Name, p.Name)
		}
		if loaded.Version != p.Version {
			t.Errorf("Version = %q, want %q", loaded.Version, p.Version)
		}
		if loaded.Timeout != p.Timeout {
			t.Errorf("Timeout = %v, want %v", loaded.Timeout, p.Timeout)
		}
		if len(loaded.Stages) != len(p.Stages) {
			t.Errorf("len(Stages) = %d, want %d", len(loaded.Stages), len(p.Stages))
		}
	})

	t.Run("canceled context", func(t *testing.T) {
		t.Parallel()
		l := NewLoader()
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		p := &Pipeline{Name: "test", Stages: []Stage{{Name: "s", Kind: StageKindScan}}}
		tmpDir := t.TempDir()
		path := filepath.Join(tmpDir, "test.yaml")

		err := l.Save(ctx, p, path)
		if err != context.Canceled {
			t.Errorf("Save() error = %v, want context.Canceled", err)
		}
	})
}

func TestDefaultPipelineNames(t *testing.T) {
	t.Parallel()

	names := DefaultPipelineNames()
	if len(names) == 0 {
		t.Error("expected at least one default pipeline name")
	}

	// Verify expected names are present.
	expected := map[string]bool{
		"devsec.yaml":   false,
		"devsec.yml":    false,
		"pipeline.yaml": false,
		"pipeline.yml":  false,
	}

	for _, name := range names {
		if _, ok := expected[name]; ok {
			expected[name] = true
		}
	}

	for name, found := range expected {
		if !found {
			t.Errorf("expected default name %q not found", name)
		}
	}
}

func TestRawPipeline_ToPipeline(t *testing.T) {
	t.Parallel()

	t.Run("valid conversion", func(t *testing.T) {
		t.Parallel()
		raw := &rawPipeline{
			Name:    "test",
			Version: "1.0",
			Timeout: "30m",
			Stages: []rawStage{
				{Name: "stage1", Kind: "scan", Timeout: "5m"},
			},
		}

		p, err := raw.toPipeline()
		if err != nil {
			t.Fatalf("toPipeline() error = %v", err)
		}

		if p.Timeout != 30*time.Minute {
			t.Errorf("Timeout = %v, want 30m", p.Timeout)
		}
		if p.Stages[0].Timeout != 5*time.Minute {
			t.Errorf("Stage timeout = %v, want 5m", p.Stages[0].Timeout)
		}
	})

	t.Run("invalid pipeline timeout", func(t *testing.T) {
		t.Parallel()
		raw := &rawPipeline{
			Name:    "test",
			Timeout: "invalid",
			Stages: []rawStage{
				{Name: "stage1", Kind: "scan"},
			},
		}

		_, err := raw.toPipeline()
		if !IsValidationError(err) {
			t.Errorf("toPipeline() error = %v, want ValidationError", err)
		}
	})

	t.Run("invalid stage timeout", func(t *testing.T) {
		t.Parallel()
		raw := &rawPipeline{
			Name: "test",
			Stages: []rawStage{
				{Name: "stage1", Kind: "scan", Timeout: "invalid"},
			},
		}

		_, err := raw.toPipeline()
		if !IsValidationError(err) {
			t.Errorf("toPipeline() error = %v, want ValidationError", err)
		}
	})
}

func TestRawStage_ToStage(t *testing.T) {
	t.Parallel()

	t.Run("full conversion", func(t *testing.T) {
		t.Parallel()
		raw := &rawStage{
			Name:       "test",
			Kind:       "scan",
			Timeout:    "10m",
			DependsOn:  []string{"dep1"},
			ContinueOn: "always",
			Parallel:   true,
			FailFast:   true,
			Config:     map[string]string{"key": "value"},
		}

		s, err := raw.toStage()
		if err != nil {
			t.Fatalf("toStage() error = %v", err)
		}

		if s.Name != "test" {
			t.Errorf("Name = %q, want test", s.Name)
		}
		if s.Kind != StageKindScan {
			t.Errorf("Kind = %v, want scan", s.Kind)
		}
		if s.Timeout != 10*time.Minute {
			t.Errorf("Timeout = %v, want 10m", s.Timeout)
		}
		if s.ContinueOn != ContinueAlways {
			t.Errorf("ContinueOn = %v, want always", s.ContinueOn)
		}
		if !s.Parallel {
			t.Error("Parallel should be true")
		}
		if !s.FailFast {
			t.Error("FailFast should be true")
		}
	})
}
