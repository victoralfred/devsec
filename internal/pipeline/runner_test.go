package pipeline

import (
	"context"
	"testing"
	"time"
)

func TestRunnerRegistry(t *testing.T) {
	t.Parallel()

	t.Run("new registry", func(t *testing.T) {
		t.Parallel()
		r := NewRunnerRegistry()
		if r == nil {
			t.Fatal("expected non-nil registry")
		}
		if len(r.Kinds()) != 0 {
			t.Error("expected empty registry")
		}
	})

	t.Run("register runner", func(t *testing.T) {
		t.Parallel()
		r := NewRunnerRegistry()
		r.Register(NewScanRunner())

		if !r.Has(StageKindScan) {
			t.Error("expected scan runner to be registered")
		}
	})

	t.Run("register nil runner", func(t *testing.T) {
		t.Parallel()
		r := NewRunnerRegistry()
		r.Register(nil)

		if len(r.Kinds()) != 0 {
			t.Error("expected empty registry after registering nil")
		}
	})

	t.Run("get runner", func(t *testing.T) {
		t.Parallel()
		r := NewRunnerRegistry()
		r.Register(NewScanRunner())

		runner, ok := r.Get(StageKindScan)
		if !ok {
			t.Fatal("expected to find runner")
		}
		if runner.Kind() != StageKindScan {
			t.Errorf("expected scan kind, got %v", runner.Kind())
		}
	})

	t.Run("get non-existent runner", func(t *testing.T) {
		t.Parallel()
		r := NewRunnerRegistry()

		_, ok := r.Get(StageKindScan)
		if ok {
			t.Error("expected runner not found")
		}
	})

	t.Run("has runner", func(t *testing.T) {
		t.Parallel()
		r := NewRunnerRegistry()
		r.Register(NewScanRunner())

		if !r.Has(StageKindScan) {
			t.Error("expected has to return true")
		}
		if r.Has(StageKindPolicy) {
			t.Error("expected has to return false for unregistered runner")
		}
	})

	t.Run("kinds", func(t *testing.T) {
		t.Parallel()
		r := NewRunnerRegistry()
		r.Register(NewScanRunner())
		r.Register(NewPolicyRunner())

		kinds := r.Kinds()
		if len(kinds) != 2 {
			t.Errorf("expected 2 kinds, got %d", len(kinds))
		}
	})
}

func TestDefaultRegistry(t *testing.T) {
	t.Parallel()

	r := DefaultRegistry()
	if r == nil {
		t.Fatal("expected non-nil registry")
	}

	// Check all default runners are registered.
	expectedKinds := []StageKind{
		StageKindScan,
		StageKindPolicy,
		StageKindReport,
		StageKindCompliance,
		StageKindCustom,
	}

	for _, kind := range expectedKinds {
		if !r.Has(kind) {
			t.Errorf("expected %v runner to be registered", kind)
		}
	}
}

func TestScanRunner(t *testing.T) {
	t.Parallel()

	runner := NewScanRunner()

	t.Run("kind", func(t *testing.T) {
		t.Parallel()
		if runner.Kind() != StageKindScan {
			t.Errorf("expected scan kind, got %v", runner.Kind())
		}
	})

	t.Run("run missing scanner", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		stage := Stage{
			Name:   "test-scan",
			Kind:   StageKindScan,
			Config: map[string]string{},
		}
		input := RunnerInput{}

		result, err := runner.Run(ctx, stage, input)
		if err == nil {
			t.Error("expected error for missing scanner")
		}
		if result.Status != StageStatusFailed {
			t.Errorf("expected failed status, got %v", result.Status)
		}
	})

	t.Run("run unknown scanner", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		stage := Stage{
			Name: "test-scan",
			Kind: StageKindScan,
			Config: map[string]string{
				"scanner": "unknown-scanner",
				"path":    t.TempDir(),
			},
		}
		input := RunnerInput{WorkDir: t.TempDir()}

		result, err := runner.Run(ctx, stage, input)
		if err == nil {
			t.Error("expected error for unknown scanner")
		}
		if result.Status != StageStatusFailed {
			t.Errorf("expected failed status, got %v", result.Status)
		}
	})

	t.Run("run canceled context", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		stage := Stage{
			Name: "test-scan",
			Kind: StageKindScan,
			Config: map[string]string{
				"scanner": "gitleaks",
			},
		}
		input := RunnerInput{}

		result, err := runner.Run(ctx, stage, input)
		if err != context.Canceled {
			t.Errorf("expected context.Canceled, got %v", err)
		}
		if result.Status != StageStatusCanceled {
			t.Errorf("expected canceled status, got %v", result.Status)
		}
	})
}

func TestPolicyRunner(t *testing.T) {
	t.Parallel()

	runner := NewPolicyRunner()

	t.Run("kind", func(t *testing.T) {
		t.Parallel()
		if runner.Kind() != StageKindPolicy {
			t.Errorf("expected policy kind, got %v", runner.Kind())
		}
	})

	t.Run("run missing policy dir", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		stage := Stage{
			Name: "test-policy",
			Kind: StageKindPolicy,
			Config: map[string]string{
				"policy_dir": "/nonexistent/path",
				"fail_on":    "critical",
			},
		}
		input := RunnerInput{WorkDir: t.TempDir()}

		result, err := runner.Run(ctx, stage, input)
		if err == nil {
			t.Error("expected error for missing policy directory")
		}
		if result.Status != StageStatusFailed {
			t.Errorf("expected failed status, got %v", result.Status)
		}
	})

	t.Run("run empty policy dir", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		tmpDir := t.TempDir()

		stage := Stage{
			Name: "test-policy",
			Kind: StageKindPolicy,
			Config: map[string]string{
				"policy_dir": tmpDir,
				"fail_on":    "high",
			},
		}
		input := RunnerInput{WorkDir: tmpDir}

		result, err := runner.Run(ctx, stage, input)
		if err == nil {
			t.Error("expected error for empty policy directory")
		}
		if result.Status != StageStatusFailed {
			t.Errorf("expected failed status, got %v", result.Status)
		}
	})

	t.Run("run canceled context", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		stage := Stage{
			Name: "test-policy",
			Kind: StageKindPolicy,
			Config: map[string]string{
				"policy_dir": "policies",
			},
		}
		input := RunnerInput{}

		result, err := runner.Run(ctx, stage, input)
		if err != context.Canceled {
			t.Errorf("expected context.Canceled, got %v", err)
		}
		if result.Status != StageStatusCanceled {
			t.Errorf("expected canceled status, got %v", result.Status)
		}
	})
}

func TestReportRunner(t *testing.T) {
	t.Parallel()

	runner := NewReportRunner()

	t.Run("kind", func(t *testing.T) {
		t.Parallel()
		if runner.Kind() != StageKindReport {
			t.Errorf("expected report kind, got %v", runner.Kind())
		}
	})

	t.Run("run success", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		stage := Stage{
			Name: "test-report",
			Kind: StageKindReport,
			Config: map[string]string{
				"format": "markdown",
				"output": "report.md",
			},
		}
		input := RunnerInput{}

		result, err := runner.Run(ctx, stage, input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != StageStatusSuccess {
			t.Errorf("expected success status, got %v", result.Status)
		}
		if result.Artifacts["format"] != "markdown" {
			t.Error("expected markdown format in artifacts")
		}
	})
}

func TestComplianceRunner(t *testing.T) {
	t.Parallel()

	runner := NewComplianceRunner()

	t.Run("kind", func(t *testing.T) {
		t.Parallel()
		if runner.Kind() != StageKindCompliance {
			t.Errorf("expected compliance kind, got %v", runner.Kind())
		}
	})

	t.Run("run success", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		stage := Stage{
			Name: "test-compliance",
			Kind: StageKindCompliance,
			Config: map[string]string{
				"frameworks": "soc2,gdpr",
			},
		}
		input := RunnerInput{}

		result, err := runner.Run(ctx, stage, input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != StageStatusSuccess {
			t.Errorf("expected success status, got %v", result.Status)
		}
	})
}

func TestCustomRunner(t *testing.T) {
	t.Parallel()

	runner := NewCustomRunner()

	t.Run("kind", func(t *testing.T) {
		t.Parallel()
		if runner.Kind() != StageKindCustom {
			t.Errorf("expected custom kind, got %v", runner.Kind())
		}
	})

	t.Run("run success with absolute path", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		tmpDir := t.TempDir()
		stage := Stage{
			Name: "test-custom",
			Kind: StageKindCustom,
			Config: map[string]string{
				"command": "/bin/echo hello",
			},
		}
		input := RunnerInput{WorkDir: tmpDir}

		result, err := runner.Run(ctx, stage, input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != StageStatusSuccess {
			t.Errorf("expected success status, got %v", result.Status)
		}
		// Verify stdout was captured.
		if stdout, ok := result.Artifacts["stdout"].(string); !ok || stdout == "" {
			t.Error("expected stdout in artifacts")
		}
	})

	t.Run("run missing command", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		stage := Stage{
			Name:   "test-custom",
			Kind:   StageKindCustom,
			Config: map[string]string{},
		}
		input := RunnerInput{}

		result, err := runner.Run(ctx, stage, input)
		if err == nil {
			t.Error("expected error for missing command")
		}
		if result.Status != StageStatusFailed {
			t.Errorf("expected failed status, got %v", result.Status)
		}
	})

	t.Run("run canceled context", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		stage := Stage{
			Name: "test-custom",
			Kind: StageKindCustom,
			Config: map[string]string{
				"command": "/bin/echo test",
			},
		}
		input := RunnerInput{}

		result, err := runner.Run(ctx, stage, input)
		if err != context.Canceled {
			t.Errorf("expected context.Canceled, got %v", err)
		}
		if result.Status != StageStatusCanceled {
			t.Errorf("expected canceled status, got %v", result.Status)
		}
	})
}

func TestCreateResult(t *testing.T) {
	t.Parallel()

	startTime := time.Now().Add(-1 * time.Second)

	t.Run("success result", func(t *testing.T) {
		t.Parallel()
		result := createResult("test", StageStatusSuccess, startTime, nil)

		if result.Name != "test" {
			t.Errorf("expected name test, got %v", result.Name)
		}
		if result.Status != StageStatusSuccess {
			t.Errorf("expected success status, got %v", result.Status)
		}
		if result.Error != "" {
			t.Error("expected no error")
		}
		if result.Duration < time.Second {
			t.Error("expected duration >= 1 second")
		}
	})

	t.Run("error result", func(t *testing.T) {
		t.Parallel()
		err := NewStageError("test", "failed", nil)
		result := createResult("test", StageStatusFailed, startTime, err)

		if result.Error == "" {
			t.Error("expected error message")
		}
		if result.Status != StageStatusFailed {
			t.Errorf("expected failed status, got %v", result.Status)
		}
	})
}
