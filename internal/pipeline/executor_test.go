package pipeline

import (
	"context"
	"testing"
	"time"
)

func TestDefaultExecuteOptions(t *testing.T) {
	t.Parallel()

	opts := DefaultExecuteOptions()

	if opts.WorkDir != "." {
		t.Errorf("expected WorkDir=., got %v", opts.WorkDir)
	}
	if opts.MaxParallel <= 0 {
		t.Error("expected MaxParallel > 0")
	}
	if opts.DryRun {
		t.Error("expected DryRun=false")
	}
	if opts.Verbose {
		t.Error("expected Verbose=false")
	}
}

func TestNewExecutor(t *testing.T) {
	t.Parallel()

	t.Run("default executor", func(t *testing.T) {
		t.Parallel()
		e := NewExecutor()
		if e == nil {
			t.Fatal("expected non-nil executor")
		}
		if e.registry == nil {
			t.Error("expected non-nil registry")
		}
	})

	t.Run("with custom registry", func(t *testing.T) {
		t.Parallel()
		registry := NewRunnerRegistry()
		e := NewExecutor(WithRegistry(registry))
		if e.registry != registry {
			t.Error("expected custom registry")
		}
	})
}

func TestExecutor_Validate(t *testing.T) {
	t.Parallel()

	e := NewExecutor()

	t.Run("valid pipeline", func(t *testing.T) {
		t.Parallel()
		p := Pipeline{
			Name: "test",
			Stages: []Stage{
				{Name: "stage1", Kind: StageKindScan},
			},
		}
		if err := e.Validate(p); err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("invalid pipeline", func(t *testing.T) {
		t.Parallel()
		p := Pipeline{Name: "test"} // no stages
		if err := e.Validate(p); err == nil {
			t.Error("expected validation error")
		}
	})

	t.Run("unknown stage kind", func(t *testing.T) {
		t.Parallel()
		registry := NewRunnerRegistry() // empty registry
		e := NewExecutor(WithRegistry(registry))

		p := Pipeline{
			Name: "test",
			Stages: []Stage{
				{Name: "stage1", Kind: StageKindScan},
			},
		}
		err := e.Validate(p)
		if err == nil {
			t.Error("expected validation error for unknown kind")
		}
		if !IsValidationError(err) {
			t.Errorf("expected ValidationError, got %T", err)
		}
	})
}

func TestExecutor_Execute(t *testing.T) {
	t.Parallel()

	e := NewExecutor()

	t.Run("nil context", func(t *testing.T) {
		t.Parallel()
		p := Pipeline{
			Name: "test",
			Stages: []Stage{
				{Name: "stage1", Kind: StageKindScan, Config: map[string]string{"scanner": "gitleaks"}},
			},
		}
var ctx context.Context = nil
		_, err := e.Execute(ctx, p, DefaultExecuteOptions()) //nolint:staticcheck // intentionally passing nil context for testing
		if err != ErrNilContext {
			t.Errorf("expected ErrNilContext, got %v", err)
		}
	})

	t.Run("simple pipeline", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		// Use report and compliance stages which don't require external binaries.
		p := Pipeline{
			Name: "test",
			Stages: []Stage{
				{Name: "report", Kind: StageKindReport, Config: map[string]string{"format": "json"}},
				{Name: "compliance", Kind: StageKindCompliance, Config: map[string]string{"frameworks": "soc2"}, DependsOn: []string{"report"}},
			},
		}
		result, err := e.Execute(ctx, p, DefaultExecuteOptions())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Name != "test" {
			t.Errorf("expected name test, got %v", result.Name)
		}
		if len(result.Stages) != 2 {
			t.Errorf("expected 2 stages, got %d", len(result.Stages))
		}
		if result.Status != StageStatusSuccess {
			t.Errorf("expected success status, got %v", result.Status)
		}
	})

	t.Run("parallel pipeline", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		// Use report and compliance stages which don't require external binaries.
		p := Pipeline{
			Name:     "test",
			Parallel: true,
			Stages: []Stage{
				{Name: "report1", Kind: StageKindReport, Config: map[string]string{"format": "json"}},
				{Name: "report2", Kind: StageKindReport, Config: map[string]string{"format": "sarif"}},
				{Name: "compliance", Kind: StageKindCompliance, Config: map[string]string{"frameworks": "soc2"}, DependsOn: []string{"report1", "report2"}},
			},
		}
		opts := DefaultExecuteOptions()
		opts.MaxParallel = 2

		result, err := e.Execute(ctx, p, opts)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(result.Stages) != 3 {
			t.Errorf("expected 3 stages, got %d", len(result.Stages))
		}
		if result.Status != StageStatusSuccess {
			t.Errorf("expected success status, got %v", result.Status)
		}
	})

	t.Run("dry run", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		p := Pipeline{
			Name: "test",
			Stages: []Stage{
				{Name: "scan", Kind: StageKindScan, Config: map[string]string{"scanner": "gitleaks"}},
			},
		}
		opts := DefaultExecuteOptions()
		opts.DryRun = true

		result, err := e.Execute(ctx, p, opts)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(result.Stages) != 1 {
			t.Fatalf("expected 1 stage, got %d", len(result.Stages))
		}
		if result.Stages[0].Status != StageStatusSkipped {
			t.Errorf("expected skipped status in dry run, got %v", result.Stages[0].Status)
		}
	})

	t.Run("canceled context", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		p := Pipeline{
			Name: "test",
			Stages: []Stage{
				{Name: "scan", Kind: StageKindScan, Config: map[string]string{"scanner": "gitleaks"}},
			},
		}
		result, err := e.Execute(ctx, p, DefaultExecuteOptions())
		if err != ErrPipelineCanceled {
			t.Errorf("expected ErrPipelineCanceled, got %v", err)
		}
		if result.Status != StageStatusFailed {
			t.Errorf("expected failed status, got %v", result.Status)
		}
	})

	t.Run("pipeline with timeout", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		p := Pipeline{
			Name:    "test",
			Timeout: 5 * time.Second,
			Stages: []Stage{
				{Name: "scan", Kind: StageKindScan, Config: map[string]string{"scanner": "gitleaks"}},
			},
		}
		result, err := e.Execute(ctx, p, DefaultExecuteOptions())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Duration <= 0 {
			t.Error("expected positive duration")
		}
	})

	t.Run("stage failure with fail-fast", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		p := Pipeline{
			Name:     "test",
			FailFast: true,
			Stages: []Stage{
				// This will fail because scanner is not specified.
				{Name: "scan", Kind: StageKindScan, Config: map[string]string{}},
				{Name: "policy", Kind: StageKindPolicy, DependsOn: []string{"scan"}},
			},
		}
		result, err := e.Execute(ctx, p, DefaultExecuteOptions())
		if err == nil {
			t.Error("expected error for failed stage")
		}
		if result.Status != StageStatusFailed {
			t.Errorf("expected failed status, got %v", result.Status)
		}
	})
}

func TestExecutor_TopologicalSort(t *testing.T) {
	t.Parallel()

	e := NewExecutor()

	t.Run("no dependencies", func(t *testing.T) {
		t.Parallel()
		stages := []Stage{
			{Name: "a"},
			{Name: "b"},
			{Name: "c"},
		}
		order, err := e.topologicalSort(stages)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(order) != 3 {
			t.Errorf("expected 3 stages, got %d", len(order))
		}
	})

	t.Run("linear dependencies", func(t *testing.T) {
		t.Parallel()
		stages := []Stage{
			{Name: "c", DependsOn: []string{"b"}},
			{Name: "b", DependsOn: []string{"a"}},
			{Name: "a"},
		}
		order, err := e.topologicalSort(stages)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(order) != 3 {
			t.Errorf("expected 3 stages, got %d", len(order))
		}
		// a should come before b, b before c.
		aIdx, bIdx, cIdx := -1, -1, -1
		for i, name := range order {
			switch name {
			case "a":
				aIdx = i
			case "b":
				bIdx = i
			case "c":
				cIdx = i
			}
		}
		if aIdx > bIdx || bIdx > cIdx {
			t.Errorf("invalid order: a=%d, b=%d, c=%d", aIdx, bIdx, cIdx)
		}
	})

	t.Run("diamond dependencies", func(t *testing.T) {
		t.Parallel()
		stages := []Stage{
			{Name: "d", DependsOn: []string{"b", "c"}},
			{Name: "b", DependsOn: []string{"a"}},
			{Name: "c", DependsOn: []string{"a"}},
			{Name: "a"},
		}
		order, err := e.topologicalSort(stages)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(order) != 4 {
			t.Errorf("expected 4 stages, got %d", len(order))
		}
	})

	t.Run("cycle detection", func(t *testing.T) {
		t.Parallel()
		stages := []Stage{
			{Name: "a", DependsOn: []string{"b"}},
			{Name: "b", DependsOn: []string{"a"}},
		}
		_, err := e.topologicalSort(stages)
		if err != ErrCircularDependency {
			t.Errorf("expected ErrCircularDependency, got %v", err)
		}
	})
}

func TestExecutor_ShouldContinue(t *testing.T) {
	t.Parallel()

	e := NewExecutor()

	tests := []struct {
		cond     ContinueCondition
		status   StageStatus
		expected bool
	}{
		{ContinueAlways, StageStatusSuccess, true},
		{ContinueAlways, StageStatusFailed, true},
		{ContinueAlways, StageStatusSkipped, true},
		{ContinueOnSuccess, StageStatusSuccess, true},
		{ContinueOnSuccess, StageStatusFailed, false},
		{ContinueOnFailure, StageStatusFailed, true},
		{ContinueOnFailure, StageStatusSuccess, false},
		{"", StageStatusSuccess, true}, // empty defaults to success
		{"", StageStatusFailed, false},
	}

	for _, tt := range tests {
		result := e.shouldContinue(tt.cond, tt.status)
		if result != tt.expected {
			t.Errorf("shouldContinue(%v, %v) = %v, want %v",
				tt.cond, tt.status, result, tt.expected)
		}
	}
}

func TestExecutor_DetermineOverallStatus(t *testing.T) {
	t.Parallel()

	e := NewExecutor()

	t.Run("all success", func(t *testing.T) {
		t.Parallel()
		stages := []StageResult{
			{Status: StageStatusSuccess},
			{Status: StageStatusSuccess},
		}
		status := e.determineOverallStatus(stages)
		if status != StageStatusSuccess {
			t.Errorf("expected success, got %v", status)
		}
	})

	t.Run("has failure", func(t *testing.T) {
		t.Parallel()
		stages := []StageResult{
			{Status: StageStatusSuccess},
			{Status: StageStatusFailed},
		}
		status := e.determineOverallStatus(stages)
		if status != StageStatusFailed {
			t.Errorf("expected failed, got %v", status)
		}
	})

	t.Run("has canceled", func(t *testing.T) {
		t.Parallel()
		stages := []StageResult{
			{Status: StageStatusSuccess},
			{Status: StageStatusCanceled},
		}
		status := e.determineOverallStatus(stages)
		if status != StageStatusCanceled {
			t.Errorf("expected canceled, got %v", status)
		}
	})

	t.Run("canceled takes precedence over failure", func(t *testing.T) {
		t.Parallel()
		stages := []StageResult{
			{Status: StageStatusFailed},
			{Status: StageStatusCanceled},
		}
		status := e.determineOverallStatus(stages)
		if status != StageStatusCanceled {
			t.Errorf("expected canceled, got %v", status)
		}
	})

	t.Run("empty stages", func(t *testing.T) {
		t.Parallel()
		stages := []StageResult{}
		status := e.determineOverallStatus(stages)
		if status != StageStatusSuccess {
			t.Errorf("expected success for empty, got %v", status)
		}
	})
}
