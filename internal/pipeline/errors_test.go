package pipeline

import (
	"errors"
	"testing"
)

func TestValidationError(t *testing.T) {
	t.Parallel()

	t.Run("with field", func(t *testing.T) {
		t.Parallel()
		err := NewValidationError("name", "cannot be empty", nil)
		want := "validation error for name: cannot be empty"
		if got := err.Error(); got != want {
			t.Errorf("Error() = %q, want %q", got, want)
		}
	})

	t.Run("without field", func(t *testing.T) {
		t.Parallel()
		err := &ValidationError{Message: "something wrong"}
		want := "validation error: something wrong"
		if got := err.Error(); got != want {
			t.Errorf("Error() = %q, want %q", got, want)
		}
	})

	t.Run("unwrap", func(t *testing.T) {
		t.Parallel()
		underlying := errors.New("underlying error")
		err := NewValidationError("field", "message", underlying)
		if !errors.Is(err, underlying) {
			t.Error("expected to unwrap to underlying error")
		}
	})
}

func TestStageError(t *testing.T) {
	t.Parallel()

	t.Run("with error", func(t *testing.T) {
		t.Parallel()
		underlying := errors.New("connection failed")
		err := NewStageError("scan", "execution failed", underlying)
		want := `stage "scan" failed: execution failed: connection failed`
		if got := err.Error(); got != want {
			t.Errorf("Error() = %q, want %q", got, want)
		}
	})

	t.Run("without error", func(t *testing.T) {
		t.Parallel()
		err := NewStageError("scan", "execution failed", nil)
		want := `stage "scan" failed: execution failed`
		if got := err.Error(); got != want {
			t.Errorf("Error() = %q, want %q", got, want)
		}
	})

	t.Run("unwrap", func(t *testing.T) {
		t.Parallel()
		underlying := errors.New("underlying error")
		err := NewStageError("stage", "message", underlying)
		if !errors.Is(err, underlying) {
			t.Error("expected to unwrap to underlying error")
		}
	})
}

func TestPipelineError(t *testing.T) {
	t.Parallel()

	t.Run("with error", func(t *testing.T) {
		t.Parallel()
		underlying := errors.New("timeout")
		err := NewPipelineError("security-scan", "execution failed", underlying)
		want := `pipeline "security-scan" failed: execution failed: timeout`
		if got := err.Error(); got != want {
			t.Errorf("Error() = %q, want %q", got, want)
		}
	})

	t.Run("without error", func(t *testing.T) {
		t.Parallel()
		err := NewPipelineError("security-scan", "execution failed", nil)
		want := `pipeline "security-scan" failed: execution failed`
		if got := err.Error(); got != want {
			t.Errorf("Error() = %q, want %q", got, want)
		}
	})

	t.Run("add stage error", func(t *testing.T) {
		t.Parallel()
		pErr := NewPipelineError("pipeline", "failed", nil)
		pErr.AddStageError(NewStageError("stage1", "failed", nil))
		pErr.AddStageError(NewStageError("stage2", "failed", nil))

		if len(pErr.StageErrors) != 2 {
			t.Errorf("expected 2 stage errors, got %d", len(pErr.StageErrors))
		}
	})

	t.Run("unwrap", func(t *testing.T) {
		t.Parallel()
		underlying := errors.New("underlying error")
		err := NewPipelineError("pipeline", "message", underlying)
		if !errors.Is(err, underlying) {
			t.Error("expected to unwrap to underlying error")
		}
	})
}

func TestLoadError(t *testing.T) {
	t.Parallel()

	t.Run("with error", func(t *testing.T) {
		t.Parallel()
		underlying := errors.New("permission denied")
		err := NewLoadError("/path/to/file.yaml", "read failed", underlying)
		want := `failed to load pipeline from "/path/to/file.yaml": read failed: permission denied`
		if got := err.Error(); got != want {
			t.Errorf("Error() = %q, want %q", got, want)
		}
	})

	t.Run("without error", func(t *testing.T) {
		t.Parallel()
		err := NewLoadError("/path/to/file.yaml", "read failed", nil)
		want := `failed to load pipeline from "/path/to/file.yaml": read failed`
		if got := err.Error(); got != want {
			t.Errorf("Error() = %q, want %q", got, want)
		}
	})

	t.Run("unwrap", func(t *testing.T) {
		t.Parallel()
		underlying := errors.New("underlying error")
		err := NewLoadError("/path", "message", underlying)
		if !errors.Is(err, underlying) {
			t.Error("expected to unwrap to underlying error")
		}
	})
}

func TestIsValidationError(t *testing.T) {
	t.Parallel()

	t.Run("is validation error", func(t *testing.T) {
		t.Parallel()
		err := NewValidationError("field", "message", nil)
		if !IsValidationError(err) {
			t.Error("expected true for ValidationError")
		}
	})

	t.Run("is not validation error", func(t *testing.T) {
		t.Parallel()
		err := errors.New("regular error")
		if IsValidationError(err) {
			t.Error("expected false for regular error")
		}
	})
}

func TestIsStageError(t *testing.T) {
	t.Parallel()

	t.Run("is stage error", func(t *testing.T) {
		t.Parallel()
		err := NewStageError("stage", "message", nil)
		if !IsStageError(err) {
			t.Error("expected true for StageError")
		}
	})

	t.Run("is not stage error", func(t *testing.T) {
		t.Parallel()
		err := errors.New("regular error")
		if IsStageError(err) {
			t.Error("expected false for regular error")
		}
	})
}

func TestIsPipelineError(t *testing.T) {
	t.Parallel()

	t.Run("is pipeline error", func(t *testing.T) {
		t.Parallel()
		err := NewPipelineError("pipeline", "message", nil)
		if !IsPipelineError(err) {
			t.Error("expected true for PipelineError")
		}
	})

	t.Run("is not pipeline error", func(t *testing.T) {
		t.Parallel()
		err := errors.New("regular error")
		if IsPipelineError(err) {
			t.Error("expected false for regular error")
		}
	})
}

func TestIsLoadError(t *testing.T) {
	t.Parallel()

	t.Run("is load error", func(t *testing.T) {
		t.Parallel()
		err := NewLoadError("/path", "message", nil)
		if !IsLoadError(err) {
			t.Error("expected true for LoadError")
		}
	})

	t.Run("is not load error", func(t *testing.T) {
		t.Parallel()
		err := errors.New("regular error")
		if IsLoadError(err) {
			t.Error("expected false for regular error")
		}
	})
}

func TestIsTimeoutError(t *testing.T) {
	t.Parallel()

	t.Run("stage timeout", func(t *testing.T) {
		t.Parallel()
		if !IsTimeoutError(ErrStageTimeout) {
			t.Error("expected true for ErrStageTimeout")
		}
	})

	t.Run("pipeline timeout", func(t *testing.T) {
		t.Parallel()
		if !IsTimeoutError(ErrPipelineTimeout) {
			t.Error("expected true for ErrPipelineTimeout")
		}
	})

	t.Run("not timeout error", func(t *testing.T) {
		t.Parallel()
		if IsTimeoutError(ErrStageFailed) {
			t.Error("expected false for ErrStageFailed")
		}
	})
}

func TestIsCancellationError(t *testing.T) {
	t.Parallel()

	t.Run("is cancellation error", func(t *testing.T) {
		t.Parallel()
		if !IsCancellationError(ErrPipelineCanceled) {
			t.Error("expected true for ErrPipelineCanceled")
		}
	})

	t.Run("is not cancellation error", func(t *testing.T) {
		t.Parallel()
		if IsCancellationError(ErrStageFailed) {
			t.Error("expected false for ErrStageFailed")
		}
	})
}

func TestSentinelErrors(t *testing.T) {
	t.Parallel()

	// Verify sentinel errors are not nil and have meaningful messages.
	sentinelErrors := []error{
		ErrNilPipeline,
		ErrEmptyPipelineName,
		ErrPipelineNameTooLong,
		ErrNoStages,
		ErrTooManyStages,
		ErrTooManyMetadataEntries,
		ErrNilStage,
		ErrEmptyStageName,
		ErrStageNameTooLong,
		ErrInvalidStageKind,
		ErrInvalidContinueCondition,
		ErrDuplicateStageName,
		ErrTooManyDependencies,
		ErrTooManyConfigEntries,
		ErrConfigKeyTooLong,
		ErrConfigValueTooLong,
		ErrInvalidDependency,
		ErrSelfDependency,
		ErrCircularDependency,
		ErrNilContext,
		ErrEmptyPath,
		ErrFileTooLarge,
		ErrInvalidYAML,
		ErrFileNotFound,
		ErrReadFailed,
		ErrUnmarshalFail,
		ErrExecutorNil,
		ErrStageTimeout,
		ErrPipelineTimeout,
		ErrStageFailed,
		ErrPipelineCanceled,
		ErrNoRunner,
		ErrRunnerFailed,
	}

	for _, err := range sentinelErrors {
		if err == nil {
			t.Error("sentinel error should not be nil")
		}
		if err.Error() == "" {
			t.Error("sentinel error message should not be empty")
		}
	}
}
