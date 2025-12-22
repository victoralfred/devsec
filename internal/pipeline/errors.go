// Package pipeline provides pipeline orchestration for security scans.
package pipeline

import (
	"errors"
	"fmt"
)

// Sentinel errors for pipeline validation.
var (
	// Pipeline errors.
	ErrNilPipeline            = errors.New("pipeline cannot be nil")
	ErrEmptyPipelineName      = errors.New("pipeline name cannot be empty")
	ErrPipelineNameTooLong    = errors.New("pipeline name exceeds maximum length")
	ErrNoStages               = errors.New("pipeline must have at least one stage")
	ErrTooManyStages          = errors.New("pipeline exceeds maximum number of stages")
	ErrTooManyMetadataEntries = errors.New("pipeline exceeds maximum metadata entries")

	// Stage errors.
	ErrNilStage                 = errors.New("stage cannot be nil")
	ErrEmptyStageName           = errors.New("stage name cannot be empty")
	ErrStageNameTooLong         = errors.New("stage name exceeds maximum length")
	ErrInvalidStageKind         = errors.New("invalid stage kind")
	ErrInvalidContinueCondition = errors.New("invalid continue condition")
	ErrDuplicateStageName       = errors.New("duplicate stage name")
	ErrTooManyDependencies      = errors.New("stage exceeds maximum dependencies")
	ErrTooManyConfigEntries     = errors.New("stage exceeds maximum config entries")
	ErrConfigKeyTooLong         = errors.New("config key exceeds maximum length")
	ErrConfigValueTooLong       = errors.New("config value exceeds maximum length")

	// Dependency errors.
	ErrInvalidDependency  = errors.New("dependency references non-existent stage")
	ErrSelfDependency     = errors.New("stage cannot depend on itself")
	ErrCircularDependency = errors.New("circular dependency detected")

	// Loader errors.
	ErrNilContext    = errors.New("context cannot be nil")
	ErrEmptyPath     = errors.New("file path cannot be empty")
	ErrFileTooLarge  = errors.New("file exceeds maximum size")
	ErrInvalidYAML   = errors.New("invalid YAML format")
	ErrFileNotFound  = errors.New("pipeline file not found")
	ErrReadFailed    = errors.New("failed to read pipeline file")
	ErrUnmarshalFail = errors.New("failed to unmarshal pipeline")

	// Executor errors.
	ErrExecutorNil      = errors.New("executor cannot be nil")
	ErrStageTimeout     = errors.New("stage execution timed out")
	ErrPipelineTimeout  = errors.New("pipeline execution timed out")
	ErrStageFailed      = errors.New("stage execution failed")
	ErrPipelineCanceled = errors.New("pipeline execution canceled")
	ErrNoRunner         = errors.New("no runner registered for stage kind")
	ErrRunnerFailed     = errors.New("stage runner failed")
)

// ValidationError represents a pipeline validation error.
type ValidationError struct {
	Err     error
	Field   string
	Message string
}

// Error implements the error interface.
func (e *ValidationError) Error() string {
	if e.Field != "" {
		return fmt.Sprintf("validation error for %s: %s", e.Field, e.Message)
	}
	return fmt.Sprintf("validation error: %s", e.Message)
}

// Unwrap returns the underlying error.
func (e *ValidationError) Unwrap() error {
	return e.Err
}

// NewValidationError creates a new validation error.
func NewValidationError(field, message string, err error) *ValidationError {
	return &ValidationError{
		Field:   field,
		Message: message,
		Err:     err,
	}
}

// StageError represents a stage execution error.
type StageError struct {
	Err       error
	StageName string
	Message   string
}

// Error implements the error interface.
func (e *StageError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("stage %q failed: %s: %v", e.StageName, e.Message, e.Err)
	}
	return fmt.Sprintf("stage %q failed: %s", e.StageName, e.Message)
}

// Unwrap returns the underlying error.
func (e *StageError) Unwrap() error {
	return e.Err
}

// NewStageError creates a new stage error.
func NewStageError(stageName, message string, err error) *StageError {
	return &StageError{
		StageName: stageName,
		Message:   message,
		Err:       err,
	}
}

// PipelineError represents a pipeline execution error.
//
//nolint:revive // Name is intentional for public API clarity
type PipelineError struct {
	Err          error
	PipelineName string
	Message      string
	StageErrors  []*StageError
}

// Error implements the error interface.
func (e *PipelineError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("pipeline %q failed: %s: %v", e.PipelineName, e.Message, e.Err)
	}
	return fmt.Sprintf("pipeline %q failed: %s", e.PipelineName, e.Message)
}

// Unwrap returns the underlying error.
func (e *PipelineError) Unwrap() error {
	return e.Err
}

// NewPipelineError creates a new pipeline error.
func NewPipelineError(pipelineName, message string, err error) *PipelineError {
	return &PipelineError{
		PipelineName: pipelineName,
		Message:      message,
		Err:          err,
	}
}

// AddStageError adds a stage error to the pipeline error.
func (e *PipelineError) AddStageError(stageErr *StageError) {
	e.StageErrors = append(e.StageErrors, stageErr)
}

// LoadError represents a pipeline loading error.
type LoadError struct {
	Err     error
	Path    string
	Message string
}

// Error implements the error interface.
func (e *LoadError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("failed to load pipeline from %q: %s: %v", e.Path, e.Message, e.Err)
	}
	return fmt.Sprintf("failed to load pipeline from %q: %s", e.Path, e.Message)
}

// Unwrap returns the underlying error.
func (e *LoadError) Unwrap() error {
	return e.Err
}

// NewLoadError creates a new load error.
func NewLoadError(path, message string, err error) *LoadError {
	return &LoadError{
		Path:    path,
		Message: message,
		Err:     err,
	}
}

// IsValidationError checks if an error is a validation error.
func IsValidationError(err error) bool {
	var ve *ValidationError
	return errors.As(err, &ve)
}

// IsStageError checks if an error is a stage error.
func IsStageError(err error) bool {
	var se *StageError
	return errors.As(err, &se)
}

// IsPipelineError checks if an error is a pipeline error.
func IsPipelineError(err error) bool {
	var pe *PipelineError
	return errors.As(err, &pe)
}

// IsLoadError checks if an error is a load error.
func IsLoadError(err error) bool {
	var le *LoadError
	return errors.As(err, &le)
}

// IsTimeoutError checks if an error is a timeout error.
func IsTimeoutError(err error) bool {
	return errors.Is(err, ErrStageTimeout) || errors.Is(err, ErrPipelineTimeout)
}

// IsCancellationError checks if an error is a cancellation error.
func IsCancellationError(err error) bool {
	return errors.Is(err, ErrPipelineCanceled)
}
