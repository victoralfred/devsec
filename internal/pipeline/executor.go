package pipeline

import (
	"context"
	"runtime"
	"sync"
	"time"
)

// ExecuteOptions configures pipeline execution.
type ExecuteOptions struct {
	WorkDir     string
	MaxParallel int
	DryRun      bool
	Verbose     bool
}

// DefaultExecuteOptions returns default execution options.
func DefaultExecuteOptions() ExecuteOptions {
	return ExecuteOptions{
		WorkDir:     ".",
		MaxParallel: runtime.NumCPU(),
		DryRun:      false,
		Verbose:     false,
	}
}

// Executor interface for running pipelines.
type Executor interface {
	Execute(ctx context.Context, pipeline Pipeline, opts ExecuteOptions) (PipelineResult, error)
	Validate(pipeline Pipeline) error
}

// DefaultExecutor is the default implementation of Executor.
type DefaultExecutor struct {
	registry *RunnerRegistry
	mu       sync.RWMutex
}

// ExecutorOption configures a DefaultExecutor.
type ExecutorOption func(*DefaultExecutor)

// WithRegistry sets a custom runner registry.
func WithRegistry(registry *RunnerRegistry) ExecutorOption {
	return func(e *DefaultExecutor) {
		e.registry = registry
	}
}

// NewExecutor creates a new pipeline executor.
func NewExecutor(opts ...ExecutorOption) *DefaultExecutor {
	e := &DefaultExecutor{
		registry: DefaultRegistry(),
	}

	for _, opt := range opts {
		opt(e)
	}

	return e
}

// Validate validates a pipeline configuration.
func (e *DefaultExecutor) Validate(pipeline Pipeline) error {
	if err := pipeline.Validate(); err != nil {
		return err
	}

	// Verify all stage kinds have runners.
	e.mu.RLock()
	defer e.mu.RUnlock()

	for i := range pipeline.Stages {
		if !e.registry.Has(pipeline.Stages[i].Kind) {
			return NewValidationError(
				"stages["+pipeline.Stages[i].Name+"].kind",
				"no runner registered for stage kind: "+string(pipeline.Stages[i].Kind),
				ErrNoRunner,
			)
		}
	}

	return nil
}

// Execute executes a pipeline.
func (e *DefaultExecutor) Execute(ctx context.Context, pipeline Pipeline, opts ExecuteOptions) (PipelineResult, error) {
	if ctx == nil {
		return PipelineResult{}, ErrNilContext
	}

	// Validate pipeline first.
	if err := e.Validate(pipeline); err != nil {
		return PipelineResult{}, err
	}

	startTime := time.Now()

	// Create pipeline-level timeout context.
	pipelineCtx, pipelineCancel := context.WithTimeout(ctx, pipeline.GetTimeout())
	defer pipelineCancel()

	result := PipelineResult{
		Name:      pipeline.Name,
		Status:    StageStatusRunning,
		StartTime: startTime,
		Stages:    make([]StageResult, 0, len(pipeline.Stages)),
	}

	// Build execution order using topological sort.
	order, err := e.topologicalSort(pipeline.Stages)
	if err != nil {
		result.Status = StageStatusFailed
		result.Error = err.Error()
		result.EndTime = time.Now()
		result.Duration = result.EndTime.Sub(startTime)
		return result, err
	}

	// Track completed stages for dependency resolution.
	completed := make(map[string]StageResult)
	var completedMu sync.Mutex

	// Execute stages.
	if pipeline.Parallel {
		err = e.executeParallel(pipelineCtx, pipeline, order, opts, completed, &completedMu, &result)
	} else {
		err = e.executeSequential(pipelineCtx, pipeline, order, opts, completed, &result)
	}

	// Finalize result.
	result.EndTime = time.Now()
	result.Duration = result.EndTime.Sub(startTime)

	if err != nil {
		result.Status = StageStatusFailed
		result.Error = err.Error()
		return result, err
	}

	// Determine overall status.
	result.Status = e.determineOverallStatus(result.Stages)

	return result, nil
}

// executeSequential executes stages sequentially.
func (e *DefaultExecutor) executeSequential(
	ctx context.Context,
	pipeline Pipeline,
	order []string,
	opts ExecuteOptions,
	completed map[string]StageResult,
	result *PipelineResult,
) error {
	for _, stageName := range order {
		select {
		case <-ctx.Done():
			return ErrPipelineCanceled
		default:
		}

		stage, _ := pipeline.GetStage(stageName)
		stageResult, err := e.executeStage(ctx, *stage, opts, completed)

		result.Stages = append(result.Stages, stageResult)
		completed[stageName] = stageResult

		// Handle failure.
		if err != nil {
			if pipeline.FailFast {
				return NewStageError(stageName, "stage failed", err)
			}
			// Mark remaining stages as skipped if fail-fast is disabled.
			continue
		}

		// Check continue condition.
		if !e.shouldContinue(stage.ContinueOn, stageResult.Status) && pipeline.FailFast {
			return NewStageError(stageName, "continue condition not met", nil)
		}
	}

	return nil
}

// executeParallel executes stages in parallel respecting dependencies.
func (e *DefaultExecutor) executeParallel(
	ctx context.Context,
	pipeline Pipeline,
	order []string,
	opts ExecuteOptions,
	completed map[string]StageResult,
	completedMu *sync.Mutex,
	result *PipelineResult,
) error {
	// Build dependency graph.
	deps := make(map[string][]string)
	for i := range pipeline.Stages {
		deps[pipeline.Stages[i].Name] = pipeline.Stages[i].DependsOn
	}

	// Track pending and running.
	pending := make(map[string]bool)
	for _, name := range order {
		pending[name] = true
	}

	// Worker pool.
	maxWorkers := opts.MaxParallel
	if maxWorkers <= 0 {
		maxWorkers = runtime.NumCPU()
	}

	semaphore := make(chan struct{}, maxWorkers)
	var wg sync.WaitGroup
	var resultMu sync.Mutex
	var firstErr error
	var errMu sync.Mutex

	for len(pending) > 0 {
		select {
		case <-ctx.Done():
			return ErrPipelineCanceled
		default:
		}

		// Find stages ready to run.
		ready := e.findReadyStages(pending, deps, completed, completedMu)

		if len(ready) == 0 {
			// Wait for running stages to complete.
			time.Sleep(10 * time.Millisecond)
			continue
		}

		// Launch ready stages.
		for _, stageName := range ready {
			delete(pending, stageName)

			stage, _ := pipeline.GetStage(stageName)
			wg.Add(1)

			go func(s Stage) {
				defer wg.Done()

				// Acquire semaphore.
				semaphore <- struct{}{}
				defer func() { <-semaphore }()

				// Check for early termination.
				errMu.Lock()
				hasErr := firstErr != nil && pipeline.FailFast
				errMu.Unlock()
				if hasErr {
					completedMu.Lock()
					completed[s.Name] = StageResult{
						Name:   s.Name,
						Status: StageStatusSkipped,
					}
					completedMu.Unlock()
					return
				}

				stageResult, err := e.executeStage(ctx, s, opts, completed)

				resultMu.Lock()
				result.Stages = append(result.Stages, stageResult)
				resultMu.Unlock()

				completedMu.Lock()
				completed[s.Name] = stageResult
				completedMu.Unlock()

				if err != nil {
					errMu.Lock()
					if firstErr == nil {
						firstErr = NewStageError(s.Name, "stage failed", err)
					}
					errMu.Unlock()
				}
			}(*stage)
		}
	}

	wg.Wait()

	return firstErr
}

// executeStage executes a single stage.
func (e *DefaultExecutor) executeStage(
	ctx context.Context,
	stage Stage,
	opts ExecuteOptions,
	completed map[string]StageResult,
) (StageResult, error) {
	// Create stage-level timeout context.
	stageCtx, stageCancel := context.WithTimeout(ctx, stage.GetTimeout())
	defer stageCancel()

	// Check for dry run.
	if opts.DryRun {
		return StageResult{
			Name:      stage.Name,
			Status:    StageStatusSkipped,
			StartTime: time.Now(),
			EndTime:   time.Now(),
		}, nil
	}

	// Get runner.
	e.mu.RLock()
	runner, ok := e.registry.Get(stage.Kind)
	e.mu.RUnlock()

	if !ok {
		return StageResult{
			Name:      stage.Name,
			Status:    StageStatusFailed,
			Error:     "no runner for stage kind: " + string(stage.Kind),
			StartTime: time.Now(),
			EndTime:   time.Now(),
		}, ErrNoRunner
	}

	// Build input.
	input := RunnerInput{
		WorkDir:         opts.WorkDir,
		PreviousResults: completed,
	}

	// Execute stage.
	return runner.Run(stageCtx, stage, input)
}

// topologicalSort returns stages in execution order.
func (e *DefaultExecutor) topologicalSort(stages []Stage) ([]string, error) {
	// Build in-degree map.
	// In-degree is the number of dependencies a stage has.
	// Stages with in-degree 0 can run first.
	inDegree := make(map[string]int, len(stages))
	for i := range stages {
		name := stages[i].Name
		inDegree[name] = len(stages[i].DependsOn)
	}

	// Nodes with in-degree 0 can run first.
	var queue []string
	for name, degree := range inDegree {
		if degree == 0 {
			queue = append(queue, name)
		}
	}

	var order []string
	for len(queue) > 0 {
		// Dequeue.
		node := queue[0]
		queue = queue[1:]
		order = append(order, node)

		// Find dependents (stages that depend on this node).
		for i := range stages {
			for _, dep := range stages[i].DependsOn {
				if dep == node {
					inDegree[stages[i].Name]--
					if inDegree[stages[i].Name] == 0 {
						queue = append(queue, stages[i].Name)
					}
				}
			}
		}
	}

	if len(order) != len(stages) {
		return nil, ErrCircularDependency
	}

	return order, nil
}

// findReadyStages finds stages whose dependencies are all complete.
func (e *DefaultExecutor) findReadyStages(
	pending map[string]bool,
	deps map[string][]string,
	completed map[string]StageResult,
	completedMu *sync.Mutex,
) []string {
	var ready []string

	completedMu.Lock()
	defer completedMu.Unlock()

	for name := range pending {
		allDepsComplete := true
		for _, dep := range deps[name] {
			if _, ok := completed[dep]; !ok {
				allDepsComplete = false
				break
			}
		}
		if allDepsComplete {
			ready = append(ready, name)
		}
	}

	return ready
}

// shouldContinue checks if pipeline should continue based on condition.
func (e *DefaultExecutor) shouldContinue(cond ContinueCondition, status StageStatus) bool {
	switch cond {
	case ContinueAlways:
		return true
	case ContinueOnFailure:
		return status == StageStatusFailed
	case ContinueOnSuccess, "":
		return status == StageStatusSuccess
	default:
		return status == StageStatusSuccess
	}
}

// determineOverallStatus determines the overall pipeline status from stage results.
func (e *DefaultExecutor) determineOverallStatus(stages []StageResult) StageStatus {
	hasFailure := false
	hasCanceled := false

	for i := range stages {
		switch stages[i].Status {
		case StageStatusFailed:
			hasFailure = true
		case StageStatusCanceled:
			hasCanceled = true
		}
	}

	switch {
	case hasCanceled:
		return StageStatusCanceled
	case hasFailure:
		return StageStatusFailed
	default:
		return StageStatusSuccess
	}
}
