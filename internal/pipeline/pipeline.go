package pipeline

import (
	"time"
)

// Limits for DoS prevention.
const (
	MaxStages           = 100
	MaxStageNameLen     = 256
	MaxPipelineNameLen  = 256
	MaxConfigEntries    = 50
	MaxConfigKeyLen     = 128
	MaxConfigValueLen   = 4096
	MaxDependencies     = 20
	MaxMetadataEntries  = 50
	DefaultStageTimeout = 10 * time.Minute
	DefaultTimeout      = 30 * time.Minute
)

// StageKind represents the type of pipeline stage.
type StageKind string

// Stage kinds.
const (
	StageKindScan       StageKind = "scan"
	StageKindPolicy     StageKind = "policy"
	StageKindReport     StageKind = "report"
	StageKindCompliance StageKind = "compliance"
	StageKindCustom     StageKind = "custom"
)

// ValidStageKinds returns all valid stage kinds.
func ValidStageKinds() []StageKind {
	return []StageKind{
		StageKindScan,
		StageKindPolicy,
		StageKindReport,
		StageKindCompliance,
		StageKindCustom,
	}
}

// IsValid checks if the stage kind is valid.
func (k StageKind) IsValid() bool {
	switch k {
	case StageKindScan, StageKindPolicy, StageKindReport, StageKindCompliance, StageKindCustom:
		return true
	default:
		return false
	}
}

// String returns the string representation of the stage kind.
func (k StageKind) String() string {
	return string(k)
}

// StageStatus represents the execution status of a stage.
type StageStatus string

// Stage statuses.
const (
	StageStatusPending  StageStatus = "pending"
	StageStatusRunning  StageStatus = "running"
	StageStatusSuccess  StageStatus = "success"
	StageStatusFailed   StageStatus = "failed"
	StageStatusSkipped  StageStatus = "skipped"
	StageStatusCanceled StageStatus = "canceled"
)

// IsTerminal returns true if the status is a terminal state.
func (s StageStatus) IsTerminal() bool {
	switch s {
	case StageStatusSuccess, StageStatusFailed, StageStatusSkipped, StageStatusCanceled:
		return true
	default:
		return false
	}
}

// IsSuccess returns true if the status indicates success.
func (s StageStatus) IsSuccess() bool {
	return s == StageStatusSuccess
}

// ContinueCondition specifies when to continue pipeline execution.
type ContinueCondition string

// Continue conditions.
const (
	ContinueOnSuccess ContinueCondition = "success"
	ContinueOnFailure ContinueCondition = "failure"
	ContinueAlways    ContinueCondition = "always"
)

// IsValid checks if the continue condition is valid.
func (c ContinueCondition) IsValid() bool {
	switch c {
	case ContinueOnSuccess, ContinueOnFailure, ContinueAlways, "":
		return true
	default:
		return false
	}
}

// Stage represents a pipeline stage.
// Fields are ordered for optimal memory alignment.
type Stage struct {
	Config     map[string]string `yaml:"config,omitempty" json:"config,omitempty"`
	Name       string            `yaml:"name" json:"name"`
	Kind       StageKind         `yaml:"kind" json:"kind"`
	ContinueOn ContinueCondition `yaml:"continue_on,omitempty" json:"continue_on,omitempty"`
	DependsOn  []string          `yaml:"depends_on,omitempty" json:"depends_on,omitempty"`
	Timeout    time.Duration     `yaml:"timeout,omitempty" json:"timeout,omitempty"`
	Parallel   bool              `yaml:"parallel,omitempty" json:"parallel,omitempty"`
	FailFast   bool              `yaml:"fail_fast,omitempty" json:"fail_fast,omitempty"`
}

// Validate validates the stage configuration.
func (s *Stage) Validate() error {
	if s == nil {
		return ErrNilStage
	}

	if s.Name == "" {
		return ErrEmptyStageName
	}

	if len(s.Name) > MaxStageNameLen {
		return ErrStageNameTooLong
	}

	if !s.Kind.IsValid() {
		return ErrInvalidStageKind
	}

	if !s.ContinueOn.IsValid() {
		return ErrInvalidContinueCondition
	}

	if len(s.DependsOn) > MaxDependencies {
		return ErrTooManyDependencies
	}

	if len(s.Config) > MaxConfigEntries {
		return ErrTooManyConfigEntries
	}

	for key, value := range s.Config {
		if len(key) > MaxConfigKeyLen {
			return ErrConfigKeyTooLong
		}
		if len(value) > MaxConfigValueLen {
			return ErrConfigValueTooLong
		}
	}

	return nil
}

// GetTimeout returns the stage timeout, using default if not set.
func (s *Stage) GetTimeout() time.Duration {
	if s.Timeout <= 0 {
		return DefaultStageTimeout
	}
	return s.Timeout
}

// Pipeline represents a security pipeline.
// Fields are ordered for optimal memory alignment.
type Pipeline struct {
	Metadata map[string]string `yaml:"metadata,omitempty" json:"metadata,omitempty"`
	Name     string            `yaml:"name" json:"name"`
	Version  string            `yaml:"version,omitempty" json:"version,omitempty"`
	Stages   []Stage           `yaml:"stages" json:"stages"`
	Timeout  time.Duration     `yaml:"timeout,omitempty" json:"timeout,omitempty"`
	Parallel bool              `yaml:"parallel,omitempty" json:"parallel,omitempty"`
	FailFast bool              `yaml:"fail_fast,omitempty" json:"fail_fast,omitempty"`
}

// Validate validates the pipeline configuration.
func (p *Pipeline) Validate() error {
	if p == nil {
		return ErrNilPipeline
	}

	if p.Name == "" {
		return ErrEmptyPipelineName
	}

	if len(p.Name) > MaxPipelineNameLen {
		return ErrPipelineNameTooLong
	}

	if len(p.Stages) == 0 {
		return ErrNoStages
	}

	if len(p.Stages) > MaxStages {
		return ErrTooManyStages
	}

	if len(p.Metadata) > MaxMetadataEntries {
		return ErrTooManyMetadataEntries
	}

	// Check for duplicate stage names.
	stageNames := make(map[string]bool, len(p.Stages))
	for i := range p.Stages {
		if stageNames[p.Stages[i].Name] {
			return ErrDuplicateStageName
		}
		stageNames[p.Stages[i].Name] = true

		if err := p.Stages[i].Validate(); err != nil {
			return err
		}
	}

	// Validate dependencies.
	for i := range p.Stages {
		for _, dep := range p.Stages[i].DependsOn {
			if !stageNames[dep] {
				return ErrInvalidDependency
			}
			// Self-dependency check.
			if dep == p.Stages[i].Name {
				return ErrSelfDependency
			}
		}
	}

	// Check for circular dependencies.
	if hasCycle(p.Stages) {
		return ErrCircularDependency
	}

	return nil
}

// GetTimeout returns the pipeline timeout, using default if not set.
func (p *Pipeline) GetTimeout() time.Duration {
	if p.Timeout <= 0 {
		return DefaultTimeout
	}
	return p.Timeout
}

// GetStage returns a stage by name.
func (p *Pipeline) GetStage(name string) (*Stage, bool) {
	for i := range p.Stages {
		if p.Stages[i].Name == name {
			return &p.Stages[i], true
		}
	}
	return nil, false
}

// GetStageIndex returns the index of a stage by name.
func (p *Pipeline) GetStageIndex(name string) (int, bool) {
	for i := range p.Stages {
		if p.Stages[i].Name == name {
			return i, true
		}
	}
	return -1, false
}

// hasCycle detects circular dependencies using DFS.
func hasCycle(stages []Stage) bool {
	// Build adjacency list.
	graph := make(map[string][]string, len(stages))
	for i := range stages {
		graph[stages[i].Name] = stages[i].DependsOn
	}

	// Track visited and recursion stack.
	visited := make(map[string]bool, len(stages))
	recStack := make(map[string]bool, len(stages))

	// DFS from each unvisited node.
	for name := range graph {
		if hasCycleDFS(name, graph, visited, recStack) {
			return true
		}
	}

	return false
}

// hasCycleDFS performs DFS cycle detection.
func hasCycleDFS(node string, graph map[string][]string, visited, recStack map[string]bool) bool {
	if recStack[node] {
		return true
	}
	if visited[node] {
		return false
	}

	visited[node] = true
	recStack[node] = true

	for _, neighbor := range graph[node] {
		if hasCycleDFS(neighbor, graph, visited, recStack) {
			return true
		}
	}

	recStack[node] = false
	return false
}

// StageResult holds the result of a stage execution.
// Fields are ordered for optimal memory alignment.
type StageResult struct {
	StartTime time.Time      `json:"start_time"`
	EndTime   time.Time      `json:"end_time"`
	Artifacts map[string]any `json:"artifacts,omitempty"`
	Error     string         `json:"error,omitempty"`
	Name      string         `json:"name"`
	Status    StageStatus    `json:"status"`
	Duration  time.Duration  `json:"duration"`
}

// PipelineResult holds the result of a pipeline execution.
// Fields are ordered for optimal memory alignment.
//
//nolint:revive // Name is intentional for public API clarity
type PipelineResult struct {
	StartTime time.Time     `json:"start_time"`
	EndTime   time.Time     `json:"end_time"`
	Error     string        `json:"error,omitempty"`
	Name      string        `json:"name"`
	Status    StageStatus   `json:"status"`
	Stages    []StageResult `json:"stages"`
	Duration  time.Duration `json:"duration"`
}

// GetStageResult returns the result for a stage by name.
func (p *PipelineResult) GetStageResult(name string) (*StageResult, bool) {
	for i := range p.Stages {
		if p.Stages[i].Name == name {
			return &p.Stages[i], true
		}
	}
	return nil, false
}

// SuccessCount returns the number of successful stages.
func (p *PipelineResult) SuccessCount() int {
	count := 0
	for i := range p.Stages {
		if p.Stages[i].Status.IsSuccess() {
			count++
		}
	}
	return count
}

// FailedCount returns the number of failed stages.
func (p *PipelineResult) FailedCount() int {
	count := 0
	for i := range p.Stages {
		if p.Stages[i].Status == StageStatusFailed {
			count++
		}
	}
	return count
}

// Summary provides a summary of the pipeline execution.
type Summary struct {
	TotalStages   int           `json:"total_stages"`
	SuccessCount  int           `json:"success_count"`
	FailedCount   int           `json:"failed_count"`
	SkippedCount  int           `json:"skipped_count"`
	CanceledCount int           `json:"canceled_count"`
	TotalDuration time.Duration `json:"total_duration"`
}

// Summarize generates a summary of the pipeline result.
func (p *PipelineResult) Summarize() Summary {
	summary := Summary{
		TotalStages:   len(p.Stages),
		TotalDuration: p.Duration,
	}

	for i := range p.Stages {
		switch p.Stages[i].Status {
		case StageStatusSuccess:
			summary.SuccessCount++
		case StageStatusFailed:
			summary.FailedCount++
		case StageStatusSkipped:
			summary.SkippedCount++
		case StageStatusCanceled:
			summary.CanceledCount++
		}
	}

	return summary
}
