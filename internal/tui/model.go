package tui

import (
	"time"

	"github.com/charmbracelet/bubbles/spinner"
	"github.com/victoralfred/devsec/internal/progress"
)

// CommandType represents the type of command being executed.
type CommandType int

const (
	// CommandTypePipeline is for pipeline commands.
	CommandTypePipeline CommandType = iota
	// CommandTypeScan is for scan commands.
	CommandTypeScan
	// CommandTypeCompliance is for compliance commands.
	CommandTypeCompliance
	// CommandTypeML is for ML commands.
	CommandTypeML
)

// Status represents the overall execution status.
type Status int

const (
	// StatusIdle indicates waiting to start.
	StatusIdle Status = iota
	// StatusInProgress indicates currently running.
	StatusInProgress
	// StatusComplete indicates successfully completed.
	StatusComplete
	// StatusError indicates completed with errors.
	StatusError
)

// Stage represents a pipeline stage with its status.
type Stage struct {
	Name     string
	Status   progress.StageStatus
	Duration time.Duration
}

// LogEntry represents a log message.
type LogEntry struct {
	Timestamp time.Time
	Level     string
	Message   string
}

// Config holds configuration for creating a new Model.
type Config struct {
	Events      <-chan progress.Event
	CommandName string
	Stages      []string
	CommandType CommandType
}

// Model is the main bubbletea model for the TUI.
type Model struct {
	startTime    time.Time
	result       any
	err          error
	progressChan <-chan progress.Event
	stageIndex   map[string]int
	activeStage  string
	commandName  string
	keys         KeyMap
	stages       []Stage
	logs         []LogEntry
	spinner      spinner.Model
	findings     progress.FindingCount
	logOffset    int
	maxLogSize   int
	width        int
	height       int
	commandType  CommandType
	status       Status
	done         bool
}

// NewModel creates a new TUI model.
func NewModel(cfg Config) Model {
	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = statusRunningStyle

	stages := make([]Stage, 0, len(cfg.Stages))
	stageIndex := make(map[string]int, len(cfg.Stages))
	for i, name := range cfg.Stages {
		stages = append(stages, Stage{
			Name:   name,
			Status: progress.StatusPending,
		})
		stageIndex[name] = i
	}

	return Model{
		commandName:  cfg.CommandName,
		commandType:  cfg.CommandType,
		status:       StatusIdle,
		startTime:    time.Now(),
		stages:       stages,
		stageIndex:   stageIndex,
		logs:         make([]LogEntry, 0, 100),
		maxLogSize:   100,
		spinner:      s,
		keys:         DefaultKeyMap(),
		progressChan: cfg.Events,
	}
}

// SetSize sets the terminal dimensions.
func (m *Model) SetSize(width, height int) {
	m.width = width
	m.height = height
}

// AddStage adds a new stage if it doesn't exist.
func (m *Model) AddStage(name string) {
	if _, exists := m.stageIndex[name]; !exists {
		m.stageIndex[name] = len(m.stages)
		m.stages = append(m.stages, Stage{
			Name:   name,
			Status: progress.StatusPending,
		})
	}
}

// UpdateStageStatus updates the status of a stage.
func (m *Model) UpdateStageStatus(name string, status progress.StageStatus, duration time.Duration) {
	if idx, exists := m.stageIndex[name]; exists {
		m.stages[idx].Status = status
		m.stages[idx].Duration = duration
	}
}

// AddLog adds a log entry.
func (m *Model) AddLog(level, message string) {
	entry := LogEntry{
		Timestamp: time.Now(),
		Level:     level,
		Message:   message,
	}

	m.logs = append(m.logs, entry)

	// Trim if exceeds max size
	if len(m.logs) > m.maxLogSize {
		m.logs = m.logs[len(m.logs)-m.maxLogSize:]
	}
}

// ElapsedTime returns the elapsed time since start.
func (m *Model) ElapsedTime() time.Duration {
	return time.Since(m.startTime)
}

// IsComplete returns true if the operation has completed.
func (m *Model) IsComplete() bool {
	return m.done
}

// Result returns the execution result and error.
func (m *Model) Result() (any, error) {
	return m.result, m.err
}
