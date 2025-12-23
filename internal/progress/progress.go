// Package progress provides progress reporting for DevSec operations.
package progress

import (
	"time"

	"github.com/victoralfred/devsec/internal/model"
)

// EventType represents the type of progress event.
type EventType int

const (
	// EventStageStarted indicates a stage has started.
	EventStageStarted EventType = iota
	// EventStageProgress indicates progress within a stage.
	EventStageProgress
	// EventStageCompleted indicates a stage has completed.
	EventStageCompleted
	// EventFindingDiscovered indicates a finding was discovered.
	EventFindingDiscovered
	// EventLogMessage indicates a log message.
	EventLogMessage
	// EventPipelineCompleted indicates the pipeline has completed.
	EventPipelineCompleted
)

// StageStatus represents the status of a pipeline stage.
type StageStatus int

const (
	// StatusPending indicates the stage is waiting to run.
	StatusPending StageStatus = iota
	// StatusRunning indicates the stage is currently running.
	StatusRunning
	// StatusSuccess indicates the stage completed successfully.
	StatusSuccess
	// StatusFailed indicates the stage failed.
	StatusFailed
	// StatusSkipped indicates the stage was skipped.
	StatusSkipped
)

// FindingCount holds counts of findings by severity.
type FindingCount struct {
	Critical int
	High     int
	Medium   int
	Low      int
	Info     int
}

// Total returns the total number of findings.
func (fc FindingCount) Total() int {
	return fc.Critical + fc.High + fc.Medium + fc.Low + fc.Info
}

// Event represents a progress update event.
type Event struct {
	Timestamp    time.Time
	Result       any
	Error        error
	Finding      *model.Finding
	StageName    string
	LogLevel     string
	LogMessage   string
	FindingCount FindingCount
	Duration     time.Duration
	Progress     float64
	Type         EventType
	StageStatus  StageStatus
}

// Reporter defines the interface for reporting progress.
type Reporter interface {
	// ReportStageStarted reports that a stage has started.
	ReportStageStarted(name string)

	// ReportStageProgress reports progress within a stage (0.0 to 1.0).
	ReportStageProgress(name string, progress float64)

	// ReportStageCompleted reports that a stage has completed.
	ReportStageCompleted(name string, status StageStatus, duration time.Duration)

	// ReportFinding reports a discovered finding.
	ReportFinding(finding model.Finding)

	// ReportFindingCount reports the current finding counts.
	ReportFindingCount(count FindingCount)

	// ReportLog reports a log message.
	ReportLog(level, message string)

	// ReportCompleted reports that the operation has completed.
	ReportCompleted(result any, err error)

	// Close closes the reporter.
	Close()
}
