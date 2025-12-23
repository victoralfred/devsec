package progress

import (
	"time"

	"github.com/victoralfred/devsec/internal/model"
)

// NoopReporter is a no-op implementation of Reporter.
// Used when TUI progress display is disabled.
type NoopReporter struct{}

// NewNoopReporter creates a new NoopReporter.
func NewNoopReporter() *NoopReporter {
	return &NoopReporter{}
}

// ReportStageStarted is a no-op.
func (r *NoopReporter) ReportStageStarted(_ string) {}

// ReportStageProgress is a no-op.
func (r *NoopReporter) ReportStageProgress(_ string, _ float64) {}

// ReportStageCompleted is a no-op.
func (r *NoopReporter) ReportStageCompleted(_ string, _ StageStatus, _ time.Duration) {}

// ReportFinding is a no-op.
func (r *NoopReporter) ReportFinding(_ model.Finding) {}

// ReportFindingCount is a no-op.
func (r *NoopReporter) ReportFindingCount(_ FindingCount) {}

// ReportLog is a no-op.
func (r *NoopReporter) ReportLog(_, _ string) {}

// ReportCompleted is a no-op.
func (r *NoopReporter) ReportCompleted(_ any, _ error) {}

// Close is a no-op.
func (r *NoopReporter) Close() {}
