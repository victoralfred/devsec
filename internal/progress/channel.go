package progress

import (
	"sync"
	"time"

	"github.com/victoralfred/devsec/internal/model"
)

// ChannelReporter sends progress events through a channel.
type ChannelReporter struct {
	events chan Event
	closed bool
	mu     sync.Mutex
}

// NewChannelReporter creates a new ChannelReporter with the given buffer size.
// Returns the reporter and a read-only channel for receiving events.
func NewChannelReporter(bufferSize int) (reporter *ChannelReporter, events <-chan Event) {
	ch := make(chan Event, bufferSize)
	return &ChannelReporter{events: ch}, ch
}

// send sends an event if the channel is not closed.
func (r *ChannelReporter) send(event Event) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.closed {
		return
	}

	select {
	case r.events <- event:
	default:
		// Channel full, drop event to prevent blocking
	}
}

// ReportStageStarted reports that a stage has started.
func (r *ChannelReporter) ReportStageStarted(name string) {
	r.send(Event{
		Type:        EventStageStarted,
		Timestamp:   time.Now(),
		StageName:   name,
		StageStatus: StatusRunning,
	})
}

// ReportStageProgress reports progress within a stage.
func (r *ChannelReporter) ReportStageProgress(name string, progress float64) {
	r.send(Event{
		Type:      EventStageProgress,
		Timestamp: time.Now(),
		StageName: name,
		Progress:  progress,
	})
}

// ReportStageCompleted reports that a stage has completed.
func (r *ChannelReporter) ReportStageCompleted(name string, status StageStatus, duration time.Duration) {
	r.send(Event{
		Type:        EventStageCompleted,
		Timestamp:   time.Now(),
		StageName:   name,
		StageStatus: status,
		Duration:    duration,
	})
}

// ReportFinding reports a discovered finding.
func (r *ChannelReporter) ReportFinding(finding model.Finding) {
	r.send(Event{
		Type:      EventFindingDiscovered,
		Timestamp: time.Now(),
		Finding:   &finding,
	})
}

// ReportFindingCount reports the current finding counts.
func (r *ChannelReporter) ReportFindingCount(count FindingCount) {
	r.send(Event{
		Type:         EventFindingDiscovered,
		Timestamp:    time.Now(),
		FindingCount: count,
	})
}

// ReportLog reports a log message.
func (r *ChannelReporter) ReportLog(level, message string) {
	r.send(Event{
		Type:       EventLogMessage,
		Timestamp:  time.Now(),
		LogLevel:   level,
		LogMessage: message,
	})
}

// ReportCompleted reports that the operation has completed.
func (r *ChannelReporter) ReportCompleted(result any, err error) {
	r.send(Event{
		Type:      EventPipelineCompleted,
		Timestamp: time.Now(),
		Result:    result,
		Error:     err,
	})
}

// Close closes the reporter and its channel.
func (r *ChannelReporter) Close() {
	r.mu.Lock()
	defer r.mu.Unlock()

	if !r.closed {
		r.closed = true
		close(r.events)
	}
}
