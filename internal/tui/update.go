package tui

import (
	"time"

	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/victoralfred/devsec/internal/progress"
)

const tickInterval = 100 * time.Millisecond

// Init initializes the model.
func (m Model) Init() tea.Cmd {
	return tea.Batch(
		m.spinner.Tick,
		tickCmd(),
		waitForEvent(m.progressChan),
	)
}

// Update handles messages and updates the model.
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd

	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			return m, tea.Quit
		case "up", "k":
			if m.logOffset > 0 {
				m.logOffset--
			}
		case "down", "j":
			maxOffset := len(m.logs) - visibleLogLines(m.height)
			if maxOffset < 0 {
				maxOffset = 0
			}
			if m.logOffset < maxOffset {
				m.logOffset++
			}
		}

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height

	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		cmds = append(cmds, cmd)

	case TickMsg:
		cmds = append(cmds, tickCmd())

	case ProgressEventMsg:
		m = handleProgressEvent(m, msg.Event)
		if !m.done {
			cmds = append(cmds, waitForEvent(m.progressChan))
		}
	}

	return m, tea.Batch(cmds...)
}

// handleProgressEvent processes a progress event.
func handleProgressEvent(m Model, event progress.Event) Model {
	switch event.Type {
	case progress.EventStageStarted:
		m.status = StatusInProgress
		m.AddStage(event.StageName)
		m.UpdateStageStatus(event.StageName, progress.StatusRunning, 0)
		m.activeStage = event.StageName
		m.AddLog("info", "Started: "+event.StageName)

	case progress.EventStageProgress:
		// Progress updates handled in view via elapsed time

	case progress.EventStageCompleted:
		m.UpdateStageStatus(event.StageName, event.StageStatus, event.Duration)
		switch event.StageStatus {
		case progress.StatusSuccess:
			m.AddLog("info", "Completed: "+event.StageName)
		case progress.StatusFailed:
			m.AddLog("error", "Failed: "+event.StageName)
		}
		if m.activeStage == event.StageName {
			m.activeStage = ""
		}

	case progress.EventFindingDiscovered:
		if event.Finding != nil {
			switch event.Finding.Severity {
			case "critical":
				m.findings.Critical++
			case "high":
				m.findings.High++
			case "medium":
				m.findings.Medium++
			case "low":
				m.findings.Low++
			default:
				m.findings.Info++
			}
		} else {
			m.findings = event.FindingCount
		}

	case progress.EventLogMessage:
		m.AddLog(event.LogLevel, event.LogMessage)

	case progress.EventPipelineCompleted:
		m.done = true
		m.result = event.Result
		m.err = event.Error
		if event.Error != nil {
			m.status = StatusError
			m.AddLog("error", "Pipeline failed: "+event.Error.Error())
		} else {
			m.status = StatusComplete
			m.AddLog("info", "Pipeline completed successfully")
		}
	}

	return m
}

// tickCmd returns a command that sends a tick message after the interval.
func tickCmd() tea.Cmd {
	return tea.Tick(tickInterval, func(time.Time) tea.Msg {
		return TickMsg{}
	})
}

// waitForEvent returns a command that waits for a progress event.
func waitForEvent(ch <-chan progress.Event) tea.Cmd {
	return func() tea.Msg {
		event, ok := <-ch
		if !ok {
			return ProgressEventMsg{
				Event: progress.Event{
					Type: progress.EventPipelineCompleted,
				},
			}
		}
		return ProgressEventMsg{Event: event}
	}
}

// visibleLogLines calculates how many log lines can be displayed.
func visibleLogLines(height int) int {
	// Account for header, stages, findings panels, and footer
	available := height - 14
	if available < 3 {
		return 3
	}
	return available
}
