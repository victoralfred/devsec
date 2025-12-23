package tui

import (
	"github.com/victoralfred/devsec/internal/progress"
)

// ProgressEventMsg wraps a progress event for the bubbletea message loop.
type ProgressEventMsg struct {
	Event progress.Event
}

// TickMsg is sent on each tick for updating elapsed time and spinners.
type TickMsg struct{}

// QuitMsg indicates the user wants to quit.
type QuitMsg struct{}

// WindowSizeMsg is sent when the terminal window size changes.
type WindowSizeMsg struct {
	Width  int
	Height int
}
