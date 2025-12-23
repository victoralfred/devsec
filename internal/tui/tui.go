// Package tui provides the terminal user interface for DevSec.
package tui

import (
	"fmt"
	"os"

	tea "github.com/charmbracelet/bubbletea"
	"golang.org/x/term"
)

// Run starts the TUI with the given model.
func Run(m Model) error {
	p := tea.NewProgram(m,
		tea.WithAltScreen(),
		tea.WithMouseCellMotion(),
	)

	finalModel, err := p.Run()
	if err != nil {
		return fmt.Errorf("TUI error: %w", err)
	}

	// Return the result error if any
	if final, ok := finalModel.(Model); ok {
		_, resultErr := final.Result()
		if resultErr != nil {
			return resultErr
		}
	}

	return nil
}

// IsTerminal checks if stdout is a terminal.
func IsTerminal() bool {
	return term.IsTerminal(int(os.Stdout.Fd()))
}

// IsTUIEnabled checks if TUI should be enabled based on environment.
func IsTUIEnabled(progressFlag bool) bool {
	// Flag must be set
	if !progressFlag {
		return false
	}

	// Must be a terminal
	if !IsTerminal() {
		return false
	}

	// Check CI environment variables
	ciVars := []string{"CI", "CONTINUOUS_INTEGRATION", "BUILD_NUMBER", "JENKINS_URL", "GITHUB_ACTIONS"}
	for _, v := range ciVars {
		if os.Getenv(v) != "" {
			return false
		}
	}

	// Check NO_COLOR
	if os.Getenv("NO_COLOR") != "" {
		return false
	}

	// Check TERM=dumb
	if os.Getenv("TERM") == "dumb" {
		return false
	}

	return true
}

// GetTerminalSize returns the current terminal dimensions.
func GetTerminalSize() (width, height int, err error) {
	return term.GetSize(int(os.Stdout.Fd()))
}
