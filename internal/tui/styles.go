package tui

import "github.com/charmbracelet/lipgloss"

var (
	// Colors.
	colorPrimary   = lipgloss.Color("#7D56F4")
	colorSecondary = lipgloss.Color("#5A5A5A")
	colorSuccess   = lipgloss.Color("#04B575")
	colorWarning   = lipgloss.Color("#FFCC00")
	colorError     = lipgloss.Color("#FF5F5F")
	colorCritical  = lipgloss.Color("#FF0000")
	colorHigh      = lipgloss.Color("#FF6600")
	colorMedium    = lipgloss.Color("#FFCC00")
	colorLow       = lipgloss.Color("#00CCFF")
	colorInfo      = lipgloss.Color("#AAAAAA")
	colorMuted     = lipgloss.Color("#666666")

	// Base styles.
	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(colorPrimary)

	subtitleStyle = lipgloss.NewStyle().
			Foreground(colorSecondary)

	// Status styles.
	statusRunningStyle = lipgloss.NewStyle().
				Bold(true).
				Foreground(lipgloss.Color("#00BFFF")).
				Background(lipgloss.Color("#1A1A2E")).
				Padding(0, 1)

	statusSuccessStyle = lipgloss.NewStyle().
				Bold(true).
				Foreground(colorSuccess).
				Background(lipgloss.Color("#0A2A1A")).
				Padding(0, 1)

	statusFailedStyle = lipgloss.NewStyle().
				Bold(true).
				Foreground(colorError).
				Background(lipgloss.Color("#2A0A0A")).
				Padding(0, 1)

	statusPendingStyle = lipgloss.NewStyle().
				Foreground(colorMuted).
				Padding(0, 1)

	// Panel styles.
	panelStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(colorSecondary).
			Padding(0, 1)

	headerPanelStyle = lipgloss.NewStyle().
				Border(lipgloss.RoundedBorder()).
				BorderForeground(colorPrimary).
				Padding(0, 1)

	// Severity styles.
	criticalStyle = lipgloss.NewStyle().Bold(true).Foreground(colorCritical)
	highStyle     = lipgloss.NewStyle().Bold(true).Foreground(colorHigh)
	mediumStyle   = lipgloss.NewStyle().Foreground(colorMedium)
	lowStyle      = lipgloss.NewStyle().Foreground(colorLow)
	infoStyle     = lipgloss.NewStyle().Foreground(colorInfo)

	// Stage status icons.
	iconPending = lipgloss.NewStyle().Foreground(colorMuted).Render("○")
	iconSuccess = lipgloss.NewStyle().Foreground(colorSuccess).Render("✓")
	iconFailed  = lipgloss.NewStyle().Foreground(colorError).Render("✗")
	iconSkipped = lipgloss.NewStyle().Foreground(colorMuted).Render("⊘")

	// Log level styles.
	logDebugStyle = lipgloss.NewStyle().Foreground(colorMuted)
	logInfoStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("#00BFFF"))
	logWarnStyle  = lipgloss.NewStyle().Foreground(colorWarning)
	logErrorStyle = lipgloss.NewStyle().Foreground(colorError)

	// Footer style.
	footerStyle = lipgloss.NewStyle().
			Foreground(colorMuted)

	helpStyle = lipgloss.NewStyle().
			Foreground(colorSecondary)
)

// SeverityStyle returns the appropriate style for a severity level.
func SeverityStyle(severity string) lipgloss.Style {
	switch severity {
	case "critical":
		return criticalStyle
	case "high":
		return highStyle
	case "medium":
		return mediumStyle
	case "low":
		return lowStyle
	default:
		return infoStyle
	}
}

// LogLevelStyle returns the appropriate style for a log level.
func LogLevelStyle(level string) lipgloss.Style {
	switch level {
	case "debug":
		return logDebugStyle
	case "info":
		return logInfoStyle
	case "warn", "warning":
		return logWarnStyle
	case "error":
		return logErrorStyle
	default:
		return logInfoStyle
	}
}
