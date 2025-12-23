package tui

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/victoralfred/devsec/internal/progress"
)

// View renders the TUI.
func (m Model) View() string {
	if m.width == 0 {
		return "Initializing..."
	}

	sections := make([]string, 0, 4)

	// Header.
	sections = append(sections, m.renderHeader())

	// Stages.
	if len(m.stages) > 0 {
		sections = append(sections, m.renderStages())
	}

	// Middle panels (findings + logs) and Footer.
	sections = append(sections, m.renderMiddle(), m.renderFooter())

	return lipgloss.JoinVertical(lipgloss.Left, sections...)
}

// renderHeader renders the header panel.
func (m Model) renderHeader() string {
	// Command name and type
	cmdType := "Pipeline"
	switch m.commandType {
	case CommandTypeScan:
		cmdType = "Scan"
	case CommandTypeCompliance:
		cmdType = "Compliance"
	case CommandTypeML:
		cmdType = "ML"
	}

	title := titleStyle.Render(fmt.Sprintf("%s: %s", cmdType, m.commandName))

	// Status badge
	var statusBadge string
	switch m.status {
	case StatusIdle:
		statusBadge = statusPendingStyle.Render("IDLE")
	case StatusInProgress:
		statusBadge = statusRunningStyle.Render("RUNNING")
	case StatusComplete:
		statusBadge = statusSuccessStyle.Render("COMPLETE")
	case StatusError:
		statusBadge = statusFailedStyle.Render("FAILED")
	}

	// Elapsed time
	elapsed := formatDuration(m.ElapsedTime())
	elapsedStr := subtitleStyle.Render(fmt.Sprintf("Elapsed: %s", elapsed))

	// Build header content
	topRow := lipgloss.JoinHorizontal(lipgloss.Center, title, "  ", statusBadge)
	content := lipgloss.JoinVertical(lipgloss.Left, topRow, elapsedStr)

	return headerPanelStyle.Width(m.width - 2).Render(content)
}

// renderStages renders the stages panel.
func (m Model) renderStages() string {
	lines := make([]string, 0, len(m.stages))

	for _, stage := range m.stages {
		line := m.renderStageLine(stage)
		lines = append(lines, line)
	}

	content := strings.Join(lines, "\n")
	return panelStyle.Width(m.width - 2).Render(content)
}

// renderStageLine renders a single stage line.
func (m Model) renderStageLine(stage Stage) string {
	var icon string
	var durationStr string

	switch stage.Status {
	case progress.StatusPending:
		icon = iconPending
		durationStr = "pending"
	case progress.StatusRunning:
		icon = m.spinner.View()
		durationStr = "..."
	case progress.StatusSuccess:
		icon = iconSuccess
		durationStr = formatDuration(stage.Duration)
	case progress.StatusFailed:
		icon = iconFailed
		durationStr = formatDuration(stage.Duration)
	case progress.StatusSkipped:
		icon = iconSkipped
		durationStr = "skipped"
	}

	name := lipgloss.NewStyle().Width(20).Render(stage.Name)
	return fmt.Sprintf("  %s %s  (%s)", icon, name, durationStr)
}

// renderMiddle renders the findings and logs panels side by side.
func (m Model) renderMiddle() string {
	halfWidth := (m.width - 4) / 2

	findingsPanel := m.renderFindings(halfWidth)
	logsPanel := m.renderLogs(halfWidth)

	return lipgloss.JoinHorizontal(lipgloss.Top, findingsPanel, logsPanel)
}

// renderFindings renders the findings panel.
func (m Model) renderFindings(width int) string {
	lines := make([]string, 0, 8)

	lines = append(lines, titleStyle.Render("FINDINGS"), "")

	// Critical
	critical := fmt.Sprintf("Critical: %d", m.findings.Critical)
	if m.findings.Critical > 0 {
		critical = criticalStyle.Render(critical)
	} else {
		critical = infoStyle.Render(critical)
	}
	lines = append(lines, critical)

	// High
	high := fmt.Sprintf("High:     %d", m.findings.High)
	if m.findings.High > 0 {
		high = highStyle.Render(high)
	} else {
		high = infoStyle.Render(high)
	}
	lines = append(lines, high)

	// Medium
	medium := fmt.Sprintf("Medium:   %d", m.findings.Medium)
	if m.findings.Medium > 0 {
		medium = mediumStyle.Render(medium)
	} else {
		medium = infoStyle.Render(medium)
	}
	lines = append(lines, medium)

	// Low
	low := fmt.Sprintf("Low:      %d", m.findings.Low)
	if m.findings.Low > 0 {
		low = lowStyle.Render(low)
	} else {
		low = infoStyle.Render(low)
	}
	lines = append(lines, low)

	// Info
	info := fmt.Sprintf("Info:     %d", m.findings.Info)
	lines = append(lines, infoStyle.Render(info))

	content := strings.Join(lines, "\n")
	return panelStyle.Width(width).Render(content)
}

// renderLogs renders the logs panel.
func (m Model) renderLogs(width int) string {
	lines := make([]string, 0, visibleLogLines(m.height)+4)

	lines = append(lines, titleStyle.Render("LOGS"), "")

	// Calculate visible lines
	visibleLines := visibleLogLines(m.height)
	startIdx := m.logOffset
	endIdx := startIdx + visibleLines
	if endIdx > len(m.logs) {
		endIdx = len(m.logs)
	}

	// Render log entries
	for i := startIdx; i < endIdx; i++ {
		entry := m.logs[i]
		levelStyle := LogLevelStyle(entry.Level)
		level := levelStyle.Render(fmt.Sprintf("[%s]", strings.ToUpper(entry.Level)))

		// Truncate message if needed
		maxMsgLen := width - 12
		msg := entry.Message
		if len(msg) > maxMsgLen && maxMsgLen > 3 {
			msg = msg[:maxMsgLen-3] + "..."
		}

		lines = append(lines, fmt.Sprintf("%s %s", level, msg))
	}

	// Pad with empty lines if needed
	for len(lines) < visibleLines+2 {
		lines = append(lines, "")
	}

	content := strings.Join(lines, "\n")
	return panelStyle.Width(width).Render(content)
}

// renderFooter renders the footer panel.
func (m Model) renderFooter() string {
	duration := formatDuration(m.ElapsedTime())

	left := footerStyle.Render(fmt.Sprintf("Duration: %s", duration))

	// Help hints
	helpItems := []string{"q=quit", "↑↓=scroll"}
	if m.done {
		helpItems = append(helpItems, "done")
	}
	right := helpStyle.Render(strings.Join(helpItems, "  "))

	// Calculate spacing
	spacing := m.width - lipgloss.Width(left) - lipgloss.Width(right) - 4
	if spacing < 1 {
		spacing = 1
	}

	return fmt.Sprintf("  %s%s%s  ", left, strings.Repeat(" ", spacing), right)
}

// formatDuration formats a duration for display.
func formatDuration(d time.Duration) string {
	d = d.Round(time.Second)
	h := d / time.Hour
	d -= h * time.Hour
	m := d / time.Minute
	d -= m * time.Minute
	s := d / time.Second

	if h > 0 {
		return fmt.Sprintf("%02d:%02d:%02d", h, m, s)
	}
	return fmt.Sprintf("%02d:%02d", m, s)
}
