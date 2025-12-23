package compliance

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Formatter formats compliance reports.
type Formatter interface {
	Format(report *Report) ([]byte, error)
	FormatFramework(report *FrameworkReport) ([]byte, error)
	FormatSummary(summary Summary) ([]byte, error)
	ContentType() string
}

// JSONFormatter formats reports as JSON.
type JSONFormatter struct {
	Pretty bool
}

// NewJSONFormatter creates a new JSON formatter.
func NewJSONFormatter(pretty bool) *JSONFormatter {
	return &JSONFormatter{Pretty: pretty}
}

// Format formats a report as JSON.
func (f *JSONFormatter) Format(report *Report) ([]byte, error) {
	if f.Pretty {
		return json.MarshalIndent(report, "", "  ")
	}
	return json.Marshal(report)
}

// FormatFramework formats a framework report as JSON.
func (f *JSONFormatter) FormatFramework(report *FrameworkReport) ([]byte, error) {
	if f.Pretty {
		return json.MarshalIndent(report, "", "  ")
	}
	return json.Marshal(report)
}

// FormatSummary formats a summary as JSON.
func (f *JSONFormatter) FormatSummary(summary Summary) ([]byte, error) {
	if f.Pretty {
		return json.MarshalIndent(summary, "", "  ")
	}
	return json.Marshal(summary)
}

// ContentType returns the content type.
func (f *JSONFormatter) ContentType() string {
	return "application/json"
}

// MarkdownFormatter formats reports as Markdown.
type MarkdownFormatter struct {
	IncludeDetails bool
}

// NewMarkdownFormatter creates a new Markdown formatter.
func NewMarkdownFormatter(includeDetails bool) *MarkdownFormatter {
	return &MarkdownFormatter{IncludeDetails: includeDetails}
}

// Format formats a report as Markdown.
func (f *MarkdownFormatter) Format(report *Report) ([]byte, error) {
	var sb strings.Builder
	sb.Grow(4096) // Pre-allocate capacity for better performance

	sb.WriteString("# Compliance Report\n\n")
	sb.WriteString(fmt.Sprintf("Generated: %s\n\n", report.GeneratedAt.Format(time.RFC3339)))

	// Overall summary.
	sb.WriteString("## Executive Summary\n\n")
	f.writeSummary(&sb, report.Summary)

	// Framework summaries.
	sb.WriteString("## Framework Summary\n\n")
	for fwID, fw := range report.Summary.FrameworkSummaries {
		sb.WriteString(fmt.Sprintf("### %s\n\n", strings.ToUpper(string(fwID))))
		sb.WriteString(fmt.Sprintf("- **Compliance**: %.1f%%\n", fw.CoveragePercent))
		sb.WriteString(fmt.Sprintf("- **Compliant**: %d/%d controls\n", fw.CompliantCount, fw.TotalControls))
		sb.WriteString(fmt.Sprintf("- **Non-Compliant**: %d\n", fw.NonCompliantCount))
		sb.WriteString(fmt.Sprintf("- **Partial**: %d\n", fw.PartialCount))
		sb.WriteString(fmt.Sprintf("- **Not Assessed**: %d\n\n", fw.NotAssessedCount))
	}

	// Gaps.
	if len(report.Gaps) > 0 {
		sb.WriteString("## Compliance Gaps\n\n")
		f.writeGaps(&sb, report.Gaps)
	}

	// Detailed assessments.
	if f.IncludeDetails {
		sb.WriteString("## Detailed Assessments\n\n")
		for framework, assessments := range report.Assessments {
			sb.WriteString(fmt.Sprintf("### %s\n\n", strings.ToUpper(string(framework))))
			f.writeAssessments(&sb, assessments)
		}
	}

	return []byte(sb.String()), nil
}

// writeSummary writes the summary section.
func (f *MarkdownFormatter) writeSummary(sb *strings.Builder, summary Summary) {
	sb.WriteString("| Metric | Value |\n")
	sb.WriteString("|--------|-------|\n")
	fmt.Fprintf(sb, "| Total Controls | %d |\n", summary.TotalControls)
	fmt.Fprintf(sb, "| Compliant | %d |\n", summary.CompliantCount)
	fmt.Fprintf(sb, "| Non-Compliant | %d |\n", summary.NonCompliantCount)
	fmt.Fprintf(sb, "| Partial | %d |\n", summary.PartialCount)
	fmt.Fprintf(sb, "| Not Assessed | %d |\n", summary.NotAssessedCount)
	fmt.Fprintf(sb, "| Overall Compliance | %.1f%% |\n\n", summary.OverallScore)
}

// writeGaps writes the gaps section.
func (f *MarkdownFormatter) writeGaps(sb *strings.Builder, gaps []Gap) {
	// Group by severity.
	critical := make([]Gap, 0)
	high := make([]Gap, 0)
	medium := make([]Gap, 0)
	low := make([]Gap, 0)

	for i := range gaps {
		switch gaps[i].Severity {
		case "critical":
			critical = append(critical, gaps[i])
		case "high":
			high = append(high, gaps[i])
		case "medium":
			medium = append(medium, gaps[i])
		case "low":
			low = append(low, gaps[i])
		}
	}

	if len(critical) > 0 {
		sb.WriteString("#### Critical\n\n")
		f.writeGapList(sb, critical)
	}
	if len(high) > 0 {
		sb.WriteString("#### High\n\n")
		f.writeGapList(sb, high)
	}
	if len(medium) > 0 {
		sb.WriteString("#### Medium\n\n")
		f.writeGapList(sb, medium)
	}
	if len(low) > 0 {
		sb.WriteString("#### Low\n\n")
		f.writeGapList(sb, low)
	}
}

// writeGapList writes a list of gaps.
func (f *MarkdownFormatter) writeGapList(sb *strings.Builder, gaps []Gap) {
	for i := range gaps {
		gap := &gaps[i]
		fmt.Fprintf(sb, "- **%s** (%s): %s\n", gap.Control.ID, gap.Control.Framework, gap.Description)
		if gap.Remediation != "" {
			fmt.Fprintf(sb, "  - Remediation: %s\n", gap.Remediation)
		}
		if gap.FindingCount > 0 {
			fmt.Fprintf(sb, "  - Findings: %d\n", gap.FindingCount)
		}
	}
	sb.WriteString("\n")
}

// writeAssessments writes the assessments section.
func (f *MarkdownFormatter) writeAssessments(sb *strings.Builder, assessments []ControlAssessment) {
	sb.WriteString("| Control | Status | Findings |\n")
	sb.WriteString("|---------|--------|----------|\n")

	for i := range assessments {
		a := &assessments[i]
		status := statusEmoji(a.Status)
		fmt.Fprintf(sb, "| %s | %s %s | %d |\n", a.Control.ID, status, a.Status, a.FindingCount)
	}
	sb.WriteString("\n")
}

// statusEmoji returns an emoji for the status.
func statusEmoji(status ControlStatus) string {
	switch status {
	case StatusCompliant:
		return "✅"
	case StatusNonCompliant:
		return "❌"
	case StatusPartial:
		return "⚠️"
	case StatusNotAssessed:
		return "❓"
	default:
		return ""
	}
}

// FormatFramework formats a framework report as Markdown.
func (f *MarkdownFormatter) FormatFramework(report *FrameworkReport) ([]byte, error) {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("# %s Compliance Report\n\n", strings.ToUpper(string(report.Framework))))
	sb.WriteString(fmt.Sprintf("Generated: %s\n\n", report.GeneratedAt.Format(time.RFC3339)))

	// Summary.
	sb.WriteString("## Summary\n\n")
	sb.WriteString(fmt.Sprintf("- **Compliance**: %.1f%%\n", report.Summary.CoveragePercent))
	sb.WriteString(fmt.Sprintf("- **Total Controls**: %d\n", report.Summary.TotalControls))
	sb.WriteString(fmt.Sprintf("- **Compliant**: %d\n", report.Summary.CompliantCount))
	sb.WriteString(fmt.Sprintf("- **Non-Compliant**: %d\n", report.Summary.NonCompliantCount))
	sb.WriteString(fmt.Sprintf("- **Partial**: %d\n", report.Summary.PartialCount))
	sb.WriteString(fmt.Sprintf("- **Not Assessed**: %d\n\n", report.Summary.NotAssessedCount))

	// Gaps.
	if len(report.Gaps) > 0 {
		sb.WriteString("## Gaps\n\n")
		f.writeGaps(&sb, report.Gaps)
	}

	// Assessments.
	if f.IncludeDetails {
		sb.WriteString("## Control Assessments\n\n")
		f.writeAssessments(&sb, report.Assessments)
	}

	return []byte(sb.String()), nil
}

// FormatSummary formats a summary as Markdown.
func (f *MarkdownFormatter) FormatSummary(summary Summary) ([]byte, error) {
	var sb strings.Builder
	sb.Grow(1024) // Pre-allocate capacity for better performance

	sb.WriteString("# Compliance Summary\n\n")
	f.writeSummary(&sb, summary)

	if len(summary.FrameworkSummaries) > 0 {
		sb.WriteString("## By Framework\n\n")
		for fwID, fw := range summary.FrameworkSummaries {
			sb.WriteString(fmt.Sprintf("- **%s**: %.1f%% (%d/%d compliant)\n",
				strings.ToUpper(string(fwID)),
				fw.CoveragePercent,
				fw.CompliantCount,
				fw.TotalControls))
		}
	}

	return []byte(sb.String()), nil
}

// ContentType returns the content type.
func (f *MarkdownFormatter) ContentType() string {
	return "text/markdown"
}

// GetFormatter returns a formatter by name.
func GetFormatter(format string, opts ...FormatterOption) Formatter {
	config := &formatterConfig{
		pretty:         true,
		includeDetails: true,
	}

	for _, opt := range opts {
		opt(config)
	}

	switch format {
	case "json":
		return NewJSONFormatter(config.pretty)
	case "markdown", "md":
		return NewMarkdownFormatter(config.includeDetails)
	default:
		return NewJSONFormatter(config.pretty)
	}
}

// formatterConfig holds formatter configuration.
type formatterConfig struct {
	pretty         bool
	includeDetails bool
}

// FormatterOption configures a formatter.
type FormatterOption func(*formatterConfig)

// WithPretty enables pretty printing.
func WithPretty(pretty bool) FormatterOption {
	return func(c *formatterConfig) {
		c.pretty = pretty
	}
}

// WithDetails includes detailed assessments.
func WithDetails(details bool) FormatterOption {
	return func(c *formatterConfig) {
		c.includeDetails = details
	}
}
