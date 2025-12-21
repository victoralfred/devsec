// Package report provides functionality for aggregating and formatting security findings.
package report

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/victoralfred/devsec/internal/model"
	"github.com/victoralfred/gowritter/safepath"
)

// Formatter defines the interface for report formatters.
type Formatter interface {
	// Format formats the report and returns the formatted bytes.
	Format(ctx context.Context, report *model.Report) ([]byte, error)
	// Extension returns the file extension for this format.
	Extension() string
}

// JSONFormatter formats reports as JSON.
type JSONFormatter struct {
	indent bool
}

// NewJSONFormatter creates a new JSON formatter.
func NewJSONFormatter(indent bool) *JSONFormatter {
	return &JSONFormatter{indent: indent}
}

// Format formats the report as JSON.
func (f *JSONFormatter) Format(ctx context.Context, report *model.Report) ([]byte, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	if f.indent {
		return json.MarshalIndent(report, "", "  ")
	}
	return json.Marshal(report)
}

// Extension returns the file extension for JSON format.
func (f *JSONFormatter) Extension() string {
	return ".json"
}

// SARIFFormatter formats reports in SARIF format.
type SARIFFormatter struct{}

// NewSARIFFormatter creates a new SARIF formatter.
func NewSARIFFormatter() *SARIFFormatter {
	return &SARIFFormatter{}
}

// SARIFReport represents a SARIF report structure.
// Fields ordered for optimal memory alignment.
type SARIFReport struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []SARIFRun `json:"runs"`
}

// SARIFRun represents a single run in a SARIF report.
// Fields ordered for optimal memory alignment.
type SARIFRun struct {
	Tool    SARIFTool     `json:"tool"`
	Results []SARIFResult `json:"results"`
}

// SARIFTool represents the tool that produced the results.
// Fields ordered for optimal memory alignment.
type SARIFTool struct {
	Driver SARIFDriver `json:"driver"`
}

// SARIFDriver represents the driver (scanner) information.
// Fields ordered for optimal memory alignment.
type SARIFDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version,omitempty"`
	InformationURI string      `json:"informationUri,omitempty"`
	Rules          []SARIFRule `json:"rules,omitempty"`
}

// SARIFRule represents a rule definition.
// Fields ordered for optimal memory alignment.
type SARIFRule struct {
	ID               string              `json:"id"`
	Name             string              `json:"name,omitempty"`
	ShortDescription SARIFMessage        `json:"shortDescription,omitempty"`
	DefaultConfig    SARIFDefaultConfig  `json:"defaultConfiguration,omitempty"`
	Properties       SARIFRuleProperties `json:"properties,omitempty"`
}

// SARIFMessage represents a message in SARIF format.
type SARIFMessage struct {
	Text string `json:"text"`
}

// SARIFDefaultConfig represents default configuration for a rule.
type SARIFDefaultConfig struct {
	Level string `json:"level"`
}

// SARIFRuleProperties represents additional rule properties.
type SARIFRuleProperties struct {
	Precision string   `json:"precision,omitempty"`
	Tags      []string `json:"tags,omitempty"`
}

// SARIFResult represents a single result in SARIF format.
// Fields ordered for optimal memory alignment.
type SARIFResult struct {
	Message   SARIFMessage    `json:"message"`
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Locations []SARIFLocation `json:"locations,omitempty"`
	RuleIndex int             `json:"ruleIndex,omitempty"`
}

// SARIFLocation represents a location in SARIF format.
type SARIFLocation struct {
	PhysicalLocation SARIFPhysicalLocation `json:"physicalLocation"`
}

// SARIFPhysicalLocation represents a physical location in SARIF format.
type SARIFPhysicalLocation struct {
	ArtifactLocation SARIFArtifactLocation `json:"artifactLocation"`
	Region           SARIFRegion           `json:"region,omitempty"`
}

// SARIFArtifactLocation represents an artifact location.
type SARIFArtifactLocation struct {
	URI string `json:"uri"`
}

// SARIFRegion represents a region in a file.
type SARIFRegion struct {
	StartLine   int `json:"startLine,omitempty"`
	EndLine     int `json:"endLine,omitempty"`
	StartColumn int `json:"startColumn,omitempty"`
}

// Format formats the report as SARIF.
func (f *SARIFFormatter) Format(ctx context.Context, report *model.Report) ([]byte, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	sarif := f.buildSARIF(report)
	return json.MarshalIndent(sarif, "", "  ")
}

// buildSARIF converts a model.Report to SARIF format.
func (f *SARIFFormatter) buildSARIF(report *model.Report) *SARIFReport {
	// Group findings by scanner
	scannerFindings := make(map[string][]model.Finding)
	for i := range report.Findings {
		scanner := report.Findings[i].Scanner
		if scanner == "" {
			scanner = "devsec"
		}
		scannerFindings[scanner] = append(scannerFindings[scanner], report.Findings[i])
	}

	runs := make([]SARIFRun, 0, len(scannerFindings))
	for scanner, findings := range scannerFindings {
		run := f.buildRun(scanner, findings)
		runs = append(runs, run)
	}

	return &SARIFReport{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs:    runs,
	}
}

// buildRun builds a SARIF run from findings.
func (f *SARIFFormatter) buildRun(scanner string, findings []model.Finding) SARIFRun {
	rules := make(map[string]SARIFRule)
	results := make([]SARIFResult, 0, len(findings))

	for i := range findings {
		finding := &findings[i]

		// Create rule if not exists
		if _, ok := rules[finding.Rule]; !ok && finding.Rule != "" {
			rules[finding.Rule] = SARIFRule{
				ID:               finding.Rule,
				Name:             finding.Title,
				ShortDescription: SARIFMessage{Text: finding.Title},
				DefaultConfig:    SARIFDefaultConfig{Level: severityToSARIFLevel(finding.Severity)},
			}
		}

		result := SARIFResult{
			RuleID:  finding.Rule,
			Level:   severityToSARIFLevel(finding.Severity),
			Message: SARIFMessage{Text: finding.Description},
		}

		if finding.Location.File != "" {
			result.Locations = []SARIFLocation{
				{
					PhysicalLocation: SARIFPhysicalLocation{
						ArtifactLocation: SARIFArtifactLocation{URI: finding.Location.File},
						Region: SARIFRegion{
							StartLine:   finding.Location.StartLine,
							EndLine:     finding.Location.EndLine,
							StartColumn: finding.Location.Column,
						},
					},
				},
			}
		}

		results = append(results, result)
	}

	rulesSlice := make([]SARIFRule, 0, len(rules))
	for _, rule := range rules {
		rulesSlice = append(rulesSlice, rule)
	}

	return SARIFRun{
		Tool: SARIFTool{
			Driver: SARIFDriver{
				Name:  scanner,
				Rules: rulesSlice,
			},
		},
		Results: results,
	}
}

// severityToSARIFLevel converts severity to SARIF level.
func severityToSARIFLevel(severity model.Severity) string {
	switch severity {
	case model.SeverityCritical, model.SeverityHigh:
		return "error"
	case model.SeverityMedium:
		return "warning"
	case model.SeverityLow, model.SeverityInfo:
		return "note"
	default:
		return "none"
	}
}

// Extension returns the file extension for SARIF format.
func (f *SARIFFormatter) Extension() string {
	return ".sarif.json"
}

// MarkdownFormatter formats reports as Markdown.
type MarkdownFormatter struct{}

// NewMarkdownFormatter creates a new Markdown formatter.
func NewMarkdownFormatter() *MarkdownFormatter {
	return &MarkdownFormatter{}
}

// Format formats the report as Markdown.
func (f *MarkdownFormatter) Format(ctx context.Context, report *model.Report) ([]byte, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	if report == nil {
		return nil, fmt.Errorf("report cannot be nil")
	}

	var sb strings.Builder
	sb.Grow(4096) // Pre-allocate capacity for better performance

	// Header
	sb.WriteString("# Security Scan Report\n\n")
	sb.WriteString(fmt.Sprintf("**Generated**: %s\n\n", report.Timestamp))

	// Summary
	sb.WriteString("## Summary\n\n")
	sb.WriteString("| Severity | Count |\n")
	sb.WriteString("|----------|-------|\n")
	sb.WriteString(fmt.Sprintf("| Critical | %d |\n", report.Summary.Critical))
	sb.WriteString(fmt.Sprintf("| High | %d |\n", report.Summary.High))
	sb.WriteString(fmt.Sprintf("| Medium | %d |\n", report.Summary.Medium))
	sb.WriteString(fmt.Sprintf("| Low | %d |\n", report.Summary.Low))
	sb.WriteString(fmt.Sprintf("| Info | %d |\n", report.Summary.Info))
	sb.WriteString(fmt.Sprintf("| **Total** | **%d** |\n\n", report.Summary.Total))

	if len(report.Findings) == 0 {
		sb.WriteString("No findings detected.\n")
		return []byte(sb.String()), nil
	}

	// Findings by severity
	sb.WriteString("## Findings\n\n")

	// Group by severity
	severities := []model.Severity{
		model.SeverityCritical,
		model.SeverityHigh,
		model.SeverityMedium,
		model.SeverityLow,
		model.SeverityInfo,
	}

	for _, sev := range severities {
		findings := filterBySeverity(report.Findings, sev)
		if len(findings) == 0 {
			continue
		}

		sb.WriteString(fmt.Sprintf("### %s (%d)\n\n", titleCase(string(sev)), len(findings)))

		for i := range findings {
			finding := &findings[i]
			sb.WriteString(fmt.Sprintf("#### %s\n\n", finding.Title))
			sb.WriteString(fmt.Sprintf("- **ID**: %s\n", finding.ID))
			sb.WriteString(fmt.Sprintf("- **Rule**: %s\n", finding.Rule))
			sb.WriteString(fmt.Sprintf("- **Scanner**: %s\n", finding.Scanner))

			if finding.Location.File != "" {
				loc := finding.Location.File
				if finding.Location.StartLine > 0 {
					loc = fmt.Sprintf("%s:%d", loc, finding.Location.StartLine)
					if finding.Location.EndLine > finding.Location.StartLine {
						loc = fmt.Sprintf("%s-%d", loc, finding.Location.EndLine)
					}
				}
				sb.WriteString(fmt.Sprintf("- **Location**: `%s`\n", loc))
			}

			if finding.Description != "" {
				sb.WriteString(fmt.Sprintf("\n%s\n", finding.Description))
			}
			sb.WriteString("\n")
		}
	}

	return []byte(sb.String()), nil
}

// filterBySeverity filters findings by severity.
func filterBySeverity(findings []model.Finding, severity model.Severity) []model.Finding {
	result := make([]model.Finding, 0)
	for i := range findings {
		if findings[i].Severity == severity {
			result = append(result, findings[i])
		}
	}
	return result
}

// titleCase converts the first character of a string to uppercase.
func titleCase(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// Extension returns the file extension for Markdown format.
func (f *MarkdownFormatter) Extension() string {
	return ".md"
}

// WriteReport writes a formatted report to a file.
func WriteReport(ctx context.Context, path string, report *model.Report, formatter Formatter) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}

	data, err := formatter.Format(ctx, report)
	if err != nil {
		return fmt.Errorf("format report: %w", err)
	}

	// Get the directory from the path for safepath
	dir := filepath.Dir(path)
	filename := filepath.Base(path)

	sp, err := safepath.New(dir)
	if err != nil {
		return fmt.Errorf("create safepath: %w", err)
	}

	if err := sp.WriteFile(filename, data, 0o644); err != nil {
		return fmt.Errorf("write report: %w", err)
	}

	return nil
}

// FormatReport formats a report using the specified format string.
func FormatReport(ctx context.Context, report *model.Report, format string) ([]byte, error) {
	var formatter Formatter

	switch strings.ToLower(format) {
	case "json":
		formatter = NewJSONFormatter(true)
	case "sarif":
		formatter = NewSARIFFormatter()
	case "markdown", "md":
		formatter = NewMarkdownFormatter()
	default:
		return nil, fmt.Errorf("unsupported format: %s", format)
	}

	return formatter.Format(ctx, report)
}

// GenerateReport creates a complete report with timestamp.
func GenerateReport(findings []model.Finding) *model.Report {
	return &model.Report{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Findings:  findings,
		Summary:   calculateSummary(findings),
		Metadata:  make(map[string]string),
	}
}
