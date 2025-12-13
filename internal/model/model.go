// Package model defines core types used throughout the devsec application.
package model

// Severity represents the severity level of a finding.
type Severity string

const (
	// SeverityCritical represents critical severity findings.
	SeverityCritical Severity = "critical"
	// SeverityHigh represents high severity findings.
	SeverityHigh Severity = "high"
	// SeverityMedium represents medium severity findings.
	SeverityMedium Severity = "medium"
	// SeverityLow represents low severity findings.
	SeverityLow Severity = "low"
	// SeverityInfo represents informational findings.
	SeverityInfo Severity = "info"
)

// Finding represents a single security or compliance finding.
// Fields ordered for optimal memory alignment.
type Finding struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Rule        string   `json:"rule"`
	Scanner     string   `json:"scanner"`
	Severity    Severity `json:"severity"`
	Location    Location `json:"location"`
}

// Location represents the location of a finding in source code.
type Location struct {
	File      string `json:"file"`
	StartLine int    `json:"start_line"`
	EndLine   int    `json:"end_line"`
	Column    int    `json:"column,omitempty"`
}

// Report represents an aggregated report from multiple scanners.
// Fields ordered for optimal memory alignment.
type Report struct {
	Metadata  map[string]string `json:"metadata"`
	Timestamp string            `json:"timestamp"`
	Findings  []Finding         `json:"findings"`
	Summary   Summary           `json:"summary"`
}

// Summary provides a summary of findings by severity.
type Summary struct {
	Total    int `json:"total"`
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
}
