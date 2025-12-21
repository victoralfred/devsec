// Package report provides functionality for aggregating and formatting security findings.
package report

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
	"time"

	"github.com/victoralfred/devsec/internal/model"
)

// Aggregator combines findings from multiple scanners.
// Fields ordered for optimal memory alignment.
type Aggregator struct {
	scannerResults map[string]ScannerResult
	findings       []model.Finding
	dedupeEnabled  bool
}

// ScannerResult holds results from a single scanner run.
// Fields ordered for optimal memory alignment.
type ScannerResult struct {
	Timestamp time.Time       `json:"timestamp"`
	Scanner   string          `json:"scanner"`
	Version   string          `json:"version,omitempty"`
	Error     string          `json:"error,omitempty"`
	Findings  []model.Finding `json:"findings"`
	Duration  time.Duration   `json:"duration"`
}

// AggregatorOption configures the aggregator.
type AggregatorOption func(*Aggregator)

// WithDeduplication enables or disables finding deduplication.
func WithDeduplication(enabled bool) AggregatorOption {
	return func(a *Aggregator) {
		a.dedupeEnabled = enabled
	}
}

// New creates a new Aggregator with the given options.
func New(opts ...AggregatorOption) *Aggregator {
	a := &Aggregator{
		findings:       make([]model.Finding, 0),
		scannerResults: make(map[string]ScannerResult),
		dedupeEnabled:  true, // dedupe by default
	}
	for _, opt := range opts {
		opt(a)
	}
	return a
}

// AddFindings adds findings from a scanner to the aggregator.
func (a *Aggregator) AddFindings(scanner string, findings []model.Finding) {
	result := ScannerResult{
		Scanner:   scanner,
		Findings:  findings,
		Timestamp: time.Now(),
	}
	a.scannerResults[scanner] = result
	a.findings = append(a.findings, findings...)
}

// AddResult adds a complete scanner result to the aggregator.
func (a *Aggregator) AddResult(result ScannerResult) {
	a.scannerResults[result.Scanner] = result
	a.findings = append(a.findings, result.Findings...)
}

// Aggregate returns the aggregated report.
func (a *Aggregator) Aggregate(ctx context.Context) (*model.Report, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	findings := a.findings
	if a.dedupeEnabled {
		findings = a.deduplicate(findings)
	}

	// Normalize severities
	findings = normalizeSeverities(findings)

	// Sort by severity (critical first) then by file
	sortFindings(findings)

	report := &model.Report{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Findings:  findings,
		Summary:   calculateSummary(findings),
		Metadata:  a.buildMetadata(),
	}

	return report, nil
}

// deduplicate removes duplicate findings based on location and rule.
func (a *Aggregator) deduplicate(findings []model.Finding) []model.Finding {
	seen := make(map[string]bool)
	result := make([]model.Finding, 0, len(findings))

	for i := range findings {
		key := generateFindingKey(&findings[i])
		if !seen[key] {
			seen[key] = true
			result = append(result, findings[i])
		}
	}

	return result
}

// generateFindingKey creates a unique key for deduplication.
func generateFindingKey(f *model.Finding) string {
	data := strings.Join([]string{
		f.Location.File,
		f.Rule,
		string(rune(f.Location.StartLine)),
		string(rune(f.Location.EndLine)),
	}, "|")
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:8])
}

// normalizeSeverities ensures all findings have valid severity levels.
func normalizeSeverities(findings []model.Finding) []model.Finding {
	result := make([]model.Finding, len(findings))
	copy(result, findings)

	for i := range result {
		result[i].Severity = normalizeSeverity(result[i].Severity)
	}

	return result
}

// normalizeSeverity converts various severity representations to standard form.
func normalizeSeverity(s model.Severity) model.Severity {
	normalized := strings.ToLower(strings.TrimSpace(string(s)))

	switch normalized {
	case "critical", "crit":
		return model.SeverityCritical
	case "high", "error":
		return model.SeverityHigh
	case "medium", "med", "moderate", "warning":
		return model.SeverityMedium
	case "low":
		return model.SeverityLow
	case "info", "informational", "note":
		return model.SeverityInfo
	default:
		if normalized == "" {
			return model.SeverityInfo
		}
		return model.Severity(normalized)
	}
}

// sortFindings sorts findings by severity (critical first) then by file path.
func sortFindings(findings []model.Finding) {
	severityOrder := map[model.Severity]int{
		model.SeverityCritical: 0,
		model.SeverityHigh:     1,
		model.SeverityMedium:   2,
		model.SeverityLow:      3,
		model.SeverityInfo:     4,
	}

	sort.Slice(findings, func(i, j int) bool {
		oi, ok := severityOrder[findings[i].Severity]
		if !ok {
			oi = 5
		}
		oj, ok := severityOrder[findings[j].Severity]
		if !ok {
			oj = 5
		}
		if oi != oj {
			return oi < oj
		}
		return findings[i].Location.File < findings[j].Location.File
	})
}

// calculateSummary generates a summary of findings by severity.
func calculateSummary(findings []model.Finding) model.Summary {
	summary := model.Summary{
		Total: len(findings),
	}

	for i := range findings {
		switch findings[i].Severity {
		case model.SeverityCritical:
			summary.Critical++
		case model.SeverityHigh:
			summary.High++
		case model.SeverityMedium:
			summary.Medium++
		case model.SeverityLow:
			summary.Low++
		case model.SeverityInfo:
			summary.Info++
		}
	}

	return summary
}

// buildMetadata creates metadata for the report.
func (a *Aggregator) buildMetadata() map[string]string {
	metadata := make(map[string]string)

	scanners := make([]string, 0, len(a.scannerResults))
	for scanner := range a.scannerResults {
		scanners = append(scanners, scanner)
	}
	sort.Strings(scanners)
	metadata["scanners"] = strings.Join(scanners, ",")
	metadata["scanner_count"] = string(rune('0' + len(scanners)))

	return metadata
}

// GetScannerResults returns results for all scanners.
func (a *Aggregator) GetScannerResults() map[string]ScannerResult {
	return a.scannerResults
}

// FindingCount returns the total number of findings before deduplication.
func (a *Aggregator) FindingCount() int {
	return len(a.findings)
}
