// Package report provides functionality for aggregating and formatting security findings.
package report

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/victoralfred/devsec/internal/model"
)

const (
	// MaxFindings is the maximum number of findings allowed to prevent memory exhaustion.
	MaxFindings = 100000
	// MaxScannerNameLength is the maximum length for scanner names.
	MaxScannerNameLength = 256
)

// Aggregator combines findings from multiple scanners.
// Fields ordered for optimal memory alignment.
type Aggregator struct {
	persister      ResultsPersister
	scannerResults map[string]ScannerResult
	findings       []model.Finding
	mu             sync.RWMutex
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

// WithPersister sets the results persister for the aggregator.
// When set, the PersistReport method can be used to save results.
func WithPersister(persister ResultsPersister) AggregatorOption {
	return func(a *Aggregator) {
		a.persister = persister
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
func (a *Aggregator) AddFindings(scanner string, findings []model.Finding) error {
	// Validate scanner name
	if scanner == "" {
		return fmt.Errorf("scanner name cannot be empty")
	}
	if len(scanner) > MaxScannerNameLength {
		return fmt.Errorf("scanner name too long: %d characters (max %d)", len(scanner), MaxScannerNameLength)
	}

	// Validate findings count
	a.mu.Lock()
	defer a.mu.Unlock()

	newCount := len(a.findings) + len(findings)
	if newCount > MaxFindings {
		return fmt.Errorf("findings limit exceeded: %d (max %d)", newCount, MaxFindings)
	}

	result := ScannerResult{
		Scanner:   scanner,
		Findings:  findings,
		Timestamp: time.Now(),
	}
	a.scannerResults[scanner] = result
	a.findings = append(a.findings, findings...)
	return nil
}

// AddResult adds a complete scanner result to the aggregator.
func (a *Aggregator) AddResult(result ScannerResult) error {
	// Validate scanner name
	if result.Scanner == "" {
		return fmt.Errorf("scanner name cannot be empty")
	}
	if len(result.Scanner) > MaxScannerNameLength {
		return fmt.Errorf("scanner name too long: %d characters (max %d)", len(result.Scanner), MaxScannerNameLength)
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	// Validate findings count
	newCount := len(a.findings) + len(result.Findings)
	if newCount > MaxFindings {
		return fmt.Errorf("findings limit exceeded: %d (max %d)", newCount, MaxFindings)
	}

	a.scannerResults[result.Scanner] = result
	a.findings = append(a.findings, result.Findings...)
	return nil
}

// Aggregate returns the aggregated report.
func (a *Aggregator) Aggregate(ctx context.Context) (*model.Report, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	a.mu.RLock()
	findings := make([]model.Finding, len(a.findings))
	copy(findings, a.findings)
	dedupeEnabled := a.dedupeEnabled
	scannerResults := make(map[string]ScannerResult, len(a.scannerResults))
	for k, v := range a.scannerResults {
		scannerResults[k] = v
	}
	a.mu.RUnlock()

	if dedupeEnabled {
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
		Metadata:  a.buildMetadata(scannerResults),
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
	if f == nil {
		return ""
	}
	data := strings.Join([]string{
		f.Location.File,
		f.Rule,
		strconv.Itoa(f.Location.StartLine),
		strconv.Itoa(f.Location.EndLine),
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
func (a *Aggregator) buildMetadata(scannerResults map[string]ScannerResult) map[string]string {
	metadata := make(map[string]string, 2)

	scanners := make([]string, 0, len(scannerResults))
	for scanner := range scannerResults {
		scanners = append(scanners, scanner)
	}
	sort.Strings(scanners)
	metadata["scanners"] = strings.Join(scanners, ",")
	metadata["scanner_count"] = strconv.Itoa(len(scanners))

	return metadata
}

// GetScannerResults returns results for all scanners.
func (a *Aggregator) GetScannerResults() map[string]ScannerResult {
	a.mu.RLock()
	defer a.mu.RUnlock()

	result := make(map[string]ScannerResult, len(a.scannerResults))
	for k, v := range a.scannerResults {
		result[k] = v
	}
	return result
}

// FindingCount returns the total number of findings before deduplication.
func (a *Aggregator) FindingCount() int {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return len(a.findings)
}

// PersistReport aggregates the report and persists it using the configured persister.
// Returns an error if no persister is configured.
func (a *Aggregator) PersistReport(ctx context.Context, format string) error {
	if a.persister == nil {
		return fmt.Errorf("no persister configured")
	}

	report, err := a.Aggregate(ctx)
	if err != nil {
		return fmt.Errorf("aggregate report: %w", err)
	}

	return a.persister.Persist(ctx, report, format)
}

// SetPersister sets the results persister after creation.
func (a *Aggregator) SetPersister(persister ResultsPersister) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.persister = persister
}

// HasPersister returns whether a persister is configured.
func (a *Aggregator) HasPersister() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.persister != nil
}
