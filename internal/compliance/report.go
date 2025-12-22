package compliance

import (
	"context"
	"fmt"
	"time"

	"github.com/victoralfred/devsec/internal/model"
)

// ReportGenerator generates compliance reports.
type ReportGenerator struct {
	mapper   *DefaultMapper
	coverage *CoverageCalculator
	gap      *GapAnalyzer
}

// NewReportGenerator creates a new report generator.
func NewReportGenerator(mapper *DefaultMapper) *ReportGenerator {
	return &ReportGenerator{
		mapper:   mapper,
		coverage: NewCoverageCalculator(mapper),
		gap:      NewGapAnalyzer(mapper),
	}
}

// GenerateOptions configures report generation.
type GenerateOptions struct {
	Frameworks      []FrameworkID
	IncludeEvidence bool
	IncludeGaps     bool
}

// DefaultGenerateOptions returns default generation options.
func DefaultGenerateOptions() GenerateOptions {
	return GenerateOptions{
		Frameworks:      nil, // All frameworks.
		IncludeEvidence: true,
		IncludeGaps:     true,
	}
}

// Generate creates a compliance report from findings.
func (r *ReportGenerator) Generate(ctx context.Context, findings []model.Finding, opts GenerateOptions) (*Report, error) {
	// Input validation.
	if r == nil {
		return nil, fmt.Errorf("report generator cannot be nil")
	}
	if ctx == nil {
		return nil, fmt.Errorf("context cannot be nil")
	}
	if findings == nil {
		findings = []model.Finding{} // Allow nil, treat as empty slice
	}

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	// Enrich findings with CWE/CVE and control mappings.
	enriched, err := r.mapper.Enrich(ctx, findings)
	if err != nil {
		return nil, err
	}

	// Map to controls.
	assessments, err := r.mapper.MapToControls(ctx, enriched, opts.Frameworks)
	if err != nil {
		return nil, err
	}

	// Create report.
	report := NewReport()

	// Add assessments.
	for framework, controls := range assessments {
		// Check limit to prevent DoS.
		if len(controls) > MaxAssessments {
			controls = controls[:MaxAssessments]
		}
		for i := range controls {
			report.AddAssessment(framework, controls[i])
		}
	}

	// Add gaps if requested.
	if opts.IncludeGaps {
		gaps, err := r.gap.Analyze(ctx, assessments)
		if err != nil {
			return nil, err
		}
		// Check limit to prevent DoS.
		if len(gaps) > MaxGaps {
			gaps = gaps[:MaxGaps]
		}
		for i := range gaps {
			report.AddGap(gaps[i])
		}
	}

	// Calculate summary.
	report.CalculateSummary()

	return report, nil
}

// GenerateFromAssessments creates a report from existing assessments.
func (r *ReportGenerator) GenerateFromAssessments(ctx context.Context, assessments map[FrameworkID][]ControlAssessment, opts GenerateOptions) (*Report, error) {
	// Input validation.
	if r == nil {
		return nil, fmt.Errorf("report generator cannot be nil")
	}
	if ctx == nil {
		return nil, fmt.Errorf("context cannot be nil")
	}
	if assessments == nil {
		assessments = make(map[FrameworkID][]ControlAssessment) // Allow nil, treat as empty map
	}

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	report := NewReport()

	// Add assessments.
	for framework, controls := range assessments {
		// Check limit to prevent DoS.
		if len(controls) > MaxAssessments {
			controls = controls[:MaxAssessments]
		}
		for i := range controls {
			report.AddAssessment(framework, controls[i])
		}
	}

	// Add gaps if requested.
	if opts.IncludeGaps {
		gaps, err := r.gap.Analyze(ctx, assessments)
		if err != nil {
			return nil, err
		}
		// Check limit to prevent DoS.
		if len(gaps) > MaxGaps {
			gaps = gaps[:MaxGaps]
		}
		for i := range gaps {
			report.AddGap(gaps[i])
		}
	}

	report.CalculateSummary()

	return report, nil
}

// GetCoverageStats returns coverage statistics for a report.
func (r *ReportGenerator) GetCoverageStats(ctx context.Context, report *Report) ([]CoverageStats, error) {
	return r.coverage.Calculate(ctx, report.Assessments)
}

// GetOverallCoverage returns overall coverage for a report.
func (r *ReportGenerator) GetOverallCoverage(ctx context.Context, report *Report) (CoverageStats, error) {
	return r.coverage.CalculateOverall(ctx, report.Assessments)
}

// GetGapSummary returns a gap summary for the report.
func (r *ReportGenerator) GetGapSummary(report *Report) GapSummary {
	return r.gap.Summarize(report.Gaps)
}

// ReportMetadata contains report metadata.
type ReportMetadata struct {
	GeneratedAt   time.Time `json:"generated_at"`
	GeneratedBy   string    `json:"generated_by"`
	Version       string    `json:"version"`
	ScanTimestamp time.Time `json:"scan_timestamp,omitempty"`
	SourceFiles   []string  `json:"source_files,omitempty"`
}

// EnhancedReport adds metadata to a standard report.
// Fields ordered for optimal memory alignment.
type EnhancedReport struct {
	Report   *Report        `json:"report"`
	Metadata ReportMetadata `json:"metadata"`
}

// NewEnhancedReport creates an enhanced report with metadata.
func NewEnhancedReport(report *Report) *EnhancedReport {
	return &EnhancedReport{
		Metadata: ReportMetadata{
			GeneratedAt: time.Now(),
			GeneratedBy: "devsec",
			Version:     "1.0.0",
		},
		Report: report,
	}
}

// WithScanTimestamp sets the scan timestamp.
func (e *EnhancedReport) WithScanTimestamp(t time.Time) *EnhancedReport {
	e.Metadata.ScanTimestamp = t
	return e
}

// WithSourceFiles sets the source files.
func (e *EnhancedReport) WithSourceFiles(files []string) *EnhancedReport {
	e.Metadata.SourceFiles = files
	return e
}

// FrameworkReport extracts a single framework report.
type FrameworkReport struct {
	Framework   FrameworkID         `json:"framework"`
	GeneratedAt time.Time           `json:"generated_at"`
	Assessments []ControlAssessment `json:"assessments"`
	Gaps        []Gap               `json:"gaps"`
	Summary     FrameworkSummary    `json:"summary"`
}

// ExtractFrameworkReport creates a report for a single framework.
func ExtractFrameworkReport(report *Report, framework FrameworkID) *FrameworkReport {
	fr := &FrameworkReport{
		Framework:   framework,
		GeneratedAt: report.GeneratedAt,
		Assessments: report.Assessments[framework],
	}

	// Filter gaps for this framework.
	for i := range report.Gaps {
		if FrameworkID(report.Gaps[i].Control.Framework) == framework {
			fr.Gaps = append(fr.Gaps, report.Gaps[i])
		}
	}

	// Calculate summary.
	fr.calculateSummary()

	return fr
}

// calculateSummary calculates the framework summary.
func (fr *FrameworkReport) calculateSummary() {
	summary := FrameworkSummary{
		Framework: fr.Framework,
	}

	for i := range fr.Assessments {
		summary.TotalControls++
		switch fr.Assessments[i].Status {
		case StatusCompliant:
			summary.CompliantCount++
		case StatusNonCompliant:
			summary.NonCompliantCount++
		case StatusPartial:
			summary.PartialCount++
		case StatusNotAssessed:
			summary.NotAssessedCount++
		}
	}

	if summary.TotalControls > 0 {
		summary.CoveragePercent = float64(summary.CompliantCount) / float64(summary.TotalControls) * 100
	}

	fr.Summary = summary
}
