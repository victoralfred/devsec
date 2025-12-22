// Package compliance provides compliance framework mapping and reporting.
package compliance

import (
	"sync"
	"time"

	"github.com/victoralfred/devsec/internal/model"
)

// FrameworkID identifies a compliance framework.
type FrameworkID string

const (
	// FrameworkSOC2 represents SOC 2 compliance framework.
	FrameworkSOC2 FrameworkID = "soc2"
	// FrameworkISO27001 represents ISO 27001 compliance framework.
	FrameworkISO27001 FrameworkID = "iso27001"
	// FrameworkGDPR represents GDPR compliance framework.
	FrameworkGDPR FrameworkID = "gdpr"
)

// Resource limits to prevent DoS and memory exhaustion.
const (
	// MaxFindings is the maximum number of findings that can be processed.
	MaxFindings = 100000
	// MaxEnrichedFindings is the maximum number of enriched findings.
	MaxEnrichedFindings = 100000
	// MaxAssessments is the maximum number of assessments per framework.
	MaxAssessments = 10000
	// MaxGaps is the maximum number of gaps that can be stored.
	MaxGaps = 5000
	// MaxControls is the maximum number of controls per framework.
	MaxControls = 10000
)

// ControlStatus represents the compliance status of a control.
type ControlStatus string

const (
	// StatusCompliant indicates the control is fully satisfied.
	StatusCompliant ControlStatus = "compliant"
	// StatusNonCompliant indicates the control has violations.
	StatusNonCompliant ControlStatus = "non_compliant"
	// StatusPartial indicates the control is partially satisfied.
	StatusPartial ControlStatus = "partial"
	// StatusNotAssessed indicates the control has not been assessed.
	StatusNotAssessed ControlStatus = "not_assessed"
)

// Control represents a compliance control requirement.
// Fields ordered for optimal memory alignment.
type Control struct {
	ID           string   `json:"id"`
	Framework    string   `json:"framework"`
	Title        string   `json:"title"`
	Description  string   `json:"description"`
	Category     string   `json:"category"`
	Subcategory  string   `json:"subcategory,omitempty"`
	CWEMappings  []string `json:"cwe_mappings,omitempty"`
	RuleMappings []string `json:"rule_mappings,omitempty"`
	Required     bool     `json:"required"`
}

// Evidence represents evidence supporting a control assessment.
// Fields ordered for optimal memory alignment.
type Evidence struct {
	Timestamp   time.Time `json:"timestamp"`
	Type        string    `json:"type"`
	Description string    `json:"description"`
	Source      string    `json:"source"`
	Hash        string    `json:"hash,omitempty"`
}

// ControlAssessment represents the assessment of a single control.
//
//nolint:govet // Contains embedded Control struct, alignment is acceptable.
type ControlAssessment struct {
	Rationale     string        `json:"rationale,omitempty"`
	Status        ControlStatus `json:"status"`
	Control       Control       `json:"control"`
	Evidence      []Evidence    `json:"evidence,omitempty"`
	Findings      []string      `json:"finding_ids,omitempty"`
	FindingCount  int           `json:"finding_count"`
	CriticalCount int           `json:"critical_count"`
	HighCount     int           `json:"high_count"`
}

// EnrichedFinding wraps a Finding with compliance metadata.
// Fields ordered for optimal memory alignment.
type EnrichedFinding struct {
	ControlIDs []string      `json:"control_ids,omitempty"`
	CWEIDs     []string      `json:"cwe_ids,omitempty"`
	CVEIDs     []string      `json:"cve_ids,omitempty"`
	CVSSVector string        `json:"cvss_vector,omitempty"`
	Finding    model.Finding `json:"finding"`
	CVSSScore  float64       `json:"cvss_score,omitempty"`
}

// Gap represents a compliance gap requiring attention.
//
//nolint:govet // Contains embedded Control struct, alignment is acceptable.
type Gap struct {
	Severity     string   `json:"severity"`
	Description  string   `json:"description"`
	Remediation  string   `json:"remediation,omitempty"`
	Control      Control  `json:"control"`
	FindingIDs   []string `json:"finding_ids,omitempty"`
	FindingCount int      `json:"finding_count"`
}

// FrameworkSummary provides per-framework statistics.
// Fields ordered for optimal memory alignment.
type FrameworkSummary struct {
	Framework         FrameworkID `json:"framework"`
	CoveragePercent   float64     `json:"coverage_percent"`
	TotalControls     int         `json:"total_controls"`
	CompliantCount    int         `json:"compliant_count"`
	NonCompliantCount int         `json:"non_compliant_count"`
	PartialCount      int         `json:"partial_count"`
	NotAssessedCount  int         `json:"not_assessed_count"`
}

// Summary provides overview statistics for compliance assessment.
// Fields ordered for optimal memory alignment.
type Summary struct {
	FrameworkSummaries map[FrameworkID]FrameworkSummary `json:"frameworks"`
	OverallScore       float64                          `json:"overall_score"`
	TotalControls      int                              `json:"total_controls"`
	CompliantCount     int                              `json:"compliant_count"`
	NonCompliantCount  int                              `json:"non_compliant_count"`
	PartialCount       int                              `json:"partial_count"`
	NotAssessedCount   int                              `json:"not_assessed_count"`
}

// Report represents a complete compliance assessment.
// Fields ordered for optimal memory alignment.
type Report struct {
	GeneratedAt   time.Time                           `json:"generated_at"`
	Metadata      map[string]string                   `json:"metadata,omitempty"`
	Assessments   map[FrameworkID][]ControlAssessment `json:"assessments"`
	ScanTimestamp string                              `json:"scan_timestamp,omitempty"`
	Version       string                              `json:"version"`
	Gaps          []Gap                               `json:"gaps,omitempty"`
	Summary       Summary                             `json:"summary"`
	mu            sync.RWMutex                        // Protects concurrent access to Assessments and Gaps
}

// NewReport creates a new empty compliance report.
func NewReport() *Report {
	return &Report{
		GeneratedAt: time.Now().UTC(),
		Version:     "1.0.0",
		Metadata:    make(map[string]string),
		Assessments: make(map[FrameworkID][]ControlAssessment),
		Summary: Summary{
			FrameworkSummaries: make(map[FrameworkID]FrameworkSummary),
		},
	}
}

// AddAssessment adds a control assessment to the report.
func (r *Report) AddAssessment(framework FrameworkID, assessment ControlAssessment) {
	// Input validation.
	if r == nil {
		return
	}
	if framework == "" {
		return
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	// Check limit to prevent DoS.
	if len(r.Assessments[framework]) >= MaxAssessments {
		return // Silently drop if limit exceeded
	}

	r.Assessments[framework] = append(r.Assessments[framework], assessment)
}

// AddGap adds a compliance gap to the report.
func (r *Report) AddGap(gap Gap) {
	// Input validation.
	if r == nil {
		return
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	// Check limit to prevent DoS.
	if len(r.Gaps) >= MaxGaps {
		return // Silently drop if limit exceeded
	}

	r.Gaps = append(r.Gaps, gap)
}

// CalculateSummary computes summary statistics from assessments.
func (r *Report) CalculateSummary() {
	// Input validation.
	if r == nil {
		return
	}

	// Make copies of data for calculation to minimize lock time.
	r.mu.RLock()
	assessmentsCopy := make(map[FrameworkID][]ControlAssessment, len(r.Assessments))
	for k, v := range r.Assessments {
		assessmentsCopy[k] = make([]ControlAssessment, len(v))
		copy(assessmentsCopy[k], v)
	}
	gapsCopy := make([]Gap, len(r.Gaps))
	copy(gapsCopy, r.Gaps)
	r.mu.RUnlock()

	// Calculate on copies (no lock needed during calculation).
	r.Summary = Summary{
		FrameworkSummaries: make(map[FrameworkID]FrameworkSummary),
	}

	for framework, assessments := range assessmentsCopy {
		fs := FrameworkSummary{
			Framework:     framework,
			TotalControls: len(assessments), // ✅ Set once, not in loop
		}

		for i := range assessments {
			r.Summary.TotalControls++

			switch assessments[i].Status {
			case StatusCompliant:
				fs.CompliantCount++
				r.Summary.CompliantCount++
			case StatusNonCompliant:
				fs.NonCompliantCount++
				r.Summary.NonCompliantCount++
			case StatusPartial:
				fs.PartialCount++
				r.Summary.PartialCount++
			case StatusNotAssessed:
				fs.NotAssessedCount++
				r.Summary.NotAssessedCount++
			}
		}

		// Calculate coverage percentage.
		assessed := fs.TotalControls - fs.NotAssessedCount
		if assessed > 0 {
			fs.CoveragePercent = float64(fs.CompliantCount) / float64(assessed) * 100
		}

		r.Summary.FrameworkSummaries[framework] = fs
	}

	// Calculate overall score.
	assessed := r.Summary.TotalControls - r.Summary.NotAssessedCount
	if assessed > 0 {
		r.Summary.OverallScore = float64(r.Summary.CompliantCount) / float64(assessed) * 100
	}
}
