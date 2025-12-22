package compliance

import (
	"context"
	"fmt"
)

// CoverageStats provides coverage statistics for a compliance assessment.
type CoverageStats struct {
	Framework         FrameworkID `json:"framework"`
	CoveragePercent   float64     `json:"coverage_percent"`
	TotalControls     int         `json:"total_controls"`
	AssessedControls  int         `json:"assessed_controls"`
	CompliantControls int         `json:"compliant_controls"`
	GapCount          int         `json:"gap_count"`
}

// CoverageCalculator calculates compliance coverage.
type CoverageCalculator struct {
	mapper *DefaultMapper
}

// NewCoverageCalculator creates a new coverage calculator.
func NewCoverageCalculator(mapper *DefaultMapper) *CoverageCalculator {
	return &CoverageCalculator{
		mapper: mapper,
	}
}

// Calculate computes coverage statistics for the given assessments.
func (c *CoverageCalculator) Calculate(ctx context.Context, assessments map[FrameworkID][]ControlAssessment) ([]CoverageStats, error) {
	// Input validation.
	if c == nil {
		return nil, fmt.Errorf("coverage calculator cannot be nil")
	}
	if ctx == nil {
		return nil, fmt.Errorf("context cannot be nil")
	}
	if assessments == nil {
		return []CoverageStats{}, nil // Allow nil, return empty slice
	}

	stats := make([]CoverageStats, 0, len(assessments))

	for framework, controlAssessments := range assessments {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		s := c.calculateFrameworkCoverage(framework, controlAssessments)
		stats = append(stats, s)
	}

	return stats, nil
}

// calculateFrameworkCoverage calculates coverage for a single framework.
func (c *CoverageCalculator) calculateFrameworkCoverage(framework FrameworkID, assessments []ControlAssessment) CoverageStats {
	stats := CoverageStats{
		Framework:     framework,
		TotalControls: len(assessments),
	}

	for i := range assessments {
		switch assessments[i].Status {
		case StatusCompliant:
			stats.AssessedControls++
			stats.CompliantControls++
		case StatusNonCompliant:
			stats.AssessedControls++
			stats.GapCount++
		case StatusPartial:
			stats.AssessedControls++
			stats.GapCount++
		case StatusNotAssessed:
			// Not counted as assessed.
		}
	}

	if stats.AssessedControls > 0 {
		stats.CoveragePercent = float64(stats.CompliantControls) / float64(stats.AssessedControls) * 100
	}

	return stats
}

// CalculateOverall computes overall coverage across all frameworks.
func (c *CoverageCalculator) CalculateOverall(ctx context.Context, assessments map[FrameworkID][]ControlAssessment) (CoverageStats, error) {
	// Input validation.
	if c == nil {
		return CoverageStats{}, fmt.Errorf("coverage calculator cannot be nil")
	}
	if ctx == nil {
		return CoverageStats{}, fmt.Errorf("context cannot be nil")
	}
	if assessments == nil {
		assessments = make(map[FrameworkID][]ControlAssessment) // Allow nil, treat as empty map
	}

	overall := CoverageStats{
		Framework: FrameworkID("overall"),
	}

	for _, controlAssessments := range assessments {
		select {
		case <-ctx.Done():
			return CoverageStats{}, ctx.Err()
		default:
		}

		for i := range controlAssessments {
			overall.TotalControls++

			switch controlAssessments[i].Status {
			case StatusCompliant:
				overall.AssessedControls++
				overall.CompliantControls++
			case StatusNonCompliant:
				overall.AssessedControls++
				overall.GapCount++
			case StatusPartial:
				overall.AssessedControls++
				overall.GapCount++
			}
		}
	}

	if overall.AssessedControls > 0 {
		overall.CoveragePercent = float64(overall.CompliantControls) / float64(overall.AssessedControls) * 100
	}

	return overall, nil
}

// GetMissingControls returns controls that have not been assessed.
func (c *CoverageCalculator) GetMissingControls(framework FrameworkID, assessments []ControlAssessment) []Control {
	var missing []Control

	for i := range assessments {
		if assessments[i].Status == StatusNotAssessed {
			missing = append(missing, assessments[i].Control)
		}
	}

	return missing
}
