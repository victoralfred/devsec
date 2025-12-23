package compliance

import (
	"context"
	"fmt"
	"sort"
)

// GapAnalyzer performs gap analysis on compliance assessments.
type GapAnalyzer struct {
	mapper *DefaultMapper
}

// NewGapAnalyzer creates a new gap analyzer.
func NewGapAnalyzer(mapper *DefaultMapper) *GapAnalyzer {
	return &GapAnalyzer{
		mapper: mapper,
	}
}

// Analyze performs gap analysis on the given assessments.
func (g *GapAnalyzer) Analyze(ctx context.Context, assessments map[FrameworkID][]ControlAssessment) ([]Gap, error) {
	// Input validation.
	if g == nil {
		return nil, fmt.Errorf("gap analyzer cannot be nil")
	}
	if ctx == nil {
		return nil, fmt.Errorf("context cannot be nil")
	}
	if assessments == nil {
		return []Gap{}, nil // Allow nil, return empty slice
	}

	gaps := make([]Gap, 0, 100) // Pre-allocate with estimated capacity

	for _, controlAssessments := range assessments {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		// Check limit to prevent DoS.
		if len(gaps) >= MaxGaps {
			break
		}

		for i := range controlAssessments {
			// Check limit in loop to prevent exceeding.
			if len(gaps) >= MaxGaps {
				break
			}

			if controlAssessments[i].Status == StatusNonCompliant ||
				controlAssessments[i].Status == StatusPartial {
				gap := g.createGap(controlAssessments[i])
				gaps = append(gaps, gap)
			}
		}
	}

	// Sort gaps by severity.
	sort.Slice(gaps, func(i, j int) bool {
		return severityOrder(gaps[i].Severity) > severityOrder(gaps[j].Severity)
	})

	return gaps, nil
}

// determineSeverity determines the severity based on finding counts.
func determineSeverity(assessment ControlAssessment) string {
	switch {
	case assessment.CriticalCount > 0:
		return "critical"
	case assessment.HighCount > 0:
		return "high"
	case assessment.FindingCount > 0:
		return "low"
	default:
		return "medium"
	}
}

// createGap creates a Gap from a control assessment.
func (g *GapAnalyzer) createGap(assessment ControlAssessment) Gap {
	severity := determineSeverity(assessment)

	description := "Control has compliance violations"
	if assessment.Status == StatusPartial {
		description = "Control is partially compliant with minor issues"
	}

	remediation := g.getRemediation(assessment.Control)

	return Gap{
		Control:      assessment.Control,
		Severity:     severity,
		Description:  description,
		Remediation:  remediation,
		FindingIDs:   assessment.Findings,
		FindingCount: assessment.FindingCount,
	}
}

// getRemediation returns remediation advice for a control.
func (g *GapAnalyzer) getRemediation(ctrl Control) string {
	// Provide generic remediation based on control category.
	switch ctrl.Category {
	case "Common Criteria":
		return "Review and remediate security findings. Implement compensating controls if needed."
	case "Technological Controls":
		return "Update system configurations and security controls to meet requirements."
	case "Organizational Controls":
		return "Review and update organizational policies and procedures."
	case "Security":
		return "Implement technical and organizational security measures."
	case "Principles":
		return "Review data processing practices for compliance with principles."
	case "Data Breach":
		return "Establish breach notification procedures and response plans."
	default:
		return "Review control requirements and implement necessary measures."
	}
}

// severityOrder returns a numeric order for sorting.
func severityOrder(severity string) int {
	switch severity {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

// GetCriticalGaps returns only critical severity gaps.
func (g *GapAnalyzer) GetCriticalGaps(gaps []Gap) []Gap {
	var critical []Gap
	for i := range gaps {
		if gaps[i].Severity == "critical" {
			critical = append(critical, gaps[i])
		}
	}
	return critical
}

// GetHighGaps returns high and critical severity gaps.
func (g *GapAnalyzer) GetHighGaps(gaps []Gap) []Gap {
	var high []Gap
	for i := range gaps {
		if gaps[i].Severity == "critical" || gaps[i].Severity == "high" {
			high = append(high, gaps[i])
		}
	}
	return high
}

// GroupByFramework groups gaps by framework.
func (g *GapAnalyzer) GroupByFramework(gaps []Gap) map[FrameworkID][]Gap {
	grouped := make(map[FrameworkID][]Gap)

	for i := range gaps {
		fwID := FrameworkID(gaps[i].Control.Framework)
		grouped[fwID] = append(grouped[fwID], gaps[i])
	}

	return grouped
}

// GapSummary provides a summary of gaps.
// Fields ordered for optimal memory alignment.
type GapSummary struct {
	ByFramework   map[string]int `json:"by_framework"`
	TotalGaps     int            `json:"total_gaps"`
	CriticalCount int            `json:"critical_count"`
	HighCount     int            `json:"high_count"`
	MediumCount   int            `json:"medium_count"`
	LowCount      int            `json:"low_count"`
}

// Summarize creates a summary of gaps.
func (g *GapAnalyzer) Summarize(gaps []Gap) GapSummary {
	summary := GapSummary{
		TotalGaps:   len(gaps),
		ByFramework: make(map[string]int),
	}

	for i := range gaps {
		switch gaps[i].Severity {
		case "critical":
			summary.CriticalCount++
		case "high":
			summary.HighCount++
		case "medium":
			summary.MediumCount++
		case "low":
			summary.LowCount++
		}

		summary.ByFramework[gaps[i].Control.Framework]++
	}

	return summary
}
