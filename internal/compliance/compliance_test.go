package compliance

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/victoralfred/devsec/internal/model"
)

func TestFrameworkIDConstants(t *testing.T) {
	tests := []struct {
		id   FrameworkID
		want string
	}{
		{FrameworkSOC2, "soc2"},
		{FrameworkISO27001, "iso27001"},
		{FrameworkGDPR, "gdpr"},
	}

	for _, tt := range tests {
		if string(tt.id) != tt.want {
			t.Errorf("FrameworkID = %q, want %q", tt.id, tt.want)
		}
	}
}

func TestControlStatusConstants(t *testing.T) {
	tests := []struct {
		status ControlStatus
		want   string
	}{
		{StatusCompliant, "compliant"},
		{StatusNonCompliant, "non_compliant"},
		{StatusPartial, "partial"},
		{StatusNotAssessed, "not_assessed"},
	}

	for _, tt := range tests {
		if string(tt.status) != tt.want {
			t.Errorf("ControlStatus = %q, want %q", tt.status, tt.want)
		}
	}
}

func TestControlJSON(t *testing.T) {
	ctrl := Control{
		ID:          "CC6.1",
		Framework:   "soc2",
		Title:       "Logical and Physical Access Controls",
		Description: "The entity implements logical access security software.",
		Category:    "Common Criteria",
		CWEMappings: []string{"CWE-287", "CWE-306"},
		Required:    true,
	}

	data, err := json.Marshal(ctrl)
	if err != nil {
		t.Fatalf("marshal control: %v", err)
	}

	var decoded Control
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal control: %v", err)
	}

	if decoded.ID != ctrl.ID {
		t.Errorf("ID = %q, want %q", decoded.ID, ctrl.ID)
	}
	if decoded.Framework != ctrl.Framework {
		t.Errorf("Framework = %q, want %q", decoded.Framework, ctrl.Framework)
	}
	if len(decoded.CWEMappings) != len(ctrl.CWEMappings) {
		t.Errorf("CWEMappings len = %d, want %d", len(decoded.CWEMappings), len(ctrl.CWEMappings))
	}
}

func TestEvidenceJSON(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	ev := Evidence{
		Timestamp:   now,
		Type:        "scan_result",
		Description: "Security scan completed",
		Source:      "trivy",
		Hash:        "abc123",
	}

	data, err := json.Marshal(ev)
	if err != nil {
		t.Fatalf("marshal evidence: %v", err)
	}

	var decoded Evidence
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal evidence: %v", err)
	}

	if decoded.Type != ev.Type {
		t.Errorf("Type = %q, want %q", decoded.Type, ev.Type)
	}
	if decoded.Source != ev.Source {
		t.Errorf("Source = %q, want %q", decoded.Source, ev.Source)
	}
}

func TestControlAssessmentJSON(t *testing.T) {
	ca := ControlAssessment{
		Control: Control{
			ID:        "CC6.1",
			Framework: "soc2",
			Title:     "Access Controls",
		},
		Status:        StatusNonCompliant,
		Findings:      []string{"finding-1", "finding-2"},
		FindingCount:  2,
		CriticalCount: 1,
		HighCount:     1,
		Rationale:     "Multiple access control violations found",
	}

	data, err := json.Marshal(ca)
	if err != nil {
		t.Fatalf("marshal assessment: %v", err)
	}

	var decoded ControlAssessment
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal assessment: %v", err)
	}

	if decoded.Status != ca.Status {
		t.Errorf("Status = %q, want %q", decoded.Status, ca.Status)
	}
	if decoded.FindingCount != ca.FindingCount {
		t.Errorf("FindingCount = %d, want %d", decoded.FindingCount, ca.FindingCount)
	}
}

func TestEnrichedFindingJSON(t *testing.T) {
	ef := EnrichedFinding{
		Finding: model.Finding{
			ID:       "vuln-1",
			Title:    "SQL Injection",
			Severity: model.SeverityCritical,
		},
		ControlIDs: []string{"CC6.1", "A.14.2.5"},
		CWEIDs:     []string{"CWE-89"},
		CVEIDs:     []string{"CVE-2023-1234"},
		CVSSScore:  9.8,
		CVSSVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
	}

	data, err := json.Marshal(ef)
	if err != nil {
		t.Fatalf("marshal enriched finding: %v", err)
	}

	var decoded EnrichedFinding
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal enriched finding: %v", err)
	}

	if decoded.CVSSScore != ef.CVSSScore {
		t.Errorf("CVSSScore = %f, want %f", decoded.CVSSScore, ef.CVSSScore)
	}
	if len(decoded.ControlIDs) != len(ef.ControlIDs) {
		t.Errorf("ControlIDs len = %d, want %d", len(decoded.ControlIDs), len(ef.ControlIDs))
	}
}

func TestGapJSON(t *testing.T) {
	gap := Gap{
		Control: Control{
			ID:        "CC6.7",
			Framework: "soc2",
			Title:     "Encryption",
		},
		Severity:     "high",
		Description:  "Missing encryption for data at rest",
		Remediation:  "Implement AES-256 encryption",
		FindingCount: 3,
	}

	data, err := json.Marshal(gap)
	if err != nil {
		t.Fatalf("marshal gap: %v", err)
	}

	var decoded Gap
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal gap: %v", err)
	}

	if decoded.Severity != gap.Severity {
		t.Errorf("Severity = %q, want %q", decoded.Severity, gap.Severity)
	}
}

func TestNewReport(t *testing.T) {
	report := NewReport()

	if report.Version != "1.0.0" {
		t.Errorf("Version = %q, want %q", report.Version, "1.0.0")
	}
	if report.Metadata == nil {
		t.Error("Metadata should not be nil")
	}
	if report.Assessments == nil {
		t.Error("Assessments should not be nil")
	}
	if report.Summary.FrameworkSummaries == nil {
		t.Error("FrameworkSummaries should not be nil")
	}
	if report.GeneratedAt.IsZero() {
		t.Error("GeneratedAt should not be zero")
	}
}

func TestReportAddAssessment(t *testing.T) {
	report := NewReport()

	assessment := ControlAssessment{
		Control: Control{
			ID:        "CC6.1",
			Framework: "soc2",
		},
		Status: StatusCompliant,
	}

	report.AddAssessment(FrameworkSOC2, assessment)

	if len(report.Assessments[FrameworkSOC2]) != 1 {
		t.Errorf("Assessments count = %d, want 1", len(report.Assessments[FrameworkSOC2]))
	}
}

func TestReportAddGap(t *testing.T) {
	report := NewReport()

	gap := Gap{
		Control: Control{
			ID: "CC6.7",
		},
		Severity: "high",
	}

	report.AddGap(gap)

	if len(report.Gaps) != 1 {
		t.Errorf("Gaps count = %d, want 1", len(report.Gaps))
	}
}

func TestReportCalculateSummary(t *testing.T) {
	report := NewReport()

	// Add SOC2 assessments.
	report.AddAssessment(FrameworkSOC2, ControlAssessment{
		Control: Control{ID: "CC6.1"},
		Status:  StatusCompliant,
	})
	report.AddAssessment(FrameworkSOC2, ControlAssessment{
		Control: Control{ID: "CC6.6"},
		Status:  StatusCompliant,
	})
	report.AddAssessment(FrameworkSOC2, ControlAssessment{
		Control: Control{ID: "CC6.7"},
		Status:  StatusNonCompliant,
	})
	report.AddAssessment(FrameworkSOC2, ControlAssessment{
		Control: Control{ID: "CC7.1"},
		Status:  StatusPartial,
	})

	// Add ISO27001 assessments.
	report.AddAssessment(FrameworkISO27001, ControlAssessment{
		Control: Control{ID: "A.9.4.2"},
		Status:  StatusCompliant,
	})
	report.AddAssessment(FrameworkISO27001, ControlAssessment{
		Control: Control{ID: "A.14.2.5"},
		Status:  StatusNotAssessed,
	})

	report.CalculateSummary()

	// Check total controls.
	if report.Summary.TotalControls != 6 {
		t.Errorf("TotalControls = %d, want 6", report.Summary.TotalControls)
	}

	// Check compliant count.
	if report.Summary.CompliantCount != 3 {
		t.Errorf("CompliantCount = %d, want 3", report.Summary.CompliantCount)
	}

	// Check non-compliant count.
	if report.Summary.NonCompliantCount != 1 {
		t.Errorf("NonCompliantCount = %d, want 1", report.Summary.NonCompliantCount)
	}

	// Check partial count.
	if report.Summary.PartialCount != 1 {
		t.Errorf("PartialCount = %d, want 1", report.Summary.PartialCount)
	}

	// Check not assessed count.
	if report.Summary.NotAssessedCount != 1 {
		t.Errorf("NotAssessedCount = %d, want 1", report.Summary.NotAssessedCount)
	}

	// Check SOC2 framework summary.
	soc2Summary := report.Summary.FrameworkSummaries[FrameworkSOC2]
	if soc2Summary.TotalControls != 4 {
		t.Errorf("SOC2 TotalControls = %d, want 4", soc2Summary.TotalControls)
	}
	if soc2Summary.CompliantCount != 2 {
		t.Errorf("SOC2 CompliantCount = %d, want 2", soc2Summary.CompliantCount)
	}

	// Check overall score (3 compliant out of 5 assessed = 60%).
	expectedScore := 60.0
	if report.Summary.OverallScore != expectedScore {
		t.Errorf("OverallScore = %f, want %f", report.Summary.OverallScore, expectedScore)
	}
}

func TestReportJSON(t *testing.T) {
	report := NewReport()
	report.ScanTimestamp = "2025-12-21T10:00:00Z"
	report.Metadata["scanner"] = "devsec"

	report.AddAssessment(FrameworkSOC2, ControlAssessment{
		Control: Control{ID: "CC6.1", Framework: "soc2"},
		Status:  StatusCompliant,
	})

	report.CalculateSummary()

	data, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("marshal report: %v", err)
	}

	var decoded Report
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal report: %v", err)
	}

	if decoded.Version != report.Version {
		t.Errorf("Version = %q, want %q", decoded.Version, report.Version)
	}
	if decoded.ScanTimestamp != report.ScanTimestamp {
		t.Errorf("ScanTimestamp = %q, want %q", decoded.ScanTimestamp, report.ScanTimestamp)
	}
	if len(decoded.Assessments[FrameworkSOC2]) != 1 {
		t.Errorf("Assessments count = %d, want 1", len(decoded.Assessments[FrameworkSOC2]))
	}
}

func TestFrameworkSummaryJSON(t *testing.T) {
	fs := FrameworkSummary{
		Framework:         FrameworkSOC2,
		TotalControls:     10,
		CompliantCount:    7,
		NonCompliantCount: 2,
		PartialCount:      1,
		CoveragePercent:   70.0,
	}

	data, err := json.Marshal(fs)
	if err != nil {
		t.Fatalf("marshal framework summary: %v", err)
	}

	var decoded FrameworkSummary
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal framework summary: %v", err)
	}

	if decoded.Framework != fs.Framework {
		t.Errorf("Framework = %q, want %q", decoded.Framework, fs.Framework)
	}
	if decoded.CoveragePercent != fs.CoveragePercent {
		t.Errorf("CoveragePercent = %f, want %f", decoded.CoveragePercent, fs.CoveragePercent)
	}
}

func TestSummaryJSON(t *testing.T) {
	cs := Summary{
		TotalControls:      20,
		CompliantCount:     15,
		NonCompliantCount:  3,
		PartialCount:       2,
		OverallScore:       75.0,
		FrameworkSummaries: make(map[FrameworkID]FrameworkSummary),
	}
	cs.FrameworkSummaries[FrameworkSOC2] = FrameworkSummary{
		Framework:     FrameworkSOC2,
		TotalControls: 10,
	}

	data, err := json.Marshal(cs)
	if err != nil {
		t.Fatalf("marshal compliance summary: %v", err)
	}

	var decoded Summary
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal compliance summary: %v", err)
	}

	if decoded.OverallScore != cs.OverallScore {
		t.Errorf("OverallScore = %f, want %f", decoded.OverallScore, cs.OverallScore)
	}
	if len(decoded.FrameworkSummaries) != 1 {
		t.Errorf("FrameworkSummaries len = %d, want 1", len(decoded.FrameworkSummaries))
	}
}
