package compliance

import (
	"context"
	"testing"
)

func TestNewGapAnalyzer(t *testing.T) {
	mapper := NewMapper()
	analyzer := NewGapAnalyzer(mapper)

	if analyzer == nil {
		t.Fatal("expected analyzer, got nil")
	}
	if analyzer.mapper == nil {
		t.Error("mapper should not be nil")
	}
}

func TestGapAnalyzerAnalyze(t *testing.T) {
	mapper := NewMapper()
	analyzer := NewGapAnalyzer(mapper)
	ctx := context.Background()

	assessments := map[FrameworkID][]ControlAssessment{
		FrameworkSOC2: {
			{
				Control:       Control{ID: "CC6.1", Framework: "soc2", Category: "Common Criteria"},
				Status:        StatusNonCompliant,
				CriticalCount: 1,
				FindingCount:  2,
				Findings:      []string{"vuln-1", "vuln-2"},
			},
			{
				Control:      Control{ID: "CC6.6", Framework: "soc2"},
				Status:       StatusCompliant,
				FindingCount: 0,
			},
			{
				Control:      Control{ID: "CC6.7", Framework: "soc2"},
				Status:       StatusPartial,
				HighCount:    1,
				FindingCount: 1,
			},
		},
	}

	gaps, err := analyzer.Analyze(ctx, assessments)
	if err != nil {
		t.Fatalf("Analyze error: %v", err)
	}

	if len(gaps) != 2 {
		t.Fatalf("expected 2 gaps, got %d", len(gaps))
	}

	// First gap should be critical (sorted by severity).
	if gaps[0].Severity != "critical" {
		t.Errorf("expected first gap to be critical, got %s", gaps[0].Severity)
	}

	// Second gap should be high.
	if gaps[1].Severity != "high" {
		t.Errorf("expected second gap to be high, got %s", gaps[1].Severity)
	}
}

func TestGapAnalyzerAnalyzeEmpty(t *testing.T) {
	mapper := NewMapper()
	analyzer := NewGapAnalyzer(mapper)
	ctx := context.Background()

	gaps, err := analyzer.Analyze(ctx, nil)
	if err != nil {
		t.Fatalf("Analyze error: %v", err)
	}

	if len(gaps) != 0 {
		t.Errorf("expected 0 gaps, got %d", len(gaps))
	}
}

func TestGapAnalyzerAnalyzeContextCancel(t *testing.T) {
	mapper := NewMapper()
	analyzer := NewGapAnalyzer(mapper)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	assessments := map[FrameworkID][]ControlAssessment{
		FrameworkSOC2: {{Control: Control{ID: "CC6.1"}, Status: StatusNonCompliant}},
	}

	_, err := analyzer.Analyze(ctx, assessments)
	if err == nil {
		t.Error("expected context error")
	}
}

func TestGapAnalyzerGetCriticalGaps(t *testing.T) {
	mapper := NewMapper()
	analyzer := NewGapAnalyzer(mapper)

	gaps := []Gap{
		{Severity: "critical"},
		{Severity: "high"},
		{Severity: "critical"},
		{Severity: "medium"},
	}

	critical := analyzer.GetCriticalGaps(gaps)
	if len(critical) != 2 {
		t.Errorf("expected 2 critical gaps, got %d", len(critical))
	}
}

func TestGapAnalyzerGetHighGaps(t *testing.T) {
	mapper := NewMapper()
	analyzer := NewGapAnalyzer(mapper)

	gaps := []Gap{
		{Severity: "critical"},
		{Severity: "high"},
		{Severity: "medium"},
		{Severity: "low"},
	}

	high := analyzer.GetHighGaps(gaps)
	if len(high) != 2 {
		t.Errorf("expected 2 high+ gaps, got %d", len(high))
	}
}

func TestGapAnalyzerGroupByFramework(t *testing.T) {
	mapper := NewMapper()
	analyzer := NewGapAnalyzer(mapper)

	gaps := []Gap{
		{Control: Control{Framework: "soc2"}},
		{Control: Control{Framework: "iso27001"}},
		{Control: Control{Framework: "soc2"}},
	}

	grouped := analyzer.GroupByFramework(gaps)
	if len(grouped) != 2 {
		t.Errorf("expected 2 frameworks, got %d", len(grouped))
	}
	if len(grouped[FrameworkSOC2]) != 2 {
		t.Errorf("expected 2 SOC2 gaps, got %d", len(grouped[FrameworkSOC2]))
	}
}

func TestGapAnalyzerSummarize(t *testing.T) {
	mapper := NewMapper()
	analyzer := NewGapAnalyzer(mapper)

	gaps := []Gap{
		{Severity: "critical", Control: Control{Framework: "soc2"}},
		{Severity: "high", Control: Control{Framework: "soc2"}},
		{Severity: "medium", Control: Control{Framework: "iso27001"}},
		{Severity: "low", Control: Control{Framework: "gdpr"}},
	}

	summary := analyzer.Summarize(gaps)

	if summary.TotalGaps != 4 {
		t.Errorf("TotalGaps = %d, want 4", summary.TotalGaps)
	}
	if summary.CriticalCount != 1 {
		t.Errorf("CriticalCount = %d, want 1", summary.CriticalCount)
	}
	if summary.HighCount != 1 {
		t.Errorf("HighCount = %d, want 1", summary.HighCount)
	}
	if summary.MediumCount != 1 {
		t.Errorf("MediumCount = %d, want 1", summary.MediumCount)
	}
	if summary.LowCount != 1 {
		t.Errorf("LowCount = %d, want 1", summary.LowCount)
	}
	if summary.ByFramework["soc2"] != 2 {
		t.Errorf("ByFramework[soc2] = %d, want 2", summary.ByFramework["soc2"])
	}
}

func TestSeverityOrder(t *testing.T) {
	tests := []struct {
		severity string
		want     int
	}{
		{"critical", 4},
		{"high", 3},
		{"medium", 2},
		{"low", 1},
		{"unknown", 0},
	}

	for _, tt := range tests {
		got := severityOrder(tt.severity)
		if got != tt.want {
			t.Errorf("severityOrder(%q) = %d, want %d", tt.severity, got, tt.want)
		}
	}
}

func TestGetRemediation(t *testing.T) {
	mapper := NewMapper()
	analyzer := NewGapAnalyzer(mapper)

	tests := []struct {
		category string
		notEmpty bool
	}{
		{"Common Criteria", true},
		{"Technological Controls", true},
		{"Organizational Controls", true},
		{"Security", true},
		{"Principles", true},
		{"Data Breach", true},
		{"Unknown", true},
	}

	for _, tt := range tests {
		ctrl := Control{Category: tt.category}
		remediation := analyzer.getRemediation(ctrl)
		if tt.notEmpty && remediation == "" {
			t.Errorf("expected remediation for category %q", tt.category)
		}
	}
}
