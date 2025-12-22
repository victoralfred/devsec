package compliance

import (
	"context"
	"testing"
	"time"

	"github.com/victoralfred/devsec/internal/model"
)

func TestNewReportGenerator(t *testing.T) {
	mapper := NewMapper()
	gen := NewReportGenerator(mapper)

	if gen == nil {
		t.Fatal("expected generator, got nil")
	}
	if gen.mapper == nil {
		t.Error("mapper should not be nil")
	}
	if gen.coverage == nil {
		t.Error("coverage should not be nil")
	}
	if gen.gap == nil {
		t.Error("gap should not be nil")
	}
}

func TestDefaultGenerateOptions(t *testing.T) {
	opts := DefaultGenerateOptions()

	if opts.Frameworks != nil {
		t.Error("expected nil frameworks (all)")
	}
	if !opts.IncludeEvidence {
		t.Error("expected IncludeEvidence to be true")
	}
	if !opts.IncludeGaps {
		t.Error("expected IncludeGaps to be true")
	}
}

func TestReportGeneratorGenerate(t *testing.T) {
	mapper := NewMapper()
	gen := NewReportGenerator(mapper)
	ctx := context.Background()

	findings := []model.Finding{
		{
			ID:          "vuln-1",
			Title:       "SQL Injection",
			Description: "CWE-89 SQL injection",
			Severity:    model.SeverityCritical,
		},
		{
			ID:       "vuln-2",
			Title:    "XSS",
			Rule:     "CWE-79",
			Severity: model.SeverityHigh,
		},
	}

	opts := GenerateOptions{
		Frameworks:  []FrameworkID{FrameworkSOC2},
		IncludeGaps: true,
	}

	report, err := gen.Generate(ctx, findings, opts)
	if err != nil {
		t.Fatalf("Generate error: %v", err)
	}

	if report == nil {
		t.Fatal("expected report, got nil")
	}

	if len(report.Assessments) == 0 {
		t.Error("expected assessments")
	}
}

func TestReportGeneratorGenerateEmpty(t *testing.T) {
	mapper := NewMapper()
	gen := NewReportGenerator(mapper)
	ctx := context.Background()

	report, err := gen.Generate(ctx, nil, DefaultGenerateOptions())
	if err != nil {
		t.Fatalf("Generate error: %v", err)
	}

	if report == nil {
		t.Fatal("expected report, got nil")
	}
}

func TestReportGeneratorGenerateContextCancel(t *testing.T) {
	mapper := NewMapper()
	gen := NewReportGenerator(mapper)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	findings := []model.Finding{{ID: "vuln-1"}}

	_, err := gen.Generate(ctx, findings, DefaultGenerateOptions())
	if err == nil {
		t.Error("expected context error")
	}
}

func TestReportGeneratorGenerateFromAssessments(t *testing.T) {
	mapper := NewMapper()
	gen := NewReportGenerator(mapper)
	ctx := context.Background()

	assessments := map[FrameworkID][]ControlAssessment{
		FrameworkSOC2: {
			{Control: Control{ID: "CC6.1"}, Status: StatusCompliant},
			{Control: Control{ID: "CC6.6"}, Status: StatusNonCompliant, CriticalCount: 1},
		},
	}

	opts := GenerateOptions{IncludeGaps: true}

	report, err := gen.GenerateFromAssessments(ctx, assessments, opts)
	if err != nil {
		t.Fatalf("GenerateFromAssessments error: %v", err)
	}

	if len(report.Assessments[FrameworkSOC2]) != 2 {
		t.Errorf("expected 2 assessments, got %d", len(report.Assessments[FrameworkSOC2]))
	}

	if len(report.Gaps) != 1 {
		t.Errorf("expected 1 gap, got %d", len(report.Gaps))
	}
}

func TestReportGeneratorGetCoverageStats(t *testing.T) {
	mapper := NewMapper()
	gen := NewReportGenerator(mapper)
	ctx := context.Background()

	report := NewReport()
	report.AddAssessment(FrameworkSOC2, ControlAssessment{
		Control: Control{ID: "CC6.1"},
		Status:  StatusCompliant,
	})
	report.AddAssessment(FrameworkSOC2, ControlAssessment{
		Control: Control{ID: "CC6.6"},
		Status:  StatusNonCompliant,
	})

	stats, err := gen.GetCoverageStats(ctx, report)
	if err != nil {
		t.Fatalf("GetCoverageStats error: %v", err)
	}

	if len(stats) != 1 {
		t.Fatalf("expected 1 stats, got %d", len(stats))
	}

	if stats[0].CoveragePercent != 50.0 {
		t.Errorf("expected 50%% coverage, got %f", stats[0].CoveragePercent)
	}
}

func TestReportGeneratorGetOverallCoverage(t *testing.T) {
	mapper := NewMapper()
	gen := NewReportGenerator(mapper)
	ctx := context.Background()

	report := NewReport()
	report.AddAssessment(FrameworkSOC2, ControlAssessment{
		Control: Control{ID: "CC6.1"},
		Status:  StatusCompliant,
	})
	report.AddAssessment(FrameworkISO27001, ControlAssessment{
		Control: Control{ID: "A.5.1"},
		Status:  StatusCompliant,
	})

	overall, err := gen.GetOverallCoverage(ctx, report)
	if err != nil {
		t.Fatalf("GetOverallCoverage error: %v", err)
	}

	if overall.TotalControls != 2 {
		t.Errorf("expected 2 total controls, got %d", overall.TotalControls)
	}

	if overall.CoveragePercent != 100.0 {
		t.Errorf("expected 100%% coverage, got %f", overall.CoveragePercent)
	}
}

func TestReportGeneratorGetGapSummary(t *testing.T) {
	mapper := NewMapper()
	gen := NewReportGenerator(mapper)

	report := NewReport()
	report.AddGap(Gap{Severity: "critical", Control: Control{Framework: "soc2"}})
	report.AddGap(Gap{Severity: "high", Control: Control{Framework: "soc2"}})
	report.AddGap(Gap{Severity: "medium", Control: Control{Framework: "iso27001"}})

	summary := gen.GetGapSummary(report)

	if summary.TotalGaps != 3 {
		t.Errorf("expected 3 gaps, got %d", summary.TotalGaps)
	}
	if summary.CriticalCount != 1 {
		t.Errorf("expected 1 critical, got %d", summary.CriticalCount)
	}
}

func TestNewEnhancedReport(t *testing.T) {
	report := NewReport()
	enhanced := NewEnhancedReport(report)

	if enhanced == nil {
		t.Fatal("expected enhanced report, got nil")
	}
	if enhanced.Report != report {
		t.Error("report should match")
	}
	if enhanced.Metadata.GeneratedBy != "devsec" {
		t.Errorf("expected devsec, got %s", enhanced.Metadata.GeneratedBy)
	}
	if enhanced.Metadata.Version != "1.0.0" {
		t.Errorf("expected 1.0.0, got %s", enhanced.Metadata.Version)
	}
}

func TestEnhancedReportWithScanTimestamp(t *testing.T) {
	report := NewReport()
	enhanced := NewEnhancedReport(report)

	ts := time.Date(2024, 1, 15, 10, 0, 0, 0, time.UTC)
	enhanced.WithScanTimestamp(ts)

	if !enhanced.Metadata.ScanTimestamp.Equal(ts) {
		t.Error("scan timestamp should match")
	}
}

func TestEnhancedReportWithSourceFiles(t *testing.T) {
	report := NewReport()
	enhanced := NewEnhancedReport(report)

	files := []string{"scan1.json", "scan2.json"}
	enhanced.WithSourceFiles(files)

	if len(enhanced.Metadata.SourceFiles) != 2 {
		t.Errorf("expected 2 source files, got %d", len(enhanced.Metadata.SourceFiles))
	}
}

func TestExtractFrameworkReport(t *testing.T) {
	report := NewReport()
	report.AddAssessment(FrameworkSOC2, ControlAssessment{
		Control: Control{ID: "CC6.1", Framework: "soc2"},
		Status:  StatusCompliant,
	})
	report.AddAssessment(FrameworkSOC2, ControlAssessment{
		Control: Control{ID: "CC6.6", Framework: "soc2"},
		Status:  StatusNonCompliant,
	})
	report.AddAssessment(FrameworkISO27001, ControlAssessment{
		Control: Control{ID: "A.5.1", Framework: "iso27001"},
		Status:  StatusCompliant,
	})
	report.AddGap(Gap{Severity: "high", Control: Control{ID: "CC6.6", Framework: "soc2"}})
	report.AddGap(Gap{Severity: "medium", Control: Control{ID: "A.8.9", Framework: "iso27001"}})

	fr := ExtractFrameworkReport(report, FrameworkSOC2)

	if fr.Framework != FrameworkSOC2 {
		t.Errorf("expected soc2, got %s", fr.Framework)
	}
	if len(fr.Assessments) != 2 {
		t.Errorf("expected 2 assessments, got %d", len(fr.Assessments))
	}
	if len(fr.Gaps) != 1 {
		t.Errorf("expected 1 gap, got %d", len(fr.Gaps))
	}
	if fr.Summary.TotalControls != 2 {
		t.Errorf("expected 2 total controls, got %d", fr.Summary.TotalControls)
	}
	if fr.Summary.CompliantCount != 1 {
		t.Errorf("expected 1 compliant, got %d", fr.Summary.CompliantCount)
	}
	if fr.Summary.NonCompliantCount != 1 {
		t.Errorf("expected 1 non-compliant, got %d", fr.Summary.NonCompliantCount)
	}
	if fr.Summary.CoveragePercent != 50.0 {
		t.Errorf("expected 50%%, got %f", fr.Summary.CoveragePercent)
	}
}

func TestFrameworkReportCalculateSummary(t *testing.T) {
	fr := &FrameworkReport{
		Framework: FrameworkSOC2,
		Assessments: []ControlAssessment{
			{Status: StatusCompliant},
			{Status: StatusCompliant},
			{Status: StatusNonCompliant},
			{Status: StatusPartial},
			{Status: StatusNotAssessed},
		},
	}

	fr.calculateSummary()

	if fr.Summary.TotalControls != 5 {
		t.Errorf("expected 5 total, got %d", fr.Summary.TotalControls)
	}
	if fr.Summary.CompliantCount != 2 {
		t.Errorf("expected 2 compliant, got %d", fr.Summary.CompliantCount)
	}
	if fr.Summary.NonCompliantCount != 1 {
		t.Errorf("expected 1 non-compliant, got %d", fr.Summary.NonCompliantCount)
	}
	if fr.Summary.PartialCount != 1 {
		t.Errorf("expected 1 partial, got %d", fr.Summary.PartialCount)
	}
	if fr.Summary.NotAssessedCount != 1 {
		t.Errorf("expected 1 not assessed, got %d", fr.Summary.NotAssessedCount)
	}
	if fr.Summary.CoveragePercent != 40.0 {
		t.Errorf("expected 40%%, got %f", fr.Summary.CoveragePercent)
	}
}
