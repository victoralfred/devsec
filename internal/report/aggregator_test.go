package report

import (
	"context"
	"testing"
	"time"

	"github.com/victoralfred/devsec/internal/model"
)

// TestNewAggregator tests aggregator creation.
func TestNewAggregator(t *testing.T) {
	a := New()
	if a == nil {
		t.Fatal("expected non-nil aggregator")
	}
	if !a.dedupeEnabled {
		t.Error("expected deduplication enabled by default")
	}
}

// TestNewAggregatorWithOptions tests aggregator creation with options.
func TestNewAggregatorWithOptions(t *testing.T) {
	a := New(WithDeduplication(false))
	if a == nil {
		t.Fatal("expected non-nil aggregator")
	}
	if a.dedupeEnabled {
		t.Error("expected deduplication disabled")
	}
}

// TestAddFindings tests adding findings from a scanner.
func TestAddFindings(t *testing.T) {
	a := New()
	findings := []model.Finding{
		{ID: "test-1", Severity: model.SeverityHigh},
		{ID: "test-2", Severity: model.SeverityLow},
	}

	a.AddFindings("gitleaks", findings)

	if a.FindingCount() != 2 {
		t.Errorf("expected 2 findings, got %d", a.FindingCount())
	}

	results := a.GetScannerResults()
	if _, ok := results["gitleaks"]; !ok {
		t.Error("expected gitleaks in scanner results")
	}
}

// TestAddResult tests adding a complete scanner result.
func TestAddResult(t *testing.T) {
	a := New()
	result := ScannerResult{
		Scanner:   "semgrep",
		Version:   "1.0.0",
		Duration:  5 * time.Second,
		Timestamp: time.Now(),
		Findings: []model.Finding{
			{ID: "test-1", Severity: model.SeverityMedium},
		},
	}

	a.AddResult(result)

	if a.FindingCount() != 1 {
		t.Errorf("expected 1 finding, got %d", a.FindingCount())
	}

	results := a.GetScannerResults()
	if r, ok := results["semgrep"]; !ok {
		t.Error("expected semgrep in scanner results")
	} else if r.Version != "1.0.0" {
		t.Errorf("expected version 1.0.0, got %s", r.Version)
	}
}

// TestAggregateBasic tests basic aggregation.
func TestAggregateBasic(t *testing.T) {
	a := New()
	a.AddFindings("scanner1", []model.Finding{
		{ID: "f1", Severity: model.SeverityCritical, Rule: "rule1", Location: model.Location{File: "file1.go"}},
	})
	a.AddFindings("scanner2", []model.Finding{
		{ID: "f2", Severity: model.SeverityHigh, Rule: "rule2", Location: model.Location{File: "file2.go"}},
	})

	ctx := context.Background()
	report, err := a.Aggregate(ctx)
	if err != nil {
		t.Fatalf("Aggregate() error = %v", err)
	}

	if report.Summary.Total != 2 {
		t.Errorf("expected 2 total findings, got %d", report.Summary.Total)
	}
	if report.Summary.Critical != 1 {
		t.Errorf("expected 1 critical, got %d", report.Summary.Critical)
	}
	if report.Summary.High != 1 {
		t.Errorf("expected 1 high, got %d", report.Summary.High)
	}
}

// TestAggregateDeduplication tests finding deduplication.
func TestAggregateDeduplication(t *testing.T) {
	a := New()

	// Add duplicate findings (same file, rule, and location)
	finding := model.Finding{
		ID:       "f1",
		Rule:     "secret-detected",
		Severity: model.SeverityHigh,
		Location: model.Location{
			File:      "config.go",
			StartLine: 10,
			EndLine:   10,
		},
	}

	a.AddFindings("gitleaks", []model.Finding{finding})
	a.AddFindings("trivy", []model.Finding{finding})

	ctx := context.Background()
	report, err := a.Aggregate(ctx)
	if err != nil {
		t.Fatalf("Aggregate() error = %v", err)
	}

	// Should be deduplicated to 1
	if report.Summary.Total != 1 {
		t.Errorf("expected 1 finding after dedup, got %d", report.Summary.Total)
	}
}

// TestAggregateWithoutDeduplication tests aggregation without deduplication.
func TestAggregateWithoutDeduplication(t *testing.T) {
	a := New(WithDeduplication(false))

	finding := model.Finding{
		ID:       "f1",
		Rule:     "secret-detected",
		Severity: model.SeverityHigh,
		Location: model.Location{
			File:      "config.go",
			StartLine: 10,
			EndLine:   10,
		},
	}

	a.AddFindings("gitleaks", []model.Finding{finding})
	a.AddFindings("trivy", []model.Finding{finding})

	ctx := context.Background()
	report, err := a.Aggregate(ctx)
	if err != nil {
		t.Fatalf("Aggregate() error = %v", err)
	}

	// Should keep both
	if report.Summary.Total != 2 {
		t.Errorf("expected 2 findings without dedup, got %d", report.Summary.Total)
	}
}

// TestAggregateSorting tests finding sorting by severity.
func TestAggregateSorting(t *testing.T) {
	a := New()
	a.AddFindings("scanner", []model.Finding{
		{ID: "low", Severity: model.SeverityLow, Rule: "r1", Location: model.Location{File: "a.go"}},
		{ID: "critical", Severity: model.SeverityCritical, Rule: "r2", Location: model.Location{File: "b.go"}},
		{ID: "medium", Severity: model.SeverityMedium, Rule: "r3", Location: model.Location{File: "c.go"}},
		{ID: "high", Severity: model.SeverityHigh, Rule: "r4", Location: model.Location{File: "d.go"}},
	})

	ctx := context.Background()
	report, err := a.Aggregate(ctx)
	if err != nil {
		t.Fatalf("Aggregate() error = %v", err)
	}

	expected := []model.Severity{
		model.SeverityCritical,
		model.SeverityHigh,
		model.SeverityMedium,
		model.SeverityLow,
	}

	if len(report.Findings) != 4 {
		t.Fatalf("expected 4 findings, got %d", len(report.Findings))
	}

	for i, f := range report.Findings {
		if f.Severity != expected[i] {
			t.Errorf("finding %d: expected severity %s, got %s", i, expected[i], f.Severity)
		}
	}
}

// TestAggregateContextCancellation tests context cancellation handling.
func TestAggregateContextCancellation(t *testing.T) {
	a := New()
	a.AddFindings("scanner", []model.Finding{
		{ID: "f1", Severity: model.SeverityHigh},
	})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := a.Aggregate(ctx)
	if err == nil {
		t.Error("expected error for canceled context")
	}
}

// TestNormalizeSeverity tests severity normalization.
func TestNormalizeSeverity(t *testing.T) {
	tests := []struct {
		input    model.Severity
		expected model.Severity
	}{
		{model.Severity("CRITICAL"), model.SeverityCritical},
		{model.Severity("crit"), model.SeverityCritical},
		{model.Severity("HIGH"), model.SeverityHigh},
		{model.Severity("error"), model.SeverityHigh},
		{model.Severity("MEDIUM"), model.SeverityMedium},
		{model.Severity("moderate"), model.SeverityMedium},
		{model.Severity("warning"), model.SeverityMedium},
		{model.Severity("LOW"), model.SeverityLow},
		{model.Severity("INFO"), model.SeverityInfo},
		{model.Severity("informational"), model.SeverityInfo},
		{model.Severity("note"), model.SeverityInfo},
		{model.Severity(""), model.SeverityInfo},
		{model.Severity("unknown"), model.Severity("unknown")},
	}

	for _, tt := range tests {
		t.Run(string(tt.input), func(t *testing.T) {
			result := normalizeSeverity(tt.input)
			if result != tt.expected {
				t.Errorf("normalizeSeverity(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

// TestGenerateFindingKey tests unique key generation.
func TestGenerateFindingKey(t *testing.T) {
	f1 := &model.Finding{
		Rule: "test-rule",
		Location: model.Location{
			File:      "file.go",
			StartLine: 10,
			EndLine:   10,
		},
	}

	f2 := &model.Finding{
		Rule: "test-rule",
		Location: model.Location{
			File:      "file.go",
			StartLine: 10,
			EndLine:   10,
		},
	}

	f3 := &model.Finding{
		Rule: "different-rule",
		Location: model.Location{
			File:      "file.go",
			StartLine: 10,
			EndLine:   10,
		},
	}

	key1 := generateFindingKey(f1)
	key2 := generateFindingKey(f2)
	key3 := generateFindingKey(f3)

	if key1 != key2 {
		t.Error("expected same key for identical findings")
	}
	if key1 == key3 {
		t.Error("expected different key for different rules")
	}
}

// TestCalculateSummary tests summary calculation.
func TestCalculateSummary(t *testing.T) {
	findings := []model.Finding{
		{Severity: model.SeverityCritical},
		{Severity: model.SeverityCritical},
		{Severity: model.SeverityHigh},
		{Severity: model.SeverityMedium},
		{Severity: model.SeverityMedium},
		{Severity: model.SeverityMedium},
		{Severity: model.SeverityLow},
		{Severity: model.SeverityInfo},
	}

	summary := calculateSummary(findings)

	if summary.Total != 8 {
		t.Errorf("expected total 8, got %d", summary.Total)
	}
	if summary.Critical != 2 {
		t.Errorf("expected critical 2, got %d", summary.Critical)
	}
	if summary.High != 1 {
		t.Errorf("expected high 1, got %d", summary.High)
	}
	if summary.Medium != 3 {
		t.Errorf("expected medium 3, got %d", summary.Medium)
	}
	if summary.Low != 1 {
		t.Errorf("expected low 1, got %d", summary.Low)
	}
	if summary.Info != 1 {
		t.Errorf("expected info 1, got %d", summary.Info)
	}
}

// TestAggregateEmptyFindings tests aggregation with no findings.
func TestAggregateEmptyFindings(t *testing.T) {
	a := New()
	ctx := context.Background()
	report, err := a.Aggregate(ctx)
	if err != nil {
		t.Fatalf("Aggregate() error = %v", err)
	}

	if report.Summary.Total != 0 {
		t.Errorf("expected 0 findings, got %d", report.Summary.Total)
	}
	if len(report.Findings) != 0 {
		t.Errorf("expected empty findings slice, got %d", len(report.Findings))
	}
}

// TestBuildMetadata tests metadata generation.
func TestBuildMetadata(t *testing.T) {
	a := New()
	a.AddFindings("gitleaks", []model.Finding{{ID: "f1"}})
	a.AddFindings("semgrep", []model.Finding{{ID: "f2"}})
	a.AddFindings("trivy", []model.Finding{{ID: "f3"}})

	metadata := a.buildMetadata()

	if _, ok := metadata["scanners"]; !ok {
		t.Error("expected scanners in metadata")
	}
	if _, ok := metadata["scanner_count"]; !ok {
		t.Error("expected scanner_count in metadata")
	}
}
