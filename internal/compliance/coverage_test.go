package compliance

import (
	"context"
	"testing"
)

func TestNewCoverageCalculator(t *testing.T) {
	mapper := NewMapper()
	calc := NewCoverageCalculator(mapper)

	if calc == nil {
		t.Fatal("expected calculator, got nil")
	}
	if calc.mapper == nil {
		t.Error("mapper should not be nil")
	}
}

func TestCoverageCalculatorCalculate(t *testing.T) {
	mapper := NewMapper()
	calc := NewCoverageCalculator(mapper)
	ctx := context.Background()

	assessments := map[FrameworkID][]ControlAssessment{
		FrameworkSOC2: {
			{Control: Control{ID: "CC6.1"}, Status: StatusCompliant},
			{Control: Control{ID: "CC6.6"}, Status: StatusCompliant},
			{Control: Control{ID: "CC6.7"}, Status: StatusNonCompliant},
			{Control: Control{ID: "CC7.1"}, Status: StatusPartial},
		},
	}

	stats, err := calc.Calculate(ctx, assessments)
	if err != nil {
		t.Fatalf("Calculate error: %v", err)
	}

	if len(stats) != 1 {
		t.Fatalf("expected 1 framework stats, got %d", len(stats))
	}

	s := stats[0]
	if s.Framework != FrameworkSOC2 {
		t.Errorf("Framework = %q, want %q", s.Framework, FrameworkSOC2)
	}
	if s.TotalControls != 4 {
		t.Errorf("TotalControls = %d, want 4", s.TotalControls)
	}
	if s.AssessedControls != 4 {
		t.Errorf("AssessedControls = %d, want 4", s.AssessedControls)
	}
	if s.CompliantControls != 2 {
		t.Errorf("CompliantControls = %d, want 2", s.CompliantControls)
	}
	if s.GapCount != 2 {
		t.Errorf("GapCount = %d, want 2", s.GapCount)
	}
	if s.CoveragePercent != 50.0 {
		t.Errorf("CoveragePercent = %f, want 50.0", s.CoveragePercent)
	}
}

func TestCoverageCalculatorCalculateEmpty(t *testing.T) {
	mapper := NewMapper()
	calc := NewCoverageCalculator(mapper)
	ctx := context.Background()

	stats, err := calc.Calculate(ctx, nil)
	if err != nil {
		t.Fatalf("Calculate error: %v", err)
	}

	if len(stats) != 0 {
		t.Errorf("expected 0 stats, got %d", len(stats))
	}
}

func TestCoverageCalculatorCalculateContextCancel(t *testing.T) {
	mapper := NewMapper()
	calc := NewCoverageCalculator(mapper)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	assessments := map[FrameworkID][]ControlAssessment{
		FrameworkSOC2: {{Control: Control{ID: "CC6.1"}, Status: StatusCompliant}},
	}

	_, err := calc.Calculate(ctx, assessments)
	if err == nil {
		t.Error("expected context error")
	}
}

func TestCoverageCalculatorCalculateOverall(t *testing.T) {
	mapper := NewMapper()
	calc := NewCoverageCalculator(mapper)
	ctx := context.Background()

	assessments := map[FrameworkID][]ControlAssessment{
		FrameworkSOC2: {
			{Control: Control{ID: "CC6.1"}, Status: StatusCompliant},
			{Control: Control{ID: "CC6.6"}, Status: StatusNonCompliant},
		},
		FrameworkISO27001: {
			{Control: Control{ID: "A.5.1"}, Status: StatusCompliant},
			{Control: Control{ID: "A.8.9"}, Status: StatusCompliant},
		},
	}

	overall, err := calc.CalculateOverall(ctx, assessments)
	if err != nil {
		t.Fatalf("CalculateOverall error: %v", err)
	}

	if overall.TotalControls != 4 {
		t.Errorf("TotalControls = %d, want 4", overall.TotalControls)
	}
	if overall.CompliantControls != 3 {
		t.Errorf("CompliantControls = %d, want 3", overall.CompliantControls)
	}
	if overall.CoveragePercent != 75.0 {
		t.Errorf("CoveragePercent = %f, want 75.0", overall.CoveragePercent)
	}
}

func TestCoverageCalculatorGetMissingControls(t *testing.T) {
	mapper := NewMapper()
	calc := NewCoverageCalculator(mapper)

	assessments := []ControlAssessment{
		{Control: Control{ID: "CC6.1"}, Status: StatusCompliant},
		{Control: Control{ID: "CC6.6"}, Status: StatusNotAssessed},
		{Control: Control{ID: "CC6.7"}, Status: StatusNotAssessed},
	}

	missing := calc.GetMissingControls(FrameworkSOC2, assessments)
	if len(missing) != 2 {
		t.Errorf("expected 2 missing controls, got %d", len(missing))
	}
}

func TestCoverageCalculatorWithNotAssessed(t *testing.T) {
	mapper := NewMapper()
	calc := NewCoverageCalculator(mapper)
	ctx := context.Background()

	assessments := map[FrameworkID][]ControlAssessment{
		FrameworkSOC2: {
			{Control: Control{ID: "CC6.1"}, Status: StatusCompliant},
			{Control: Control{ID: "CC6.6"}, Status: StatusNotAssessed},
		},
	}

	stats, err := calc.Calculate(ctx, assessments)
	if err != nil {
		t.Fatalf("Calculate error: %v", err)
	}

	s := stats[0]
	if s.TotalControls != 2 {
		t.Errorf("TotalControls = %d, want 2", s.TotalControls)
	}
	if s.AssessedControls != 1 {
		t.Errorf("AssessedControls = %d, want 1", s.AssessedControls)
	}
	if s.CoveragePercent != 100.0 {
		t.Errorf("CoveragePercent = %f, want 100.0", s.CoveragePercent)
	}
}
