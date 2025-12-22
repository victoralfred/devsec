package compliance

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestNewJSONFormatter(t *testing.T) {
	f := NewJSONFormatter(true)
	if f == nil {
		t.Fatal("expected formatter, got nil")
	}
	if !f.Pretty {
		t.Error("expected Pretty to be true")
	}
}

func TestJSONFormatterFormat(t *testing.T) {
	f := NewJSONFormatter(true)

	report := NewReport()
	report.AddAssessment(FrameworkSOC2, ControlAssessment{
		Control: Control{ID: "CC6.1"},
		Status:  StatusCompliant,
	})
	report.CalculateSummary()

	data, err := f.Format(report)
	if err != nil {
		t.Fatalf("Format error: %v", err)
	}

	if len(data) == 0 {
		t.Error("expected non-empty output")
	}

	// Verify it's valid JSON.
	var result map[string]interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		t.Errorf("invalid JSON: %v", err)
	}

	// Pretty should have indentation.
	if !strings.Contains(string(data), "\n") {
		t.Error("expected pretty-printed output with newlines")
	}
}

func TestJSONFormatterFormatCompact(t *testing.T) {
	f := NewJSONFormatter(false)

	report := NewReport()
	report.AddAssessment(FrameworkSOC2, ControlAssessment{
		Control: Control{ID: "CC6.1"},
		Status:  StatusCompliant,
	})

	data, err := f.Format(report)
	if err != nil {
		t.Fatalf("Format error: %v", err)
	}

	// Compact should not have indentation newlines.
	lines := strings.Split(string(data), "\n")
	if len(lines) > 1 {
		t.Error("expected compact output without newlines")
	}
}

func TestJSONFormatterFormatFramework(t *testing.T) {
	f := NewJSONFormatter(true)

	report := &FrameworkReport{
		Framework:   FrameworkSOC2,
		GeneratedAt: time.Now(),
		Assessments: []ControlAssessment{
			{Control: Control{ID: "CC6.1"}, Status: StatusCompliant},
		},
	}

	data, err := f.FormatFramework(report)
	if err != nil {
		t.Fatalf("FormatFramework error: %v", err)
	}

	if len(data) == 0 {
		t.Error("expected non-empty output")
	}
}

func TestJSONFormatterFormatSummary(t *testing.T) {
	f := NewJSONFormatter(true)

	summary := Summary{
		TotalControls:  10,
		CompliantCount: 8,
		OverallScore:   80.0,
	}

	data, err := f.FormatSummary(summary)
	if err != nil {
		t.Fatalf("FormatSummary error: %v", err)
	}

	if !strings.Contains(string(data), "80") {
		t.Error("expected compliance percentage in output")
	}
}

func TestJSONFormatterContentType(t *testing.T) {
	f := NewJSONFormatter(true)
	if f.ContentType() != "application/json" {
		t.Errorf("expected application/json, got %s", f.ContentType())
	}
}

func TestNewMarkdownFormatter(t *testing.T) {
	f := NewMarkdownFormatter(true)
	if f == nil {
		t.Fatal("expected formatter, got nil")
	}
	if !f.IncludeDetails {
		t.Error("expected IncludeDetails to be true")
	}
}

func TestMarkdownFormatterFormat(t *testing.T) {
	f := NewMarkdownFormatter(true)

	report := NewReport()
	report.AddAssessment(FrameworkSOC2, ControlAssessment{
		Control: Control{ID: "CC6.1", Framework: "soc2"},
		Status:  StatusCompliant,
	})
	report.AddAssessment(FrameworkSOC2, ControlAssessment{
		Control: Control{ID: "CC6.6", Framework: "soc2"},
		Status:  StatusNonCompliant,
	})
	report.AddGap(Gap{
		Severity:    "high",
		Description: "Test gap",
		Control:     Control{ID: "CC6.6", Framework: "soc2"},
		Remediation: "Fix it",
	})
	report.CalculateSummary()

	data, err := f.Format(report)
	if err != nil {
		t.Fatalf("Format error: %v", err)
	}

	output := string(data)

	if !strings.Contains(output, "# Compliance Report") {
		t.Error("expected title")
	}
	if !strings.Contains(output, "Executive Summary") {
		t.Error("expected executive summary")
	}
	if !strings.Contains(output, "SOC2") {
		t.Error("expected SOC2 framework")
	}
	if !strings.Contains(output, "Compliance Gaps") {
		t.Error("expected gaps section")
	}
	if !strings.Contains(output, "Test gap") {
		t.Error("expected gap description")
	}
	if !strings.Contains(output, "Detailed Assessments") {
		t.Error("expected detailed assessments")
	}
}

func TestMarkdownFormatterFormatWithoutDetails(t *testing.T) {
	f := NewMarkdownFormatter(false)

	report := NewReport()
	report.AddAssessment(FrameworkSOC2, ControlAssessment{
		Control: Control{ID: "CC6.1"},
		Status:  StatusCompliant,
	})
	report.CalculateSummary()

	data, err := f.Format(report)
	if err != nil {
		t.Fatalf("Format error: %v", err)
	}

	output := string(data)

	if strings.Contains(output, "Detailed Assessments") {
		t.Error("should not include detailed assessments")
	}
}

func TestMarkdownFormatterFormatFramework(t *testing.T) {
	f := NewMarkdownFormatter(true)

	report := &FrameworkReport{
		Framework:   FrameworkSOC2,
		GeneratedAt: time.Now(),
		Assessments: []ControlAssessment{
			{Control: Control{ID: "CC6.1"}, Status: StatusCompliant},
			{Control: Control{ID: "CC6.6"}, Status: StatusNonCompliant},
		},
		Gaps: []Gap{
			{Severity: "high", Control: Control{ID: "CC6.6"}, Description: "Gap found"},
		},
	}
	report.calculateSummary()

	data, err := f.FormatFramework(report)
	if err != nil {
		t.Fatalf("FormatFramework error: %v", err)
	}

	output := string(data)

	if !strings.Contains(output, "SOC2 Compliance Report") {
		t.Error("expected SOC2 title")
	}
	if !strings.Contains(output, "50.0%") {
		t.Error("expected 50% compliance")
	}
}

func TestMarkdownFormatterFormatSummary(t *testing.T) {
	f := NewMarkdownFormatter(true)

	summary := Summary{
		TotalControls:     10,
		CompliantCount:    8,
		NonCompliantCount: 2,
		OverallScore:      80.0,
		FrameworkSummaries: map[FrameworkID]FrameworkSummary{
			FrameworkSOC2:     {Framework: FrameworkSOC2, TotalControls: 5, CompliantCount: 4, CoveragePercent: 80.0},
			FrameworkISO27001: {Framework: FrameworkISO27001, TotalControls: 5, CompliantCount: 4, CoveragePercent: 80.0},
		},
	}

	data, err := f.FormatSummary(summary)
	if err != nil {
		t.Fatalf("FormatSummary error: %v", err)
	}

	output := string(data)

	if !strings.Contains(output, "Compliance Summary") {
		t.Error("expected title")
	}
	if !strings.Contains(output, "SOC2") {
		t.Error("expected SOC2")
	}
	if !strings.Contains(output, "ISO27001") {
		t.Error("expected ISO27001")
	}
}

func TestMarkdownFormatterContentType(t *testing.T) {
	f := NewMarkdownFormatter(true)
	if f.ContentType() != "text/markdown" {
		t.Errorf("expected text/markdown, got %s", f.ContentType())
	}
}

func TestStatusEmoji(t *testing.T) {
	tests := []struct {
		status ControlStatus
		want   string
	}{
		{StatusCompliant, "✅"},
		{StatusNonCompliant, "❌"},
		{StatusPartial, "⚠️"},
		{StatusNotAssessed, "❓"},
		{ControlStatus("unknown"), ""},
	}

	for _, tt := range tests {
		got := statusEmoji(tt.status)
		if got != tt.want {
			t.Errorf("statusEmoji(%s) = %q, want %q", tt.status, got, tt.want)
		}
	}
}

func TestGetFormatter(t *testing.T) {
	tests := []struct {
		format      string
		contentType string
	}{
		{"json", "application/json"},
		{"markdown", "text/markdown"},
		{"md", "text/markdown"},
		{"unknown", "application/json"}, // Default.
	}

	for _, tt := range tests {
		f := GetFormatter(tt.format)
		if f.ContentType() != tt.contentType {
			t.Errorf("GetFormatter(%q).ContentType() = %q, want %q",
				tt.format, f.ContentType(), tt.contentType)
		}
	}
}

func TestGetFormatterWithOptions(t *testing.T) {
	f := GetFormatter("json", WithPretty(false))
	jsonF, ok := f.(*JSONFormatter)
	if !ok {
		t.Fatal("expected JSONFormatter")
	}
	if jsonF.Pretty {
		t.Error("expected Pretty to be false")
	}

	f = GetFormatter("markdown", WithDetails(false))
	mdF, ok := f.(*MarkdownFormatter)
	if !ok {
		t.Fatal("expected MarkdownFormatter")
	}
	if mdF.IncludeDetails {
		t.Error("expected IncludeDetails to be false")
	}
}

func TestMarkdownFormatterGapsBySeverity(t *testing.T) {
	f := NewMarkdownFormatter(true)

	report := NewReport()
	report.AddGap(Gap{Severity: "critical", Control: Control{ID: "C1"}, Description: "Critical gap"})
	report.AddGap(Gap{Severity: "high", Control: Control{ID: "C2"}, Description: "High gap"})
	report.AddGap(Gap{Severity: "medium", Control: Control{ID: "C3"}, Description: "Medium gap"})
	report.AddGap(Gap{Severity: "low", Control: Control{ID: "C4"}, Description: "Low gap"})
	report.CalculateSummary()

	data, err := f.Format(report)
	if err != nil {
		t.Fatalf("Format error: %v", err)
	}

	output := string(data)

	if !strings.Contains(output, "#### Critical") {
		t.Error("expected critical section")
	}
	if !strings.Contains(output, "#### High") {
		t.Error("expected high section")
	}
	if !strings.Contains(output, "#### Medium") {
		t.Error("expected medium section")
	}
	if !strings.Contains(output, "#### Low") {
		t.Error("expected low section")
	}
}
