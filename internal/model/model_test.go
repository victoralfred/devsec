package model

import (
	"encoding/json"
	"testing"
)

func TestSeverityConstants(t *testing.T) {
	tests := []struct {
		severity Severity
		expected string
	}{
		{SeverityCritical, "critical"},
		{SeverityHigh, "high"},
		{SeverityMedium, "medium"},
		{SeverityLow, "low"},
		{SeverityInfo, "info"},
	}

	for _, tt := range tests {
		if string(tt.severity) != tt.expected {
			t.Errorf("expected %s, got %s", tt.expected, tt.severity)
		}
	}
}

func TestFindingJSON(t *testing.T) {
	finding := Finding{
		ID:          "test-001",
		Title:       "Test Finding",
		Description: "A test finding",
		Severity:    SeverityHigh,
		Location: Location{
			File:      "test.go",
			StartLine: 10,
			EndLine:   15,
			Column:    5,
		},
		Rule:    "test-rule",
		Scanner: "test-scanner",
	}

	data, err := json.Marshal(finding)
	if err != nil {
		t.Fatalf("failed to marshal finding: %v", err)
	}

	var decoded Finding
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal finding: %v", err)
	}

	if decoded.ID != finding.ID {
		t.Errorf("expected ID %s, got %s", finding.ID, decoded.ID)
	}
	if decoded.Severity != finding.Severity {
		t.Errorf("expected severity %s, got %s", finding.Severity, decoded.Severity)
	}
	if decoded.Location.File != finding.Location.File {
		t.Errorf("expected file %s, got %s", finding.Location.File, decoded.Location.File)
	}
}

func TestReportJSON(t *testing.T) {
	report := Report{
		Findings: []Finding{
			{
				ID:       "f1",
				Title:    "Finding 1",
				Severity: SeverityCritical,
			},
		},
		Summary: Summary{
			Total:    1,
			Critical: 1,
		},
		Metadata: map[string]string{
			"version": "1.0.0",
		},
		Timestamp: "2025-01-01T00:00:00Z",
	}

	data, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("failed to marshal report: %v", err)
	}

	var decoded Report
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal report: %v", err)
	}

	if len(decoded.Findings) != 1 {
		t.Errorf("expected 1 finding, got %d", len(decoded.Findings))
	}
	if decoded.Summary.Critical != 1 {
		t.Errorf("expected 1 critical, got %d", decoded.Summary.Critical)
	}
}

func TestLocationJSON(t *testing.T) {
	location := Location{
		File:      "path/to/file.go",
		StartLine: 100,
		EndLine:   110,
		Column:    15,
	}

	data, err := json.Marshal(location)
	if err != nil {
		t.Fatalf("failed to marshal location: %v", err)
	}

	var decoded Location
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal location: %v", err)
	}

	if decoded.File != location.File {
		t.Errorf("expected file %s, got %s", location.File, decoded.File)
	}
	if decoded.StartLine != location.StartLine {
		t.Errorf("expected start line %d, got %d", location.StartLine, decoded.StartLine)
	}
}

func TestSummaryJSON(t *testing.T) {
	summary := Summary{
		Total:    10,
		Critical: 1,
		High:     2,
		Medium:   3,
		Low:      3,
		Info:     1,
	}

	data, err := json.Marshal(summary)
	if err != nil {
		t.Fatalf("failed to marshal summary: %v", err)
	}

	var decoded Summary
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal summary: %v", err)
	}

	if decoded.Total != summary.Total {
		t.Errorf("expected total %d, got %d", summary.Total, decoded.Total)
	}
}
