package cli

import (
	"bytes"
	"testing"

	"github.com/victoralfred/devsec/internal/compliance"
)

func TestNewComplianceCmd(t *testing.T) {
	cmd := NewComplianceCmd()

	if cmd == nil {
		t.Fatal("expected command, got nil")
	}

	if cmd.Use != "compliance" {
		t.Errorf("expected use 'compliance', got %s", cmd.Use)
	}

	// Verify subcommands.
	subcommands := cmd.Commands()
	expectedSubs := []string{"assess", "report", "coverage", "gaps", "controls"}

	for _, expected := range expectedSubs {
		found := false
		for _, sub := range subcommands {
			if sub.Use == expected || (len(sub.Use) > len(expected) && sub.Use[:len(expected)] == expected) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected subcommand '%s' not found", expected)
		}
	}
}

func TestNewComplianceAssessCmd(t *testing.T) {
	cmd := NewComplianceAssessCmd()

	if cmd == nil {
		t.Fatal("expected command, got nil")
	}

	// Verify flags.
	flags := []string{"output", "format", "frameworks", "timeout", "scan-file"}
	for _, flag := range flags {
		if cmd.Flags().Lookup(flag) == nil {
			t.Errorf("expected flag '%s' not found", flag)
		}
	}
}

func TestNewComplianceReportCmd(t *testing.T) {
	cmd := NewComplianceReportCmd()

	if cmd == nil {
		t.Fatal("expected command, got nil")
	}

	// Verify required flag.
	outputFlag := cmd.Flags().Lookup("output")
	if outputFlag == nil {
		t.Error("expected output flag")
	}
}

func TestNewComplianceCoverageCmd(t *testing.T) {
	cmd := NewComplianceCoverageCmd()

	if cmd == nil {
		t.Fatal("expected command, got nil")
	}
}

func TestNewComplianceGapsCmd(t *testing.T) {
	cmd := NewComplianceGapsCmd()

	if cmd == nil {
		t.Fatal("expected command, got nil")
	}
}

func TestNewComplianceControlsCmd(t *testing.T) {
	cmd := NewComplianceControlsCmd()

	if cmd == nil {
		t.Fatal("expected command, got nil")
	}

	// Should have list subcommand.
	listCmd, _, err := cmd.Find([]string{"list"})
	if err != nil {
		t.Errorf("expected list subcommand: %v", err)
	}
	if listCmd == nil {
		t.Error("list subcommand should not be nil")
	}
}

func TestParseFrameworks(t *testing.T) {
	tests := []struct {
		input    string
		expected int
	}{
		{"", 0},
		{"soc2", 1},
		{"soc2,iso27001", 2},
		{"soc2,iso27001,gdpr", 3},
		{"SOC2,ISO27001", 2}, // Case insensitive.
		{"unknown", 0},
		{"soc2,unknown,gdpr", 2},
	}

	for _, tt := range tests {
		result := parseFrameworks(tt.input)
		if len(result) != tt.expected {
			t.Errorf("parseFrameworks(%q) = %d frameworks, want %d", tt.input, len(result), tt.expected)
		}
	}
}

func TestFormatCoverageStats(t *testing.T) {
	overall := compliance.CoverageStats{
		Framework:         "overall",
		CoveragePercent:   75.0,
		TotalControls:     100,
		CompliantControls: 75,
		GapCount:          25,
	}

	stats := []compliance.CoverageStats{
		{
			Framework:         compliance.FrameworkSOC2,
			CoveragePercent:   80.0,
			TotalControls:     50,
			CompliantControls: 40,
			GapCount:          10,
		},
	}

	output := formatCoverageStats(overall, stats)

	if output == "" {
		t.Error("expected non-empty output")
	}

	if !bytes.Contains([]byte(output), []byte("75.0%")) {
		t.Error("expected overall coverage percentage")
	}

	if !bytes.Contains([]byte(output), []byte("SOC2")) {
		t.Error("expected SOC2 framework")
	}
}

func TestFormatGapsText(t *testing.T) {
	summary := compliance.GapSummary{
		TotalGaps:     3,
		CriticalCount: 1,
		HighCount:     1,
		MediumCount:   1,
	}

	gaps := []compliance.Gap{
		{
			Severity:    "critical",
			Description: "Critical issue",
			Control:     compliance.Control{ID: "CC6.1", Framework: "soc2"},
			Remediation: "Fix it now",
		},
	}

	output := formatGapsText(summary, gaps)

	if output == "" {
		t.Error("expected non-empty output")
	}

	if !bytes.Contains([]byte(output), []byte("CRITICAL")) {
		t.Error("expected CRITICAL severity")
	}

	if !bytes.Contains([]byte(output), []byte("CC6.1")) {
		t.Error("expected control ID")
	}
}

func TestFormatGapsMarkdown(t *testing.T) {
	summary := compliance.GapSummary{
		TotalGaps:     2,
		CriticalCount: 1,
		HighCount:     1,
	}

	gaps := []compliance.Gap{
		{
			Severity:     "high",
			Description:  "High severity issue",
			Control:      compliance.Control{ID: "A.9.4.2", Framework: "iso27001"},
			Remediation:  "Update authentication",
			FindingCount: 3,
		},
	}

	output := formatGapsMarkdown(summary, gaps)

	if output == "" {
		t.Error("expected non-empty output")
	}

	if !bytes.Contains([]byte(output), []byte("# Compliance Gaps")) {
		t.Error("expected markdown title")
	}

	if !bytes.Contains([]byte(output), []byte("A.9.4.2")) {
		t.Error("expected control ID")
	}

	if !bytes.Contains([]byte(output), []byte("**Remediation**")) {
		t.Error("expected remediation section")
	}
}
