package compliance

import (
	"context"
	"testing"

	"github.com/victoralfred/devsec/internal/model"
)

func TestNewMapper(t *testing.T) {
	m := NewMapper()

	if m == nil {
		t.Fatal("expected mapper, got nil")
	}
	if m.frameworks == nil {
		t.Error("frameworks should not be nil")
	}
	if m.cweMapper == nil {
		t.Error("cweMapper should not be nil")
	}

	// Verify all frameworks are loaded.
	if len(m.frameworks) != 3 {
		t.Errorf("expected 3 frameworks, got %d", len(m.frameworks))
	}
}

func TestMapperWithCWEMapper(t *testing.T) {
	customCWE := NewCWEMapper()
	customCWE.AddMapping("CWE-999", FrameworkSOC2, "CC9.9")

	m := NewMapper(WithCWEMapper(customCWE))

	controls := m.cweMapper.GetControls("CWE-999")
	if len(controls) == 0 {
		t.Error("expected custom CWE mapping")
	}
}

func TestMapperEnrich(t *testing.T) {
	m := NewMapper()
	ctx := context.Background()

	findings := []model.Finding{
		{
			ID:          "vuln-1",
			Title:       "SQL Injection",
			Description: "CWE-89 SQL injection vulnerability",
			Rule:        "sql-injection",
			Severity:    model.SeverityCritical,
		},
		{
			ID:       "vuln-2",
			Title:    "XSS",
			Rule:     "CWE-79",
			Severity: model.SeverityHigh,
		},
	}

	enriched, err := m.Enrich(ctx, findings)
	if err != nil {
		t.Fatalf("Enrich error: %v", err)
	}

	if len(enriched) != 2 {
		t.Fatalf("expected 2 enriched findings, got %d", len(enriched))
	}

	// First finding should have CWE-89.
	if len(enriched[0].CWEIDs) == 0 {
		t.Error("expected CWE IDs for first finding")
	}
	if enriched[0].CWEIDs[0] != "CWE-89" {
		t.Errorf("expected CWE-89, got %s", enriched[0].CWEIDs[0])
	}

	// Should have control mappings.
	if len(enriched[0].ControlIDs) == 0 {
		t.Error("expected control IDs for first finding")
	}
}

func TestMapperEnrichEmpty(t *testing.T) {
	m := NewMapper()
	ctx := context.Background()

	enriched, err := m.Enrich(ctx, nil)
	if err != nil {
		t.Fatalf("Enrich error: %v", err)
	}

	if enriched != nil {
		t.Error("expected nil for empty input")
	}
}

func TestMapperEnrichContextCancel(t *testing.T) {
	m := NewMapper()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	findings := []model.Finding{
		{ID: "vuln-1", Title: "Test"},
	}

	_, err := m.Enrich(ctx, findings)
	if err == nil {
		t.Error("expected context error")
	}
}

func TestMapperMapToControls(t *testing.T) {
	m := NewMapper()
	ctx := context.Background()

	enriched := []EnrichedFinding{
		{
			Finding: model.Finding{
				ID:       "vuln-1",
				Severity: model.SeverityCritical,
			},
			CWEIDs:     []string{"CWE-89"},
			ControlIDs: []string{"soc2:CC6.1", "soc2:CC7.1"},
		},
	}

	assessments, err := m.MapToControls(ctx, enriched, []FrameworkID{FrameworkSOC2})
	if err != nil {
		t.Fatalf("MapToControls error: %v", err)
	}

	if len(assessments) != 1 {
		t.Fatalf("expected 1 framework, got %d", len(assessments))
	}

	soc2 := assessments[FrameworkSOC2]
	if len(soc2) == 0 {
		t.Error("expected SOC2 assessments")
	}
}

func TestMapperMapToControlsAllFrameworks(t *testing.T) {
	m := NewMapper()
	ctx := context.Background()

	enriched := []EnrichedFinding{
		{
			Finding: model.Finding{
				ID:       "vuln-1",
				Severity: model.SeverityHigh,
			},
			CWEIDs: []string{"CWE-287"},
		},
	}

	// Pass empty frameworks to use all.
	assessments, err := m.MapToControls(ctx, enriched, nil)
	if err != nil {
		t.Fatalf("MapToControls error: %v", err)
	}

	if len(assessments) != 3 {
		t.Errorf("expected 3 frameworks, got %d", len(assessments))
	}
}

func TestMapperGetControlByID(t *testing.T) {
	m := NewMapper()

	ctrl, found := m.GetControlByID(FrameworkSOC2, "CC6.1")
	if !found {
		t.Error("expected to find CC6.1")
	}
	if ctrl.ID != "CC6.1" {
		t.Errorf("expected CC6.1, got %s", ctrl.ID)
	}

	_, found = m.GetControlByID(FrameworkSOC2, "CC99.99")
	if found {
		t.Error("expected not to find CC99.99")
	}

	_, found = m.GetControlByID(FrameworkID("unknown"), "CC6.1")
	if found {
		t.Error("expected not to find in unknown framework")
	}
}

func TestMapperListControls(t *testing.T) {
	m := NewMapper()

	controls := m.ListControls(FrameworkSOC2)
	if len(controls) == 0 {
		t.Error("expected SOC2 controls")
	}

	controls = m.ListControls(FrameworkID("unknown"))
	if len(controls) != 0 {
		t.Error("expected no controls for unknown framework")
	}
}

func TestExtractCWEFromString(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"CWE-89 SQL injection", "CWE-89"},
		{"Vulnerability CWE-79 detected", "CWE-79"},
		{"No CWE here", ""},
		{"CWE- incomplete", ""},
		{"CWE-123 first CWE-456 second", "CWE-123"},
	}

	for _, tt := range tests {
		got := extractCWEFromString(tt.input)
		if got != tt.want {
			t.Errorf("extractCWEFromString(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestExtractCVEFromString(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"CVE-2023-12345", "CVE-2023-12345"},
		{"Vulnerability CVE-2024-1234 found", "CVE-2024-1234"},
		{"No CVE here", ""},
		{"CVE-202-123 invalid year", ""},
		{"CVE-2023-12 too short", ""},
	}

	for _, tt := range tests {
		got := extractCVEFromString(tt.input)
		if got != tt.want {
			t.Errorf("extractCVEFromString(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestExtractCWEsFromFinding(t *testing.T) {
	f := model.Finding{
		ID:          "vuln-1",
		Rule:        "CWE-89",
		Description: "SQL injection (CWE-79 also mentioned)",
	}

	cwes := extractCWEsFromFinding(f)
	if len(cwes) != 2 {
		t.Errorf("expected 2 CWEs, got %d", len(cwes))
	}
}

func TestExtractCVEsFromFinding(t *testing.T) {
	f := model.Finding{
		ID:          "CVE-2023-12345",
		Rule:        "vuln-check",
		Description: "CVE-2024-5678 vulnerability",
	}

	cves := extractCVEsFromFinding(f)
	if len(cves) != 2 {
		t.Errorf("expected 2 CVEs, got %d", len(cves))
	}
}

func TestAssessControlWithCriticalFindings(t *testing.T) {
	m := NewMapper()

	ctrl := Control{
		ID:          "CC6.1",
		Framework:   "soc2",
		CWEMappings: []string{"CWE-89"},
	}

	findings := []EnrichedFinding{
		{
			Finding: model.Finding{
				ID:       "vuln-1",
				Severity: model.SeverityCritical,
			},
			CWEIDs:     []string{"CWE-89"},
			ControlIDs: []string{"soc2:CC6.1"},
		},
	}

	assessment := m.assessControl(ctrl, findings)

	if assessment.Status != StatusNonCompliant {
		t.Errorf("expected non_compliant, got %s", assessment.Status)
	}
	if assessment.CriticalCount != 1 {
		t.Errorf("expected 1 critical, got %d", assessment.CriticalCount)
	}
}

func TestAssessControlWithLowFindings(t *testing.T) {
	m := NewMapper()

	ctrl := Control{
		ID:          "CC6.1",
		Framework:   "soc2",
		CWEMappings: []string{"CWE-89"},
	}

	findings := []EnrichedFinding{
		{
			Finding: model.Finding{
				ID:       "vuln-1",
				Severity: model.SeverityLow,
			},
			CWEIDs:     []string{"CWE-89"},
			ControlIDs: []string{"soc2:CC6.1"},
		},
	}

	assessment := m.assessControl(ctrl, findings)

	if assessment.Status != StatusPartial {
		t.Errorf("expected partial, got %s", assessment.Status)
	}
}

func TestAssessControlNoFindings(t *testing.T) {
	m := NewMapper()

	ctrl := Control{
		ID:        "CC6.1",
		Framework: "soc2",
	}

	findings := []EnrichedFinding{}

	assessment := m.assessControl(ctrl, findings)

	if assessment.Status != StatusCompliant {
		t.Errorf("expected compliant, got %s", assessment.Status)
	}
}
