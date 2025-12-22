package compliance

import (
	"testing"
)

func TestNewCWEMapper(t *testing.T) {
	m := NewCWEMapper()

	if m == nil {
		t.Fatal("expected mapper, got nil")
	}
	if m.cweToControls == nil {
		t.Error("cweToControls should not be nil")
	}
	if m.controlToCWEs == nil {
		t.Error("controlToCWEs should not be nil")
	}

	// Verify default mappings are loaded.
	cwes := m.GetAllMappedCWEs()
	if len(cwes) == 0 {
		t.Error("expected default CWE mappings to be loaded")
	}
}

func TestCWEMapperGetControls(t *testing.T) {
	m := NewCWEMapper()

	// Test SQL Injection (CWE-89) mappings.
	controls := m.GetControls("CWE-89")
	if len(controls) == 0 {
		t.Error("expected CWE-89 to map to controls")
	}

	// Verify mappings include expected frameworks.
	frameworks := make(map[FrameworkID]bool)
	for _, ref := range controls {
		frameworks[ref.Framework] = true
	}

	if !frameworks[FrameworkSOC2] {
		t.Error("expected CWE-89 to map to SOC2 controls")
	}
	if !frameworks[FrameworkISO27001] {
		t.Error("expected CWE-89 to map to ISO27001 controls")
	}
	if !frameworks[FrameworkGDPR] {
		t.Error("expected CWE-89 to map to GDPR controls")
	}
}

func TestCWEMapperGetControlsNonExistent(t *testing.T) {
	m := NewCWEMapper()

	controls := m.GetControls("CWE-99999")
	if len(controls) != 0 {
		t.Errorf("expected no controls for CWE-99999, got %d", len(controls))
	}
}

func TestCWEMapperGetCWEs(t *testing.T) {
	m := NewCWEMapper()

	// Test SOC2 CC6.1 CWE mappings.
	cwes := m.GetCWEs(FrameworkSOC2, "CC6.1")
	if len(cwes) == 0 {
		t.Error("expected CC6.1 to have CWE mappings")
	}

	// Verify expected CWEs are mapped.
	cweSet := make(map[string]bool)
	for _, cwe := range cwes {
		cweSet[cwe] = true
	}

	// CC6.1 should map to authentication/injection CWEs.
	expectedCWEs := []string{"CWE-287", "CWE-89", "CWE-79"}
	for _, expected := range expectedCWEs {
		if !cweSet[expected] {
			t.Errorf("expected %s to be mapped to CC6.1", expected)
		}
	}
}

func TestCWEMapperGetCWEsNonExistent(t *testing.T) {
	m := NewCWEMapper()

	cwes := m.GetCWEs(FrameworkSOC2, "CC999")
	if len(cwes) != 0 {
		t.Errorf("expected no CWEs for CC999, got %d", len(cwes))
	}
}

func TestCWEMapperAddMapping(t *testing.T) {
	m := NewCWEMapper()

	// Add a custom mapping.
	m.AddMapping("CWE-1234", FrameworkSOC2, "CC9.9")

	// Verify the mapping is added.
	controls := m.GetControls("CWE-1234")
	if len(controls) != 1 {
		t.Fatalf("expected 1 control for CWE-1234, got %d", len(controls))
	}
	if controls[0].Framework != FrameworkSOC2 {
		t.Errorf("Framework = %q, want %q", controls[0].Framework, FrameworkSOC2)
	}
	if controls[0].ControlID != "CC9.9" {
		t.Errorf("ControlID = %q, want %q", controls[0].ControlID, "CC9.9")
	}

	// Verify reverse mapping.
	cwes := m.GetCWEs(FrameworkSOC2, "CC9.9")
	if len(cwes) != 1 {
		t.Fatalf("expected 1 CWE for CC9.9, got %d", len(cwes))
	}
	if cwes[0] != "CWE-1234" {
		t.Errorf("CWE = %q, want %q", cwes[0], "CWE-1234")
	}
}

func TestNormalizeCWE(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"CWE-89", "CWE-89"},
		{"cwe-89", "CWE-89"},
		{"CWE89", "CWE-89"},
		{"89", "CWE-89"},
		{"  CWE-89  ", "CWE-89"},
	}

	for _, tt := range tests {
		got := normalizeCWE(tt.input)
		if got != tt.want {
			t.Errorf("normalizeCWE(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestCWEMapperGetAllMappedCWEs(t *testing.T) {
	m := NewCWEMapper()

	cwes := m.GetAllMappedCWEs()
	if len(cwes) == 0 {
		t.Error("expected mapped CWEs")
	}

	// Verify some expected CWEs are present.
	cweSet := make(map[string]bool)
	for _, cwe := range cwes {
		cweSet[cwe] = true
	}

	expectedCWEs := []string{"CWE-79", "CWE-89", "CWE-287", "CWE-326"}
	for _, expected := range expectedCWEs {
		if !cweSet[expected] {
			t.Errorf("expected %s in mapped CWEs", expected)
		}
	}
}

func TestCWEMapperConcurrentAccess(t *testing.T) {
	m := NewCWEMapper()

	done := make(chan bool, 10)

	// Concurrent reads.
	for i := 0; i < 5; i++ {
		go func() {
			_ = m.GetControls("CWE-89")
			_ = m.GetCWEs(FrameworkSOC2, "CC6.1")
			_ = m.GetAllMappedCWEs()
			done <- true
		}()
	}

	// Concurrent writes.
	for i := 0; i < 5; i++ {
		go func(i int) {
			m.AddMapping("CWE-9999", FrameworkSOC2, "CC9."+string(rune('0'+i)))
			done <- true
		}(i)
	}

	// Wait for all goroutines.
	for i := 0; i < 10; i++ {
		<-done
	}
}

func TestGetCWECategories(t *testing.T) {
	categories := GetCWECategories()

	if len(categories) == 0 {
		t.Error("expected CWE categories")
	}

	// Verify expected categories exist.
	categoryNames := make(map[string]bool)
	for _, cat := range categories {
		categoryNames[cat.Name] = true
		if len(cat.CWEIDs) == 0 {
			t.Errorf("category %q has no CWE IDs", cat.Name)
		}
	}

	expectedCategories := []string{"Injection", "Broken Authentication", "Cryptographic Failures"}
	for _, name := range expectedCategories {
		if !categoryNames[name] {
			t.Errorf("expected category %q", name)
		}
	}
}

func TestGetCWEDescription(t *testing.T) {
	tests := []struct {
		cweID string
		want  string
	}{
		{"CWE-89", "SQL Injection"},
		{"CWE-79", "Cross-site Scripting (XSS)"},
		{"CWE-287", "Improper Authentication"},
		{"cwe-89", "SQL Injection"}, // Normalized.
		{"89", "SQL Injection"},     // Just number.
		{"CWE-99999", "Unknown CWE"},
	}

	for _, tt := range tests {
		got := GetCWEDescription(tt.cweID)
		if got != tt.want {
			t.Errorf("GetCWEDescription(%q) = %q, want %q", tt.cweID, got, tt.want)
		}
	}
}

func TestControlRefJSON(t *testing.T) {
	ref := ControlRef{
		Framework: FrameworkSOC2,
		ControlID: "CC6.1",
	}

	if ref.Framework != FrameworkSOC2 {
		t.Errorf("Framework = %q, want %q", ref.Framework, FrameworkSOC2)
	}
	if ref.ControlID != "CC6.1" {
		t.Errorf("ControlID = %q, want %q", ref.ControlID, "CC6.1")
	}
}

func TestDefaultMappingsCompleteness(t *testing.T) {
	m := NewCWEMapper()

	// Verify OWASP Top 10 CWEs are mapped.
	owaspCWEs := []string{
		"CWE-89",  // Injection.
		"CWE-287", // Auth.
		"CWE-327", // Crypto.
		"CWE-200", // Data exposure.
		"CWE-502", // Deserialization.
	}

	for _, cwe := range owaspCWEs {
		controls := m.GetControls(cwe)
		if len(controls) == 0 {
			t.Errorf("expected OWASP CWE %s to have control mappings", cwe)
		}
	}
}

func TestCWECategoryJSON(t *testing.T) {
	cat := CWECategory{
		Name:        "Injection",
		Description: "Test description",
		CWEIDs:      []string{"CWE-89", "CWE-79"},
	}

	if cat.Name != "Injection" {
		t.Errorf("Name = %q, want %q", cat.Name, "Injection")
	}
	if cat.Description != "Test description" {
		t.Errorf("Description = %q, want %q", cat.Description, "Test description")
	}
	if len(cat.CWEIDs) != 2 {
		t.Errorf("CWEIDs len = %d, want 2", len(cat.CWEIDs))
	}
}
