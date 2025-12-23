package compliance

import (
	"encoding/json"
	"testing"
)

func TestNewFramework(t *testing.T) {
	f := NewFramework(FrameworkSOC2, "Test Framework", "1.0", "Test description")

	if f.ID != FrameworkSOC2 {
		t.Errorf("ID = %q, want %q", f.ID, FrameworkSOC2)
	}
	if f.Name != "Test Framework" {
		t.Errorf("Name = %q, want %q", f.Name, "Test Framework")
	}
	if f.Version != "1.0" {
		t.Errorf("Version = %q, want %q", f.Version, "1.0")
	}
	if f.Controls == nil {
		t.Error("Controls should not be nil")
	}
	if f.Categories == nil {
		t.Error("Categories should not be nil")
	}
	if f.Metadata == nil {
		t.Error("Metadata should not be nil")
	}
}

func TestFrameworkAddControl(t *testing.T) {
	f := NewFramework(FrameworkSOC2, "Test", "1.0", "Test")

	ctrl := Control{
		ID:    "CC6.1",
		Title: "Test Control",
	}

	f.AddControl(ctrl)

	if len(f.Controls) != 1 {
		t.Fatalf("Controls count = %d, want 1", len(f.Controls))
	}

	// Verify framework is set.
	if f.Controls[0].Framework != string(FrameworkSOC2) {
		t.Errorf("Control.Framework = %q, want %q", f.Controls[0].Framework, FrameworkSOC2)
	}
}

func TestFrameworkGetControl(t *testing.T) {
	f := NewFramework(FrameworkSOC2, "Test", "1.0", "Test")
	f.AddControl(Control{ID: "CC6.1", Title: "Control 1"})
	f.AddControl(Control{ID: "CC6.6", Title: "Control 2"})

	// Test existing control.
	ctrl, found := f.GetControl("CC6.1")
	if !found {
		t.Error("expected to find CC6.1")
	}
	if ctrl.Title != "Control 1" {
		t.Errorf("Title = %q, want %q", ctrl.Title, "Control 1")
	}

	// Test non-existing control.
	_, found = f.GetControl("CC999")
	if found {
		t.Error("expected not to find CC999")
	}
}

func TestFrameworkGetControlsByCategory(t *testing.T) {
	f := NewFramework(FrameworkSOC2, "Test", "1.0", "Test")
	f.AddControl(Control{ID: "CC6.1", Category: "Access"})
	f.AddControl(Control{ID: "CC6.6", Category: "Access"})
	f.AddControl(Control{ID: "CC7.1", Category: "Operations"})

	accessControls := f.GetControlsByCategory("Access")
	if len(accessControls) != 2 {
		t.Errorf("Access controls count = %d, want 2", len(accessControls))
	}

	opsControls := f.GetControlsByCategory("Operations")
	if len(opsControls) != 1 {
		t.Errorf("Operations controls count = %d, want 1", len(opsControls))
	}

	noControls := f.GetControlsByCategory("NonExistent")
	if len(noControls) != 0 {
		t.Errorf("NonExistent controls count = %d, want 0", len(noControls))
	}
}

func TestFrameworkGetControlsByCWE(t *testing.T) {
	f := NewFramework(FrameworkSOC2, "Test", "1.0", "Test")
	f.AddControl(Control{ID: "CC6.1", CWEMappings: []string{"CWE-287", "CWE-306"}})
	f.AddControl(Control{ID: "CC6.7", CWEMappings: []string{"CWE-326", "CWE-327"}})
	f.AddControl(Control{ID: "CC7.1", CWEMappings: []string{"CWE-89", "CWE-287"}})

	// CWE-287 maps to CC6.1 and CC7.1.
	cwe287Controls := f.GetControlsByCWE("CWE-287")
	if len(cwe287Controls) != 2 {
		t.Errorf("CWE-287 controls count = %d, want 2", len(cwe287Controls))
	}

	// CWE-326 maps to CC6.7 only.
	cwe326Controls := f.GetControlsByCWE("CWE-326")
	if len(cwe326Controls) != 1 {
		t.Errorf("CWE-326 controls count = %d, want 1", len(cwe326Controls))
	}

	// CWE-999 maps to nothing.
	cwe999Controls := f.GetControlsByCWE("CWE-999")
	if len(cwe999Controls) != 0 {
		t.Errorf("CWE-999 controls count = %d, want 0", len(cwe999Controls))
	}
}

func TestNewSOC2Framework(t *testing.T) {
	f := NewSOC2Framework()

	if f.ID != FrameworkSOC2 {
		t.Errorf("ID = %q, want %q", f.ID, FrameworkSOC2)
	}
	if f.Name != "SOC 2 Type II" {
		t.Errorf("Name = %q, want %q", f.Name, "SOC 2 Type II")
	}
	if len(f.Controls) == 0 {
		t.Error("SOC2 framework should have controls")
	}
	if len(f.Categories) == 0 {
		t.Error("SOC2 framework should have categories")
	}

	// Verify key controls exist.
	controlIDs := []string{"CC6.1", "CC6.6", "CC6.7", "CC7.1", "CC7.2", "CC8.1", "CC9.1"}
	for _, id := range controlIDs {
		if _, found := f.GetControl(id); !found {
			t.Errorf("expected SOC2 control %s to exist", id)
		}
	}

	// Verify CWE mappings.
	ctrl, _ := f.GetControl("CC6.1")
	if len(ctrl.CWEMappings) == 0 {
		t.Error("CC6.1 should have CWE mappings")
	}
}

func TestNewISO27001Framework(t *testing.T) {
	f := NewISO27001Framework()

	if f.ID != FrameworkISO27001 {
		t.Errorf("ID = %q, want %q", f.ID, FrameworkISO27001)
	}
	if f.Name != "ISO/IEC 27001:2022" {
		t.Errorf("Name = %q, want %q", f.Name, "ISO/IEC 27001:2022")
	}
	if len(f.Controls) == 0 {
		t.Error("ISO27001 framework should have controls")
	}

	// Verify key controls exist.
	controlIDs := []string{"A.5.1", "A.8.24", "A.8.25", "A.8.26", "A.8.28", "A.5.33", "A.5.34", "A.8.5"}
	for _, id := range controlIDs {
		if _, found := f.GetControl(id); !found {
			t.Errorf("expected ISO27001 control %s to exist", id)
		}
	}
}

func TestNewGDPRFramework(t *testing.T) {
	f := NewGDPRFramework()

	if f.ID != FrameworkGDPR {
		t.Errorf("ID = %q, want %q", f.ID, FrameworkGDPR)
	}
	if f.Name != "General Data Protection Regulation" {
		t.Errorf("Name = %q, want %q", f.Name, "General Data Protection Regulation")
	}
	if len(f.Controls) == 0 {
		t.Error("GDPR framework should have controls")
	}

	// Verify key articles exist.
	articleIDs := []string{"Art.5", "Art.25", "Art.32", "Art.33", "Art.34"}
	for _, id := range articleIDs {
		if _, found := f.GetControl(id); !found {
			t.Errorf("expected GDPR article %s to exist", id)
		}
	}

	// Verify Art.32 has comprehensive CWE mappings.
	art32, _ := f.GetControl("Art.32")
	if len(art32.CWEMappings) < 5 {
		t.Errorf("Art.32 should have at least 5 CWE mappings, got %d", len(art32.CWEMappings))
	}
}

func TestAllFrameworks(t *testing.T) {
	frameworks := AllFrameworks()

	if len(frameworks) != 3 {
		t.Errorf("AllFrameworks count = %d, want 3", len(frameworks))
	}

	// Verify all expected frameworks are present.
	expectedIDs := map[FrameworkID]bool{
		FrameworkSOC2:     false,
		FrameworkISO27001: false,
		FrameworkGDPR:     false,
	}

	for _, f := range frameworks {
		expectedIDs[f.ID] = true
	}

	for id, found := range expectedIDs {
		if !found {
			t.Errorf("expected framework %s to be in AllFrameworks", id)
		}
	}
}

func TestGetFramework(t *testing.T) {
	tests := []struct {
		id    FrameworkID
		found bool
	}{
		{FrameworkSOC2, true},
		{FrameworkISO27001, true},
		{FrameworkGDPR, true},
		{FrameworkID("unknown"), false},
	}

	for _, tt := range tests {
		f, found := GetFramework(tt.id)
		if found != tt.found {
			t.Errorf("GetFramework(%q) found = %v, want %v", tt.id, found, tt.found)
		}
		if tt.found && f.ID != tt.id {
			t.Errorf("GetFramework(%q).ID = %q, want %q", tt.id, f.ID, tt.id)
		}
	}
}

func TestSupportedFrameworks(t *testing.T) {
	supported := SupportedFrameworks()

	if len(supported) != 3 {
		t.Errorf("SupportedFrameworks count = %d, want 3", len(supported))
	}

	expected := map[FrameworkID]bool{
		FrameworkSOC2:     false,
		FrameworkISO27001: false,
		FrameworkGDPR:     false,
	}

	for _, id := range supported {
		expected[id] = true
	}

	for id, found := range expected {
		if !found {
			t.Errorf("expected %s in SupportedFrameworks", id)
		}
	}
}

func TestFrameworkJSON(t *testing.T) {
	f := NewSOC2Framework()

	data, err := json.Marshal(f)
	if err != nil {
		t.Fatalf("marshal framework: %v", err)
	}

	var decoded Framework
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal framework: %v", err)
	}

	if decoded.ID != f.ID {
		t.Errorf("ID = %q, want %q", decoded.ID, f.ID)
	}
	if decoded.Name != f.Name {
		t.Errorf("Name = %q, want %q", decoded.Name, f.Name)
	}
	if len(decoded.Controls) != len(f.Controls) {
		t.Errorf("Controls count = %d, want %d", len(decoded.Controls), len(f.Controls))
	}
}

func TestControlCWEMappingsConsistency(t *testing.T) {
	// Verify that CWE mappings across frameworks are consistent.
	frameworks := AllFrameworks()

	// Common injection CWEs should map to security controls in all frameworks.
	injectionCWEs := []string{"CWE-78", "CWE-79", "CWE-89"}

	for _, cwe := range injectionCWEs {
		foundInAny := false
		for _, f := range frameworks {
			controls := f.GetControlsByCWE(cwe)
			if len(controls) > 0 {
				foundInAny = true
			}
		}
		if !foundInAny {
			t.Errorf("expected %s to map to at least one control across frameworks", cwe)
		}
	}
}
