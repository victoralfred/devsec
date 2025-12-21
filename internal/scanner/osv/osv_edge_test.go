package osv

import (
	"context"
	"testing"
)

// TestParseGoModContentEdgeCases tests edge cases in go.mod parsing.
func TestParseGoModContentEdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		content  []byte
		expected int
	}{
		{"empty content", []byte{}, 0},
		{"only module declaration", []byte("module test"), 0},
		{"no requires", []byte("module test\ngo 1.21"), 0},
		{"require with comments", []byte("require github.com/test v1.0.0 // comment"), 1},
		{"indirect dependency", []byte("require github.com/test v1.0.0 // indirect"), 0},
		{"multiple requires", []byte("require (\n\tgithub.com/test1 v1.0.0\n\tgithub.com/test2 v2.0.0\n)"), 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			deps := parseGoModContent(tt.content, "go.mod")
			if len(deps) != tt.expected {
				t.Errorf("expected %d dependencies, got %d", tt.expected, len(deps))
			}
		})
	}
}

// TestParsePackageJSONContentEdgeCases tests edge cases in package.json parsing.
func TestParsePackageJSONContentEdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		content  []byte
		expected int
	}{
		{"empty content", []byte{}, 0},
		{"invalid JSON", []byte("not json"), 0},
		{"empty dependencies", []byte(`{"name": "test"}`), 0},
		{"only dependencies", []byte(`{"dependencies": {"test": "1.0.0"}}`), 1},
		{"only devDependencies", []byte(`{"devDependencies": {"test": "1.0.0"}}`), 1},
		{"both dependencies", []byte(`{"dependencies": {"test1": "1.0.0"}, "devDependencies": {"test2": "2.0.0"}}`), 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			deps := parsePackageJSONContent(tt.content, "package.json")
			if len(deps) != tt.expected {
				t.Errorf("expected %d dependencies, got %d", tt.expected, len(deps))
			}
		})
	}
}

// TestParseRequirementsTxtContentEdgeCases tests edge cases in requirements.txt parsing.
func TestParseRequirementsTxtContentEdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		content  []byte
		expected int
	}{
		{"empty content", []byte{}, 0},
		{"only comments", []byte("# comment\n# another comment"), 0},
		{"only empty lines", []byte("\n\n\n"), 0},
		{"valid requirement", []byte("requests==2.28.0"), 1},
		{"requirement with comment", []byte("requests==2.28.0 # comment"), 1},
		{"multiple requirements", []byte("requests==2.28.0\nflask>=2.0.0"), 2},
		{"requirement with file reference", []byte("-r base.txt"), 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			deps := parseRequirementsTxtContent(tt.content, "requirements.txt")
			if len(deps) != tt.expected {
				t.Errorf("expected %d dependencies, got %d", tt.expected, len(deps))
			}
		})
	}
}

// TestCleanVersionEdgeCases tests edge cases in version cleaning.
func TestCleanVersionEdgeCases(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"", ""},
		{"1.0.0", "1.0.0"},
		{"^1.0.0", "1.0.0"},
		{"~1.0.0", "1.0.0"},
		{">=1.0.0", "1.0.0"},
		{"<=1.0.0", "1.0.0"},
		{">1.0.0", "1.0.0"},
		{"<1.0.0", "1.0.0"},
		{"=1.0.0", "1.0.0"},
		{" 1.0.0 ", "1.0.0"},
		{"^~1.0.0", "1.0.0"},
		{"multiple operators", "multiple operators"}, // cleanVersion only removes prefix operators
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := cleanVersion(tt.input)
			if result != tt.expected {
				t.Errorf("cleanVersion(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

// TestMapVulnerabilityEdgeCases tests edge cases in vulnerability mapping.
func TestMapVulnerabilityEdgeCases(t *testing.T) {
	scanner := New()

	tests := []struct { //nolint:govet // test struct
		name string
		vuln *Vulnerability
		dep  *Dependency
	}{
		{"empty vulnerability", &Vulnerability{}, &Dependency{}},
		{"vulnerability without summary", &Vulnerability{ID: "TEST-001"}, &Dependency{}},
		{"vulnerability with empty ID", &Vulnerability{Summary: "Test"}, &Dependency{}},
		{"dependency with empty fields", &Vulnerability{ID: "TEST-001"}, &Dependency{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			finding := scanner.mapVulnerability(tt.vuln, tt.dep)
			if finding.ID == "" {
				t.Error("expected non-empty finding ID")
			}
		})
	}
}

// TestDetermineSeverityEdgeCases tests edge cases in severity determination.
func TestDetermineSeverityEdgeCases(t *testing.T) {
	scanner := New()

	tests := []struct { //nolint:govet // test struct
		name     string
		vuln     *Vulnerability
		expected bool // true if should have valid severity
	}{
		{"empty vulnerability", &Vulnerability{}, true},
		{"vulnerability with CVSS", &Vulnerability{
			Severity: []Severity{{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}},
		}, true},
		{"vulnerability with GHSA ID", &Vulnerability{ID: "GHSA-xxxx-yyyy-zzzz"}, true},
		{"vulnerability with unknown ID", &Vulnerability{ID: "UNKNOWN-123"}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			severity := scanner.determineSeverity(tt.vuln)
			if severity == "" {
				t.Error("expected non-empty severity")
			}
		})
	}
}

// TestBuildDescriptionEdgeCases tests edge cases in description building.
func TestBuildDescriptionEdgeCases(t *testing.T) {
	scanner := New()

	tests := []struct { //nolint:govet // test struct
		name string
		vuln *Vulnerability
		dep  *Dependency
	}{
		{"empty fields", &Vulnerability{}, &Dependency{}},
		{"vulnerability without details", &Vulnerability{ID: "TEST-001"}, &Dependency{Name: "test"}},
		{"dependency without version", &Vulnerability{ID: "TEST-001"}, &Dependency{Name: "test"}},
		{"vulnerability with aliases", &Vulnerability{
			ID:      "TEST-001",
			Aliases: []string{"CVE-2023-1234"},
		}, &Dependency{Name: "test", Version: "1.0.0"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			desc := scanner.buildDescription(tt.vuln, tt.dep)
			// Description should not be empty (at least contain package name)
			if desc == "" {
				t.Error("expected non-empty description")
			}
		})
	}
}

// TestFindFixedVersionEdgeCases tests edge cases in finding fixed version.
func TestFindFixedVersionEdgeCases(t *testing.T) {
	scanner := New()

	tests := []struct {
		name     string
		vuln     *Vulnerability
		dep      *Dependency
		expected string
	}{
		{"no affected", &Vulnerability{}, &Dependency{}, ""},
		{"affected without ranges", &Vulnerability{
			Affected: []Affected{{Package: &Package{Ecosystem: "npm"}}},
		}, &Dependency{Ecosystem: "npm"}, ""},
		{"affected with fixed version", &Vulnerability{
			Affected: []Affected{
				{
					Package: &Package{Ecosystem: "npm"},
					Ranges: []Range{
						{
							Events: []Event{{Fixed: "2.0.0"}},
						},
					},
				},
			},
		}, &Dependency{Ecosystem: "npm"}, "2.0.0"},
		{"wrong ecosystem", &Vulnerability{
			Affected: []Affected{
				{
					Package: &Package{Ecosystem: "Go"},
					Ranges: []Range{
						{
							Events: []Event{{Fixed: "2.0.0"}},
						},
					},
				},
			},
		}, &Dependency{Ecosystem: "npm"}, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fixed := scanner.findFixedVersion(tt.vuln, tt.dep)
			if fixed != tt.expected {
				t.Errorf("findFixedVersion() = %q, want %q", fixed, tt.expected)
			}
		})
	}
}

// TestScanFileInsteadOfDirectory tests scanning with file instead of directory.
func TestScanFileInsteadOfDirectory(t *testing.T) {
	scanner := New()
	ctx := context.Background()

	// This should fail because Scan expects a directory
	_, err := scanner.Scan(ctx, "/etc/passwd")
	if err == nil {
		t.Error("expected error for file path")
	}
}
