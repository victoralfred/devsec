package sbom

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/victoralfred/gowritter/safepath"
)

// TestNewGenerator tests generator creation.
func TestNewGenerator(t *testing.T) {
	gen := NewGenerator("1.0.0")
	if gen == nil {
		t.Fatal("expected non-nil generator")
	}
	if gen.toolVersion != "1.0.0" {
		t.Errorf("expected version 1.0.0, got %s", gen.toolVersion)
	}
}

// TestParseGoMod tests go.mod parsing.
func TestParseGoMod(t *testing.T) {
	content := []byte(`module example.com/test

go 1.21

require (
	github.com/example/pkg v1.2.3
	github.com/another/lib v0.1.0
	github.com/indirect/dep v2.0.0 // indirect
)

require github.com/single/pkg v1.0.0
`)

	components, err := parseGoMod(content)
	if err != nil {
		t.Fatalf("parseGoMod() error = %v", err)
	}

	// Should have 3 components (indirect is skipped).
	if len(components) != 3 {
		t.Errorf("expected 3 components, got %d", len(components))
	}

	// Check first component.
	found := false
	for _, c := range components {
		if c.Name == "github.com/example/pkg" {
			found = true
			if c.Version != "1.2.3" {
				t.Errorf("expected version 1.2.3, got %s", c.Version)
			}
			if c.Type != "library" {
				t.Errorf("expected type library, got %s", c.Type)
			}
			if !strings.Contains(c.PURL, "pkg:golang/") {
				t.Errorf("expected golang PURL, got %s", c.PURL)
			}
		}
	}
	if !found {
		t.Error("expected to find github.com/example/pkg")
	}
}

// TestParsePackageJSON tests package.json parsing.
func TestParsePackageJSON(t *testing.T) {
	content := []byte(`{
  "name": "test-package",
  "version": "1.0.0",
  "dependencies": {
    "lodash": "^4.17.21",
    "express": "~4.18.2"
  },
  "devDependencies": {
    "jest": "^29.0.0"
  }
}`)

	components, err := parsePackageJSON(content)
	if err != nil {
		t.Fatalf("parsePackageJSON() error = %v", err)
	}

	// Should have 3 components.
	if len(components) != 3 {
		t.Errorf("expected 3 components, got %d", len(components))
	}

	// Check version cleaning.
	for _, c := range components {
		if c.Name == "lodash" {
			if c.Version != "4.17.21" {
				t.Errorf("expected cleaned version 4.17.21, got %s", c.Version)
			}
		}
		if !strings.Contains(c.PURL, "pkg:npm/") {
			t.Errorf("expected npm PURL, got %s", c.PURL)
		}
	}
}

// TestParseRequirements tests requirements.txt parsing.
func TestParseRequirements(t *testing.T) {
	content := []byte(`# Python dependencies
requests==2.28.0
flask>=2.0.0
django~=4.0  # web framework
-r base.txt
-e git+https://github.com/example/pkg.git
numpy
`)

	components, err := parseRequirements(content)
	if err != nil {
		t.Fatalf("parseRequirements() error = %v", err)
	}

	// Should have 4 components (comments, -r, -e are skipped).
	if len(components) != 4 {
		t.Errorf("expected 4 components, got %d", len(components))
	}

	for _, c := range components {
		if c.Name == "requests" {
			if c.Version != "2.28.0" {
				t.Errorf("expected version 2.28.0, got %s", c.Version)
			}
		}
		if c.Name == "numpy" {
			if c.Version != "unknown" {
				t.Errorf("expected version unknown for numpy, got %s", c.Version)
			}
		}
		if !strings.Contains(c.PURL, "pkg:pypi/") {
			t.Errorf("expected pypi PURL, got %s", c.PURL)
		}
	}
}

// TestCleanVersion tests version string cleaning.
func TestCleanVersion(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"^1.0.0", "1.0.0"},
		{"~2.3.4", "2.3.4"},
		{">=3.0.0", "3.0.0"},
		{"<=4.0.0", "4.0.0"},
		{">5.0.0", "5.0.0"},
		{"<6.0.0", "6.0.0"},
		{"=7.0.0", "7.0.0"},
		{"1.0.0", "1.0.0"},
		{"  1.0.0  ", "1.0.0"},
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

// TestGenerateSBOM tests SBOM generation.
func TestGenerateSBOM(t *testing.T) {
	tmpDir := t.TempDir()
	sp, err := safepath.New(tmpDir)
	if err != nil {
		t.Fatalf("failed to create safepath: %v", err)
	}

	// Create a test go.mod file.
	goMod := []byte(`module test

go 1.21

require github.com/example/pkg v1.0.0
`)
	writeErr := sp.WriteFile("go.mod", goMod, 0o644)
	if writeErr != nil {
		t.Fatalf("failed to write go.mod: %v", writeErr)
	}

	gen := NewGenerator("1.0.0")
	ctx := context.Background()

	sbom, err := gen.Generate(ctx, tmpDir, FormatSPDX)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	if sbom == nil {
		t.Fatal("expected non-nil SBOM")
	}
	if sbom.Name == "" {
		t.Error("expected non-empty SBOM name")
	}
	if sbom.Format != FormatSPDX {
		t.Errorf("expected format SPDX, got %s", sbom.Format)
	}
	if len(sbom.Components) != 1 {
		t.Errorf("expected 1 component, got %d", len(sbom.Components))
	}
}

// TestGenerateSBOMContextCancellation tests context cancellation.
func TestGenerateSBOMContextCancellation(t *testing.T) {
	gen := NewGenerator("1.0.0")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := gen.Generate(ctx, "/tmp", FormatSPDX)
	if err == nil {
		t.Error("expected error for canceled context")
	}
}

// TestToSPDX tests SPDX output formatting.
func TestToSPDX(t *testing.T) {
	sbom := &SBOM{
		Name:      "test-project",
		Version:   "1.0.0",
		Format:    FormatSPDX,
		CreatedAt: time.Now().UTC(),
		Components: []Component{
			{
				Name:    "example-lib",
				Version: "2.0.0",
				Type:    "library",
				PURL:    "pkg:golang/example-lib@2.0.0",
			},
		},
		Tool: ToolInfo{
			Name:    "devsec",
			Version: "1.0.0",
		},
	}

	data, err := ToSPDX(sbom)
	if err != nil {
		t.Fatalf("ToSPDX() error = %v", err)
	}

	var spdxDoc SPDXDocument
	if err := json.Unmarshal(data, &spdxDoc); err != nil {
		t.Fatalf("failed to unmarshal SPDX: %v", err)
	}

	if spdxDoc.SPDXVersion != "SPDX-2.3" {
		t.Errorf("expected SPDX version 2.3, got %s", spdxDoc.SPDXVersion)
	}
	if spdxDoc.Name != "test-project" {
		t.Errorf("expected name test-project, got %s", spdxDoc.Name)
	}
	if len(spdxDoc.Packages) != 1 {
		t.Errorf("expected 1 package, got %d", len(spdxDoc.Packages))
	}
}

// TestToCycloneDX tests CycloneDX output formatting.
func TestToCycloneDX(t *testing.T) {
	sbom := &SBOM{
		Name:      "test-project",
		Version:   "1.0.0",
		Format:    FormatCycloneDX,
		CreatedAt: time.Now().UTC(),
		Components: []Component{
			{
				Name:    "example-lib",
				Version: "2.0.0",
				Type:    "library",
				PURL:    "pkg:npm/example-lib@2.0.0",
				Hashes: []Hash{
					{Algorithm: "sha256", Value: "abc123"},
				},
			},
		},
		Tool: ToolInfo{
			Name:    "devsec",
			Version: "1.0.0",
			Vendor:  "devsec",
		},
	}

	data, err := ToCycloneDX(sbom)
	if err != nil {
		t.Fatalf("ToCycloneDX() error = %v", err)
	}

	var cdxBOM CycloneDXBOM
	if err := json.Unmarshal(data, &cdxBOM); err != nil {
		t.Fatalf("failed to unmarshal CycloneDX: %v", err)
	}

	if cdxBOM.BOMFormat != "CycloneDX" {
		t.Errorf("expected BOM format CycloneDX, got %s", cdxBOM.BOMFormat)
	}
	if cdxBOM.SpecVersion != "1.5" {
		t.Errorf("expected spec version 1.5, got %s", cdxBOM.SpecVersion)
	}
	if len(cdxBOM.Components) != 1 {
		t.Errorf("expected 1 component, got %d", len(cdxBOM.Components))
	}
}

// TestSBOMMarshal tests SBOM Marshal method.
func TestSBOMMarshal(t *testing.T) {
	tests := []struct {
		name   string
		format Format
	}{
		{"SPDX", FormatSPDX},
		{"CycloneDX", FormatCycloneDX},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sbom := &SBOM{
				Name:       "test",
				Version:    "1.0.0",
				Format:     tt.format,
				CreatedAt:  time.Now().UTC(),
				Components: []Component{},
				Tool: ToolInfo{
					Name:    "devsec",
					Version: "1.0.0",
				},
			}

			data, err := sbom.Marshal()
			if err != nil {
				t.Fatalf("Marshal() error = %v", err)
			}
			if len(data) == 0 {
				t.Error("expected non-empty output")
			}
		})
	}
}

// TestSBOMMarshalUnsupportedFormat tests unsupported format error.
func TestSBOMMarshalUnsupportedFormat(t *testing.T) {
	sbom := &SBOM{
		Name:    "test",
		Version: "1.0.0",
		Format:  Format("invalid"),
	}

	_, err := sbom.Marshal()
	if err == nil {
		t.Error("expected error for unsupported format")
	}
}

// TestSBOMWriteToFile tests writing SBOM to file.
func TestSBOMWriteToFile(t *testing.T) {
	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "sbom.json")

	sbom := &SBOM{
		Name:       "test",
		Version:    "1.0.0",
		Format:     FormatSPDX,
		CreatedAt:  time.Now().UTC(),
		Components: []Component{},
		Tool: ToolInfo{
			Name:    "devsec",
			Version: "1.0.0",
		},
	}

	err := sbom.WriteToFile(outputPath)
	if err != nil {
		t.Fatalf("WriteToFile() error = %v", err)
	}

	// Verify file was written.
	sp, err := safepath.New(tmpDir)
	if err != nil {
		t.Fatalf("failed to create safepath: %v", err)
	}

	data, err := sp.ReadFile("sbom.json")
	if err != nil {
		t.Fatalf("failed to read output file: %v", err)
	}
	if len(data) == 0 {
		t.Error("expected non-empty file content")
	}
}

// TestSBOMComputeHash tests hash computation.
func TestSBOMComputeHash(t *testing.T) {
	sbom := &SBOM{
		Name:    "test",
		Version: "1.0.0",
		Components: []Component{
			{Name: "pkg", Version: "1.0.0"},
		},
	}

	hash := sbom.ComputeHash()
	if hash == "" {
		t.Error("expected non-empty hash")
	}
	if len(hash) != 64 {
		t.Errorf("expected SHA-256 hash (64 chars), got %d chars", len(hash))
	}

	// Same SBOM should produce same hash.
	hash2 := sbom.ComputeHash()
	if hash != hash2 {
		t.Error("expected same hash for same content")
	}
}

// TestSanitizeID tests ID sanitization.
func TestSanitizeID(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"simple", "simple"},
		{"with/slash", "with-slash"},
		{"with@at", "with-at"},
		{"with.dot", "with-dot"},
		{"complex/path@v1.0.0", "complex-path-v1-0-0"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := sanitizeID(tt.input)
			if result != tt.expected {
				t.Errorf("sanitizeID(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

// TestMapHashAlgorithm tests hash algorithm mapping.
func TestMapHashAlgorithm(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"sha256", "SHA-256"},
		{"SHA256", "SHA-256"},
		{"sha-256", "SHA-256"},
		{"sha512", "SHA-512"},
		{"sha1", "SHA-1"},
		{"md5", "MD5"},
		{"unknown", "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := mapHashAlgorithm(tt.input)
			if result != tt.expected {
				t.Errorf("mapHashAlgorithm(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

// TestGenerateUUID tests UUID generation.
func TestGenerateUUID(t *testing.T) {
	sbom := &SBOM{
		Name:      "test",
		Version:   "1.0.0",
		CreatedAt: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
	}

	uuid := generateUUID(sbom)
	if uuid == "" {
		t.Error("expected non-empty UUID")
	}

	// Should be consistent for same input.
	uuid2 := generateUUID(sbom)
	if uuid != uuid2 {
		t.Error("expected consistent UUID for same input")
	}
}

// TestBuildSPDXWithDependencies tests SPDX building with dependencies.
func TestBuildSPDXWithDependencies(t *testing.T) {
	sbom := &SBOM{
		Name:      "test-project",
		Version:   "1.0.0",
		CreatedAt: time.Now().UTC(),
		Components: []Component{
			{
				Name:    "pkg-a",
				Version: "1.0.0",
				Type:    "library",
				PURL:    "pkg:golang/pkg-a@1.0.0",
				Hashes: []Hash{
					{Algorithm: "sha256", Value: "abc123"},
				},
			},
			{
				Name:    "pkg-b",
				Version: "2.0.0",
				Type:    "library",
			},
		},
		Tool: ToolInfo{
			Name:    "devsec",
			Version: "1.0.0",
		},
	}

	spdx := buildSPDX(sbom)

	if spdx.SPDXVersion != "SPDX-2.3" {
		t.Errorf("expected SPDX version 2.3, got %s", spdx.SPDXVersion)
	}
	if spdx.DataLicense != "CC0-1.0" {
		t.Errorf("expected data license CC0-1.0, got %s", spdx.DataLicense)
	}
	if len(spdx.Packages) != 2 {
		t.Errorf("expected 2 packages, got %d", len(spdx.Packages))
	}
	if len(spdx.Relationships) != 3 {
		t.Errorf("expected 3 relationships, got %d", len(spdx.Relationships))
	}

	// Check first package has external refs.
	for _, pkg := range spdx.Packages {
		if strings.Contains(pkg.SPDXID, "pkg-a") {
			if len(pkg.ExternalRefs) != 1 {
				t.Errorf("expected 1 external ref for pkg-a, got %d", len(pkg.ExternalRefs))
			}
			if len(pkg.Checksums) != 1 {
				t.Errorf("expected 1 checksum for pkg-a, got %d", len(pkg.Checksums))
			}
		}
	}
}

// TestBuildCycloneDXWithLicenses tests CycloneDX building with licenses.
func TestBuildCycloneDXWithLicenses(t *testing.T) {
	sbom := &SBOM{
		Name:      "test-project",
		Version:   "1.0.0",
		CreatedAt: time.Now().UTC(),
		Components: []Component{
			{
				Name:     "licensed-pkg",
				Version:  "1.0.0",
				Type:     "library",
				Licenses: []string{"MIT", "Apache-2.0"},
			},
		},
		Dependencies: []Dependency{
			{
				Ref:       "licensed-pkg@1.0.0",
				DependsOn: []string{"other-pkg@1.0.0"},
			},
		},
		Tool: ToolInfo{
			Name:    "devsec",
			Version: "1.0.0",
			Vendor:  "test",
		},
	}

	cdx := buildCycloneDX(sbom)

	if cdx.BOMFormat != "CycloneDX" {
		t.Errorf("expected BOM format CycloneDX, got %s", cdx.BOMFormat)
	}
	if cdx.Version != 1 {
		t.Errorf("expected version 1, got %d", cdx.Version)
	}
	if len(cdx.Components) != 1 {
		t.Errorf("expected 1 component, got %d", len(cdx.Components))
	}
	if len(cdx.Components[0].Licenses) != 2 {
		t.Errorf("expected 2 licenses, got %d", len(cdx.Components[0].Licenses))
	}
	if len(cdx.Dependencies) != 1 {
		t.Errorf("expected 1 dependency, got %d", len(cdx.Dependencies))
	}
}

// TestScanComponentsMultipleTypes tests scanning multiple dependency file types.
func TestScanComponentsMultipleTypes(t *testing.T) {
	tmpDir := t.TempDir()
	sp, err := safepath.New(tmpDir)
	if err != nil {
		t.Fatalf("failed to create safepath: %v", err)
	}

	// Create go.mod.
	goMod := []byte(`module test

go 1.21

require github.com/go-pkg v1.0.0
`)
	err = sp.WriteFile("go.mod", goMod, 0o644)
	if err != nil {
		t.Fatalf("failed to write go.mod: %v", err)
	}

	// Create package.json.
	pkgJSON := []byte(`{"dependencies": {"npm-pkg": "1.0.0"}}`)
	err = sp.WriteFile("package.json", pkgJSON, 0o644)
	if err != nil {
		t.Fatalf("failed to write package.json: %v", err)
	}

	// Create requirements.txt.
	reqTxt := []byte("pip-pkg==1.0.0")
	err = sp.WriteFile("requirements.txt", reqTxt, 0o644)
	if err != nil {
		t.Fatalf("failed to write requirements.txt: %v", err)
	}

	gen := NewGenerator("1.0.0")
	ctx := context.Background()

	sbom, err := gen.Generate(ctx, tmpDir, FormatCycloneDX)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	// Should have components from all three sources.
	if len(sbom.Components) != 3 {
		t.Errorf("expected 3 components, got %d", len(sbom.Components))
	}

	// Verify different PURLs.
	purlTypes := make(map[string]bool)
	for _, c := range sbom.Components {
		if strings.Contains(c.PURL, "pkg:golang/") {
			purlTypes["golang"] = true
		}
		if strings.Contains(c.PURL, "pkg:npm/") {
			purlTypes["npm"] = true
		}
		if strings.Contains(c.PURL, "pkg:pypi/") {
			purlTypes["pypi"] = true
		}
	}

	if len(purlTypes) != 3 {
		t.Errorf("expected 3 PURL types, got %d", len(purlTypes))
	}
}
