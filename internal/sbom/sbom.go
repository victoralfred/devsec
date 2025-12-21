// Package sbom provides Software Bill of Materials generation functionality.
package sbom

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/victoralfred/gowritter/safepath"
)

// Format represents the SBOM output format.
type Format string

const (
	// FormatSPDX represents SPDX format.
	FormatSPDX Format = "spdx"
	// FormatCycloneDX represents CycloneDX format.
	FormatCycloneDX Format = "cyclonedx"
	// MaxSBOMFileSize is the maximum size for dependency files (10MB).
	MaxSBOMFileSize = 10 * 1024 * 1024
	// MaxComponents is the maximum number of components to prevent DoS.
	MaxComponents = 50000
)

// Component represents a software component in the SBOM.
// Fields ordered for optimal memory alignment.
type Component struct {
	Name        string   `json:"name"`
	Version     string   `json:"version"`
	Type        string   `json:"type"`
	PURL        string   `json:"purl,omitempty"`
	Description string   `json:"description,omitempty"`
	Supplier    string   `json:"supplier,omitempty"`
	Licenses    []string `json:"licenses,omitempty"`
	Hashes      []Hash   `json:"hashes,omitempty"`
}

// Hash represents a cryptographic hash of a component.
type Hash struct {
	Algorithm string `json:"algorithm"`
	Value     string `json:"value"`
}

// SBOM represents a Software Bill of Materials.
// Fields ordered for optimal memory alignment.
type SBOM struct {
	CreatedAt    time.Time         `json:"created_at"`
	Metadata     map[string]string `json:"metadata,omitempty"`
	Tool         ToolInfo          `json:"tool"`
	Name         string            `json:"name"`
	Version      string            `json:"version"`
	Format       Format            `json:"format"`
	Components   []Component       `json:"components"`
	Dependencies []Dependency      `json:"dependencies,omitempty"`
}

// Dependency represents a dependency relationship.
type Dependency struct {
	Ref       string   `json:"ref"`
	DependsOn []string `json:"dependsOn,omitempty"`
}

// ToolInfo contains information about the tool that generated the SBOM.
type ToolInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Vendor  string `json:"vendor,omitempty"`
}

// Generator generates SBOMs from project files.
type Generator struct {
	toolVersion string
}

// NewGenerator creates a new SBOM generator.
func NewGenerator(toolVersion string) *Generator {
	return &Generator{
		toolVersion: toolVersion,
	}
}

// Generate generates an SBOM for the given path.
func (g *Generator) Generate(ctx context.Context, path string, format Format) (*SBOM, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	// Validate path
	if path == "" {
		return nil, fmt.Errorf("path cannot be empty")
	}
	if strings.Contains(path, "..") {
		return nil, fmt.Errorf("path contains invalid characters: %s", path)
	}

	components, err := g.scanComponents(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("scan components: %w", err)
	}

	sbom := &SBOM{
		Name:       filepath.Base(path),
		Version:    "1.0.0",
		Format:     format,
		CreatedAt:  time.Now().UTC(),
		Components: components,
		Tool: ToolInfo{
			Name:    "devsec",
			Version: g.toolVersion,
			Vendor:  "devsec",
		},
		Metadata: map[string]string{
			"path":     path,
			"platform": runtime.GOOS + "/" + runtime.GOARCH,
		},
	}

	return sbom, nil
}

// scanComponents scans for components in the given path.
func (g *Generator) scanComponents(ctx context.Context, path string) ([]Component, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	components := make([]Component, 0, 100) // Pre-allocate with capacity

	// Scan Go modules
	goComponents, err := g.scanGoMod(ctx, path)
	if err == nil {
		if len(components)+len(goComponents) > MaxComponents {
			return nil, fmt.Errorf("component limit exceeded: %d (max %d)", len(components)+len(goComponents), MaxComponents)
		}
		components = append(components, goComponents...)
	}

	// Scan Node.js packages
	nodeComponents, err := g.scanPackageJSON(ctx, path)
	if err == nil {
		if len(components)+len(nodeComponents) > MaxComponents {
			return nil, fmt.Errorf("component limit exceeded: %d (max %d)", len(components)+len(nodeComponents), MaxComponents)
		}
		components = append(components, nodeComponents...)
	}

	// Scan Python requirements
	pyComponents, err := g.scanRequirements(ctx, path)
	if err == nil {
		if len(components)+len(pyComponents) > MaxComponents {
			return nil, fmt.Errorf("component limit exceeded: %d (max %d)", len(components)+len(pyComponents), MaxComponents)
		}
		components = append(components, pyComponents...)
	}

	return components, nil
}

// scanGoMod scans go.mod for Go dependencies.
func (g *Generator) scanGoMod(ctx context.Context, path string) ([]Component, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	sp, err := safepath.New(path)
	if err != nil {
		return nil, err
	}

	// Check file size
	info, statErr := sp.Stat("go.mod")
	if statErr != nil {
		return nil, statErr
	}
	if info.Size() > MaxSBOMFileSize {
		return nil, fmt.Errorf("go.mod file too large: %d bytes (max %d)", info.Size(), MaxSBOMFileSize)
	}

	content, err := sp.ReadFile("go.mod")
	if err != nil {
		return nil, err
	}

	return parseGoMod(content)
}

// parseGoMod parses go.mod content and extracts dependencies.
func parseGoMod(content []byte) ([]Component, error) {
	components := make([]Component, 0)
	lines := strings.Split(string(content), "\n")
	inRequire := false

	for _, line := range lines {
		line = strings.TrimSpace(line)

		if strings.HasPrefix(line, "require (") {
			inRequire = true
			continue
		}
		if line == ")" {
			inRequire = false
			continue
		}

		if inRequire || strings.HasPrefix(line, "require ") {
			// Skip indirect dependencies
			if strings.Contains(line, "// indirect") {
				continue
			}

			parts := strings.Fields(line)
			if len(parts) >= 2 {
				name := parts[0]
				if strings.HasPrefix(name, "require") {
					if len(parts) < 2 {
						continue // Skip malformed line
					}
					name = parts[1]
					if len(parts) >= 3 {
						parts[1] = parts[2]
					}
				}
				if len(parts) < 2 {
					continue // Skip if not enough parts after processing
				}
				version := strings.TrimPrefix(parts[1], "v")

				comp := Component{
					Name:    name,
					Version: version,
					Type:    "library",
					PURL:    fmt.Sprintf("pkg:golang/%s@%s", name, version),
				}
				components = append(components, comp)
			}
		}
	}

	return components, nil
}

// scanPackageJSON scans package.json for Node.js dependencies.
func (g *Generator) scanPackageJSON(ctx context.Context, path string) ([]Component, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	sp, err := safepath.New(path)
	if err != nil {
		return nil, err
	}

	// Check file size before reading
	info, statErr := sp.Stat("package.json")
	if statErr != nil {
		return nil, statErr
	}
	if info.Size() > MaxSBOMFileSize {
		return nil, fmt.Errorf("package.json file too large: %d bytes (max %d)", info.Size(), MaxSBOMFileSize)
	}

	content, err := sp.ReadFile("package.json")
	if err != nil {
		return nil, err
	}

	return parsePackageJSON(content)
}

// parsePackageJSON parses package.json content and extracts dependencies.
func parsePackageJSON(content []byte) ([]Component, error) {
	var pkg struct {
		Dependencies    map[string]string `json:"dependencies"`
		DevDependencies map[string]string `json:"devDependencies"`
	}

	if err := json.Unmarshal(content, &pkg); err != nil {
		return nil, err
	}

	components := make([]Component, 0, len(pkg.Dependencies)+len(pkg.DevDependencies))

	for name, version := range pkg.Dependencies {
		version = cleanVersion(version)
		comp := Component{
			Name:    name,
			Version: version,
			Type:    "library",
			PURL:    fmt.Sprintf("pkg:npm/%s@%s", name, version),
		}
		components = append(components, comp)
	}

	for name, version := range pkg.DevDependencies {
		version = cleanVersion(version)
		comp := Component{
			Name:    name,
			Version: version,
			Type:    "library",
			PURL:    fmt.Sprintf("pkg:npm/%s@%s", name, version),
		}
		components = append(components, comp)
	}

	return components, nil
}

// scanRequirements scans requirements.txt for Python dependencies.
func (g *Generator) scanRequirements(ctx context.Context, path string) ([]Component, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	sp, err := safepath.New(path)
	if err != nil {
		return nil, err
	}

	// Check file size before reading
	info, statErr := sp.Stat("requirements.txt")
	if statErr != nil {
		return nil, statErr
	}
	if info.Size() > MaxSBOMFileSize {
		return nil, fmt.Errorf("requirements.txt file too large: %d bytes (max %d)", info.Size(), MaxSBOMFileSize)
	}

	content, err := sp.ReadFile("requirements.txt")
	if err != nil {
		return nil, err
	}

	return parseRequirements(content)
}

// parseRequirements parses requirements.txt content and extracts dependencies.
func parseRequirements(content []byte) ([]Component, error) {
	components := make([]Component, 0)
	lines := strings.Split(string(content), "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Skip comments and empty lines
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Skip file references
		if strings.HasPrefix(line, "-r") || strings.HasPrefix(line, "-e") {
			continue
		}

		// Remove inline comments
		if idx := strings.Index(line, "#"); idx > 0 {
			line = strings.TrimSpace(line[:idx])
		}

		// Parse name and version
		var name, version string
		for _, sep := range []string{"==", ">=", "<=", "~=", "!=", ">", "<"} {
			if idx := strings.Index(line, sep); idx > 0 {
				name = strings.TrimSpace(line[:idx])
				version = strings.TrimSpace(line[idx+len(sep):])
				break
			}
		}

		if name == "" {
			name = line
			version = "unknown"
		}

		comp := Component{
			Name:    name,
			Version: version,
			Type:    "library",
			PURL:    fmt.Sprintf("pkg:pypi/%s@%s", name, version),
		}
		components = append(components, comp)
	}

	return components, nil
}

// cleanVersion removes version prefixes like ^, ~, >=, etc.
func cleanVersion(version string) string {
	version = strings.TrimSpace(version)
	for _, prefix := range []string{"^", "~", ">=", "<=", ">", "<", "="} {
		version = strings.TrimPrefix(version, prefix)
	}
	return version
}

// ToSPDX formats the SBOM as SPDX JSON.
func ToSPDX(sbom *SBOM) ([]byte, error) {
	spdx := buildSPDX(sbom)
	return json.MarshalIndent(spdx, "", "  ")
}

// ToCycloneDX formats the SBOM as CycloneDX JSON.
func ToCycloneDX(sbom *SBOM) ([]byte, error) {
	cdx := buildCycloneDX(sbom)
	return json.MarshalIndent(cdx, "", "  ")
}

// Marshal formats the SBOM in the specified format.
func (s *SBOM) Marshal() ([]byte, error) {
	switch s.Format {
	case FormatSPDX:
		return ToSPDX(s)
	case FormatCycloneDX:
		return ToCycloneDX(s)
	default:
		return nil, fmt.Errorf("unsupported format: %s", s.Format)
	}
}

// WriteToFile writes the SBOM to a file.
func (s *SBOM) WriteToFile(path string) error {
	data, err := s.Marshal()
	if err != nil {
		return err
	}

	dir := filepath.Dir(path)
	filename := filepath.Base(path)

	sp, err := safepath.New(dir)
	if err != nil {
		return fmt.Errorf("create safepath: %w", err)
	}

	return sp.WriteFile(filename, data, 0o644)
}

// ComputeHash computes a SHA-256 hash of the SBOM.
func (s *SBOM) ComputeHash() string {
	data, _ := json.Marshal(s)
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

// SPDXDocument represents an SPDX 2.3 document.
// Fields ordered for optimal memory alignment.
type SPDXDocument struct {
	CreationInfo      SPDXCreationInfo `json:"creationInfo"`
	SPDXID            string           `json:"SPDXID"`
	SPDXVersion       string           `json:"spdxVersion"`
	Name              string           `json:"name"`
	DocumentNamespace string           `json:"documentNamespace"`
	DataLicense       string           `json:"dataLicense"`
	Packages          []SPDXPackage    `json:"packages"`
	Relationships     []SPDXRelation   `json:"relationships,omitempty"`
}

// SPDXCreationInfo contains SPDX creation metadata.
// Fields ordered for optimal memory alignment.
type SPDXCreationInfo struct {
	Created  string   `json:"created"`
	Creators []string `json:"creators"`
}

// SPDXPackage represents a package in SPDX format.
// Fields ordered for optimal memory alignment.
type SPDXPackage struct {
	SPDXID           string         `json:"SPDXID"`
	Name             string         `json:"name"`
	VersionInfo      string         `json:"versionInfo"`
	DownloadLocation string         `json:"downloadLocation"`
	Checksums        []SPDXChecksum `json:"checksums,omitempty"`
	ExternalRefs     []SPDXExtRef   `json:"externalRefs,omitempty"`
	FilesAnalyzed    bool           `json:"filesAnalyzed"`
}

// SPDXChecksum represents a checksum in SPDX format.
type SPDXChecksum struct {
	Algorithm     string `json:"algorithm"`
	ChecksumValue string `json:"checksumValue"`
}

// SPDXExtRef represents an external reference in SPDX format.
type SPDXExtRef struct {
	ReferenceCategory string `json:"referenceCategory"`
	ReferenceType     string `json:"referenceType"`
	ReferenceLocator  string `json:"referenceLocator"`
}

// SPDXRelation represents a relationship in SPDX format.
type SPDXRelation struct {
	SpdxElementID      string `json:"spdxElementId"`
	RelationshipType   string `json:"relationshipType"`
	RelatedSpdxElement string `json:"relatedSpdxElement"`
}

// buildSPDX builds an SPDX document from the SBOM.
func buildSPDX(sbom *SBOM) *SPDXDocument {
	packages := make([]SPDXPackage, 0, len(sbom.Components))
	relationships := make([]SPDXRelation, 0)

	// Add document relationship.
	relationships = append(relationships, SPDXRelation{
		SpdxElementID:      "SPDXRef-DOCUMENT",
		RelationshipType:   "DESCRIBES",
		RelatedSpdxElement: "SPDXRef-Package-" + sanitizeID(sbom.Name),
	})

	for i := range sbom.Components {
		comp := &sbom.Components[i]
		pkgID := fmt.Sprintf("SPDXRef-Package-%s-%s", sanitizeID(comp.Name), sanitizeID(comp.Version))

		pkg := SPDXPackage{
			SPDXID:           pkgID,
			Name:             comp.Name,
			VersionInfo:      comp.Version,
			DownloadLocation: "NOASSERTION",
			FilesAnalyzed:    false,
		}

		if comp.PURL != "" {
			pkg.ExternalRefs = []SPDXExtRef{
				{
					ReferenceCategory: "PACKAGE-MANAGER",
					ReferenceType:     "purl",
					ReferenceLocator:  comp.PURL,
				},
			}
		}

		for _, h := range comp.Hashes {
			pkg.Checksums = append(pkg.Checksums, SPDXChecksum{
				Algorithm:     h.Algorithm,
				ChecksumValue: h.Value,
			})
		}

		packages = append(packages, pkg)

		// Add dependency relationship.
		relationships = append(relationships, SPDXRelation{
			SpdxElementID:      "SPDXRef-Package-" + sanitizeID(sbom.Name),
			RelationshipType:   "DEPENDS_ON",
			RelatedSpdxElement: pkgID,
		})
	}

	return &SPDXDocument{
		SPDXVersion:       "SPDX-2.3",
		DataLicense:       "CC0-1.0",
		SPDXID:            "SPDXRef-DOCUMENT",
		Name:              sbom.Name,
		DocumentNamespace: fmt.Sprintf("https://spdx.org/spdxdocs/%s-%s", sbom.Name, sbom.CreatedAt.Format("20060102150405")),
		CreationInfo: SPDXCreationInfo{
			Created: sbom.CreatedAt.Format(time.RFC3339),
			Creators: []string{
				fmt.Sprintf("Tool: %s-%s", sbom.Tool.Name, sbom.Tool.Version),
			},
		},
		Packages:      packages,
		Relationships: relationships,
	}
}

// CycloneDXBOM represents a CycloneDX 1.5 BOM.
// Fields ordered for optimal memory alignment.
type CycloneDXBOM struct {
	Metadata     CycloneDXMetadata `json:"metadata"`
	BOMFormat    string            `json:"bomFormat"`
	SpecVersion  string            `json:"specVersion"`
	SerialNumber string            `json:"serialNumber,omitempty"`
	Components   []CycloneDXComp   `json:"components,omitempty"`
	Dependencies []CycloneDXDep    `json:"dependencies,omitempty"`
	Version      int               `json:"version"`
}

// CycloneDXMetadata contains CycloneDX metadata.
// Fields ordered for optimal memory alignment.
type CycloneDXMetadata struct {
	Timestamp string          `json:"timestamp"`
	Tools     []CycloneDXTool `json:"tools,omitempty"`
}

// CycloneDXTool represents a tool in CycloneDX format.
type CycloneDXTool struct {
	Vendor  string `json:"vendor,omitempty"`
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
}

// CycloneDXComp represents a component in CycloneDX format.
// Fields ordered for optimal memory alignment.
type CycloneDXComp struct {
	BOMRef      string             `json:"bom-ref,omitempty"`
	Type        string             `json:"type"`
	Name        string             `json:"name"`
	Version     string             `json:"version,omitempty"`
	PURL        string             `json:"purl,omitempty"`
	Description string             `json:"description,omitempty"`
	Licenses    []CycloneDXLicense `json:"licenses,omitempty"`
	Hashes      []CycloneDXHash    `json:"hashes,omitempty"`
}

// CycloneDXLicense represents a license in CycloneDX format.
type CycloneDXLicense struct {
	License CycloneDXLicenseID `json:"license,omitempty"`
}

// CycloneDXLicenseID contains a license identifier.
type CycloneDXLicenseID struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
}

// CycloneDXHash represents a hash in CycloneDX format.
type CycloneDXHash struct {
	Algorithm string `json:"alg"`
	Content   string `json:"content"`
}

// CycloneDXDep represents a dependency in CycloneDX format.
type CycloneDXDep struct {
	Ref       string   `json:"ref"`
	DependsOn []string `json:"dependsOn,omitempty"`
}

// buildCycloneDX builds a CycloneDX BOM from the SBOM.
func buildCycloneDX(sbom *SBOM) *CycloneDXBOM {
	components := make([]CycloneDXComp, 0, len(sbom.Components))

	for i := range sbom.Components {
		comp := &sbom.Components[i]

		cdxComp := CycloneDXComp{
			BOMRef:      fmt.Sprintf("%s@%s", comp.Name, comp.Version),
			Type:        comp.Type,
			Name:        comp.Name,
			Version:     comp.Version,
			PURL:        comp.PURL,
			Description: comp.Description,
		}

		for _, license := range comp.Licenses {
			cdxComp.Licenses = append(cdxComp.Licenses, CycloneDXLicense{
				License: CycloneDXLicenseID{ID: license},
			})
		}

		for _, h := range comp.Hashes {
			cdxComp.Hashes = append(cdxComp.Hashes, CycloneDXHash{
				Algorithm: mapHashAlgorithm(h.Algorithm),
				Content:   h.Value,
			})
		}

		components = append(components, cdxComp)
	}

	// Build dependencies if available.
	deps := make([]CycloneDXDep, 0, len(sbom.Dependencies))
	for i := range sbom.Dependencies {
		d := &sbom.Dependencies[i]
		deps = append(deps, CycloneDXDep{
			Ref:       d.Ref,
			DependsOn: d.DependsOn,
		})
	}

	return &CycloneDXBOM{
		BOMFormat:    "CycloneDX",
		SpecVersion:  "1.5",
		SerialNumber: fmt.Sprintf("urn:uuid:%s", generateUUID(sbom)),
		Version:      1,
		Metadata: CycloneDXMetadata{
			Timestamp: sbom.CreatedAt.Format(time.RFC3339),
			Tools: []CycloneDXTool{
				{
					Vendor:  sbom.Tool.Vendor,
					Name:    sbom.Tool.Name,
					Version: sbom.Tool.Version,
				},
			},
		},
		Components:   components,
		Dependencies: deps,
	}
}

// sanitizeID sanitizes a string for use as an SPDX ID.
func sanitizeID(s string) string {
	result := strings.ReplaceAll(s, "/", "-")
	result = strings.ReplaceAll(result, "@", "-")
	result = strings.ReplaceAll(result, ".", "-")
	return result
}

// mapHashAlgorithm maps algorithm names to CycloneDX format.
func mapHashAlgorithm(alg string) string {
	switch strings.ToLower(alg) {
	case "sha256", "sha-256":
		return "SHA-256"
	case "sha512", "sha-512":
		return "SHA-512"
	case "sha1", "sha-1":
		return "SHA-1"
	case "md5":
		return "MD5"
	default:
		return alg
	}
}

// generateUUID generates a deterministic UUID from the SBOM content.
func generateUUID(sbom *SBOM) string {
	data := fmt.Sprintf("%s-%s-%s", sbom.Name, sbom.Version, sbom.CreatedAt.Format(time.RFC3339))
	hash := sha256.Sum256([]byte(data))
	// Format as UUID v4-like string.
	return fmt.Sprintf("%x-%x-%x-%x-%x",
		hash[0:4], hash[4:6], hash[6:8], hash[8:10], hash[10:16])
}
