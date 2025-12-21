// Package osv provides a scanner implementation for OSV vulnerability detection.
package osv

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/victoralfred/devsec/internal/model"
	"github.com/victoralfred/gowritter/safepath"
)

// DefaultAPIURL is the default OSV API endpoint.
const DefaultAPIURL = "https://api.osv.dev/v1"

// DefaultTimeout is the default timeout for API requests.
const DefaultTimeout = 2 * time.Minute

// DefaultBatchSize is the default number of packages to query at once.
const DefaultBatchSize = 100

// MaxFileSize is the maximum size of a dependency file to parse (10MB).
const MaxFileSize = 10 * 1024 * 1024

// Scanner implements the scanner.Scanner interface for OSV.
type Scanner struct {
	httpClient *http.Client
	apiURL     string
	timeout    time.Duration
	batchSize  int
}

// Option configures a Scanner.
type Option func(*Scanner)

// WithAPIURL sets a custom API URL.
func WithAPIURL(url string) Option {
	return func(s *Scanner) {
		s.apiURL = url
	}
}

// WithTimeout sets a custom timeout.
func WithTimeout(timeout time.Duration) Option {
	return func(s *Scanner) {
		s.timeout = timeout
	}
}

// WithBatchSize sets a custom batch size.
func WithBatchSize(size int) Option {
	return func(s *Scanner) {
		s.batchSize = size
	}
}

// WithHTTPClient sets a custom HTTP client.
func WithHTTPClient(client *http.Client) Option {
	return func(s *Scanner) {
		s.httpClient = client
	}
}

// New creates a new OSV scanner.
func New(opts ...Option) *Scanner {
	s := &Scanner{
		apiURL:    DefaultAPIURL,
		timeout:   DefaultTimeout,
		batchSize: DefaultBatchSize,
	}

	for _, opt := range opts {
		opt(s)
	}

	if s.httpClient == nil {
		s.httpClient = &http.Client{
			Timeout: s.timeout,
		}
	}

	return s
}

// Name returns the scanner name.
func (s *Scanner) Name() string {
	return "osv"
}

// Scan scans the given path for dependency vulnerabilities.
func (s *Scanner) Scan(ctx context.Context, path string) ([]model.Finding, error) {
	if path == "" {
		return nil, fmt.Errorf("path cannot be empty")
	}

	absPath, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve absolute path: %w", err)
	}

	// Verify path exists and is a directory.
	sp, err := safepath.New(absPath)
	if err != nil {
		return nil, fmt.Errorf("path does not exist or is not accessible: %w", err)
	}
	info, err := sp.Stat(".")
	if err != nil {
		return nil, fmt.Errorf("failed to stat path: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("path must be a directory: %s", absPath)
	}

	// Check for context cancellation.
	if ctxErr := ctx.Err(); ctxErr != nil {
		return nil, fmt.Errorf("context canceled: %w", ctxErr)
	}

	// Parse dependencies from manifest files.
	deps, err := s.parseDependencies(ctx, absPath)
	if err != nil {
		return nil, fmt.Errorf("failed to parse dependencies: %w", err)
	}

	if len(deps) == 0 {
		return []model.Finding{}, nil
	}

	// Check for context cancellation.
	if ctxErr := ctx.Err(); ctxErr != nil {
		return nil, fmt.Errorf("context canceled: %w", ctxErr)
	}

	// Query OSV API for vulnerabilities.
	findings, err := s.queryVulnerabilities(ctx, deps)
	if err != nil {
		return nil, fmt.Errorf("failed to query vulnerabilities: %w", err)
	}

	return findings, nil
}

// parseDependencies parses dependency files in the given directory.
func (s *Scanner) parseDependencies(ctx context.Context, basePath string) ([]Dependency, error) {
	var deps []Dependency

	sp, err := safepath.New(basePath)
	if err != nil {
		return nil, fmt.Errorf("failed to create safe path: %w", err)
	}

	// Check for Go modules.
	goModDeps, err := s.parseGoMod(ctx, sp)
	if err == nil {
		deps = append(deps, goModDeps...)
	}

	// Check for npm packages.
	npmDeps, err := s.parsePackageJSON(ctx, sp)
	if err == nil {
		deps = append(deps, npmDeps...)
	}

	// Check for Python packages.
	pipDeps, err := s.parseRequirementsTxt(ctx, sp)
	if err == nil {
		deps = append(deps, pipDeps...)
	}

	return deps, nil
}

// parseGoMod parses a go.mod file.
func (s *Scanner) parseGoMod(ctx context.Context, sp *safepath.SafePath) ([]Dependency, error) {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return nil, ctxErr
	}

	info, err := sp.Stat("go.mod")
	if err != nil {
		return nil, err
	}
	if info.Size() > MaxFileSize {
		return nil, fmt.Errorf("go.mod too large: %d bytes", info.Size())
	}

	data, err := sp.ReadFile("go.mod")
	if err != nil {
		return nil, err
	}

	return parseGoModContent(data, "go.mod"), nil
}

// parseGoModContent parses go.mod content.
func parseGoModContent(data []byte, filename string) []Dependency {
	var deps []Dependency
	lines := strings.Split(string(data), "\n")
	inRequire := false

	// Regex for require line: module version
	requireRegex := regexp.MustCompile(`^\s*(\S+)\s+v(\S+)`)

	for _, line := range lines {
		line = strings.TrimSpace(line)

		if strings.HasPrefix(line, "require (") {
			inRequire = true
			continue
		}
		if inRequire && line == ")" {
			inRequire = false
			continue
		}

		// Single require statement.
		line = strings.TrimPrefix(line, "require ")

		if inRequire || strings.Contains(line, " v") {
			matches := requireRegex.FindStringSubmatch(line)
			if len(matches) >= 3 {
				// Skip indirect dependencies.
				if strings.Contains(line, "// indirect") {
					continue
				}
				deps = append(deps, Dependency{
					Name:      matches[1],
					Version:   matches[2],
					Ecosystem: "Go",
					File:      filename,
				})
			}
		}
	}

	return deps
}

// parsePackageJSON parses a package.json file.
func (s *Scanner) parsePackageJSON(ctx context.Context, sp *safepath.SafePath) ([]Dependency, error) {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return nil, ctxErr
	}

	info, err := sp.Stat("package.json")
	if err != nil {
		return nil, err
	}
	if info.Size() > MaxFileSize {
		return nil, fmt.Errorf("package.json too large: %d bytes", info.Size())
	}

	data, err := sp.ReadFile("package.json")
	if err != nil {
		return nil, err
	}

	return parsePackageJSONContent(data, "package.json"), nil
}

// packageJSON represents the structure of package.json.
type packageJSON struct {
	Dependencies    map[string]string `json:"dependencies"`
	DevDependencies map[string]string `json:"devDependencies"`
}

// parsePackageJSONContent parses package.json content.
func parsePackageJSONContent(data []byte, filename string) []Dependency {
	var pkg packageJSON
	if err := json.Unmarshal(data, &pkg); err != nil {
		return nil
	}

	deps := make([]Dependency, 0, len(pkg.Dependencies)+len(pkg.DevDependencies))

	for name, version := range pkg.Dependencies {
		deps = append(deps, Dependency{
			Name:      name,
			Version:   cleanVersion(version),
			Ecosystem: "npm",
			File:      filename,
		})
	}

	for name, version := range pkg.DevDependencies {
		deps = append(deps, Dependency{
			Name:      name,
			Version:   cleanVersion(version),
			Ecosystem: "npm",
			File:      filename,
		})
	}

	return deps
}

// parseRequirementsTxt parses a requirements.txt file.
func (s *Scanner) parseRequirementsTxt(ctx context.Context, sp *safepath.SafePath) ([]Dependency, error) {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return nil, ctxErr
	}

	info, err := sp.Stat("requirements.txt")
	if err != nil {
		return nil, err
	}
	if info.Size() > MaxFileSize {
		return nil, fmt.Errorf("requirements.txt too large: %d bytes", info.Size())
	}

	data, err := sp.ReadFile("requirements.txt")
	if err != nil {
		return nil, err
	}

	return parseRequirementsTxtContent(data, "requirements.txt"), nil
}

// parseRequirementsTxtContent parses requirements.txt content.
func parseRequirementsTxtContent(data []byte, filename string) []Dependency {
	var deps []Dependency
	lines := strings.Split(string(data), "\n")

	// Regex for requirement line: package==version or package>=version etc.
	reqRegex := regexp.MustCompile(`^([a-zA-Z0-9_-]+)\s*[=<>!~]+\s*(\d[^\s;#]*)`)

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Skip comments and empty lines.
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
			continue
		}

		matches := reqRegex.FindStringSubmatch(line)
		if len(matches) >= 3 {
			deps = append(deps, Dependency{
				Name:      matches[1],
				Version:   matches[2],
				Ecosystem: "PyPI",
				File:      filename,
			})
		}
	}

	return deps
}

// cleanVersion removes version specifiers like ^, ~, >=.
func cleanVersion(version string) string {
	version = strings.TrimPrefix(version, "^")
	version = strings.TrimPrefix(version, "~")
	version = strings.TrimPrefix(version, ">=")
	version = strings.TrimPrefix(version, "<=")
	version = strings.TrimPrefix(version, ">")
	version = strings.TrimPrefix(version, "<")
	version = strings.TrimPrefix(version, "=")
	return strings.TrimSpace(version)
}

// queryVulnerabilities queries the OSV API for vulnerabilities.
func (s *Scanner) queryVulnerabilities(ctx context.Context, deps []Dependency) ([]model.Finding, error) {
	var allFindings []model.Finding

	// Process in batches.
	for i := 0; i < len(deps); i += s.batchSize {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, fmt.Errorf("context canceled: %w", ctxErr)
		}

		end := i + s.batchSize
		if end > len(deps) {
			end = len(deps)
		}

		batch := deps[i:end]
		findings, err := s.queryBatch(ctx, batch)
		if err != nil {
			return nil, err
		}

		allFindings = append(allFindings, findings...)
	}

	return allFindings, nil
}

// queryBatch queries a batch of dependencies.
func (s *Scanner) queryBatch(ctx context.Context, deps []Dependency) ([]model.Finding, error) {
	queries := make([]QueryRequest, 0, len(deps))
	for i := range deps {
		dep := &deps[i]
		queries = append(queries, QueryRequest{
			Package: &Package{
				Name:      dep.Name,
				Ecosystem: dep.Ecosystem,
			},
			Version: dep.Version,
		})
	}

	batchReq := BatchQueryRequest{Queries: queries}
	reqBody, err := json.Marshal(batchReq)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	url := s.apiURL + "/querybatch"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API returned status %d", resp.StatusCode)
	}

	// Limit response size.
	const maxResponseSize = 50 * 1024 * 1024 // 50MB
	limitedReader := io.LimitReader(resp.Body, maxResponseSize)

	var batchResp BatchQueryResponse
	if err := json.NewDecoder(limitedReader).Decode(&batchResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return s.mapBatchResults(batchResp, deps), nil
}

// mapBatchResults maps batch API results to findings.
func (s *Scanner) mapBatchResults(resp BatchQueryResponse, deps []Dependency) []model.Finding {
	var findings []model.Finding

	for i, result := range resp.Results {
		if i >= len(deps) {
			break
		}
		dep := &deps[i]

		for j := range result.Vulns {
			vuln := &result.Vulns[j]
			finding := s.mapVulnerability(vuln, dep)
			findings = append(findings, finding)
		}
	}

	return findings
}

// mapVulnerability maps an OSV vulnerability to a model.Finding.
func (s *Scanner) mapVulnerability(vuln *Vulnerability, dep *Dependency) model.Finding {
	severity := s.determineSeverity(vuln)
	description := s.buildDescription(vuln, dep)
	findingID := s.generateFindingID(vuln, dep)

	title := vuln.Summary
	if title == "" {
		title = vuln.ID
	}

	return model.Finding{
		ID:          findingID,
		Scanner:     "osv",
		Rule:        vuln.ID,
		Title:       title,
		Description: description,
		Severity:    severity,
		Location: model.Location{
			File: dep.File,
		},
	}
}

// determineSeverity determines the severity from OSV data.
func (s *Scanner) determineSeverity(vuln *Vulnerability) model.Severity {
	for _, sev := range vuln.Severity {
		if sev.Type == "CVSS_V3" {
			return s.mapCVSSScore(sev.Score)
		}
	}

	// Check affected severities.
	for i := range vuln.Affected {
		aff := &vuln.Affected[i]
		for _, sev := range aff.Severities {
			if sev.Type == "CVSS_V3" {
				return s.mapCVSSScore(sev.Score)
			}
		}
	}

	// Default based on ID prefix.
	if strings.HasPrefix(vuln.ID, "GHSA-") {
		return model.SeverityMedium
	}

	return model.SeverityInfo
}

// mapCVSSScore maps a CVSS score string to severity.
func (s *Scanner) mapCVSSScore(score string) model.Severity {
	// CVSS v3 scores: 0.0-3.9 Low, 4.0-6.9 Medium, 7.0-8.9 High, 9.0-10.0 Critical
	// Score format is typically a vector string, but we can extract numeric score.
	if strings.Contains(score, "CVSS:3") {
		// Parse base score from vector if available.
		// For now, use heuristics based on common patterns.
		if strings.Contains(score, "/AV:N") && strings.Contains(score, "/AC:L") {
			if strings.Contains(score, "/C:H") || strings.Contains(score, "/I:H") || strings.Contains(score, "/A:H") {
				return model.SeverityHigh
			}
			return model.SeverityMedium
		}
	}
	return model.SeverityMedium
}

// buildDescription builds a detailed description.
func (s *Scanner) buildDescription(vuln *Vulnerability, dep *Dependency) string {
	var builder strings.Builder
	builder.Grow(500)

	builder.WriteString("Package: ")
	builder.WriteString(dep.Name)
	builder.WriteString("\nVersion: ")
	builder.WriteString(dep.Version)
	builder.WriteString("\nEcosystem: ")
	builder.WriteString(dep.Ecosystem)

	if len(vuln.Aliases) > 0 {
		builder.WriteString("\nAliases: ")
		builder.WriteString(strings.Join(vuln.Aliases, ", "))
	}

	// Find fixed version.
	fixedVersion := s.findFixedVersion(vuln, dep)
	if fixedVersion != "" {
		builder.WriteString("\nFixed in: ")
		builder.WriteString(fixedVersion)
	}

	if vuln.Details != "" {
		builder.WriteString("\n\n")
		builder.WriteString(vuln.Details)
	}

	return builder.String()
}

// findFixedVersion finds the fixed version from affected data.
func (s *Scanner) findFixedVersion(vuln *Vulnerability, dep *Dependency) string {
	for i := range vuln.Affected {
		aff := &vuln.Affected[i]
		if aff.Package != nil && aff.Package.Ecosystem == dep.Ecosystem {
			for _, r := range aff.Ranges {
				for _, event := range r.Events {
					if event.Fixed != "" {
						return event.Fixed
					}
				}
			}
		}
	}
	return ""
}

// generateFindingID generates a unique finding ID.
func (s *Scanner) generateFindingID(vuln *Vulnerability, dep *Dependency) string {
	id := fmt.Sprintf("%s:%s:%s", vuln.ID, dep.Name, dep.Version)
	return fmt.Sprintf("%s-%s", id, uuid.New().String()[:8])
}

// Close is a no-op for OSV scanner (no resources to release).
func (s *Scanner) Close(_ context.Context) error {
	return nil
}
