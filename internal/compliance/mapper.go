package compliance

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/victoralfred/devsec/internal/model"
)

// Mapper maps findings to compliance controls.
type Mapper interface {
	// Enrich adds compliance metadata to findings.
	Enrich(ctx context.Context, findings []model.Finding) ([]EnrichedFinding, error)

	// MapToControls maps enriched findings to control assessments.
	MapToControls(ctx context.Context, findings []EnrichedFinding, frameworks []FrameworkID) (map[FrameworkID][]ControlAssessment, error)

	// GetControlByID returns a control by its ID.
	GetControlByID(framework FrameworkID, controlID string) (Control, bool)

	// ListControls returns all controls for a framework.
	ListControls(framework FrameworkID) []Control
}

// DefaultMapper is the default implementation of Mapper.
type DefaultMapper struct {
	frameworks map[FrameworkID]*Framework
	cweMapper  *CWEMapper
	mu         sync.RWMutex
}

// MapperOption configures a DefaultMapper.
type MapperOption func(*DefaultMapper)

// WithCWEMapper sets a custom CWE mapper.
func WithCWEMapper(m *CWEMapper) MapperOption {
	return func(dm *DefaultMapper) {
		dm.cweMapper = m
	}
}

// NewMapper creates a new DefaultMapper with all supported frameworks.
func NewMapper(opts ...MapperOption) *DefaultMapper {
	m := &DefaultMapper{
		frameworks: make(map[FrameworkID]*Framework),
		cweMapper:  NewCWEMapper(),
	}

	// Load all frameworks.
	for _, f := range AllFrameworks() {
		m.frameworks[f.ID] = f
	}

	// Apply options.
	for _, opt := range opts {
		opt(m)
	}

	return m
}

// Enrich adds compliance metadata to findings.
func (m *DefaultMapper) Enrich(ctx context.Context, findings []model.Finding) ([]EnrichedFinding, error) {
	// Input validation.
	if m == nil {
		return nil, fmt.Errorf("mapper cannot be nil")
	}
	if ctx == nil {
		return nil, fmt.Errorf("context cannot be nil")
	}
	if findings == nil {
		return nil, nil // Allow nil, return nil (backward compatibility)
	}

	if len(findings) == 0 {
		return nil, nil
	}

	// Check limit to prevent DoS.
	if len(findings) > MaxFindings {
		return nil, fmt.Errorf("findings limit exceeded: %d (max %d)", len(findings), MaxFindings)
	}

	result := make([]EnrichedFinding, 0, len(findings))

	for i := range findings {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		enriched := EnrichedFinding{
			Finding: findings[i],
		}

		// Extract CWE IDs from finding description/rule if available.
		cweIDs := extractCWEsFromFinding(findings[i])
		if len(cweIDs) > 0 {
			enriched.CWEIDs = cweIDs

			// Map CWEs to controls.
			controlIDs := m.mapCWEsToControls(cweIDs)
			enriched.ControlIDs = controlIDs
		}

		// Extract CVE IDs if present.
		cveIDs := extractCVEsFromFinding(findings[i])
		if len(cveIDs) > 0 {
			enriched.CVEIDs = cveIDs
		}

		result = append(result, enriched)
	}

	return result, nil
}

// MapToControls maps enriched findings to control assessments.
func (m *DefaultMapper) MapToControls(ctx context.Context, findings []EnrichedFinding, frameworks []FrameworkID) (map[FrameworkID][]ControlAssessment, error) {
	// Input validation.
	if m == nil {
		return nil, fmt.Errorf("mapper cannot be nil")
	}
	if ctx == nil {
		return nil, fmt.Errorf("context cannot be nil")
	}
	if findings == nil {
		return make(map[FrameworkID][]ControlAssessment), nil // Allow nil, return empty map
	}

	// Check limit to prevent DoS.
	if len(findings) > MaxEnrichedFindings {
		return nil, fmt.Errorf("enriched findings limit exceeded: %d (max %d)", len(findings), MaxEnrichedFindings)
	}

	result := make(map[FrameworkID][]ControlAssessment)

	// If no frameworks specified, use all.
	if len(frameworks) == 0 {
		frameworks = SupportedFrameworks()
	}

	for _, fwID := range frameworks {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		// Use read lock to safely access frameworks map.
		m.mu.RLock()
		framework, ok := m.frameworks[fwID]
		m.mu.RUnlock()

		if !ok {
			continue
		}

		// Framework is immutable after creation, safe to use without lock.
		assessments := m.assessFramework(framework, findings)
		result[fwID] = assessments
	}

	return result, nil
}

// GetControlByID returns a control by its ID.
func (m *DefaultMapper) GetControlByID(framework FrameworkID, controlID string) (Control, bool) {
	// Input validation.
	if m == nil {
		return Control{}, false
	}
	if framework == "" {
		return Control{}, false
	}
	if controlID == "" {
		return Control{}, false
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	f, ok := m.frameworks[framework]
	if !ok {
		return Control{}, false
	}

	return f.GetControl(controlID)
}

// ListControls returns all controls for a framework.
func (m *DefaultMapper) ListControls(framework FrameworkID) []Control {
	// Input validation.
	if m == nil {
		return nil
	}
	if framework == "" {
		return nil
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	f, ok := m.frameworks[framework]
	if !ok {
		return nil
	}

	result := make([]Control, len(f.Controls))
	copy(result, f.Controls)
	return result
}

// assessFramework assesses all controls in a framework against findings.
func (m *DefaultMapper) assessFramework(framework *Framework, findings []EnrichedFinding) []ControlAssessment {
	// Check limit to prevent DoS.
	maxControls := len(framework.Controls)
	if maxControls > MaxControls {
		maxControls = MaxControls
	}

	assessments := make([]ControlAssessment, 0, maxControls)

	for i := range framework.Controls {
		// Check limit in loop to prevent exceeding.
		if len(assessments) >= MaxControls {
			break
		}

		ctrl := framework.Controls[i]
		assessment := m.assessControl(ctrl, findings)
		assessments = append(assessments, assessment)
	}

	return assessments
}

// assessControl assesses a single control against findings.
func (m *DefaultMapper) assessControl(ctrl Control, findings []EnrichedFinding) ControlAssessment {
	assessment := ControlAssessment{
		Control: ctrl,
		Status:  StatusNotAssessed,
	}

	// Use map for O(1) duplicate checking instead of O(n) linear search.
	matchedSet := make(map[string]bool)
	matchedFindings := make([]string, 0, len(findings))
	var criticalCount, highCount int

	controlKey := string(FrameworkID(ctrl.Framework)) + ":" + ctrl.ID

	// Build CWE set for O(1) lookup.
	cweSet := make(map[string]bool, len(ctrl.CWEMappings))
	for _, cwe := range ctrl.CWEMappings {
		cweSet[cwe] = true
	}

	for i := range findings {
		findingID := findings[i].Finding.ID

		// Check if already matched.
		if matchedSet[findingID] {
			continue
		}

		// Check control ID mappings.
		matched := false
		for _, ctrlID := range findings[i].ControlIDs {
			if ctrlID == controlKey || ctrlID == ctrl.ID {
				matched = true
				break
			}
		}

		// Check CWE mappings using set for O(1) lookup.
		if !matched {
			for _, cwe := range findings[i].CWEIDs {
				if cweSet[cwe] {
					matched = true
					break
				}
			}
		}

		if matched {
			matchedSet[findingID] = true
			matchedFindings = append(matchedFindings, findingID)

			switch findings[i].Finding.Severity {
			case model.SeverityCritical:
				criticalCount++
			case model.SeverityHigh:
				highCount++
			}
		}
	}

	assessment.Findings = matchedFindings
	assessment.FindingCount = len(matchedFindings)
	assessment.CriticalCount = criticalCount
	assessment.HighCount = highCount

	// Determine status based on findings.
	switch {
	case len(matchedFindings) == 0:
		assessment.Status = StatusCompliant
		assessment.Rationale = "No violations detected"
	case criticalCount > 0 || highCount > 0:
		assessment.Status = StatusNonCompliant
		assessment.Rationale = "Critical or high severity violations detected"
	default:
		assessment.Status = StatusPartial
		assessment.Rationale = "Low or medium severity issues detected"
	}

	return assessment
}

// mapCWEsToControls maps CWE IDs to control IDs.
func (m *DefaultMapper) mapCWEsToControls(cweIDs []string) []string {
	controlSet := make(map[string]bool)

	for _, cwe := range cweIDs {
		refs := m.cweMapper.GetControls(cwe)
		for _, ref := range refs {
			key := string(ref.Framework) + ":" + ref.ControlID
			controlSet[key] = true
		}
	}

	result := make([]string, 0, len(controlSet))
	for key := range controlSet {
		result = append(result, key)
	}

	return result
}

// extractCWEsFromFinding extracts CWE IDs from a finding.
// Optimized to use a single pass with map for O(1) duplicate checking.
func extractCWEsFromFinding(f model.Finding) []string {
	cweSet := make(map[string]bool)

	// Extract from rule ID.
	if cwe := extractCWEFromString(f.Rule); cwe != "" {
		cweSet[cwe] = true
	}

	// Extract from description.
	if cwe := extractCWEFromString(f.Description); cwe != "" {
		cweSet[cwe] = true
	}

	// Convert set to slice.
	if len(cweSet) == 0 {
		return nil
	}
	cwes := make([]string, 0, len(cweSet))
	for cwe := range cweSet {
		cwes = append(cwes, cwe)
	}
	return cwes
}

// extractCWEFromString extracts a CWE ID from a string.
func extractCWEFromString(s string) string {
	// Simple pattern matching for CWE-XXX.
	const prefix = "CWE-"
	idx := 0
	for {
		// Use strings.Index for efficient substring search.
		pos := strings.Index(s[idx:], prefix)
		if pos == -1 {
			break
		}

		start := idx + pos
		end := start + len(prefix)

		// Bounds check before accessing.
		if end > len(s) {
			break
		}

		// Extract digits after prefix.
		for end < len(s) && s[end] >= '0' && s[end] <= '9' {
			end++
		}

		if end > start+len(prefix) {
			return s[start:end]
		}

		idx = start + len(prefix)
		if idx >= len(s) {
			break
		}
	}

	return ""
}

// extractCVEsFromFinding extracts CVE IDs from a finding.
// Optimized to use a single pass with map for O(1) duplicate checking.
func extractCVEsFromFinding(f model.Finding) []string {
	cveSet := make(map[string]bool)

	// Extract from rule ID.
	if cve := extractCVEFromString(f.Rule); cve != "" {
		cveSet[cve] = true
	}

	// Extract from ID.
	if cve := extractCVEFromString(f.ID); cve != "" {
		cveSet[cve] = true
	}

	// Extract from description.
	if cve := extractCVEFromString(f.Description); cve != "" {
		cveSet[cve] = true
	}

	// Convert set to slice.
	if len(cveSet) == 0 {
		return nil
	}
	cves := make([]string, 0, len(cveSet))
	for cve := range cveSet {
		cves = append(cves, cve)
	}
	return cves
}

// extractCVEFromString extracts a CVE ID from a string.
func extractCVEFromString(s string) string {
	// Simple pattern matching for CVE-YYYY-XXXXX.
	const prefix = "CVE-"
	idx := 0
	for {
		// Use strings.Index for efficient substring search.
		pos := strings.Index(s[idx:], prefix)
		if pos == -1 {
			break
		}

		start := idx + pos
		end := start + len(prefix)

		// Bounds check before accessing.
		if end > len(s) {
			break
		}

		// Extract year (4 digits).
		yearEnd := end
		for yearEnd < len(s) && s[yearEnd] >= '0' && s[yearEnd] <= '9' {
			yearEnd++
		}

		if yearEnd-end != 4 {
			idx = start + len(prefix)
			if idx >= len(s) {
				break
			}
			continue
		}

		// Check for dash.
		if yearEnd >= len(s) || s[yearEnd] != '-' {
			idx = start + len(prefix)
			if idx >= len(s) {
				break
			}
			continue
		}

		// Extract ID (4+ digits).
		idStart := yearEnd + 1
		if idStart >= len(s) {
			idx = start + len(prefix)
			if idx >= len(s) {
				break
			}
			continue
		}

		idEnd := idStart
		for idEnd < len(s) && s[idEnd] >= '0' && s[idEnd] <= '9' {
			idEnd++
		}

		if idEnd-idStart >= 4 {
			return s[start:idEnd]
		}

		idx = start + len(prefix)
		if idx >= len(s) {
			break
		}
	}

	return ""
}
