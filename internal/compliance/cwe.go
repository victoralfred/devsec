package compliance

import (
	"strings"
	"sync"
)

// ControlRef references a control in a specific framework.
type ControlRef struct {
	Framework FrameworkID `json:"framework"`
	ControlID string      `json:"control_id"`
}

// CWEMapper maps CWE IDs to compliance controls.
// Fields ordered for optimal memory alignment.
type CWEMapper struct {
	cweToControls map[string][]ControlRef
	controlToCWEs map[string][]string
	mu            sync.RWMutex
}

// NewCWEMapper creates a new CWE mapper with default mappings.
func NewCWEMapper() *CWEMapper {
	m := &CWEMapper{
		cweToControls: make(map[string][]ControlRef),
		controlToCWEs: make(map[string][]string),
	}
	m.loadDefaultMappings()
	return m
}

// GetControls returns all controls mapped to a CWE ID.
func (m *CWEMapper) GetControls(cweID string) []ControlRef {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Normalize CWE ID.
	cweID = normalizeCWE(cweID)
	if refs, ok := m.cweToControls[cweID]; ok {
		result := make([]ControlRef, len(refs))
		copy(result, refs)
		return result
	}
	return nil
}

// GetCWEs returns all CWE IDs mapped to a control.
func (m *CWEMapper) GetCWEs(framework FrameworkID, controlID string) []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	key := string(framework) + ":" + controlID
	if cwes, ok := m.controlToCWEs[key]; ok {
		result := make([]string, len(cwes))
		copy(result, cwes)
		return result
	}
	return nil
}

// AddMapping adds a CWE to control mapping.
func (m *CWEMapper) AddMapping(cweID string, framework FrameworkID, controlID string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	cweID = normalizeCWE(cweID)
	ref := ControlRef{Framework: framework, ControlID: controlID}

	// Add to CWE -> Controls map.
	m.cweToControls[cweID] = append(m.cweToControls[cweID], ref)

	// Add to Control -> CWEs map.
	key := string(framework) + ":" + controlID
	m.controlToCWEs[key] = append(m.controlToCWEs[key], cweID)
}

// GetAllMappedCWEs returns all CWE IDs that have control mappings.
func (m *CWEMapper) GetAllMappedCWEs() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]string, 0, len(m.cweToControls))
	for cwe := range m.cweToControls {
		result = append(result, cwe)
	}
	return result
}

// normalizeCWE ensures CWE ID is in standard format (CWE-XXX).
func normalizeCWE(cweID string) string {
	cweID = strings.TrimSpace(cweID)
	cweID = strings.ToUpper(cweID)

	// Handle various formats.
	if strings.HasPrefix(cweID, "CWE-") {
		return cweID
	}
	if strings.HasPrefix(cweID, "CWE") {
		return "CWE-" + cweID[3:]
	}
	// Assume it's just the number.
	return "CWE-" + cweID
}

// loadDefaultMappings loads the default CWE to control mappings.
func (m *CWEMapper) loadDefaultMappings() {
	// Injection vulnerabilities.
	injectionCWEs := []string{"CWE-78", "CWE-79", "CWE-89", "CWE-94", "CWE-77"}
	for _, cwe := range injectionCWEs {
		m.AddMapping(cwe, FrameworkSOC2, "CC6.1")
		m.AddMapping(cwe, FrameworkSOC2, "CC7.1")
		m.AddMapping(cwe, FrameworkISO27001, "A.8.25")
		m.AddMapping(cwe, FrameworkISO27001, "A.8.26")
		m.AddMapping(cwe, FrameworkISO27001, "A.8.28")
		m.AddMapping(cwe, FrameworkGDPR, "Art.32")
	}

	// Authentication/Authorization vulnerabilities.
	authCWEs := []string{"CWE-287", "CWE-306", "CWE-798", "CWE-862", "CWE-863", "CWE-521"}
	for _, cwe := range authCWEs {
		m.AddMapping(cwe, FrameworkSOC2, "CC6.1")
		m.AddMapping(cwe, FrameworkSOC2, "CC6.6")
		m.AddMapping(cwe, FrameworkISO27001, "A.8.5")
		m.AddMapping(cwe, FrameworkGDPR, "Art.32")
	}

	// Cryptography vulnerabilities.
	cryptoCWEs := []string{"CWE-326", "CWE-327", "CWE-328", "CWE-330", "CWE-338", "CWE-311", "CWE-319"}
	for _, cwe := range cryptoCWEs {
		m.AddMapping(cwe, FrameworkSOC2, "CC6.7")
		m.AddMapping(cwe, FrameworkISO27001, "A.8.24")
		m.AddMapping(cwe, FrameworkGDPR, "Art.32")
	}

	// Information disclosure / Secrets.
	disclosureCWEs := []string{"CWE-200", "CWE-312", "CWE-532", "CWE-359", "CWE-538"}
	for _, cwe := range disclosureCWEs {
		m.AddMapping(cwe, FrameworkSOC2, "CC6.1")
		m.AddMapping(cwe, FrameworkSOC2, "CC6.7")
		m.AddMapping(cwe, FrameworkISO27001, "A.5.33")
		m.AddMapping(cwe, FrameworkISO27001, "A.5.34")
		m.AddMapping(cwe, FrameworkGDPR, "Art.5")
		m.AddMapping(cwe, FrameworkGDPR, "Art.32")
		m.AddMapping(cwe, FrameworkGDPR, "Art.33")
	}

	// Input validation vulnerabilities.
	inputCWEs := []string{"CWE-20", "CWE-22", "CWE-73"}
	for _, cwe := range inputCWEs {
		m.AddMapping(cwe, FrameworkSOC2, "CC6.1")
		m.AddMapping(cwe, FrameworkISO27001, "A.8.26")
		m.AddMapping(cwe, FrameworkGDPR, "Art.32")
	}

	// Memory safety vulnerabilities.
	memoryCWEs := []string{"CWE-119", "CWE-120", "CWE-125", "CWE-787"}
	for _, cwe := range memoryCWEs {
		m.AddMapping(cwe, FrameworkSOC2, "CC7.1")
		m.AddMapping(cwe, FrameworkISO27001, "A.8.28")
		m.AddMapping(cwe, FrameworkGDPR, "Art.32")
	}

	// Deserialization vulnerabilities.
	deserializationCWEs := []string{"CWE-502", "CWE-915"}
	for _, cwe := range deserializationCWEs {
		m.AddMapping(cwe, FrameworkSOC2, "CC7.1")
		m.AddMapping(cwe, FrameworkISO27001, "A.8.25")
		m.AddMapping(cwe, FrameworkGDPR, "Art.32")
	}

	// Supply chain vulnerabilities.
	supplyCWEs := []string{"CWE-829", "CWE-494", "CWE-1104"}
	for _, cwe := range supplyCWEs {
		m.AddMapping(cwe, FrameworkSOC2, "CC8.1")
		m.AddMapping(cwe, FrameworkISO27001, "A.8.9")
		m.AddMapping(cwe, FrameworkGDPR, "Art.32")
	}

	// Logging/Monitoring vulnerabilities.
	loggingCWEs := []string{"CWE-778", "CWE-779"}
	for _, cwe := range loggingCWEs {
		m.AddMapping(cwe, FrameworkSOC2, "CC7.2")
		m.AddMapping(cwe, FrameworkISO27001, "A.8.9")
	}

	// Configuration vulnerabilities.
	configCWEs := []string{"CWE-16", "CWE-1188"}
	for _, cwe := range configCWEs {
		m.AddMapping(cwe, FrameworkSOC2, "CC8.1")
		m.AddMapping(cwe, FrameworkISO27001, "A.8.9")
	}
}

// CWECategory represents a category of CWE weaknesses.
type CWECategory struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	CWEIDs      []string `json:"cwe_ids"`
}

// GetCWECategories returns predefined CWE categories.
func GetCWECategories() []CWECategory {
	return []CWECategory{
		{
			Name:        "Injection",
			Description: "Injection flaws, such as SQL, NoSQL, OS, and LDAP injection",
			CWEIDs:      []string{"CWE-77", "CWE-78", "CWE-79", "CWE-89", "CWE-94"},
		},
		{
			Name:        "Broken Authentication",
			Description: "Authentication and session management flaws",
			CWEIDs:      []string{"CWE-287", "CWE-306", "CWE-521", "CWE-798"},
		},
		{
			Name:        "Broken Access Control",
			Description: "Failures related to access control enforcement",
			CWEIDs:      []string{"CWE-862", "CWE-863", "CWE-22", "CWE-73"},
		},
		{
			Name:        "Cryptographic Failures",
			Description: "Failures related to cryptography or lack thereof",
			CWEIDs:      []string{"CWE-311", "CWE-319", "CWE-326", "CWE-327", "CWE-328", "CWE-330", "CWE-338"},
		},
		{
			Name:        "Sensitive Data Exposure",
			Description: "Exposure of sensitive data",
			CWEIDs:      []string{"CWE-200", "CWE-312", "CWE-359", "CWE-532", "CWE-538"},
		},
		{
			Name:        "Insecure Deserialization",
			Description: "Insecure deserialization leading to remote code execution",
			CWEIDs:      []string{"CWE-502", "CWE-915"},
		},
		{
			Name:        "Vulnerable Components",
			Description: "Using components with known vulnerabilities",
			CWEIDs:      []string{"CWE-829", "CWE-494", "CWE-1104"},
		},
		{
			Name:        "Security Logging Failures",
			Description: "Insufficient logging and monitoring",
			CWEIDs:      []string{"CWE-778", "CWE-779"},
		},
	}
}

// GetCWEDescription returns a human-readable description for a CWE ID.
func GetCWEDescription(cweID string) string {
	cweID = normalizeCWE(cweID)

	descriptions := map[string]string{
		"CWE-16":   "Configuration",
		"CWE-20":   "Improper Input Validation",
		"CWE-22":   "Path Traversal",
		"CWE-73":   "External Control of File Name or Path",
		"CWE-77":   "Command Injection",
		"CWE-78":   "OS Command Injection",
		"CWE-79":   "Cross-site Scripting (XSS)",
		"CWE-89":   "SQL Injection",
		"CWE-94":   "Code Injection",
		"CWE-119":  "Buffer Errors",
		"CWE-120":  "Buffer Overflow",
		"CWE-125":  "Out-of-bounds Read",
		"CWE-200":  "Exposure of Sensitive Information",
		"CWE-287":  "Improper Authentication",
		"CWE-306":  "Missing Authentication",
		"CWE-311":  "Missing Encryption of Sensitive Data",
		"CWE-312":  "Cleartext Storage of Sensitive Information",
		"CWE-319":  "Cleartext Transmission of Sensitive Information",
		"CWE-326":  "Inadequate Encryption Strength",
		"CWE-327":  "Use of Broken Crypto Algorithm",
		"CWE-328":  "Reversible One-Way Hash",
		"CWE-330":  "Insufficient Randomness",
		"CWE-338":  "Use of Weak PRNG",
		"CWE-359":  "Privacy Violation",
		"CWE-494":  "Download of Code Without Integrity Check",
		"CWE-502":  "Deserialization of Untrusted Data",
		"CWE-521":  "Weak Password Requirements",
		"CWE-532":  "Insertion of Sensitive Info into Log File",
		"CWE-538":  "Insertion of Sensitive Info into Externally-Accessible File",
		"CWE-778":  "Insufficient Logging",
		"CWE-779":  "Logging of Excessive Data",
		"CWE-787":  "Out-of-bounds Write",
		"CWE-798":  "Use of Hard-coded Credentials",
		"CWE-829":  "Inclusion of Untrusted Functionality",
		"CWE-862":  "Missing Authorization",
		"CWE-863":  "Incorrect Authorization",
		"CWE-915":  "Improperly Controlled Modification of Object Attributes",
		"CWE-1104": "Use of Unmaintained Third Party Components",
		"CWE-1188": "Insecure Default Variable Initialization",
	}

	if desc, ok := descriptions[cweID]; ok {
		return desc
	}
	return "Unknown CWE"
}
