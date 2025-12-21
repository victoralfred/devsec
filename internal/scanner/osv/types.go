// Package osv provides a scanner implementation for OSV vulnerability detection.
package osv

// QueryRequest represents a request to the OSV API.
type QueryRequest struct {
	Package *Package `json:"package,omitempty"`
	Version string   `json:"version,omitempty"`
	Commit  string   `json:"commit,omitempty"`
}

// Package represents a package identifier.
type Package struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

// BatchQueryRequest represents a batch query request.
type BatchQueryRequest struct {
	Queries []QueryRequest `json:"queries"`
}

// QueryResponse represents a response from the OSV API.
type QueryResponse struct {
	Vulns []Vulnerability `json:"vulns"`
}

// BatchQueryResponse represents a batch query response.
type BatchQueryResponse struct {
	Results []QueryResponse `json:"results"`
}

// Vulnerability represents a vulnerability from OSV.
type Vulnerability struct {
	DatabaseSpec  interface{} `json:"database_specific,omitempty"`
	SchemaVersion string      `json:"schema_version"`
	ID            string      `json:"id"`
	Modified      string      `json:"modified"`
	Published     string      `json:"published"`
	Withdrawn     string      `json:"withdrawn,omitempty"`
	Summary       string      `json:"summary"`
	Details       string      `json:"details"`
	Aliases       []string    `json:"aliases"`
	Severity      []Severity  `json:"severity"`
	Affected      []Affected  `json:"affected"`
	References    []Reference `json:"references"`
}

// Severity represents CVSS severity information.
type Severity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

// Affected represents affected package information.
type Affected struct {
	Package       *Package    `json:"package"`
	Ranges        []Range     `json:"ranges"`
	Versions      []string    `json:"versions"`
	EcosystemSpec interface{} `json:"ecosystem_specific,omitempty"`
	DatabaseSpec  interface{} `json:"database_specific,omitempty"`
	Severities    []Severity  `json:"severities,omitempty"`
}

// Range represents version range information.
type Range struct {
	Type   string  `json:"type"`
	Repo   string  `json:"repo,omitempty"`
	Events []Event `json:"events"`
}

// Event represents a version event (introduced, fixed, etc.).
type Event struct {
	Introduced   string `json:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty"`
	Limit        string `json:"limit,omitempty"`
}

// Reference represents a reference link.
type Reference struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

// Dependency represents a parsed dependency from a manifest file.
type Dependency struct {
	Name      string
	Version   string
	Ecosystem string
	File      string
}
