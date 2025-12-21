package trivy

// Report represents the top-level Trivy JSON report structure.
type Report struct {
	Metadata      Metadata `json:"Metadata"`
	ArtifactName  string   `json:"ArtifactName"`
	ArtifactType  string   `json:"ArtifactType"`
	Results       []Result `json:"Results"`
	SchemaVersion int      `json:"SchemaVersion"`
}

// Metadata contains metadata about the scanned artifact.
type Metadata struct {
	OS          *OS          `json:"OS,omitempty"`
	ImageConfig *ImageConfig `json:"ImageConfig,omitempty"`
	ImageID     string       `json:"ImageID,omitempty"`
	DiffIDs     []string     `json:"DiffIDs,omitempty"`
	RepoTags    []string     `json:"RepoTags,omitempty"`
	RepoDigests []string     `json:"RepoDigests,omitempty"`
}

// OS contains operating system information.
type OS struct {
	Family string `json:"Family"`
	Name   string `json:"Name"`
}

// ImageConfig contains Docker image configuration.
type ImageConfig struct {
	Architecture string `json:"architecture"`
	OS           string `json:"os"`
}

// Result represents scan results for a single target.
type Result struct {
	Target          string          `json:"Target"`
	Class           string          `json:"Class"`
	Type            string          `json:"Type"`
	Vulnerabilities []Vulnerability `json:"Vulnerabilities"`
}

// Vulnerability represents a single vulnerability finding.
type Vulnerability struct {
	CVSS             CVSS     `json:"CVSS"`
	Layer            *Layer   `json:"Layer,omitempty"`
	DataSource       *DataSrc `json:"DataSource,omitempty"`
	PrimaryURL       string   `json:"PrimaryURL"`
	Title            string   `json:"Title"`
	Status           string   `json:"Status"`
	InstalledVersion string   `json:"InstalledVersion"`
	SeveritySource   string   `json:"SeveritySource"`
	VulnerabilityID  string   `json:"VulnerabilityID"`
	PkgName          string   `json:"PkgName"`
	FixedVersion     string   `json:"FixedVersion"`
	Description      string   `json:"Description"`
	Severity         string   `json:"Severity"`
	LastModifiedDate string   `json:"LastModifiedDate"`
	PkgID            string   `json:"PkgID"`
	PublishedDate    string   `json:"PublishedDate"`
	References       []string `json:"References"`
	CweIDs           []string `json:"CweIDs"`
}

// Layer contains information about the Docker layer where vulnerability was found.
type Layer struct {
	Digest string `json:"Digest"`
	DiffID string `json:"DiffID"`
}

// DataSrc contains information about the vulnerability data source.
type DataSrc struct {
	ID   string `json:"ID"`
	Name string `json:"Name"`
	URL  string `json:"URL"`
}

// CVSS contains CVSS scoring information.
type CVSS struct {
	Nvd    *CVSSData `json:"nvd,omitempty"`
	Redhat *CVSSData `json:"redhat,omitempty"`
}

// CVSSData contains CVSS version-specific data.
type CVSSData struct {
	V2Vector string  `json:"V2Vector,omitempty"`
	V3Vector string  `json:"V3Vector,omitempty"`
	V2Score  float64 `json:"V2Score,omitempty"`
	V3Score  float64 `json:"V3Score,omitempty"`
}
