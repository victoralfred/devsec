package semgrep

// SARIFReport represents the top-level SARIF report structure.
type SARIFReport struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []SARIFRun `json:"runs"`
}

// SARIFRun represents a single run in a SARIF report.
type SARIFRun struct {
	Tool    SARIFTool     `json:"tool"`
	Results []SARIFResult `json:"results"`
}

// SARIFTool represents the tool that generated the results.
type SARIFTool struct {
	Driver SARIFDriver `json:"driver"`
}

// SARIFDriver contains information about the analysis tool.
type SARIFDriver struct {
	Name            string      `json:"name"`
	Version         string      `json:"version"`
	InformationURI  string      `json:"informationUri"`
	SemanticVersion string      `json:"semanticVersion"`
	Rules           []SARIFRule `json:"rules"`
}

// SARIFDefaultConfiguration represents default configuration for a rule.
type SARIFDefaultConfiguration struct {
	Level string `json:"level"`
}

// SARIFRule represents a rule definition.
type SARIFRule struct {
	ShortDescription     SARIFMessage              `json:"shortDescription"`
	FullDescription      SARIFMessage              `json:"fullDescription"`
	DefaultConfiguration SARIFDefaultConfiguration `json:"defaultConfiguration"`
	ID                   string                    `json:"id"`
	Name                 string                    `json:"name"`
	HelpURI              string                    `json:"helpUri"`
	Properties           SARIFProperties           `json:"properties"`
}

// SARIFResult represents a single finding in the SARIF report.
type SARIFResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   SARIFMessage    `json:"message"`
	Locations []SARIFLocation `json:"locations"`
	RuleIndex int             `json:"ruleIndex"`
}

// SARIFMessage represents a message in SARIF format.
type SARIFMessage struct {
	Text string `json:"text"`
}

// SARIFLocation represents a location in source code.
type SARIFLocation struct {
	PhysicalLocation SARIFPhysicalLocation `json:"physicalLocation"`
}

// SARIFPhysicalLocation contains physical location details.
type SARIFPhysicalLocation struct {
	ArtifactLocation SARIFArtifactLocation `json:"artifactLocation"`
	Region           SARIFRegion           `json:"region"`
}

// SARIFArtifactLocation identifies a file/artifact.
type SARIFArtifactLocation struct {
	URI   string `json:"uri"`
	Index int    `json:"index"`
}

// SARIFRegion represents a region within a file.
type SARIFRegion struct {
	StartLine   int `json:"startLine"`
	StartColumn int `json:"startColumn"`
	EndLine     int `json:"endLine"`
	EndColumn   int `json:"endColumn"`
}

// SARIFProperties contains additional rule metadata.
type SARIFProperties struct {
	Precision string   `json:"precision"`
	Tags      []string `json:"tags"`
}
