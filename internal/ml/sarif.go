// Package ml provides ML-specific validation and detection capabilities.
package ml

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/victoralfred/gowritter/safepath"
)

// SARIF version used by this implementation.
const sarifVersion = "2.1.0"

// SARIFReport represents a SARIF report.
type SARIFReport struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []SARIFRun `json:"runs"`
}

// SARIFRun represents a single analysis run.
type SARIFRun struct {
	Tool        SARIFTool       `json:"tool"`
	Results     []SARIFResult   `json:"results"`
	Invocations []SARIFInvoke   `json:"invocations,omitempty"`
	Artifacts   []SARIFArtifact `json:"artifacts,omitempty"`
}

// SARIFTool represents the analysis tool.
type SARIFTool struct {
	Driver SARIFDriver `json:"driver"`
}

// SARIFDriver represents the tool driver information.
//
//nolint:govet // SARIF spec field order preserved for readability.
type SARIFDriver struct {
	Name            string      `json:"name"`
	Version         string      `json:"version,omitempty"`
	InformationURI  string      `json:"informationUri,omitempty"`
	Rules           []SARIFRule `json:"rules,omitempty"`
	SemanticVersion string      `json:"semanticVersion,omitempty"`
}

// SARIFRule represents an analysis rule.
type SARIFRule struct {
	ID               string              `json:"id"`
	Name             string              `json:"name,omitempty"`
	ShortDescription SARIFMessage        `json:"shortDescription,omitempty"`
	FullDescription  SARIFMessage        `json:"fullDescription,omitempty"`
	HelpURI          string              `json:"helpUri,omitempty"`
	DefaultConfig    SARIFConfiguration  `json:"defaultConfiguration,omitempty"`
	Properties       map[string]string   `json:"properties,omitempty"`
	Help             *SARIFMultiMessage  `json:"help,omitempty"`
	Relationships    []SARIFRelationship `json:"relationships,omitempty"`
}

// SARIFConfiguration represents rule configuration.
type SARIFConfiguration struct {
	Level string `json:"level,omitempty"`
}

// SARIFResult represents a single finding.
//
//nolint:govet // SARIF spec field order preserved for readability.
type SARIFResult struct {
	RuleID       string            `json:"ruleId"`
	RuleIndex    int               `json:"ruleIndex,omitempty"`
	Level        string            `json:"level,omitempty"`
	Message      SARIFMessage      `json:"message"`
	Locations    []SARIFLocation   `json:"locations,omitempty"`
	Fixes        []SARIFFix        `json:"fixes,omitempty"`
	Fingerprints map[string]string `json:"fingerprints,omitempty"`
}

// SARIFMessage represents a text message.
type SARIFMessage struct {
	Text     string `json:"text,omitempty"`
	Markdown string `json:"markdown,omitempty"`
}

// SARIFMultiMessage represents a message with multiple formats.
type SARIFMultiMessage struct {
	Text     string `json:"text,omitempty"`
	Markdown string `json:"markdown,omitempty"`
}

// SARIFLocation represents a code location.
type SARIFLocation struct {
	PhysicalLocation SARIFPhysicalLocation  `json:"physicalLocation,omitempty"`
	LogicalLocations []SARIFLogicalLocation `json:"logicalLocations,omitempty"`
}

// SARIFPhysicalLocation represents a physical file location.
//
//nolint:govet // SARIF spec field order preserved for readability.
type SARIFPhysicalLocation struct {
	ArtifactLocation SARIFArtifactLocation `json:"artifactLocation"`
	Region           *SARIFRegion          `json:"region,omitempty"`
}

// SARIFArtifactLocation represents an artifact location.
type SARIFArtifactLocation struct {
	URI       string `json:"uri"`
	URIBaseID string `json:"uriBaseId,omitempty"`
	Index     int    `json:"index,omitempty"`
}

// SARIFRegion represents a region within a file.
type SARIFRegion struct {
	StartLine   int `json:"startLine,omitempty"`
	StartColumn int `json:"startColumn,omitempty"`
	EndLine     int `json:"endLine,omitempty"`
	EndColumn   int `json:"endColumn,omitempty"`
}

// SARIFLogicalLocation represents a logical location.
type SARIFLogicalLocation struct {
	Name               string `json:"name,omitempty"`
	FullyQualifiedName string `json:"fullyQualifiedName,omitempty"`
	Kind               string `json:"kind,omitempty"`
}

// SARIFFix represents a suggested fix.
type SARIFFix struct {
	Description     SARIFMessage          `json:"description,omitempty"`
	ArtifactChanges []SARIFArtifactChange `json:"artifactChanges,omitempty"`
}

// SARIFArtifactChange represents a change to an artifact.
type SARIFArtifactChange struct {
	ArtifactLocation SARIFArtifactLocation `json:"artifactLocation"`
	Replacements     []SARIFReplacement    `json:"replacements,omitempty"`
}

// SARIFReplacement represents a text replacement.
//
//nolint:govet // SARIF spec field order preserved for readability.
type SARIFReplacement struct {
	DeletedRegion   SARIFRegion  `json:"deletedRegion"`
	InsertedContent SARIFContent `json:"insertedContent,omitempty"`
}

// SARIFContent represents content to be inserted.
type SARIFContent struct {
	Text string `json:"text,omitempty"`
}

// SARIFInvoke represents an invocation of the tool.
//
//nolint:govet // SARIF spec field order preserved for readability.
type SARIFInvoke struct {
	CommandLine      string                `json:"commandLine,omitempty"`
	ExecutionSuccess bool                  `json:"executionSuccessful"`
	StartTimeUTC     string                `json:"startTimeUtc,omitempty"`
	EndTimeUTC       string                `json:"endTimeUtc,omitempty"`
	WorkingDirectory SARIFArtifactLocation `json:"workingDirectory,omitempty"`
}

// SARIFArtifact represents a scanned artifact.
//
//nolint:govet // SARIF spec field order preserved for readability.
type SARIFArtifact struct {
	Location SARIFArtifactLocation `json:"location"`
	MimeType string                `json:"mimeType,omitempty"`
	Length   int64                 `json:"length,omitempty"`
}

// SARIFRelationship represents a relationship between rules.
type SARIFRelationship struct {
	Target SARIFReportingDescriptor `json:"target"`
	Kinds  []string                 `json:"kinds,omitempty"`
}

// SARIFReportingDescriptor represents a reporting descriptor reference.
type SARIFReportingDescriptor struct {
	ID            string                      `json:"id"`
	ToolComponent SARIFToolComponentReference `json:"toolComponent,omitempty"`
}

// SARIFToolComponentReference represents a tool component reference.
type SARIFToolComponentReference struct {
	Name string `json:"name,omitempty"`
}

// SARIFExporter exports detection results to SARIF format.
type SARIFExporter struct {
	ToolName    string
	ToolVersion string
	InfoURI     string
}

// NewSARIFExporter creates a new SARIF exporter.
func NewSARIFExporter(toolName, toolVersion, infoURI string) *SARIFExporter {
	return &SARIFExporter{
		ToolName:    toolName,
		ToolVersion: toolVersion,
		InfoURI:     infoURI,
	}
}

// DefaultSARIFExporter creates a SARIF exporter with default settings.
func DefaultSARIFExporter() *SARIFExporter {
	return NewSARIFExporter("devsec-ml", "1.0.0", "https://github.com/victoralfred/devsec")
}

// ExportDetectionResult exports a DetectionResult to SARIF format.
func (e *SARIFExporter) ExportDetectionResult(result *DetectionResult) (*SARIFReport, error) {
	if result == nil {
		return nil, fmt.Errorf("result cannot be nil")
	}

	rules := e.createRules()
	results := e.convertDetectionResults(result)

	report := &SARIFReport{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Version: sarifVersion,
		Runs: []SARIFRun{
			{
				Tool: SARIFTool{
					Driver: SARIFDriver{
						Name:            e.ToolName,
						Version:         e.ToolVersion,
						SemanticVersion: e.ToolVersion,
						InformationURI:  e.InfoURI,
						Rules:           rules,
					},
				},
				Results: results,
				Invocations: []SARIFInvoke{
					{
						ExecutionSuccess: true,
						StartTimeUTC:     time.Now().UTC().Format(time.RFC3339),
					},
				},
			},
		},
	}

	return report, nil
}

// ExportFairnessResult exports a FairnessResult to SARIF format.
func (e *SARIFExporter) ExportFairnessResult(result *FairnessResult) (*SARIFReport, error) {
	if result == nil {
		return nil, fmt.Errorf("result cannot be nil")
	}

	rules := e.createFairnessRules()
	results := e.convertFairnessResults(result)

	report := &SARIFReport{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Version: sarifVersion,
		Runs: []SARIFRun{
			{
				Tool: SARIFTool{
					Driver: SARIFDriver{
						Name:            e.ToolName,
						Version:         e.ToolVersion,
						SemanticVersion: e.ToolVersion,
						InformationURI:  e.InfoURI,
						Rules:           rules,
					},
				},
				Results: results,
			},
		},
	}

	return report, nil
}

// ExportBiasReport exports a BiasReport to SARIF format.
func (e *SARIFExporter) ExportBiasReport(report *BiasReport) (*SARIFReport, error) {
	if report == nil {
		return nil, fmt.Errorf("report cannot be nil")
	}

	rules := e.createBiasRules()
	results := e.convertBiasResults(report)

	sarifReport := &SARIFReport{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Version: sarifVersion,
		Runs: []SARIFRun{
			{
				Tool: SARIFTool{
					Driver: SARIFDriver{
						Name:            e.ToolName,
						Version:         e.ToolVersion,
						SemanticVersion: e.ToolVersion,
						InformationURI:  e.InfoURI,
						Rules:           rules,
					},
				},
				Results: results,
			},
		},
	}

	return sarifReport, nil
}

// ToJSON converts a SARIF report to JSON.
func (r *SARIFReport) ToJSON() ([]byte, error) {
	return json.MarshalIndent(r, "", "  ")
}

// WriteToFile writes the SARIF report to a file.
func (r *SARIFReport) WriteToFile(path string) error {
	data, err := r.ToJSON()
	if err != nil {
		return fmt.Errorf("marshal SARIF: %w", err)
	}

	dir, file := splitPath(path)
	sp, spErr := safepath.New(dir)
	if spErr != nil {
		return fmt.Errorf("create safepath: %w", spErr)
	}

	if writeErr := sp.WriteFile(file, data, 0o644); writeErr != nil {
		return fmt.Errorf("write SARIF file: %w", writeErr)
	}

	return nil
}

// createRules creates SARIF rules for ML detection.
func (e *SARIFExporter) createRules() []SARIFRule {
	return []SARIFRule{
		{
			ID:   "ML001",
			Name: "ml-framework-detected",
			ShortDescription: SARIFMessage{
				Text: "ML framework detected in codebase",
			},
			FullDescription: SARIFMessage{
				Text: "An ML framework import or usage was detected in the codebase.",
			},
			DefaultConfig: SARIFConfiguration{
				Level: "note",
			},
		},
		{
			ID:   "ML002",
			Name: "ml-model-file-detected",
			ShortDescription: SARIFMessage{
				Text: "ML model file detected",
			},
			FullDescription: SARIFMessage{
				Text: "An ML model file was detected in the repository.",
			},
			DefaultConfig: SARIFConfiguration{
				Level: "note",
			},
		},
		{
			ID:   "ML003",
			Name: "ml-pipeline-detected",
			ShortDescription: SARIFMessage{
				Text: "ML training pipeline detected",
			},
			FullDescription: SARIFMessage{
				Text: "An ML training pipeline was detected in the codebase.",
			},
			DefaultConfig: SARIFConfiguration{
				Level: "note",
			},
		},
	}
}

// createFairnessRules creates SARIF rules for fairness analysis.
func (e *SARIFExporter) createFairnessRules() []SARIFRule {
	return []SARIFRule{
		{
			ID:   "FAIR001",
			Name: "disparate-impact-violation",
			ShortDescription: SARIFMessage{
				Text: "Disparate impact threshold violation",
			},
			FullDescription: SARIFMessage{
				Text: "The model exhibits disparate impact between protected groups.",
			},
			DefaultConfig: SARIFConfiguration{
				Level: "warning",
			},
		},
		{
			ID:   "FAIR002",
			Name: "statistical-parity-violation",
			ShortDescription: SARIFMessage{
				Text: "Statistical parity threshold violation",
			},
			FullDescription: SARIFMessage{
				Text: "The model violates statistical parity between groups.",
			},
			DefaultConfig: SARIFConfiguration{
				Level: "warning",
			},
		},
		{
			ID:   "FAIR003",
			Name: "equal-opportunity-violation",
			ShortDescription: SARIFMessage{
				Text: "Equal opportunity threshold violation",
			},
			FullDescription: SARIFMessage{
				Text: "The model violates equal opportunity between groups.",
			},
			DefaultConfig: SARIFConfiguration{
				Level: "warning",
			},
		},
	}
}

// createBiasRules creates SARIF rules for bias detection.
func (e *SARIFExporter) createBiasRules() []SARIFRule {
	return []SARIFRule{
		{
			ID:   "BIAS001",
			Name: "selection-bias-detected",
			ShortDescription: SARIFMessage{
				Text: "Selection bias detected",
			},
			FullDescription: SARIFMessage{
				Text: "Selection bias was detected in the dataset.",
			},
			DefaultConfig: SARIFConfiguration{
				Level: "warning",
			},
		},
		{
			ID:   "BIAS002",
			Name: "sampling-bias-detected",
			ShortDescription: SARIFMessage{
				Text: "Sampling bias detected",
			},
			FullDescription: SARIFMessage{
				Text: "Sampling bias was detected in the dataset.",
			},
			DefaultConfig: SARIFConfiguration{
				Level: "warning",
			},
		},
		{
			ID:   "BIAS003",
			Name: "label-bias-detected",
			ShortDescription: SARIFMessage{
				Text: "Label bias detected",
			},
			FullDescription: SARIFMessage{
				Text: "Label bias was detected in the dataset.",
			},
			DefaultConfig: SARIFConfiguration{
				Level: "warning",
			},
		},
		{
			ID:   "BIAS004",
			Name: "feature-bias-detected",
			ShortDescription: SARIFMessage{
				Text: "Feature bias detected",
			},
			FullDescription: SARIFMessage{
				Text: "Feature bias was detected in the dataset.",
			},
			DefaultConfig: SARIFConfiguration{
				Level: "warning",
			},
		},
	}
}

// convertDetectionResults converts DetectionResult to SARIF results.
func (e *SARIFExporter) convertDetectionResults(result *DetectionResult) []SARIFResult {
	results := make([]SARIFResult, 0, len(result.Frameworks)+len(result.Models))

	// Convert frameworks.
	for _, fw := range result.Frameworks {
		ruleID := "ML001"
		if fw.IsMLPipeline {
			ruleID = "ML003"
		}

		results = append(results, SARIFResult{
			RuleID: ruleID,
			Level:  "note",
			Message: SARIFMessage{
				Text: fmt.Sprintf("Detected %s framework with %.0f%% confidence", fw.Name, fw.Confidence*100),
			},
			Locations: []SARIFLocation{
				{
					PhysicalLocation: SARIFPhysicalLocation{
						ArtifactLocation: SARIFArtifactLocation{
							URI: fw.SourceFile,
						},
					},
				},
			},
		})
	}

	// Convert models.
	for _, model := range result.Models {
		results = append(results, SARIFResult{
			RuleID: "ML002",
			Level:  "note",
			Message: SARIFMessage{
				Text: fmt.Sprintf("Detected %s model file (%s framework)", model.Type, model.Framework),
			},
			Locations: []SARIFLocation{
				{
					PhysicalLocation: SARIFPhysicalLocation{
						ArtifactLocation: SARIFArtifactLocation{
							URI: model.Path,
						},
					},
				},
			},
		})
	}

	return results
}

// convertFairnessResults converts FairnessResult to SARIF results.
func (e *SARIFExporter) convertFairnessResults(result *FairnessResult) []SARIFResult {
	results := make([]SARIFResult, 0, len(result.FairnessMetrics))

	for _, metric := range result.FairnessMetrics {
		if !metric.Passed {
			ruleID := "FAIR001"
			switch metric.Type {
			case MetricStatisticalParity:
				ruleID = "FAIR002"
			case MetricEqualOpportunity:
				ruleID = "FAIR003"
			}

			results = append(results, SARIFResult{
				RuleID: ruleID,
				Level:  "warning",
				Message: SARIFMessage{
					Text: fmt.Sprintf("%s violation: value=%.4f, threshold=%.4f",
						metric.Type, metric.Value, metric.Threshold),
				},
			})
		}
	}

	return results
}

// convertBiasResults converts BiasReport to SARIF results.
func (e *SARIFExporter) convertBiasResults(report *BiasReport) []SARIFResult {
	results := make([]SARIFResult, 0, len(report.Indicators))

	for _, indicator := range report.Indicators {
		ruleID := "BIAS001"
		switch indicator.Type {
		case BiasSampling:
			ruleID = "BIAS002"
		case BiasLabel:
			ruleID = "BIAS003"
		case BiasFeature:
			ruleID = "BIAS004"
		}

		level := "note"
		switch indicator.Severity {
		case "high", "critical":
			level = "error"
		case "medium":
			level = "warning"
		}

		results = append(results, SARIFResult{
			RuleID: ruleID,
			Level:  level,
			Message: SARIFMessage{
				Text: fmt.Sprintf("%s bias detected: %s (severity: %s, score: %.4f)",
					indicator.Type, indicator.Description, indicator.Severity, indicator.Score),
			},
		})
	}

	return results
}

// splitPath splits a path into directory and filename.
func splitPath(path string) (dir, file string) {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' || path[i] == '\\' {
			return path[:i], path[i+1:]
		}
	}
	return ".", path
}
