package ml

import (
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/victoralfred/gowritter/safepath"
)

func TestNewSARIFExporter(t *testing.T) {
	exporter := NewSARIFExporter("test-tool", "1.0.0", "https://example.com")

	if exporter.ToolName != "test-tool" {
		t.Errorf("expected ToolName 'test-tool', got %s", exporter.ToolName)
	}
	if exporter.ToolVersion != "1.0.0" {
		t.Errorf("expected ToolVersion '1.0.0', got %s", exporter.ToolVersion)
	}
	if exporter.InfoURI != "https://example.com" {
		t.Errorf("expected InfoURI 'https://example.com', got %s", exporter.InfoURI)
	}
}

func TestDefaultSARIFExporter(t *testing.T) {
	exporter := DefaultSARIFExporter()

	if exporter.ToolName != "devsec-ml" {
		t.Errorf("expected ToolName 'devsec-ml', got %s", exporter.ToolName)
	}
	if exporter.ToolVersion == "" {
		t.Error("expected non-empty ToolVersion")
	}
}

func TestExportDetectionResult(t *testing.T) {
	exporter := DefaultSARIFExporter()

	result := &DetectionResult{
		Frameworks: []DetectedFramework{
			{
				Name:         FrameworkTensorFlow,
				SourceFile:   "train.py",
				Confidence:   0.9,
				IsMLPipeline: true,
			},
			{
				Name:         FrameworkPyTorch,
				SourceFile:   "model.py",
				Confidence:   0.8,
				IsMLPipeline: false,
			},
		},
		Models: []DetectedModel{
			{
				Path:      "model.h5",
				Name:      "model.h5",
				Type:      ModelTypeH5,
				Framework: FrameworkTensorFlow,
			},
		},
	}

	sarif, err := exporter.ExportDetectionResult(result)
	if err != nil {
		t.Fatalf("ExportDetectionResult failed: %v", err)
	}

	if sarif.Version != sarifVersion {
		t.Errorf("expected version %s, got %s", sarifVersion, sarif.Version)
	}

	if len(sarif.Runs) != 1 {
		t.Fatalf("expected 1 run, got %d", len(sarif.Runs))
	}

	run := sarif.Runs[0]
	if run.Tool.Driver.Name != "devsec-ml" {
		t.Errorf("expected tool name 'devsec-ml', got %s", run.Tool.Driver.Name)
	}

	// Should have 3 results: 2 frameworks + 1 model.
	if len(run.Results) != 3 {
		t.Errorf("expected 3 results, got %d", len(run.Results))
	}

	// Check rules exist.
	if len(run.Tool.Driver.Rules) < 3 {
		t.Errorf("expected at least 3 rules, got %d", len(run.Tool.Driver.Rules))
	}
}

func TestExportDetectionResultNil(t *testing.T) {
	exporter := DefaultSARIFExporter()

	_, err := exporter.ExportDetectionResult(nil)
	if err == nil {
		t.Error("expected error for nil result")
	}
}

func TestExportFairnessResult(t *testing.T) {
	exporter := DefaultSARIFExporter()

	result := &FairnessResult{
		FairnessMetrics: []FairnessMetric{
			{
				Type:      MetricDisparateImpact,
				Value:     0.75,
				Threshold: 0.8,
				Passed:    false,
			},
			{
				Type:      MetricStatisticalParity,
				Value:     0.15,
				Threshold: 0.1,
				Passed:    false,
			},
		},
	}

	sarif, err := exporter.ExportFairnessResult(result)
	if err != nil {
		t.Fatalf("ExportFairnessResult failed: %v", err)
	}

	if len(sarif.Runs) != 1 {
		t.Fatalf("expected 1 run, got %d", len(sarif.Runs))
	}

	// Should have 2 results (both violations).
	if len(sarif.Runs[0].Results) != 2 {
		t.Errorf("expected 2 results, got %d", len(sarif.Runs[0].Results))
	}

	// Check that violations have warning level.
	for _, result := range sarif.Runs[0].Results {
		if result.Level != "warning" {
			t.Errorf("expected level 'warning', got %s", result.Level)
		}
	}
}

func TestExportFairnessResultNil(t *testing.T) {
	exporter := DefaultSARIFExporter()

	_, err := exporter.ExportFairnessResult(nil)
	if err == nil {
		t.Error("expected error for nil result")
	}
}

func TestExportBiasReport(t *testing.T) {
	exporter := DefaultSARIFExporter()

	report := &BiasReport{
		Indicators: []BiasIndicator{
			{
				Type:        BiasSelection,
				Attribute:   "feature_x",
				Description: "Selection bias in feature X",
				Severity:    "high",
				Score:       0.8,
			},
			{
				Type:        BiasSampling,
				Attribute:   "sampling",
				Description: "Undersampling of minority group",
				Severity:    "medium",
				Score:       0.5,
			},
			{
				Type:        BiasLabel,
				Attribute:   "label",
				Description: "Label noise in positive class",
				Severity:    "low",
				Score:       0.2,
			},
		},
	}

	sarif, err := exporter.ExportBiasReport(report)
	if err != nil {
		t.Fatalf("ExportBiasReport failed: %v", err)
	}

	if len(sarif.Runs) != 1 {
		t.Fatalf("expected 1 run, got %d", len(sarif.Runs))
	}

	if len(sarif.Runs[0].Results) != 3 {
		t.Errorf("expected 3 results, got %d", len(sarif.Runs[0].Results))
	}

	// Check severity mapping.
	levels := make(map[string]int)
	for _, result := range sarif.Runs[0].Results {
		levels[result.Level]++
	}

	if levels["error"] != 1 {
		t.Errorf("expected 1 error level result, got %d", levels["error"])
	}
	if levels["warning"] != 1 {
		t.Errorf("expected 1 warning level result, got %d", levels["warning"])
	}
	if levels["note"] != 1 {
		t.Errorf("expected 1 note level result, got %d", levels["note"])
	}
}

func TestExportBiasReportNil(t *testing.T) {
	exporter := DefaultSARIFExporter()

	_, err := exporter.ExportBiasReport(nil)
	if err == nil {
		t.Error("expected error for nil report")
	}
}

func TestSARIFReportToJSON(t *testing.T) {
	exporter := DefaultSARIFExporter()

	result := &DetectionResult{
		Frameworks: []DetectedFramework{
			{
				Name:       FrameworkTensorFlow,
				SourceFile: "train.py",
				Confidence: 0.9,
			},
		},
	}

	sarif, err := exporter.ExportDetectionResult(result)
	if err != nil {
		t.Fatalf("ExportDetectionResult failed: %v", err)
	}

	jsonData, err := sarif.ToJSON()
	if err != nil {
		t.Fatalf("ToJSON failed: %v", err)
	}

	// Verify it's valid JSON.
	var parsed SARIFReport
	if unmarshalErr := json.Unmarshal(jsonData, &parsed); unmarshalErr != nil {
		t.Fatalf("Invalid JSON: %v", unmarshalErr)
	}

	if parsed.Version != sarifVersion {
		t.Errorf("expected version %s, got %s", sarifVersion, parsed.Version)
	}
}

func TestSARIFReportWriteToFile(t *testing.T) {
	tmpDir := t.TempDir()
	exporter := DefaultSARIFExporter()

	result := &DetectionResult{
		Frameworks: []DetectedFramework{
			{
				Name:       FrameworkPyTorch,
				SourceFile: "model.py",
				Confidence: 0.85,
			},
		},
	}

	sarif, err := exporter.ExportDetectionResult(result)
	if err != nil {
		t.Fatalf("ExportDetectionResult failed: %v", err)
	}

	outputPath := filepath.Join(tmpDir, "report.sarif")
	if writeErr := sarif.WriteToFile(outputPath); writeErr != nil {
		t.Fatalf("WriteToFile failed: %v", writeErr)
	}

	// Read and verify.
	sp, spErr := safepath.New(tmpDir)
	if spErr != nil {
		t.Fatalf("create safepath: %v", spErr)
	}

	data, readErr := sp.ReadFile("report.sarif")
	if readErr != nil {
		t.Fatalf("read file: %v", readErr)
	}

	var parsed SARIFReport
	if unmarshalErr := json.Unmarshal(data, &parsed); unmarshalErr != nil {
		t.Fatalf("Invalid JSON: %v", unmarshalErr)
	}

	if len(parsed.Runs) != 1 || len(parsed.Runs[0].Results) != 1 {
		t.Error("expected 1 run with 1 result")
	}
}

func TestSplitPath(t *testing.T) {
	tests := []struct {
		path         string
		expectedDir  string
		expectedFile string
	}{
		{"/home/user/file.txt", "/home/user", "file.txt"},
		{"file.txt", ".", "file.txt"},
		{"/file.txt", "", "file.txt"},
		{"dir/file.txt", "dir", "file.txt"},
		{"dir\\file.txt", "dir", "file.txt"},
	}

	for _, tt := range tests {
		dir, file := splitPath(tt.path)
		if dir != tt.expectedDir {
			t.Errorf("splitPath(%q): expected dir %q, got %q", tt.path, tt.expectedDir, dir)
		}
		if file != tt.expectedFile {
			t.Errorf("splitPath(%q): expected file %q, got %q", tt.path, tt.expectedFile, file)
		}
	}
}

func TestSARIFRuleIDs(t *testing.T) {
	exporter := DefaultSARIFExporter()

	// Check detection rules.
	rules := exporter.createRules()
	ruleIDs := make(map[string]bool)
	for _, rule := range rules {
		if ruleIDs[rule.ID] {
			t.Errorf("duplicate rule ID: %s", rule.ID)
		}
		ruleIDs[rule.ID] = true
	}

	if !ruleIDs["ML001"] || !ruleIDs["ML002"] || !ruleIDs["ML003"] {
		t.Error("missing expected detection rule IDs")
	}

	// Check fairness rules.
	fairnessRules := exporter.createFairnessRules()
	for _, rule := range fairnessRules {
		if ruleIDs[rule.ID] {
			t.Errorf("duplicate rule ID: %s", rule.ID)
		}
		ruleIDs[rule.ID] = true
	}

	if !ruleIDs["FAIR001"] || !ruleIDs["FAIR002"] || !ruleIDs["FAIR003"] {
		t.Error("missing expected fairness rule IDs")
	}

	// Check bias rules.
	biasRules := exporter.createBiasRules()
	for _, rule := range biasRules {
		if ruleIDs[rule.ID] {
			t.Errorf("duplicate rule ID: %s", rule.ID)
		}
		ruleIDs[rule.ID] = true
	}

	if !ruleIDs["BIAS001"] || !ruleIDs["BIAS002"] || !ruleIDs["BIAS003"] || !ruleIDs["BIAS004"] {
		t.Error("missing expected bias rule IDs")
	}
}

func TestConvertDetectionResultsEmpty(t *testing.T) {
	exporter := DefaultSARIFExporter()

	result := &DetectionResult{
		Frameworks: []DetectedFramework{},
		Models:     []DetectedModel{},
	}

	sarif, err := exporter.ExportDetectionResult(result)
	if err != nil {
		t.Fatalf("ExportDetectionResult failed: %v", err)
	}

	if len(sarif.Runs[0].Results) != 0 {
		t.Errorf("expected 0 results, got %d", len(sarif.Runs[0].Results))
	}
}

func TestFairnessResultPassedThreshold(t *testing.T) {
	exporter := DefaultSARIFExporter()

	// Test with all metrics passing threshold.
	result := &FairnessResult{
		FairnessMetrics: []FairnessMetric{
			{
				Type:      MetricDisparateImpact,
				Value:     0.85,
				Threshold: 0.8,
				Passed:    true,
			},
		},
	}

	sarif, err := exporter.ExportFairnessResult(result)
	if err != nil {
		t.Fatalf("ExportFairnessResult failed: %v", err)
	}

	// Passed thresholds should not produce results.
	if len(sarif.Runs[0].Results) != 0 {
		t.Errorf("expected 0 results for passed thresholds, got %d", len(sarif.Runs[0].Results))
	}
}
