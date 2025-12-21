package ml

import (
	"bytes"
	"encoding/csv"
	"encoding/xml"
	"path/filepath"
	"strings"
	"testing"

	"github.com/victoralfred/gowritter/safepath"
)

func TestCSVExporterDetectionResult(t *testing.T) {
	exporter := NewCSVExporter()

	result := &DetectionResult{
		Frameworks: []DetectedFramework{
			{
				Name:         FrameworkTensorFlow,
				SourceFile:   "train.py",
				Confidence:   0.9,
				IsMLPipeline: true,
			},
		},
		Models: []DetectedModel{
			{
				Name:      "model.h5",
				Path:      "/path/to/model.h5",
				Type:      ModelTypeH5,
				Framework: FrameworkTensorFlow,
			},
		},
	}

	data, err := exporter.ExportDetectionResult(result)
	if err != nil {
		t.Fatalf("ExportDetectionResult failed: %v", err)
	}

	// Parse CSV and verify.
	r := csv.NewReader(strings.NewReader(string(data)))
	records, err := r.ReadAll()
	if err != nil {
		t.Fatalf("parse CSV failed: %v", err)
	}

	if len(records) != 3 { // Header + 1 framework + 1 model
		t.Errorf("expected 3 records, got %d", len(records))
	}

	// Check header.
	if records[0][0] != "Type" {
		t.Errorf("expected first header 'Type', got %s", records[0][0])
	}

	// Check framework row.
	if records[1][0] != "framework" {
		t.Errorf("expected type 'framework', got %s", records[1][0])
	}
}

func TestCSVExporterDetectionResultNil(t *testing.T) {
	exporter := NewCSVExporter()

	_, err := exporter.ExportDetectionResult(nil)
	if err == nil {
		t.Error("expected error for nil result")
	}
}

func TestCSVExporterFairnessResult(t *testing.T) {
	exporter := NewCSVExporter()

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

	data, err := exporter.ExportFairnessResult(result)
	if err != nil {
		t.Fatalf("ExportFairnessResult failed: %v", err)
	}

	if !strings.Contains(string(data), "disparate_impact") {
		t.Error("expected CSV to contain metric type")
	}
}

func TestCSVExporterFairnessResultNil(t *testing.T) {
	exporter := NewCSVExporter()

	_, err := exporter.ExportFairnessResult(nil)
	if err == nil {
		t.Error("expected error for nil result")
	}
}

func TestCSVExporterBiasReport(t *testing.T) {
	exporter := NewCSVExporter()

	report := &BiasReport{
		Indicators: []BiasIndicator{
			{
				Type:        BiasSelection,
				Attribute:   "gender",
				Description: "Selection bias detected",
				Severity:    "high",
				Score:       0.8,
			},
		},
	}

	data, err := exporter.ExportBiasReport(report)
	if err != nil {
		t.Fatalf("ExportBiasReport failed: %v", err)
	}

	if !strings.Contains(string(data), "selection") {
		t.Error("expected CSV to contain bias type")
	}
}

func TestCSVExporterBiasReportNil(t *testing.T) {
	exporter := NewCSVExporter()

	_, err := exporter.ExportBiasReport(nil)
	if err == nil {
		t.Error("expected error for nil report")
	}
}

func TestCSVExporterValidationResult(t *testing.T) {
	exporter := NewCSVExporter()

	result := &ValidationResult{
		SchemaName: "test-schema",
		Valid:      false,
		Errors: []ValidationError{
			{
				Row:     1,
				Column:  "age",
				Message: "value out of range",
				Code:    "RANGE_ERROR",
			},
		},
	}

	data, err := exporter.ExportValidationResult(result)
	if err != nil {
		t.Fatalf("ExportValidationResult failed: %v", err)
	}

	if !strings.Contains(string(data), "age") {
		t.Error("expected CSV to contain column name")
	}
}

func TestCSVExporterValidationResultNil(t *testing.T) {
	exporter := NewCSVExporter()

	_, err := exporter.ExportValidationResult(nil)
	if err == nil {
		t.Error("expected error for nil result")
	}
}

func TestHTMLExporterDetectionResult(t *testing.T) {
	exporter := NewHTMLExporter("ML Detection Report")

	result := &DetectionResult{
		Frameworks: []DetectedFramework{
			{
				Name:         FrameworkPyTorch,
				SourceFile:   "model.py",
				Confidence:   0.85,
				IsMLPipeline: false,
			},
		},
	}

	data, err := exporter.ExportDetectionResult(result)
	if err != nil {
		t.Fatalf("ExportDetectionResult failed: %v", err)
	}

	html := string(data)
	if !strings.Contains(html, "<!DOCTYPE html>") {
		t.Error("expected valid HTML doctype")
	}
	if !strings.Contains(html, "ML Detection Report") {
		t.Error("expected title in HTML")
	}
	if !strings.Contains(html, "pytorch") {
		t.Error("expected framework name in HTML")
	}
}

func TestHTMLExporterDetectionResultNil(t *testing.T) {
	exporter := NewHTMLExporter("Test")

	_, err := exporter.ExportDetectionResult(nil)
	if err == nil {
		t.Error("expected error for nil result")
	}
}

func TestHTMLExporterFairnessResult(t *testing.T) {
	exporter := NewHTMLExporter("Fairness Report")

	result := &FairnessResult{
		FairnessMetrics: []FairnessMetric{
			{
				Type:      MetricStatisticalParity,
				Value:     0.05,
				Threshold: 0.1,
				Passed:    true,
			},
		},
	}

	data, err := exporter.ExportFairnessResult(result)
	if err != nil {
		t.Fatalf("ExportFairnessResult failed: %v", err)
	}

	html := string(data)
	if !strings.Contains(html, "Fairness Report") {
		t.Error("expected title in HTML")
	}
	if !strings.Contains(html, "PASS") {
		t.Error("expected PASS status in HTML")
	}
}

func TestHTMLExporterFairnessResultNil(t *testing.T) {
	exporter := NewHTMLExporter("Test")

	_, err := exporter.ExportFairnessResult(nil)
	if err == nil {
		t.Error("expected error for nil result")
	}
}

func TestHTMLExporterBiasReport(t *testing.T) {
	exporter := NewHTMLExporter("Bias Report")

	report := &BiasReport{
		Indicators: []BiasIndicator{
			{
				Type:        BiasSampling,
				Attribute:   "age",
				Description: "Undersampling of elderly",
				Severity:    "medium",
				Score:       0.6,
			},
		},
	}

	data, err := exporter.ExportBiasReport(report)
	if err != nil {
		t.Fatalf("ExportBiasReport failed: %v", err)
	}

	html := string(data)
	if !strings.Contains(html, "Bias Report") {
		t.Error("expected title in HTML")
	}
	if !strings.Contains(html, "sampling") {
		t.Error("expected bias type in HTML")
	}
}

func TestHTMLExporterBiasReportNil(t *testing.T) {
	exporter := NewHTMLExporter("Test")

	_, err := exporter.ExportBiasReport(nil)
	if err == nil {
		t.Error("expected error for nil report")
	}
}

func TestJUnitExporterDetectionResult(t *testing.T) {
	exporter := NewJUnitExporter("ML Detection")

	result := &DetectionResult{
		Frameworks: []DetectedFramework{
			{
				Name:       FrameworkTensorFlow,
				SourceFile: "train.py",
				Confidence: 0.9,
			},
		},
		Models: []DetectedModel{
			{
				Name: "model.onnx",
				Path: "/path/model.onnx",
				Type: ModelTypeONNX,
			},
		},
	}

	data, err := exporter.ExportDetectionResult(result)
	if err != nil {
		t.Fatalf("ExportDetectionResult failed: %v", err)
	}

	// Verify XML structure.
	var suites JUnitTestSuites
	if unmarshalErr := xml.Unmarshal(data, &suites); unmarshalErr != nil {
		t.Fatalf("invalid XML: %v", unmarshalErr)
	}

	if len(suites.Suites) != 1 {
		t.Errorf("expected 1 suite, got %d", len(suites.Suites))
	}

	suite := suites.Suites[0]
	if suite.Tests != 2 { // 1 framework + 1 model
		t.Errorf("expected 2 tests, got %d", suite.Tests)
	}
	if suite.Failures != 0 {
		t.Errorf("expected 0 failures, got %d", suite.Failures)
	}
}

func TestJUnitExporterDetectionResultNil(t *testing.T) {
	exporter := NewJUnitExporter("Test")

	_, err := exporter.ExportDetectionResult(nil)
	if err == nil {
		t.Error("expected error for nil result")
	}
}

func TestJUnitExporterFairnessResult(t *testing.T) {
	exporter := NewJUnitExporter("Fairness Tests")

	result := &FairnessResult{
		FairnessMetrics: []FairnessMetric{
			{
				Type:      MetricDisparateImpact,
				Value:     0.85,
				Threshold: 0.8,
				Passed:    true,
			},
			{
				Type:      MetricStatisticalParity,
				Value:     0.15,
				Threshold: 0.1,
				Passed:    false,
			},
		},
	}

	data, err := exporter.ExportFairnessResult(result)
	if err != nil {
		t.Fatalf("ExportFairnessResult failed: %v", err)
	}

	var suites JUnitTestSuites
	if unmarshalErr := xml.Unmarshal(data, &suites); unmarshalErr != nil {
		t.Fatalf("invalid XML: %v", unmarshalErr)
	}

	suite := suites.Suites[0]
	if suite.Tests != 2 {
		t.Errorf("expected 2 tests, got %d", suite.Tests)
	}
	if suite.Failures != 1 {
		t.Errorf("expected 1 failure, got %d", suite.Failures)
	}
}

func TestJUnitExporterFairnessResultNil(t *testing.T) {
	exporter := NewJUnitExporter("Test")

	_, err := exporter.ExportFairnessResult(nil)
	if err == nil {
		t.Error("expected error for nil result")
	}
}

func TestJUnitExporterBiasReport(t *testing.T) {
	exporter := NewJUnitExporter("Bias Tests")

	report := &BiasReport{
		Indicators: []BiasIndicator{
			{
				Type:        BiasSelection,
				Attribute:   "gender",
				Description: "Selection bias",
				Severity:    "high",
				Score:       0.8,
			},
			{
				Type:        BiasSampling,
				Attribute:   "age",
				Description: "Minor sampling issue",
				Severity:    "low",
				Score:       0.2,
			},
		},
	}

	data, err := exporter.ExportBiasReport(report)
	if err != nil {
		t.Fatalf("ExportBiasReport failed: %v", err)
	}

	var suites JUnitTestSuites
	if unmarshalErr := xml.Unmarshal(data, &suites); unmarshalErr != nil {
		t.Fatalf("invalid XML: %v", unmarshalErr)
	}

	suite := suites.Suites[0]
	if suite.Tests != 2 {
		t.Errorf("expected 2 tests, got %d", suite.Tests)
	}
	if suite.Failures != 1 { // Only high severity counts as failure
		t.Errorf("expected 1 failure, got %d", suite.Failures)
	}
}

func TestJUnitExporterBiasReportNil(t *testing.T) {
	exporter := NewJUnitExporter("Test")

	_, err := exporter.ExportBiasReport(nil)
	if err == nil {
		t.Error("expected error for nil report")
	}
}

func TestWriteCSV(t *testing.T) {
	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "output.csv")

	data := []byte("col1,col2\nval1,val2\n")
	if err := WriteCSV(outputPath, data); err != nil {
		t.Fatalf("WriteCSV failed: %v", err)
	}

	sp, err := safepath.New(tmpDir)
	if err != nil {
		t.Fatalf("create safepath: %v", err)
	}

	content, err := sp.ReadFile("output.csv")
	if err != nil {
		t.Fatalf("read file: %v", err)
	}

	if !bytes.Equal(content, data) {
		t.Errorf("content mismatch: got %s", string(content))
	}
}

func TestWriteHTML(t *testing.T) {
	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "output.html")

	data := []byte("<html><body>Test</body></html>")
	if err := WriteHTML(outputPath, data); err != nil {
		t.Fatalf("WriteHTML failed: %v", err)
	}

	sp, err := safepath.New(tmpDir)
	if err != nil {
		t.Fatalf("create safepath: %v", err)
	}

	content, err := sp.ReadFile("output.html")
	if err != nil {
		t.Fatalf("read file: %v", err)
	}

	if !bytes.Equal(content, data) {
		t.Errorf("content mismatch: got %s", string(content))
	}
}

func TestWriteJUnit(t *testing.T) {
	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "output.xml")

	data := []byte("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<testsuites></testsuites>")
	if err := WriteJUnit(outputPath, data); err != nil {
		t.Fatalf("WriteJUnit failed: %v", err)
	}

	sp, err := safepath.New(tmpDir)
	if err != nil {
		t.Fatalf("create safepath: %v", err)
	}

	content, err := sp.ReadFile("output.xml")
	if err != nil {
		t.Fatalf("read file: %v", err)
	}

	if !bytes.Equal(content, data) {
		t.Errorf("content mismatch: got %s", string(content))
	}
}

func TestJUnitXMLHeader(t *testing.T) {
	exporter := NewJUnitExporter("Test")

	result := &DetectionResult{
		Frameworks: []DetectedFramework{},
		Models:     []DetectedModel{},
	}

	data, err := exporter.ExportDetectionResult(result)
	if err != nil {
		t.Fatalf("ExportDetectionResult failed: %v", err)
	}

	if !strings.HasPrefix(string(data), "<?xml") {
		t.Error("expected XML header")
	}
}
