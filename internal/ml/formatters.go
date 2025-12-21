// Package ml provides ML-specific validation and detection capabilities.
package ml

import (
	"encoding/csv"
	"encoding/xml"
	"fmt"
	"html/template"
	"strings"
	"time"

	"github.com/victoralfred/gowritter/safepath"
)

// CSVExporter exports results to CSV format.
type CSVExporter struct{}

// NewCSVExporter creates a new CSV exporter.
func NewCSVExporter() *CSVExporter {
	return &CSVExporter{}
}

// ExportDetectionResult exports detection results to CSV.
func (e *CSVExporter) ExportDetectionResult(result *DetectionResult) ([]byte, error) {
	if result == nil {
		return nil, ErrEmptyData
	}

	var sb strings.Builder
	w := csv.NewWriter(&sb)

	// Write frameworks header and data.
	if err := w.Write([]string{"Type", "Name", "SourceFile", "Confidence", "IsMLPipeline"}); err != nil {
		return nil, fmt.Errorf("write header: %w", err)
	}

	for _, fw := range result.Frameworks {
		record := []string{
			"framework",
			string(fw.Name),
			fw.SourceFile,
			fmt.Sprintf("%.2f", fw.Confidence),
			fmt.Sprintf("%t", fw.IsMLPipeline),
		}
		if err := w.Write(record); err != nil {
			return nil, fmt.Errorf("write framework: %w", err)
		}
	}

	// Write models.
	for _, m := range result.Models {
		record := []string{
			"model",
			m.Name,
			m.Path,
			"1.00",
			"false",
		}
		if err := w.Write(record); err != nil {
			return nil, fmt.Errorf("write model: %w", err)
		}
	}

	w.Flush()
	if err := w.Error(); err != nil {
		return nil, fmt.Errorf("flush csv: %w", err)
	}

	return []byte(sb.String()), nil
}

// ExportFairnessResult exports fairness results to CSV.
func (e *CSVExporter) ExportFairnessResult(result *FairnessResult) ([]byte, error) {
	if result == nil {
		return nil, ErrEmptyData
	}

	var sb strings.Builder
	w := csv.NewWriter(&sb)

	// Write header.
	if err := w.Write([]string{"MetricType", "Value", "Threshold", "Passed"}); err != nil {
		return nil, fmt.Errorf("write header: %w", err)
	}

	for _, m := range result.FairnessMetrics {
		record := []string{
			string(m.Type),
			fmt.Sprintf("%.4f", m.Value),
			fmt.Sprintf("%.4f", m.Threshold),
			fmt.Sprintf("%t", m.Passed),
		}
		if err := w.Write(record); err != nil {
			return nil, fmt.Errorf("write metric: %w", err)
		}
	}

	w.Flush()
	if err := w.Error(); err != nil {
		return nil, fmt.Errorf("flush csv: %w", err)
	}

	return []byte(sb.String()), nil
}

// ExportBiasReport exports bias report to CSV.
func (e *CSVExporter) ExportBiasReport(report *BiasReport) ([]byte, error) {
	if report == nil {
		return nil, ErrEmptyData
	}

	var sb strings.Builder
	w := csv.NewWriter(&sb)

	// Write header.
	if err := w.Write([]string{"BiasType", "Attribute", "Description", "Severity", "Score"}); err != nil {
		return nil, fmt.Errorf("write header: %w", err)
	}

	for _, ind := range report.Indicators {
		record := []string{
			string(ind.Type),
			ind.Attribute,
			ind.Description,
			ind.Severity,
			fmt.Sprintf("%.4f", ind.Score),
		}
		if err := w.Write(record); err != nil {
			return nil, fmt.Errorf("write indicator: %w", err)
		}
	}

	w.Flush()
	if err := w.Error(); err != nil {
		return nil, fmt.Errorf("flush csv: %w", err)
	}

	return []byte(sb.String()), nil
}

// ExportValidationResult exports validation results to CSV.
func (e *CSVExporter) ExportValidationResult(result *ValidationResult) ([]byte, error) {
	if result == nil {
		return nil, ErrEmptyData
	}

	var sb strings.Builder
	w := csv.NewWriter(&sb)

	// Write header.
	if err := w.Write([]string{"Row", "Column", "Message", "Code"}); err != nil {
		return nil, fmt.Errorf("write header: %w", err)
	}

	for _, ve := range result.Errors {
		record := []string{
			fmt.Sprintf("%d", ve.Row),
			ve.Column,
			ve.Message,
			ve.Code,
		}
		if writeErr := w.Write(record); writeErr != nil {
			return nil, fmt.Errorf("write error: %w", writeErr)
		}
	}

	w.Flush()
	if err := w.Error(); err != nil {
		return nil, fmt.Errorf("flush csv: %w", err)
	}

	return []byte(sb.String()), nil
}

// HTMLExporter exports results to HTML format.
type HTMLExporter struct {
	Title string
}

// NewHTMLExporter creates a new HTML exporter.
func NewHTMLExporter(title string) *HTMLExporter {
	return &HTMLExporter{Title: title}
}

const detectionHTMLTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{.Title}}</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 40px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        h1 { color: #333; border-bottom: 2px solid #4a90d9; padding-bottom: 10px; }
        h2 { color: #555; margin-top: 30px; }
        table { width: 100%; border-collapse: collapse; margin-top: 15px; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background: #4a90d9; color: white; }
        tr:hover { background: #f9f9f9; }
        .badge { padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: bold; }
        .badge-high { background: #ff6b6b; color: white; }
        .badge-medium { background: #ffd93d; color: #333; }
        .badge-low { background: #6bcb77; color: white; }
        .timestamp { color: #888; font-size: 12px; margin-top: 20px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>{{.Title}}</h1>
        {{if .Frameworks}}
        <h2>Detected Frameworks</h2>
        <table>
            <thead>
                <tr><th>Framework</th><th>Source File</th><th>Confidence</th><th>ML Pipeline</th></tr>
            </thead>
            <tbody>
                {{range .Frameworks}}
                <tr>
                    <td>{{.Name}}</td>
                    <td>{{.SourceFile}}</td>
                    <td>{{printf "%.0f" (mul .Confidence 100)}}%</td>
                    <td>{{if .IsMLPipeline}}Yes{{else}}No{{end}}</td>
                </tr>
                {{end}}
            </tbody>
        </table>
        {{end}}
        {{if .Models}}
        <h2>Detected Models</h2>
        <table>
            <thead>
                <tr><th>Name</th><th>Path</th><th>Type</th><th>Framework</th></tr>
            </thead>
            <tbody>
                {{range .Models}}
                <tr>
                    <td>{{.Name}}</td>
                    <td>{{.Path}}</td>
                    <td>{{.Type}}</td>
                    <td>{{.Framework}}</td>
                </tr>
                {{end}}
            </tbody>
        </table>
        {{end}}
        <p class="timestamp">Generated: {{.Timestamp}}</p>
    </div>
</body>
</html>`

const fairnessHTMLTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{.Title}}</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 40px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        h1 { color: #333; border-bottom: 2px solid #4a90d9; padding-bottom: 10px; }
        table { width: 100%; border-collapse: collapse; margin-top: 15px; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background: #4a90d9; color: white; }
        tr:hover { background: #f9f9f9; }
        .pass { color: #6bcb77; font-weight: bold; }
        .fail { color: #ff6b6b; font-weight: bold; }
        .timestamp { color: #888; font-size: 12px; margin-top: 20px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>{{.Title}}</h1>
        <h2>Fairness Metrics</h2>
        <table>
            <thead>
                <tr><th>Metric</th><th>Value</th><th>Threshold</th><th>Status</th></tr>
            </thead>
            <tbody>
                {{range .Metrics}}
                <tr>
                    <td>{{.Type}}</td>
                    <td>{{printf "%.4f" .Value}}</td>
                    <td>{{printf "%.4f" .Threshold}}</td>
                    <td class="{{if .Passed}}pass{{else}}fail{{end}}">{{if .Passed}}PASS{{else}}FAIL{{end}}</td>
                </tr>
                {{end}}
            </tbody>
        </table>
        <p class="timestamp">Generated: {{.Timestamp}}</p>
    </div>
</body>
</html>`

const biasHTMLTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{.Title}}</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 40px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        h1 { color: #333; border-bottom: 2px solid #4a90d9; padding-bottom: 10px; }
        table { width: 100%; border-collapse: collapse; margin-top: 15px; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background: #4a90d9; color: white; }
        tr:hover { background: #f9f9f9; }
        .severity-high { background: #ff6b6b; color: white; padding: 4px 8px; border-radius: 4px; }
        .severity-medium { background: #ffd93d; color: #333; padding: 4px 8px; border-radius: 4px; }
        .severity-low { background: #6bcb77; color: white; padding: 4px 8px; border-radius: 4px; }
        .timestamp { color: #888; font-size: 12px; margin-top: 20px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>{{.Title}}</h1>
        <h2>Bias Indicators</h2>
        <table>
            <thead>
                <tr><th>Type</th><th>Attribute</th><th>Description</th><th>Severity</th><th>Score</th></tr>
            </thead>
            <tbody>
                {{range .Indicators}}
                <tr>
                    <td>{{.Type}}</td>
                    <td>{{.Attribute}}</td>
                    <td>{{.Description}}</td>
                    <td><span class="severity-{{.Severity}}">{{.Severity}}</span></td>
                    <td>{{printf "%.2f" .Score}}</td>
                </tr>
                {{end}}
            </tbody>
        </table>
        <p class="timestamp">Generated: {{.Timestamp}}</p>
    </div>
</body>
</html>`

// ExportDetectionResult exports detection results to HTML.
func (e *HTMLExporter) ExportDetectionResult(result *DetectionResult) ([]byte, error) {
	if result == nil {
		return nil, ErrEmptyData
	}

	funcMap := template.FuncMap{
		"mul": func(a, b float64) float64 { return a * b },
	}

	tmpl, err := template.New("detection").Funcs(funcMap).Parse(detectionHTMLTemplate)
	if err != nil {
		return nil, fmt.Errorf("parse template: %w", err)
	}

	//nolint:govet // Anonymous struct for template rendering.
	data := struct {
		Frameworks []DetectedFramework
		Models     []DetectedModel
		Title      string
		Timestamp  string
	}{
		Title:      e.Title,
		Frameworks: result.Frameworks,
		Models:     result.Models,
		Timestamp:  time.Now().Format(time.RFC3339),
	}

	var sb strings.Builder
	if err := tmpl.Execute(&sb, data); err != nil {
		return nil, fmt.Errorf("execute template: %w", err)
	}

	return []byte(sb.String()), nil
}

// ExportFairnessResult exports fairness results to HTML.
func (e *HTMLExporter) ExportFairnessResult(result *FairnessResult) ([]byte, error) {
	if result == nil {
		return nil, ErrEmptyData
	}

	tmpl, err := template.New("fairness").Parse(fairnessHTMLTemplate)
	if err != nil {
		return nil, fmt.Errorf("parse template: %w", err)
	}

	//nolint:govet // Anonymous struct for template rendering.
	data := struct {
		Metrics   []FairnessMetric
		Title     string
		Timestamp string
	}{
		Title:     e.Title,
		Metrics:   result.FairnessMetrics,
		Timestamp: time.Now().Format(time.RFC3339),
	}

	var sb strings.Builder
	if err := tmpl.Execute(&sb, data); err != nil {
		return nil, fmt.Errorf("execute template: %w", err)
	}

	return []byte(sb.String()), nil
}

// ExportBiasReport exports bias report to HTML.
func (e *HTMLExporter) ExportBiasReport(report *BiasReport) ([]byte, error) {
	if report == nil {
		return nil, ErrEmptyData
	}

	tmpl, err := template.New("bias").Parse(biasHTMLTemplate)
	if err != nil {
		return nil, fmt.Errorf("parse template: %w", err)
	}

	//nolint:govet // Anonymous struct for template rendering.
	data := struct {
		Indicators []BiasIndicator
		Title      string
		Timestamp  string
	}{
		Title:      e.Title,
		Indicators: report.Indicators,
		Timestamp:  time.Now().Format(time.RFC3339),
	}

	var sb strings.Builder
	if err := tmpl.Execute(&sb, data); err != nil {
		return nil, fmt.Errorf("execute template: %w", err)
	}

	return []byte(sb.String()), nil
}

// JUnitExporter exports results to JUnit XML format.
type JUnitExporter struct {
	SuiteName string
}

// NewJUnitExporter creates a new JUnit exporter.
func NewJUnitExporter(suiteName string) *JUnitExporter {
	return &JUnitExporter{SuiteName: suiteName}
}

// JUnitTestSuites represents JUnit test suites.
type JUnitTestSuites struct {
	XMLName xml.Name         `xml:"testsuites"`
	Suites  []JUnitTestSuite `xml:"testsuite"`
}

// JUnitTestSuite represents a JUnit test suite.
//
//nolint:govet // Field order matches JUnit XML spec for readability.
type JUnitTestSuite struct {
	XMLName   xml.Name        `xml:"testsuite"`
	TestCases []JUnitTestCase `xml:"testcase"`
	Name      string          `xml:"name,attr"`
	Timestamp string          `xml:"timestamp,attr"`
	Time      float64         `xml:"time,attr"`
	Tests     int             `xml:"tests,attr"`
	Failures  int             `xml:"failures,attr"`
	Errors    int             `xml:"errors,attr"`
}

// JUnitTestCase represents a JUnit test case.
type JUnitTestCase struct {
	XMLName   xml.Name      `xml:"testcase"`
	Failure   *JUnitFailure `xml:"failure,omitempty"`
	Name      string        `xml:"name,attr"`
	ClassName string        `xml:"classname,attr"`
	Time      float64       `xml:"time,attr"`
}

// JUnitFailure represents a JUnit failure.
type JUnitFailure struct {
	Message string `xml:"message,attr"`
	Type    string `xml:"type,attr"`
	Content string `xml:",chardata"`
}

// ExportDetectionResult exports detection results to JUnit XML.
func (e *JUnitExporter) ExportDetectionResult(result *DetectionResult) ([]byte, error) {
	if result == nil {
		return nil, ErrEmptyData
	}

	testCases := make([]JUnitTestCase, 0, len(result.Frameworks)+len(result.Models))

	// Each framework detection is a test case.
	for _, fw := range result.Frameworks {
		tc := JUnitTestCase{
			Name:      fmt.Sprintf("Framework: %s", fw.Name),
			ClassName: "ml.detection.framework",
			Time:      0.001,
		}
		testCases = append(testCases, tc)
	}

	// Each model detection is a test case.
	for _, m := range result.Models {
		tc := JUnitTestCase{
			Name:      fmt.Sprintf("Model: %s", m.Name),
			ClassName: "ml.detection.model",
			Time:      0.001,
		}
		testCases = append(testCases, tc)
	}

	suite := JUnitTestSuite{
		Name:      e.SuiteName,
		Tests:     len(testCases),
		Failures:  0,
		Errors:    0,
		Time:      0.01,
		Timestamp: time.Now().Format(time.RFC3339),
		TestCases: testCases,
	}

	suites := JUnitTestSuites{
		Suites: []JUnitTestSuite{suite},
	}

	data, err := xml.MarshalIndent(suites, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal xml: %w", err)
	}

	return append([]byte(xml.Header), data...), nil
}

// ExportFairnessResult exports fairness results to JUnit XML.
func (e *JUnitExporter) ExportFairnessResult(result *FairnessResult) ([]byte, error) {
	if result == nil {
		return nil, ErrEmptyData
	}

	testCases := make([]JUnitTestCase, 0, len(result.FairnessMetrics))
	failures := 0

	for _, m := range result.FairnessMetrics {
		tc := JUnitTestCase{
			Name:      fmt.Sprintf("Fairness: %s", m.Type),
			ClassName: "ml.fairness.metric",
			Time:      0.001,
		}
		if !m.Passed {
			failures++
			tc.Failure = &JUnitFailure{
				Message: fmt.Sprintf("Metric %s failed: value %.4f, threshold %.4f", m.Type, m.Value, m.Threshold),
				Type:    "FairnessViolation",
				Content: fmt.Sprintf("Value: %.4f\nThreshold: %.4f", m.Value, m.Threshold),
			}
		}
		testCases = append(testCases, tc)
	}

	suite := JUnitTestSuite{
		Name:      e.SuiteName,
		Tests:     len(testCases),
		Failures:  failures,
		Errors:    0,
		Time:      0.01,
		Timestamp: time.Now().Format(time.RFC3339),
		TestCases: testCases,
	}

	suites := JUnitTestSuites{
		Suites: []JUnitTestSuite{suite},
	}

	data, err := xml.MarshalIndent(suites, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal xml: %w", err)
	}

	return append([]byte(xml.Header), data...), nil
}

// ExportBiasReport exports bias report to JUnit XML.
func (e *JUnitExporter) ExportBiasReport(report *BiasReport) ([]byte, error) {
	if report == nil {
		return nil, ErrEmptyData
	}

	testCases := make([]JUnitTestCase, 0, len(report.Indicators))
	failures := 0

	for _, ind := range report.Indicators {
		tc := JUnitTestCase{
			Name:      fmt.Sprintf("Bias: %s - %s", ind.Type, ind.Attribute),
			ClassName: "ml.bias.indicator",
			Time:      0.001,
		}
		if ind.Severity == "high" {
			failures++
			tc.Failure = &JUnitFailure{
				Message: ind.Description,
				Type:    string(ind.Type),
				Content: fmt.Sprintf("Attribute: %s\nScore: %.4f\nSeverity: %s", ind.Attribute, ind.Score, ind.Severity),
			}
		}
		testCases = append(testCases, tc)
	}

	suite := JUnitTestSuite{
		Name:      e.SuiteName,
		Tests:     len(testCases),
		Failures:  failures,
		Errors:    0,
		Time:      0.01,
		Timestamp: time.Now().Format(time.RFC3339),
		TestCases: testCases,
	}

	suites := JUnitTestSuites{
		Suites: []JUnitTestSuite{suite},
	}

	data, err := xml.MarshalIndent(suites, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal xml: %w", err)
	}

	return append([]byte(xml.Header), data...), nil
}

// WriteCSV writes CSV data to a file.
func WriteCSV(path string, data []byte) error {
	dir, file := splitPath(path)
	sp, err := safepath.New(dir)
	if err != nil {
		return fmt.Errorf("create safepath: %w", err)
	}
	return sp.WriteFile(file, data, 0o644)
}

// WriteHTML writes HTML data to a file.
func WriteHTML(path string, data []byte) error {
	dir, file := splitPath(path)
	sp, err := safepath.New(dir)
	if err != nil {
		return fmt.Errorf("create safepath: %w", err)
	}
	return sp.WriteFile(file, data, 0o644)
}

// WriteJUnit writes JUnit XML data to a file.
func WriteJUnit(path string, data []byte) error {
	dir, file := splitPath(path)
	sp, err := safepath.New(dir)
	if err != nil {
		return fmt.Errorf("create safepath: %w", err)
	}
	return sp.WriteFile(file, data, 0o644)
}
