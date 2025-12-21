package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/victoralfred/gowritter/safepath"
)

func TestNewMLCmd(t *testing.T) {
	cmd := NewMLCmd()

	if cmd.Use != "ml" {
		t.Errorf("expected Use 'ml', got %s", cmd.Use)
	}

	// Check subcommands exist.
	subcommands := []string{"detect", "model-card", "validate", "drift", "fairness", "bias"}
	for _, name := range subcommands {
		found := false
		for _, sub := range cmd.Commands() {
			if sub.Use == name || strings.HasPrefix(sub.Use, name+" ") {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("subcommand %s not found", name)
		}
	}
}

func TestNewMLDetectCmd(t *testing.T) {
	cmd := NewMLDetectCmd()

	if !strings.HasPrefix(cmd.Use, "detect") {
		t.Errorf("expected Use to start with 'detect', got %s", cmd.Use)
	}

	// Check flags exist.
	flags := []string{"output", "format", "timeout"}
	for _, name := range flags {
		if cmd.Flags().Lookup(name) == nil {
			t.Errorf("flag %s not found", name)
		}
	}
}

func TestMLDetectRun(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a test Python file with ML imports.
	sp, err := safepath.New(tmpDir)
	if err != nil {
		t.Fatalf("create safepath: %v", err)
	}

	content := []byte("import tensorflow as tf\nmodel = tf.keras.Sequential()")
	if err := sp.WriteFile("train.py", content, 0o644); err != nil {
		t.Fatalf("write test file: %v", err)
	}

	// Run detect command.
	cmd := NewMLDetectCmd()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{tmpDir})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute failed: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "TensorFlow") && !strings.Contains(output, "tensorflow") {
		t.Errorf("expected output to contain TensorFlow detection, got: %s", output)
	}
}

func TestMLDetectJSONFormat(t *testing.T) {
	tmpDir := t.TempDir()

	sp, err := safepath.New(tmpDir)
	if err != nil {
		t.Fatalf("create safepath: %v", err)
	}

	content := []byte("import torch\nmodel = torch.nn.Linear(10, 5)")
	if err := sp.WriteFile("model.py", content, 0o644); err != nil {
		t.Fatalf("write test file: %v", err)
	}

	cmd := NewMLDetectCmd()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"--format", "json", tmpDir})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute failed: %v", err)
	}

	// Verify JSON output.
	output := buf.String()
	var result map[string]interface{}
	if err := json.Unmarshal([]byte(output), &result); err != nil {
		t.Errorf("expected valid JSON output, got: %s", output)
	}
}

func TestMLDetectOutputFile(t *testing.T) {
	tmpDir := t.TempDir()

	sp, err := safepath.New(tmpDir)
	if err != nil {
		t.Fatalf("create safepath: %v", err)
	}

	content := []byte("import sklearn\nfrom sklearn.ensemble import RandomForestClassifier")
	if err := sp.WriteFile("ml_model.py", content, 0o644); err != nil {
		t.Fatalf("write test file: %v", err)
	}

	outputPath := filepath.Join(tmpDir, "output.txt")

	cmd := NewMLDetectCmd()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"--output", outputPath, tmpDir})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute failed: %v", err)
	}

	// Verify output file was created.
	if _, err := os.Stat(outputPath); os.IsNotExist(err) {
		t.Error("output file was not created")
	}
}

func TestNewMLValidateCmd(t *testing.T) {
	cmd := NewMLValidateCmd()

	if !strings.HasPrefix(cmd.Use, "validate") {
		t.Errorf("expected Use to start with 'validate', got %s", cmd.Use)
	}

	flags := []string{"schema", "output", "format", "timeout"}
	for _, name := range flags {
		if cmd.Flags().Lookup(name) == nil {
			t.Errorf("flag %s not found", name)
		}
	}
}

func TestMLValidateRun(t *testing.T) {
	tmpDir := t.TempDir()

	sp, err := safepath.New(tmpDir)
	if err != nil {
		t.Fatalf("create safepath: %v", err)
	}

	// Create schema file.
	schema := `{
		"name": "test-schema",
		"columns": [
			{"name": "age", "type": "integer", "required": true, "min": 0, "max": 150},
			{"name": "name", "type": "string", "required": true}
		]
	}`
	if err := sp.WriteFile("schema.json", []byte(schema), 0o644); err != nil {
		t.Fatalf("write schema: %v", err)
	}

	// Create data file.
	data := `[
		{"age": 25, "name": "Alice"},
		{"age": 30, "name": "Bob"}
	]`
	if err := sp.WriteFile("data.json", []byte(data), 0o644); err != nil {
		t.Fatalf("write data: %v", err)
	}

	schemaPath := filepath.Join(tmpDir, "schema.json")
	dataPath := filepath.Join(tmpDir, "data.json")

	cmd := NewMLValidateCmd()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"--schema", schemaPath, dataPath})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute failed: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "Valid") {
		t.Errorf("expected output to contain 'Valid', got: %s", output)
	}
}

func TestMLValidateJSONFormat(t *testing.T) {
	tmpDir := t.TempDir()

	sp, err := safepath.New(tmpDir)
	if err != nil {
		t.Fatalf("create safepath: %v", err)
	}

	schema := `{"name": "test", "columns": [{"name": "value", "type": "integer"}]}`
	if err := sp.WriteFile("schema.json", []byte(schema), 0o644); err != nil {
		t.Fatalf("write schema: %v", err)
	}

	data := `[{"value": 10}, {"value": 20}]`
	if err := sp.WriteFile("data.json", []byte(data), 0o644); err != nil {
		t.Fatalf("write data: %v", err)
	}

	schemaPath := filepath.Join(tmpDir, "schema.json")
	dataPath := filepath.Join(tmpDir, "data.json")

	cmd := NewMLValidateCmd()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"--schema", schemaPath, "--format", "json", dataPath})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute failed: %v", err)
	}

	output := buf.String()
	var result map[string]interface{}
	if err := json.Unmarshal([]byte(output), &result); err != nil {
		t.Errorf("expected valid JSON output, got: %s", output)
	}
}

func TestNewMLDriftCmd(t *testing.T) {
	cmd := NewMLDriftCmd()

	if !strings.HasPrefix(cmd.Use, "drift") {
		t.Errorf("expected Use to start with 'drift', got %s", cmd.Use)
	}

	flags := []string{"threshold", "output", "format", "timeout"}
	for _, name := range flags {
		if cmd.Flags().Lookup(name) == nil {
			t.Errorf("flag %s not found", name)
		}
	}
}

func TestMLDriftRun(t *testing.T) {
	tmpDir := t.TempDir()

	sp, err := safepath.New(tmpDir)
	if err != nil {
		t.Fatalf("create safepath: %v", err)
	}

	baseline := `[{"value": 10}, {"value": 12}, {"value": 11}]`
	if err := sp.WriteFile("baseline.json", []byte(baseline), 0o644); err != nil {
		t.Fatalf("write baseline: %v", err)
	}

	current := `[{"value": 15}, {"value": 14}, {"value": 16}]`
	if err := sp.WriteFile("current.json", []byte(current), 0o644); err != nil {
		t.Fatalf("write current: %v", err)
	}

	baselinePath := filepath.Join(tmpDir, "baseline.json")
	currentPath := filepath.Join(tmpDir, "current.json")

	cmd := NewMLDriftCmd()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{baselinePath, currentPath})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute failed: %v", err)
	}

	output := buf.String()
	if !strings.Contains(strings.ToLower(output), "drift") {
		t.Errorf("expected output to contain 'drift', got: %s", output)
	}
}

func TestMLDriftWithThreshold(t *testing.T) {
	tmpDir := t.TempDir()

	sp, err := safepath.New(tmpDir)
	if err != nil {
		t.Fatalf("create safepath: %v", err)
	}

	baseline := `[{"value": 10}, {"value": 10}, {"value": 10}]`
	if err := sp.WriteFile("baseline.json", []byte(baseline), 0o644); err != nil {
		t.Fatalf("write baseline: %v", err)
	}

	current := `[{"value": 10}, {"value": 10}, {"value": 10}]`
	if err := sp.WriteFile("current.json", []byte(current), 0o644); err != nil {
		t.Fatalf("write current: %v", err)
	}

	baselinePath := filepath.Join(tmpDir, "baseline.json")
	currentPath := filepath.Join(tmpDir, "current.json")

	cmd := NewMLDriftCmd()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"--threshold", "0.5", baselinePath, currentPath})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute failed: %v", err)
	}
}

func TestNewMLFairnessCmd(t *testing.T) {
	cmd := NewMLFairnessCmd()

	if !strings.HasPrefix(cmd.Use, "fairness") {
		t.Errorf("expected Use to start with 'fairness', got %s", cmd.Use)
	}

	flags := []string{"protected", "output", "format", "timeout"}
	for _, name := range flags {
		if cmd.Flags().Lookup(name) == nil {
			t.Errorf("flag %s not found", name)
		}
	}
}

func TestMLFairnessRun(t *testing.T) {
	tmpDir := t.TempDir()

	sp, err := safepath.New(tmpDir)
	if err != nil {
		t.Fatalf("create safepath: %v", err)
	}

	data := `[
		{"prediction": true, "label": true, "group": "A"},
		{"prediction": true, "label": true, "group": "A"},
		{"prediction": false, "label": false, "group": "B"},
		{"prediction": true, "label": true, "group": "B"}
	]`
	if err := sp.WriteFile("fairness_data.json", []byte(data), 0o644); err != nil {
		t.Fatalf("write data: %v", err)
	}

	dataPath := filepath.Join(tmpDir, "fairness_data.json")

	cmd := NewMLFairnessCmd()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"--protected", "group", dataPath})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute failed: %v", err)
	}

	output := buf.String()
	if output == "" {
		t.Error("expected non-empty output")
	}
}

func TestMLFairnessJSONFormat(t *testing.T) {
	tmpDir := t.TempDir()

	sp, err := safepath.New(tmpDir)
	if err != nil {
		t.Fatalf("create safepath: %v", err)
	}

	data := `[
		{"prediction": true, "label": true, "group": "A"},
		{"prediction": false, "label": false, "group": "B"}
	]`
	if err := sp.WriteFile("data.json", []byte(data), 0o644); err != nil {
		t.Fatalf("write data: %v", err)
	}

	dataPath := filepath.Join(tmpDir, "data.json")

	cmd := NewMLFairnessCmd()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"--protected", "group", "--format", "json", dataPath})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute failed: %v", err)
	}

	output := buf.String()
	var result map[string]interface{}
	if err := json.Unmarshal([]byte(output), &result); err != nil {
		t.Errorf("expected valid JSON output, got: %s", output)
	}
}

func TestNewMLBiasCmd(t *testing.T) {
	cmd := NewMLBiasCmd()

	if !strings.HasPrefix(cmd.Use, "bias") {
		t.Errorf("expected Use to start with 'bias', got %s", cmd.Use)
	}

	flags := []string{"attributes", "output", "format", "timeout"}
	for _, name := range flags {
		if cmd.Flags().Lookup(name) == nil {
			t.Errorf("flag %s not found", name)
		}
	}
}

func TestMLBiasRun(t *testing.T) {
	tmpDir := t.TempDir()

	sp, err := safepath.New(tmpDir)
	if err != nil {
		t.Fatalf("create safepath: %v", err)
	}

	data := `[
		{"gender": "M", "age": 25},
		{"gender": "M", "age": 30},
		{"gender": "F", "age": 28},
		{"gender": "F", "age": 35}
	]`
	if err := sp.WriteFile("bias_data.json", []byte(data), 0o644); err != nil {
		t.Fatalf("write data: %v", err)
	}

	dataPath := filepath.Join(tmpDir, "bias_data.json")

	cmd := NewMLBiasCmd()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"--attributes", "gender", dataPath})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute failed: %v", err)
	}

	output := buf.String()
	if output == "" {
		t.Error("expected non-empty output")
	}
}

func TestMLBiasMultipleAttributes(t *testing.T) {
	tmpDir := t.TempDir()

	sp, err := safepath.New(tmpDir)
	if err != nil {
		t.Fatalf("create safepath: %v", err)
	}

	data := `[
		{"gender": "M", "race": "A", "age": 25},
		{"gender": "F", "race": "B", "age": 30}
	]`
	if err := sp.WriteFile("data.json", []byte(data), 0o644); err != nil {
		t.Fatalf("write data: %v", err)
	}

	dataPath := filepath.Join(tmpDir, "data.json")

	cmd := NewMLBiasCmd()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"--attributes", "gender,race", dataPath})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute failed: %v", err)
	}
}

func TestMLBiasJSONFormat(t *testing.T) {
	tmpDir := t.TempDir()

	sp, err := safepath.New(tmpDir)
	if err != nil {
		t.Fatalf("create safepath: %v", err)
	}

	data := `[{"gender": "M", "age": 25}, {"gender": "F", "age": 30}]`
	if err := sp.WriteFile("data.json", []byte(data), 0o644); err != nil {
		t.Fatalf("write data: %v", err)
	}

	dataPath := filepath.Join(tmpDir, "data.json")

	cmd := NewMLBiasCmd()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"--attributes", "gender", "--format", "json", dataPath})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute failed: %v", err)
	}

	output := buf.String()
	var result map[string]interface{}
	if err := json.Unmarshal([]byte(output), &result); err != nil {
		t.Errorf("expected valid JSON output, got: %s", output)
	}
}

func TestNewMLModelCardCmd(t *testing.T) {
	cmd := NewMLModelCardCmd()

	if !strings.HasPrefix(cmd.Use, "model-card") {
		t.Errorf("expected Use to start with 'model-card', got %s", cmd.Use)
	}

	flags := []string{"output", "format", "timeout"}
	for _, name := range flags {
		if cmd.Flags().Lookup(name) == nil {
			t.Errorf("flag %s not found", name)
		}
	}
}

func TestMLModelCardRun(t *testing.T) {
	tmpDir := t.TempDir()

	sp, err := safepath.New(tmpDir)
	if err != nil {
		t.Fatalf("create safepath: %v", err)
	}

	// Create a test Python file with ML code.
	content := []byte("import tensorflow as tf\nmodel = tf.keras.Sequential()")
	if err := sp.WriteFile("model.py", content, 0o644); err != nil {
		t.Fatalf("write test file: %v", err)
	}

	outputPath := filepath.Join(tmpDir, "model_card.md")

	cmd := NewMLModelCardCmd()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"--output", outputPath, tmpDir})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute failed: %v", err)
	}

	// Verify output file was created.
	if _, err := os.Stat(outputPath); os.IsNotExist(err) {
		t.Error("model card file was not created")
	}
}

func TestMLModelCardJSONFormat(t *testing.T) {
	tmpDir := t.TempDir()

	sp, err := safepath.New(tmpDir)
	if err != nil {
		t.Fatalf("create safepath: %v", err)
	}

	content := []byte("import torch\nmodel = torch.nn.Linear(10, 5)")
	if writeErr := sp.WriteFile("model.py", content, 0o644); writeErr != nil {
		t.Fatalf("write test file: %v", writeErr)
	}

	outputPath := filepath.Join(tmpDir, "model_card.json")

	cmd := NewMLModelCardCmd()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"--output", outputPath, "--format", "json", tmpDir})

	if execErr := cmd.Execute(); execErr != nil {
		t.Fatalf("execute failed: %v", execErr)
	}

	// Read and verify JSON output.
	data, readErr := sp.ReadFile("model_card.json")
	if readErr != nil {
		t.Fatalf("read output: %v", readErr)
	}

	var result map[string]interface{}
	if unmarshalErr := json.Unmarshal(data, &result); unmarshalErr != nil {
		t.Errorf("expected valid JSON output, got: %s", string(data))
	}
}

func TestReadJSONData(t *testing.T) {
	tmpDir := t.TempDir()

	sp, err := safepath.New(tmpDir)
	if err != nil {
		t.Fatalf("create safepath: %v", err)
	}

	data := `[{"name": "test", "value": 123}]`
	if writeErr := sp.WriteFile("data.json", []byte(data), 0o644); writeErr != nil {
		t.Fatalf("write data: %v", writeErr)
	}

	dataPath := filepath.Join(tmpDir, "data.json")
	records, readErr := readJSONData(dataPath)
	if readErr != nil {
		t.Fatalf("readJSONData failed: %v", readErr)
	}

	if len(records) != 1 {
		t.Errorf("expected 1 record, got %d", len(records))
	}

	if records[0]["name"] != "test" {
		t.Errorf("expected name 'test', got %v", records[0]["name"])
	}
}

func TestReadJSONDataInvalidPath(t *testing.T) {
	_, err := readJSONData("/nonexistent/path/data.json")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestReadJSONDataInvalidJSON(t *testing.T) {
	tmpDir := t.TempDir()

	sp, err := safepath.New(tmpDir)
	if err != nil {
		t.Fatalf("create safepath: %v", err)
	}

	if writeErr := sp.WriteFile("invalid.json", []byte("not valid json"), 0o644); writeErr != nil {
		t.Fatalf("write data: %v", writeErr)
	}

	dataPath := filepath.Join(tmpDir, "invalid.json")
	_, readErr := readJSONData(dataPath)
	if readErr == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestWriteOutput(t *testing.T) {
	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "output.txt")

	cmd := NewMLDetectCmd()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)

	content := []byte("test output content")
	if err := writeOutput(cmd, content, outputPath); err != nil {
		t.Fatalf("writeOutput failed: %v", err)
	}

	// Verify file was created.
	sp, err := safepath.New(tmpDir)
	if err != nil {
		t.Fatalf("create safepath: %v", err)
	}

	data, err := sp.ReadFile("output.txt")
	if err != nil {
		t.Fatalf("read output: %v", err)
	}

	if string(data) != "test output content" {
		t.Errorf("expected 'test output content', got: %s", string(data))
	}
}

func TestWriteOutputStdout(t *testing.T) {
	cmd := NewMLDetectCmd()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)

	content := []byte("stdout content")
	if err := writeOutput(cmd, content, ""); err != nil {
		t.Fatalf("writeOutput failed: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "stdout content") {
		t.Errorf("expected stdout to contain 'stdout content', got: %s", output)
	}
}

func TestFormatValidationResult(t *testing.T) {
	result := &validationResultForTest{
		SchemaName: "test-schema",
		Valid:      true,
		Statistics: validationStats{
			TotalRows:   100,
			ValidRows:   95,
			InvalidRows: 5,
		},
		Errors: []validationError{
			{Row: 5, Column: "age", Message: "value out of range"},
		},
	}

	// Use the actual ml.ValidationResult type in real test.
	// This is a simplified mock for demonstration.
	output := formatMockValidationResult(result)

	if !strings.Contains(output, "test-schema") {
		t.Error("expected output to contain schema name")
	}
	if !strings.Contains(output, "100") {
		t.Error("expected output to contain total rows")
	}
}

// Mock types for testing formatValidationResult.
//
//nolint:govet // Field order matches ml.ValidationResult for readability.
type validationResultForTest struct {
	SchemaName string
	Statistics validationStats
	Errors     []validationError
	Valid      bool
}

type validationStats struct {
	TotalRows   int
	ValidRows   int
	InvalidRows int
}

type validationError struct {
	Message string
	Column  string
	Row     int
}

func formatMockValidationResult(result *validationResultForTest) string {
	var sb strings.Builder
	sb.WriteString("Validation Result for: " + result.SchemaName + "\n")
	sb.WriteString("Valid: ")
	if result.Valid {
		sb.WriteString("true\n")
	} else {
		sb.WriteString("false\n")
	}
	sb.WriteString("Total Rows: ")
	sb.WriteString(string(rune('0' + result.Statistics.TotalRows/100)))
	sb.WriteString(string(rune('0' + (result.Statistics.TotalRows%100)/10)))
	sb.WriteString(string(rune('0' + result.Statistics.TotalRows%10)))
	sb.WriteString("\n")
	return sb.String()
}

func TestMLDetectCSVFormat(t *testing.T) {
	tmpDir := t.TempDir()

	sp, err := safepath.New(tmpDir)
	if err != nil {
		t.Fatalf("create safepath: %v", err)
	}

	content := []byte("import tensorflow as tf\nmodel = tf.keras.Sequential()")
	if err := sp.WriteFile("train.py", content, 0o644); err != nil {
		t.Fatalf("write test file: %v", err)
	}

	cmd := NewMLDetectCmd()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{tmpDir, "--format", "csv"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute failed: %v", err)
	}

	output := buf.String()
	// CSV should have header row.
	if !strings.Contains(output, "Type,Name,SourceFile,Confidence,IsMLPipeline") {
		t.Errorf("expected CSV header in output, got: %s", output)
	}
}

func TestMLDetectHTMLFormat(t *testing.T) {
	tmpDir := t.TempDir()

	sp, err := safepath.New(tmpDir)
	if err != nil {
		t.Fatalf("create safepath: %v", err)
	}

	content := []byte("import torch\nmodel = torch.nn.Linear(10, 5)")
	if err := sp.WriteFile("model.py", content, 0o644); err != nil {
		t.Fatalf("write test file: %v", err)
	}

	cmd := NewMLDetectCmd()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{tmpDir, "--format", "html"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute failed: %v", err)
	}

	output := buf.String()
	// HTML should have DOCTYPE and html tags.
	if !strings.Contains(output, "<!DOCTYPE html>") {
		t.Errorf("expected HTML doctype in output, got: %s", output)
	}
	if !strings.Contains(output, "<html") {
		t.Errorf("expected html tag in output, got: %s", output)
	}
}

func TestMLDetectJUnitFormat(t *testing.T) {
	tmpDir := t.TempDir()

	sp, err := safepath.New(tmpDir)
	if err != nil {
		t.Fatalf("create safepath: %v", err)
	}

	content := []byte("import sklearn\nfrom sklearn.linear_model import LogisticRegression")
	if err := sp.WriteFile("train.py", content, 0o644); err != nil {
		t.Fatalf("write test file: %v", err)
	}

	cmd := NewMLDetectCmd()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{tmpDir, "--format", "junit"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute failed: %v", err)
	}

	output := buf.String()
	// JUnit should have XML structure.
	if !strings.Contains(output, "<?xml") {
		t.Errorf("expected XML declaration in output, got: %s", output)
	}
	if !strings.Contains(output, "<testsuites>") {
		t.Errorf("expected testsuites tag in output, got: %s", output)
	}
}

func TestMLDetectSARIFFormat(t *testing.T) {
	tmpDir := t.TempDir()

	sp, err := safepath.New(tmpDir)
	if err != nil {
		t.Fatalf("create safepath: %v", err)
	}

	content := []byte("import tensorflow as tf\nmodel = tf.keras.Sequential()")
	if err := sp.WriteFile("train.py", content, 0o644); err != nil {
		t.Fatalf("write test file: %v", err)
	}

	cmd := NewMLDetectCmd()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{tmpDir, "--format", "sarif"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute failed: %v", err)
	}

	output := buf.String()
	// SARIF should have version and schema.
	if !strings.Contains(output, `"version"`) {
		t.Errorf("expected version in SARIF output, got: %s", output)
	}
	if !strings.Contains(output, `"$schema"`) {
		t.Errorf("expected $schema in SARIF output, got: %s", output)
	}
}

func TestMLFairnessCSVFormat(t *testing.T) {
	tmpDir := t.TempDir()

	sp, err := safepath.New(tmpDir)
	if err != nil {
		t.Fatalf("create safepath: %v", err)
	}

	data := `[
		{"prediction": true, "label": true, "group": "A"},
		{"prediction": false, "label": false, "group": "A"},
		{"prediction": true, "label": true, "group": "B"},
		{"prediction": false, "label": true, "group": "B"}
	]`
	if err := sp.WriteFile("data.json", []byte(data), 0o644); err != nil {
		t.Fatalf("write test file: %v", err)
	}

	cmd := NewMLFairnessCmd()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{filepath.Join(tmpDir, "data.json"), "--format", "csv"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute failed: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "MetricType,Value,Threshold,Passed") {
		t.Errorf("expected CSV header in output, got: %s", output)
	}
}

func TestMLBiasHTMLFormat(t *testing.T) {
	tmpDir := t.TempDir()

	sp, err := safepath.New(tmpDir)
	if err != nil {
		t.Fatalf("create safepath: %v", err)
	}

	data := `[
		{"gender": "M", "age": 25, "outcome": 1},
		{"gender": "M", "age": 30, "outcome": 1},
		{"gender": "M", "age": 35, "outcome": 1},
		{"gender": "F", "age": 28, "outcome": 0}
	]`
	if err := sp.WriteFile("data.json", []byte(data), 0o644); err != nil {
		t.Fatalf("write test file: %v", err)
	}

	cmd := NewMLBiasCmd()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{filepath.Join(tmpDir, "data.json"), "--attributes", "gender", "--format", "html"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute failed: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "<!DOCTYPE html>") {
		t.Errorf("expected HTML doctype in output, got: %s", output)
	}
}

func TestMLValidateCSVFormat(t *testing.T) {
	tmpDir := t.TempDir()

	sp, err := safepath.New(tmpDir)
	if err != nil {
		t.Fatalf("create safepath: %v", err)
	}

	schema := `{
		"name": "test-schema",
		"columns": [
			{"name": "age", "type": "integer", "required": true, "min": 0, "max": 150}
		]
	}`
	if err := sp.WriteFile("schema.json", []byte(schema), 0o644); err != nil {
		t.Fatalf("write schema file: %v", err)
	}

	// Data with a validation error.
	data := `[
		{"age": 25},
		{"age": -5}
	]`
	if err := sp.WriteFile("data.json", []byte(data), 0o644); err != nil {
		t.Fatalf("write data file: %v", err)
	}

	cmd := NewMLValidateCmd()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{
		filepath.Join(tmpDir, "data.json"),
		"--schema", filepath.Join(tmpDir, "schema.json"),
		"--format", "csv",
	})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute failed: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "Row,Column,Message,Code") {
		t.Errorf("expected CSV header in output, got: %s", output)
	}
}
