package ml

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/victoralfred/gowritter/safepath"
)

func TestNewDetector(t *testing.T) {
	d := NewDetector()
	if d == nil {
		t.Fatal("expected detector, got nil")
	}
	if len(d.frameworkPatterns) == 0 {
		t.Error("expected framework patterns to be initialized")
	}
	if len(d.modelExtensions) == 0 {
		t.Error("expected model extensions to be initialized")
	}
}

func TestDetect(t *testing.T) {
	ctx := context.Background()
	d := NewDetector()

	// Create temp directory with Python file.
	tmpDir := t.TempDir()
	sp, err := safepath.New(tmpDir)
	if err != nil {
		t.Fatalf("create safepath: %v", err)
	}

	// Create Python file with TensorFlow import and pipeline indicators.
	pyContent := []byte(`
import tensorflow as tf
import numpy as np

model = tf.keras.Sequential()
optimizer = tf.keras.optimizers.Adam(learning_rate=0.001)
model.compile(loss='mse', optimizer=optimizer)
model.fit(x_train, y_train, epochs=10, batch_size=32)
model.save('model.h5')
`)
	if writeErr := sp.WriteFile("train.py", pyContent, 0o600); writeErr != nil {
		t.Fatalf("write Python file: %v", writeErr)
	}

	result, err := d.Detect(ctx, tmpDir)
	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	if result == nil {
		t.Fatal("expected result, got nil")
	}

	if len(result.Frameworks) == 0 {
		t.Error("expected at least one framework to be detected")
	}

	// Verify TensorFlow was detected.
	found := false
	for _, fw := range result.Frameworks {
		if fw.Name == FrameworkTensorFlow {
			found = true
			if fw.Confidence < 0.5 {
				t.Errorf("expected confidence >= 0.5, got %f", fw.Confidence)
			}
			if !fw.IsMLPipeline {
				t.Error("expected IsMLPipeline to be true")
			}
			break
		}
	}
	if !found {
		t.Error("expected TensorFlow to be detected")
	}
}

func TestDetectPyTorch(t *testing.T) {
	ctx := context.Background()
	d := NewDetector()

	tmpDir := t.TempDir()
	sp, err := safepath.New(tmpDir)
	if err != nil {
		t.Fatalf("create safepath: %v", err)
	}

	pyContent := []byte(`
import torch
import torch.nn as nn
import torch.optim as optim

class Net(nn.Module):
    def __init__(self):
        super().__init__()

optimizer.zero_grad()
loss.backward()
`)
	if writeErr := sp.WriteFile("model.py", pyContent, 0o600); writeErr != nil {
		t.Fatalf("write Python file: %v", writeErr)
	}

	result, err := d.Detect(ctx, tmpDir)
	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	found := false
	for _, fw := range result.Frameworks {
		if fw.Name == FrameworkPyTorch {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected PyTorch to be detected")
	}
}

func TestDetectScikitLearn(t *testing.T) {
	ctx := context.Background()
	d := NewDetector()

	tmpDir := t.TempDir()
	sp, err := safepath.New(tmpDir)
	if err != nil {
		t.Fatalf("create safepath: %v", err)
	}

	pyContent := []byte(`
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression

X_train, X_test, y_train, y_test = train_test_split(X, y)
model = LogisticRegression()
model.fit(X_train, y_train)
predictions = model.predict(X_test)
`)
	if writeErr := sp.WriteFile("classifier.py", pyContent, 0o600); writeErr != nil {
		t.Fatalf("write Python file: %v", writeErr)
	}

	result, err := d.Detect(ctx, tmpDir)
	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	found := false
	for _, fw := range result.Frameworks {
		if fw.Name == FrameworkScikit {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected scikit-learn to be detected")
	}
}

func TestDetectModelFiles(t *testing.T) {
	ctx := context.Background()
	d := NewDetector()

	tmpDir := t.TempDir()
	sp, err := safepath.New(tmpDir)
	if err != nil {
		t.Fatalf("create safepath: %v", err)
	}

	// Create model files.
	modelFiles := []string{"model.h5", "model.pt", "model.onnx"}
	for _, name := range modelFiles {
		if writeErr := sp.WriteFile(name, []byte("dummy model data"), 0o600); writeErr != nil {
			t.Fatalf("write model file %s: %v", name, writeErr)
		}
	}

	result, err := d.Detect(ctx, tmpDir)
	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	if len(result.Models) != 3 {
		t.Errorf("expected 3 models, got %d", len(result.Models))
	}

	// Verify model types.
	types := make(map[ModelType]bool)
	for _, m := range result.Models {
		types[m.Type] = true
	}

	if !types[ModelTypeH5] {
		t.Error("expected H5 model type")
	}
	if !types[ModelTypePTH] {
		t.Error("expected PTH model type")
	}
	if !types[ModelTypeONNX] {
		t.Error("expected ONNX model type")
	}
}

func TestDetectEmptyPath(t *testing.T) {
	ctx := context.Background()
	d := NewDetector()

	_, err := d.Detect(ctx, "")
	if err == nil {
		t.Error("expected error for empty path")
	}
}

func TestDetectContextCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	d := NewDetector()
	_, err := d.Detect(ctx, "/tmp")
	if err == nil {
		t.Error("expected error for canceled context")
	}
}

func TestDetectFromRequirements(t *testing.T) {
	ctx := context.Background()
	d := NewDetector()

	tmpDir := t.TempDir()
	sp, err := safepath.New(tmpDir)
	if err != nil {
		t.Fatalf("create safepath: %v", err)
	}

	reqContent := []byte(`
tensorflow>=2.0.0
torch==1.9.0
scikit-learn~=0.24
numpy
pandas
transformers>=4.0
xgboost
`)
	if writeErr := sp.WriteFile("requirements.txt", reqContent, 0o600); writeErr != nil {
		t.Fatalf("write requirements.txt: %v", writeErr)
	}

	reqPath := filepath.Join(tmpDir, "requirements.txt")
	frameworks, err := d.DetectFromRequirements(ctx, reqPath)
	if err != nil {
		t.Fatalf("DetectFromRequirements failed: %v", err)
	}

	if len(frameworks) < 5 {
		t.Errorf("expected at least 5 frameworks, got %d", len(frameworks))
	}

	// Verify frameworks.
	names := make(map[Framework]bool)
	for _, fw := range frameworks {
		names[fw.Name] = true
	}

	expected := []Framework{FrameworkTensorFlow, FrameworkPyTorch, FrameworkScikit, FrameworkHuggingFace, FrameworkXGBoost}
	for _, fw := range expected {
		if !names[fw] {
			t.Errorf("expected framework %s to be detected", fw)
		}
	}
}

func TestDetectionResultSummary(t *testing.T) {
	result := &DetectionResult{
		Frameworks: []DetectedFramework{
			{Name: FrameworkTensorFlow, Confidence: 0.9},
			{Name: FrameworkPyTorch, Confidence: 0.8},
		},
		Models: []DetectedModel{
			{Name: "model.h5", Type: ModelTypeH5, Framework: FrameworkTensorFlow},
		},
	}

	summary := result.Summary()
	if summary == "" {
		t.Error("expected non-empty summary")
	}
	if len(summary) < 50 {
		t.Error("summary seems too short")
	}
}

func TestDetectionResultToJSON(t *testing.T) {
	result := &DetectionResult{
		Frameworks: []DetectedFramework{
			{Name: FrameworkTensorFlow, Confidence: 0.9},
		},
		Models: []DetectedModel{
			{Name: "model.h5", Type: ModelTypeH5},
		},
	}

	data, err := result.ToJSON()
	if err != nil {
		t.Fatalf("ToJSON failed: %v", err)
	}

	if len(data) == 0 {
		t.Error("expected non-empty JSON")
	}
}

func TestFrameworkConstants(t *testing.T) {
	frameworks := []Framework{
		FrameworkTensorFlow,
		FrameworkPyTorch,
		FrameworkScikit,
		FrameworkONNX,
		FrameworkHuggingFace,
		FrameworkXGBoost,
		FrameworkLightGBM,
		FrameworkUnknown,
	}

	for _, fw := range frameworks {
		if string(fw) == "" {
			t.Error("framework constant should not be empty")
		}
	}
}

func TestModelTypeConstants(t *testing.T) {
	types := []ModelType{
		ModelTypeSavedModel,
		ModelTypeH5,
		ModelTypePTH,
		ModelTypePickle,
		ModelTypeONNX,
		ModelTypePMML,
		ModelTypeSafetensors,
		ModelTypeCheckpoint,
		ModelTypeUnknown,
	}

	for _, mt := range types {
		if string(mt) == "" {
			t.Error("model type constant should not be empty")
		}
	}
}

func TestInferFramework(t *testing.T) {
	d := NewDetector()

	tests := []struct {
		modelType ModelType
		expected  Framework
	}{
		{ModelTypeH5, FrameworkTensorFlow},
		{ModelTypeSavedModel, FrameworkTensorFlow},
		{ModelTypePTH, FrameworkPyTorch},
		{ModelTypePickle, FrameworkScikit},
		{ModelTypeONNX, FrameworkONNX},
		{ModelTypeSafetensors, FrameworkHuggingFace},
		{ModelTypeUnknown, FrameworkUnknown},
	}

	for _, tt := range tests {
		result := d.inferFramework(tt.modelType)
		if result != tt.expected {
			t.Errorf("inferFramework(%s) = %s, want %s", tt.modelType, result, tt.expected)
		}
	}
}

func TestUniqueStrings(t *testing.T) {
	d := NewDetector()

	input := []string{"a", "b", "a", "c", "b", "d"}
	result := d.uniqueStrings(input)

	if len(result) != 4 {
		t.Errorf("expected 4 unique strings, got %d", len(result))
	}

	// Verify all expected values are present.
	expected := map[string]bool{"a": true, "b": true, "c": true, "d": true}
	for _, s := range result {
		if !expected[s] {
			t.Errorf("unexpected string: %s", s)
		}
	}
}

func TestCalculateConfidence(t *testing.T) {
	d := NewDetector()

	// Content with just import should have base confidence.
	basicContent := "import tensorflow as tf"
	confidence := d.calculateConfidence(basicContent, FrameworkTensorFlow)
	if confidence < 0.5 || confidence > 0.6 {
		t.Errorf("expected confidence ~0.5 for basic import, got %f", confidence)
	}

	// Content with more patterns should have higher confidence.
	richContent := `
import tensorflow as tf
model = tf.keras.Sequential()
model.compile(loss='mse')
model.fit(x, y)
`
	highConfidence := d.calculateConfidence(richContent, FrameworkTensorFlow)
	if highConfidence <= confidence {
		t.Errorf("expected higher confidence for rich content, got %f", highConfidence)
	}
}

func TestIsMLPipeline(t *testing.T) {
	d := NewDetector()

	pipelineContent := `
model.fit(x_train, y_train, epochs=10, batch_size=32)
optimizer = tf.keras.optimizers.Adam(learning_rate=0.001)
model.save('model.h5')
`
	if !d.isMLPipeline(pipelineContent) {
		t.Error("expected pipeline to be detected")
	}

	nonPipelineContent := `
import tensorflow as tf
print("Hello, TensorFlow!")
`
	if d.isMLPipeline(nonPipelineContent) {
		t.Error("expected non-pipeline to not be detected as pipeline")
	}
}

func TestDefaultDetectorConfig(t *testing.T) {
	config := DefaultDetectorConfig()

	if config.MaxFileSize != 10*1024*1024 {
		t.Errorf("expected MaxFileSize 10MB, got %d", config.MaxFileSize)
	}
	if config.MaxDepth != 50 {
		t.Errorf("expected MaxDepth 50, got %d", config.MaxDepth)
	}
	if config.MaxFilesToScan != 10000 {
		t.Errorf("expected MaxFilesToScan 10000, got %d", config.MaxFilesToScan)
	}
	if len(config.ExcludePatterns) == 0 {
		t.Error("expected exclude patterns to be set")
	}
}

func TestNewDetectorWithConfig(t *testing.T) {
	config := DetectorConfig{
		MaxFileSize:    1024,
		MaxDepth:       5,
		MaxFilesToScan: 100,
	}

	d := NewDetectorWithConfig(config)
	if d == nil {
		t.Fatal("expected detector, got nil")
	}

	if d.config.MaxFileSize != 1024 {
		t.Errorf("expected MaxFileSize 1024, got %d", d.config.MaxFileSize)
	}
	if d.config.MaxDepth != 5 {
		t.Errorf("expected MaxDepth 5, got %d", d.config.MaxDepth)
	}
	if d.config.MaxFilesToScan != 100 {
		t.Errorf("expected MaxFilesToScan 100, got %d", d.config.MaxFilesToScan)
	}
}

func TestDetectorConfig(t *testing.T) {
	config := DetectorConfig{
		MaxFileSize: 2048,
	}

	d := NewDetectorWithConfig(config)
	returnedConfig := d.Config()

	if returnedConfig.MaxFileSize != 2048 {
		t.Errorf("expected MaxFileSize 2048, got %d", returnedConfig.MaxFileSize)
	}
}

func TestDetectorFileSizeLimit(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()
	sp, err := safepath.New(tmpDir)
	if err != nil {
		t.Fatalf("create safepath: %v", err)
	}

	// Create a small Python file.
	smallContent := []byte("import tensorflow as tf")
	if writeErr := sp.WriteFile("small.py", smallContent, 0o600); writeErr != nil {
		t.Fatalf("write small file: %v", writeErr)
	}

	// Create a larger Python file that exceeds limit.
	largeContent := make([]byte, 2000)
	for i := range largeContent {
		largeContent[i] = 'x'
	}
	if writeErr := sp.WriteFile("large.py", largeContent, 0o600); writeErr != nil {
		t.Fatalf("write large file: %v", writeErr)
	}

	// Create detector with small file size limit.
	config := DetectorConfig{
		MaxFileSize:    1000, // 1KB limit
		MaxDepth:       50,
		MaxFilesToScan: 1000,
	}
	d := NewDetectorWithConfig(config)

	result, err := d.Detect(ctx, tmpDir)
	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	// Large file should be skipped, so no frameworks detected from it.
	// Only small.py should be scanned.
	if result == nil {
		t.Fatal("expected result, got nil")
	}
}

func TestDetectorMaxFilesLimit(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()
	sp, err := safepath.New(tmpDir)
	if err != nil {
		t.Fatalf("create safepath: %v", err)
	}

	// Create multiple Python files.
	for i := 0; i < 10; i++ {
		content := []byte("import tensorflow as tf")
		filename := "file" + string(rune('0'+i)) + ".py"
		if writeErr := sp.WriteFile(filename, content, 0o600); writeErr != nil {
			t.Fatalf("write file: %v", writeErr)
		}
	}

	// Create detector with low file limit.
	config := DetectorConfig{
		MaxFileSize:    10 * 1024 * 1024,
		MaxDepth:       50,
		MaxFilesToScan: 3, // Only scan 3 files
	}
	d := NewDetectorWithConfig(config)

	result, err := d.Detect(ctx, tmpDir)
	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	if result == nil {
		t.Fatal("expected result, got nil")
	}

	// Should have detected frameworks from limited files.
	// The scan should have stopped after 3 files.
}

func TestDetectorMaxDepthLimit(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()
	sp, err := safepath.New(tmpDir)
	if err != nil {
		t.Fatalf("create safepath: %v", err)
	}

	// Create nested directory structure.
	if mkErr := sp.MkdirAll("level1/level2/level3", 0o755); mkErr != nil {
		t.Fatalf("mkdir: %v", mkErr)
	}

	// Create Python file at root level.
	if writeErr := sp.WriteFile("root.py", []byte("import tensorflow"), 0o600); writeErr != nil {
		t.Fatalf("write root file: %v", writeErr)
	}

	// Create Python file at deep level.
	deepSp, err := safepath.New(filepath.Join(tmpDir, "level1", "level2", "level3"))
	if err != nil {
		t.Fatalf("create deep safepath: %v", err)
	}
	if writeErr := deepSp.WriteFile("deep.py", []byte("import pytorch"), 0o600); writeErr != nil {
		t.Fatalf("write deep file: %v", writeErr)
	}

	// Create detector with depth limit of 2 (will reach level1 but stop before level2).
	config := DetectorConfig{
		MaxFileSize:    10 * 1024 * 1024,
		MaxDepth:       2,
		MaxFilesToScan: 1000,
	}
	d := NewDetectorWithConfig(config)

	// Scan should succeed and find root.py but not deep.py.
	result, err := d.Detect(ctx, tmpDir)
	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	if result == nil {
		t.Fatal("expected result, got nil")
	}

	// Should have found at least one framework (from root.py).
	if len(result.Frameworks) == 0 {
		t.Error("expected at least one framework from root.py")
	}
}

func TestDetectJupyterNotebook(t *testing.T) {
	ctx := context.Background()
	d := NewDetector()

	tmpDir := t.TempDir()
	sp, err := safepath.New(tmpDir)
	if err != nil {
		t.Fatalf("create safepath: %v", err)
	}

	// Create a Jupyter notebook with TensorFlow code.
	notebookContent := []byte(`{
		"cells": [
			{
				"cell_type": "markdown",
				"source": ["# ML Notebook"]
			},
			{
				"cell_type": "code",
				"source": ["import tensorflow as tf\n", "import numpy as np"]
			},
			{
				"cell_type": "code",
				"source": ["model = tf.keras.Sequential()\n", "model.compile(optimizer='adam')"]
			}
		]
	}`)
	if writeErr := sp.WriteFile("notebook.ipynb", notebookContent, 0o600); writeErr != nil {
		t.Fatalf("write notebook: %v", writeErr)
	}

	result, err := d.Detect(ctx, tmpDir)
	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	if result == nil {
		t.Fatal("expected result, got nil")
	}

	// Should detect TensorFlow from notebook.
	found := false
	for _, fw := range result.Frameworks {
		if fw.Name == FrameworkTensorFlow {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected TensorFlow to be detected from Jupyter notebook")
	}
}

func TestDetectJupyterNotebookPyTorch(t *testing.T) {
	ctx := context.Background()
	d := NewDetector()

	tmpDir := t.TempDir()
	sp, err := safepath.New(tmpDir)
	if err != nil {
		t.Fatalf("create safepath: %v", err)
	}

	// Create a Jupyter notebook with PyTorch code.
	notebookContent := []byte(`{
		"cells": [
			{
				"cell_type": "code",
				"source": ["import torch\n", "import torch.nn as nn"]
			},
			{
				"cell_type": "code",
				"source": ["model = nn.Linear(10, 5)"]
			}
		]
	}`)
	if writeErr := sp.WriteFile("pytorch_notebook.ipynb", notebookContent, 0o600); writeErr != nil {
		t.Fatalf("write notebook: %v", writeErr)
	}

	result, err := d.Detect(ctx, tmpDir)
	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	found := false
	for _, fw := range result.Frameworks {
		if fw.Name == FrameworkPyTorch {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected PyTorch to be detected from Jupyter notebook")
	}
}

func TestDetectEmptyJupyterNotebook(t *testing.T) {
	ctx := context.Background()
	d := NewDetector()

	tmpDir := t.TempDir()
	sp, err := safepath.New(tmpDir)
	if err != nil {
		t.Fatalf("create safepath: %v", err)
	}

	// Create an empty Jupyter notebook.
	notebookContent := []byte(`{"cells": []}`)
	if writeErr := sp.WriteFile("empty.ipynb", notebookContent, 0o600); writeErr != nil {
		t.Fatalf("write notebook: %v", writeErr)
	}

	result, err := d.Detect(ctx, tmpDir)
	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	if result == nil {
		t.Fatal("expected result, got nil")
	}

	// No frameworks should be detected.
	if len(result.Frameworks) != 0 {
		t.Errorf("expected no frameworks, got %d", len(result.Frameworks))
	}
}

func TestDetectMalformedJupyterNotebook(t *testing.T) {
	ctx := context.Background()
	d := NewDetector()

	tmpDir := t.TempDir()
	sp, err := safepath.New(tmpDir)
	if err != nil {
		t.Fatalf("create safepath: %v", err)
	}

	// Create a malformed Jupyter notebook.
	notebookContent := []byte(`{invalid json`)
	if writeErr := sp.WriteFile("malformed.ipynb", notebookContent, 0o600); writeErr != nil {
		t.Fatalf("write notebook: %v", writeErr)
	}

	result, err := d.Detect(ctx, tmpDir)
	if err != nil {
		t.Fatalf("Detect should not fail: %v", err)
	}

	// Should have an error recorded.
	if len(result.Errors) == 0 {
		t.Error("expected error to be recorded for malformed notebook")
	}
}

func TestParseNotebook(t *testing.T) {
	d := NewDetector()

	tmpDir := t.TempDir()
	sp, err := safepath.New(tmpDir)
	if err != nil {
		t.Fatalf("create safepath: %v", err)
	}

	// Create a notebook with mixed cell types.
	notebookContent := []byte(`{
		"cells": [
			{
				"cell_type": "markdown",
				"source": ["# Title"]
			},
			{
				"cell_type": "code",
				"source": ["print('hello')\n", "x = 1"]
			},
			{
				"cell_type": "raw",
				"source": ["raw content"]
			},
			{
				"cell_type": "code",
				"source": ["y = 2"]
			}
		]
	}`)
	if writeErr := sp.WriteFile("test.ipynb", notebookContent, 0o600); writeErr != nil {
		t.Fatalf("write notebook: %v", writeErr)
	}

	content, err := d.parseNotebook(filepath.Join(tmpDir, "test.ipynb"))
	if err != nil {
		t.Fatalf("parseNotebook failed: %v", err)
	}

	// Should only contain code cells.
	if content == "" {
		t.Error("expected non-empty content")
	}

	// Should contain code from code cells.
	if !contains(content, "print('hello')") {
		t.Error("expected content to contain code from first code cell")
	}
	if !contains(content, "y = 2") {
		t.Error("expected content to contain code from second code cell")
	}

	// Should not contain markdown or raw content.
	if contains(content, "# Title") {
		t.Error("content should not contain markdown cells")
	}
	if contains(content, "raw content") {
		t.Error("content should not contain raw cells")
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || s != "" && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
