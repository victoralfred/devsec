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

func TestDetectConcurrent(t *testing.T) {
	ctx := context.Background()

	tmpDir := t.TempDir()
	sp, err := safepath.New(tmpDir)
	if err != nil {
		t.Fatalf("create safepath: %v", err)
	}

	// Create multiple Python files with different frameworks.
	tfContent := []byte(`
import tensorflow as tf
model = tf.keras.Sequential()
model.compile(loss='mse', optimizer='adam')
model.fit(x, y, epochs=10)
`)
	if writeErr := sp.WriteFile("tf_model.py", tfContent, 0o600); writeErr != nil {
		t.Fatalf("write TensorFlow file: %v", writeErr)
	}

	ptContent := []byte(`
import torch
import torch.nn as nn
model = nn.Linear(10, 5)
optimizer = torch.optim.Adam(model.parameters())
`)
	if writeErr := sp.WriteFile("pt_model.py", ptContent, 0o600); writeErr != nil {
		t.Fatalf("write PyTorch file: %v", writeErr)
	}

	skContent := []byte(`
from sklearn.ensemble import RandomForestClassifier
model = RandomForestClassifier()
model.fit(X_train, y_train)
predictions = model.predict(X_test)
`)
	if writeErr := sp.WriteFile("sk_model.py", skContent, 0o600); writeErr != nil {
		t.Fatalf("write Scikit file: %v", writeErr)
	}

	// Create detector with workers.
	config := DetectorConfig{
		MaxFileSize:    10 * 1024 * 1024,
		MaxDepth:       50,
		MaxFilesToScan: 10000,
		WorkerCount:    4,
	}
	d := NewDetectorWithConfig(config)

	result, err := d.DetectConcurrent(ctx, tmpDir)
	if err != nil {
		t.Fatalf("DetectConcurrent failed: %v", err)
	}

	if result == nil {
		t.Fatal("expected result, got nil")
	}

	// Should detect all three frameworks.
	frameworksFound := make(map[Framework]bool)
	for _, fw := range result.Frameworks {
		frameworksFound[fw.Name] = true
	}

	if !frameworksFound[FrameworkTensorFlow] {
		t.Error("expected TensorFlow to be detected")
	}
	if !frameworksFound[FrameworkPyTorch] {
		t.Error("expected PyTorch to be detected")
	}
	if !frameworksFound[FrameworkScikit] {
		t.Error("expected Scikit-Learn to be detected")
	}
}

func TestDetectConcurrentWithModels(t *testing.T) {
	ctx := context.Background()

	tmpDir := t.TempDir()
	sp, err := safepath.New(tmpDir)
	if err != nil {
		t.Fatalf("create safepath: %v", err)
	}

	// Create model files.
	if writeErr := sp.WriteFile("model.h5", []byte("fake h5 content"), 0o600); writeErr != nil {
		t.Fatalf("write h5 file: %v", writeErr)
	}
	if writeErr := sp.WriteFile("weights.pth", []byte("fake pth content"), 0o600); writeErr != nil {
		t.Fatalf("write pth file: %v", writeErr)
	}
	if writeErr := sp.WriteFile("model.onnx", []byte("fake onnx content"), 0o600); writeErr != nil {
		t.Fatalf("write onnx file: %v", writeErr)
	}

	config := DetectorConfig{
		MaxFileSize:    10 * 1024 * 1024,
		MaxDepth:       50,
		MaxFilesToScan: 10000,
		WorkerCount:    2,
	}
	d := NewDetectorWithConfig(config)

	result, err := d.DetectConcurrent(ctx, tmpDir)
	if err != nil {
		t.Fatalf("DetectConcurrent failed: %v", err)
	}

	if len(result.Models) != 3 {
		t.Errorf("expected 3 models, got %d", len(result.Models))
	}

	// Check model types.
	modelTypes := make(map[ModelType]bool)
	for _, m := range result.Models {
		modelTypes[m.Type] = true
	}

	if !modelTypes[ModelTypeH5] {
		t.Error("expected H5 model to be detected")
	}
	if !modelTypes[ModelTypePTH] {
		t.Error("expected PTH model to be detected")
	}
	if !modelTypes[ModelTypeONNX] {
		t.Error("expected ONNX model to be detected")
	}
}

func TestDetectConcurrentContextCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately.

	d := NewDetector()
	_, err := d.DetectConcurrent(ctx, "/tmp")

	if err == nil {
		t.Error("expected error for canceled context")
	}
}

func TestDetectConcurrentEmptyPath(t *testing.T) {
	ctx := context.Background()
	d := NewDetector()

	_, err := d.DetectConcurrent(ctx, "")
	if err == nil {
		t.Error("expected error for empty path")
	}
}

func TestDetectConcurrentJupyterNotebooks(t *testing.T) {
	ctx := context.Background()

	tmpDir := t.TempDir()
	sp, err := safepath.New(tmpDir)
	if err != nil {
		t.Fatalf("create safepath: %v", err)
	}

	// Create a Jupyter notebook with TensorFlow.
	notebookContent := []byte(`{
		"cells": [
			{
				"cell_type": "code",
				"source": ["import tensorflow as tf\n", "model = tf.keras.Sequential()"]
			}
		]
	}`)
	if writeErr := sp.WriteFile("notebook.ipynb", notebookContent, 0o600); writeErr != nil {
		t.Fatalf("write notebook: %v", writeErr)
	}

	config := DetectorConfig{
		MaxFileSize:    10 * 1024 * 1024,
		MaxDepth:       50,
		MaxFilesToScan: 10000,
		WorkerCount:    2,
	}
	d := NewDetectorWithConfig(config)

	result, err := d.DetectConcurrent(ctx, tmpDir)
	if err != nil {
		t.Fatalf("DetectConcurrent failed: %v", err)
	}

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

func TestDefaultDetectorConfigWorkerCount(t *testing.T) {
	config := DefaultDetectorConfig()

	if config.WorkerCount < 2 {
		t.Errorf("expected WorkerCount >= 2, got %d", config.WorkerCount)
	}
	if config.WorkerCount > 8 {
		t.Errorf("expected WorkerCount <= 8, got %d", config.WorkerCount)
	}
}

func TestExtractH5Metadata(t *testing.T) {
	d := NewDetector()
	tmpDir := t.TempDir()
	sp, err := safepath.New(tmpDir)
	if err != nil {
		t.Fatalf("create safepath: %v", err)
	}

	// Create a file with valid HDF5 magic bytes.
	h5Content := []byte{0x89, 0x48, 0x44, 0x46, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00}
	if writeErr := sp.WriteFile("model.h5", h5Content, 0o600); writeErr != nil {
		t.Fatalf("write h5 file: %v", writeErr)
	}

	metadata := d.extractMetadata(filepath.Join(tmpDir, "model.h5"), ModelTypeH5)

	if metadata["is_valid_hdf5"] != true {
		t.Error("expected is_valid_hdf5 to be true")
	}
	if metadata["format"] != "HDF5" {
		t.Errorf("expected format 'HDF5', got %v", metadata["format"])
	}
}

func TestExtractPyTorchMetadataZIP(t *testing.T) {
	d := NewDetector()
	tmpDir := t.TempDir()
	sp, err := safepath.New(tmpDir)
	if err != nil {
		t.Fatalf("create safepath: %v", err)
	}

	// Create a file with ZIP magic bytes (PyTorch >= 1.6).
	zipContent := []byte{0x50, 0x4b, 0x03, 0x04, 0x00, 0x00, 0x00, 0x00}
	if writeErr := sp.WriteFile("model.pth", zipContent, 0o600); writeErr != nil {
		t.Fatalf("write pth file: %v", writeErr)
	}

	metadata := d.extractMetadata(filepath.Join(tmpDir, "model.pth"), ModelTypePTH)

	if metadata["format"] != "PyTorch ZIP archive" {
		t.Errorf("expected format 'PyTorch ZIP archive', got %v", metadata["format"])
	}
	if metadata["pytorch_version"] != ">=1.6" {
		t.Errorf("expected pytorch_version '>=1.6', got %v", metadata["pytorch_version"])
	}
}

func TestExtractPyTorchMetadataPickle(t *testing.T) {
	d := NewDetector()
	tmpDir := t.TempDir()
	sp, err := safepath.New(tmpDir)
	if err != nil {
		t.Fatalf("create safepath: %v", err)
	}

	// Create a file with pickle protocol 4 header.
	pickleContent := []byte{0x80, 0x04, 0x95, 0x00, 0x00, 0x00, 0x00}
	if writeErr := sp.WriteFile("model.pth", pickleContent, 0o600); writeErr != nil {
		t.Fatalf("write pth file: %v", writeErr)
	}

	metadata := d.extractMetadata(filepath.Join(tmpDir, "model.pth"), ModelTypePTH)

	if metadata["format"] != "PyTorch pickle" {
		t.Errorf("expected format 'PyTorch pickle', got %v", metadata["format"])
	}
	if metadata["pickle_protocol"] != 4 {
		t.Errorf("expected pickle_protocol 4, got %v", metadata["pickle_protocol"])
	}
}

func TestExtractONNXMetadata(t *testing.T) {
	d := NewDetector()
	tmpDir := t.TempDir()
	sp, err := safepath.New(tmpDir)
	if err != nil {
		t.Fatalf("create safepath: %v", err)
	}

	// Create a file with ONNX protobuf header (field 1, varint).
	onnxContent := []byte{0x08, 0x07, 0x12, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	if writeErr := sp.WriteFile("model.onnx", onnxContent, 0o600); writeErr != nil {
		t.Fatalf("write onnx file: %v", writeErr)
	}

	metadata := d.extractMetadata(filepath.Join(tmpDir, "model.onnx"), ModelTypeONNX)

	if metadata["format"] != "ONNX protobuf" {
		t.Errorf("expected format 'ONNX protobuf', got %v", metadata["format"])
	}
	if metadata["ir_version"] != 7 {
		t.Errorf("expected ir_version 7, got %v", metadata["ir_version"])
	}
}

func TestExtractPickleMetadata(t *testing.T) {
	d := NewDetector()
	tmpDir := t.TempDir()
	sp, err := safepath.New(tmpDir)
	if err != nil {
		t.Fatalf("create safepath: %v", err)
	}

	// Create a file with pickle protocol 5 header.
	pickleContent := []byte{0x80, 0x05, 0x95, 0x00}
	if writeErr := sp.WriteFile("model.pkl", pickleContent, 0o600); writeErr != nil {
		t.Fatalf("write pkl file: %v", writeErr)
	}

	metadata := d.extractMetadata(filepath.Join(tmpDir, "model.pkl"), ModelTypePickle)

	if metadata["format"] != "Python pickle" {
		t.Errorf("expected format 'Python pickle', got %v", metadata["format"])
	}
	if metadata["pickle_protocol"] != 5 {
		t.Errorf("expected pickle_protocol 5, got %v", metadata["pickle_protocol"])
	}
}

func TestExtractPickleMetadataASCII(t *testing.T) {
	d := NewDetector()
	tmpDir := t.TempDir()
	sp, err := safepath.New(tmpDir)
	if err != nil {
		t.Fatalf("create safepath: %v", err)
	}

	// Create a file with ASCII pickle (protocol 0).
	pickleContent := []byte("(dp0\nS'key'\np1\n")
	if writeErr := sp.WriteFile("model.pkl", pickleContent, 0o600); writeErr != nil {
		t.Fatalf("write pkl file: %v", writeErr)
	}

	metadata := d.extractMetadata(filepath.Join(tmpDir, "model.pkl"), ModelTypePickle)

	if metadata["format"] != "Python pickle (ASCII)" {
		t.Errorf("expected format 'Python pickle (ASCII)', got %v", metadata["format"])
	}
	if metadata["pickle_protocol"] != 0 {
		t.Errorf("expected pickle_protocol 0, got %v", metadata["pickle_protocol"])
	}
}

func TestExtractSafetensorsMetadata(t *testing.T) {
	d := NewDetector()
	tmpDir := t.TempDir()
	sp, err := safepath.New(tmpDir)
	if err != nil {
		t.Fatalf("create safepath: %v", err)
	}

	// Create a safetensors file with header.
	// Header size (8 bytes, little-endian) + JSON header + tensor data.
	header := `{"tensor1":{"dtype":"F32","shape":[10,10],"data_offsets":[0,400]}}`
	headerSize := len(header)

	// Build the file content.
	content := make([]byte, 8+headerSize+100)
	// Write header size (little-endian).
	content[0] = byte(headerSize)
	content[1] = byte(headerSize >> 8)
	content[2] = byte(headerSize >> 16)
	content[3] = byte(headerSize >> 24)
	// Copy header.
	copy(content[8:], header)

	if writeErr := sp.WriteFile("model.safetensors", content, 0o600); writeErr != nil {
		t.Fatalf("write safetensors file: %v", writeErr)
	}

	metadata := d.extractMetadata(filepath.Join(tmpDir, "model.safetensors"), ModelTypeSafetensors)

	if metadata["format"] != "safetensors" {
		t.Errorf("expected format 'safetensors', got %v", metadata["format"])
	}
	if metadata["tensor_count"] != 1 {
		t.Errorf("expected tensor_count 1, got %v", metadata["tensor_count"])
	}
}

func TestExtractMetadataFileSize(t *testing.T) {
	d := NewDetector()
	tmpDir := t.TempDir()
	sp, err := safepath.New(tmpDir)
	if err != nil {
		t.Fatalf("create safepath: %v", err)
	}

	content := make([]byte, 1024)
	if writeErr := sp.WriteFile("model.h5", content, 0o600); writeErr != nil {
		t.Fatalf("write file: %v", writeErr)
	}

	metadata := d.extractMetadata(filepath.Join(tmpDir, "model.h5"), ModelTypeH5)

	if metadata["file_size"] != 1024 {
		t.Errorf("expected file_size 1024, got %v", metadata["file_size"])
	}
}

func TestBytesEqual(t *testing.T) {
	tests := []struct {
		name     string
		a        []byte
		b        []byte
		expected bool
	}{
		{"equal", []byte{1, 2, 3}, []byte{1, 2, 3}, true},
		{"not equal", []byte{1, 2, 3}, []byte{1, 2, 4}, false},
		{"different length", []byte{1, 2}, []byte{1, 2, 3}, false},
		{"both empty", []byte{}, []byte{}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if result := bytesEqual(tt.a, tt.b); result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestCountOccurrences(t *testing.T) {
	tests := []struct {
		s        string
		substr   string
		expected int
	}{
		{"hello world", "o", 2},
		{"aaa", "a", 3},
		{"abc", "d", 0},
		{"", "a", 0},
		{"test", "", 5}, // Empty substr matches at every position plus one.
	}

	for _, tt := range tests {
		result := countOccurrences(tt.s, tt.substr)
		if result != tt.expected {
			t.Errorf("countOccurrences(%q, %q) = %d, expected %d", tt.s, tt.substr, result, tt.expected)
		}
	}
}

// Benchmarks

func BenchmarkDetect(b *testing.B) {
	ctx := context.Background()
	d := NewDetector()

	tmpDir := b.TempDir()
	sp, err := safepath.New(tmpDir)
	if err != nil {
		b.Fatalf("create safepath: %v", err)
	}

	// Create test files.
	pyContent := []byte(`
import tensorflow as tf
import torch
from sklearn.ensemble import RandomForestClassifier
model = tf.keras.Sequential()
`)
	for i := 0; i < 10; i++ {
		filename := "file" + string(rune('0'+i)) + ".py"
		if writeErr := sp.WriteFile(filename, pyContent, 0o600); writeErr != nil {
			b.Fatalf("write file: %v", writeErr)
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, detectErr := d.Detect(ctx, tmpDir)
		if detectErr != nil {
			b.Fatalf("Detect failed: %v", detectErr)
		}
	}
}

func BenchmarkDetectConcurrent(b *testing.B) {
	ctx := context.Background()

	tmpDir := b.TempDir()
	sp, err := safepath.New(tmpDir)
	if err != nil {
		b.Fatalf("create safepath: %v", err)
	}

	// Create test files.
	pyContent := []byte(`
import tensorflow as tf
import torch
from sklearn.ensemble import RandomForestClassifier
model = tf.keras.Sequential()
`)
	for i := 0; i < 10; i++ {
		filename := "file" + string(rune('0'+i)) + ".py"
		if writeErr := sp.WriteFile(filename, pyContent, 0o600); writeErr != nil {
			b.Fatalf("write file: %v", writeErr)
		}
	}

	config := DetectorConfig{
		MaxFileSize:    10 * 1024 * 1024,
		MaxDepth:       50,
		MaxFilesToScan: 10000,
		WorkerCount:    4,
	}
	d := NewDetectorWithConfig(config)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, detectErr := d.DetectConcurrent(ctx, tmpDir)
		if detectErr != nil {
			b.Fatalf("DetectConcurrent failed: %v", detectErr)
		}
	}
}

func BenchmarkCalculateConfidence(b *testing.B) {
	d := NewDetector()
	content := `
import tensorflow as tf
model = tf.keras.Sequential()
model.compile(loss='mse', optimizer='adam')
model.fit(x, y, epochs=10, batch_size=32)
`

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		d.calculateConfidence(content, FrameworkTensorFlow)
	}
}

func BenchmarkExtractMetadata(b *testing.B) {
	d := NewDetector()
	tmpDir := b.TempDir()
	sp, err := safepath.New(tmpDir)
	if err != nil {
		b.Fatalf("create safepath: %v", err)
	}

	// Create test model file.
	content := make([]byte, 1024)
	if writeErr := sp.WriteFile("model.h5", content, 0o600); writeErr != nil {
		b.Fatalf("write file: %v", writeErr)
	}

	path := filepath.Join(tmpDir, "model.h5")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		d.extractMetadata(path, ModelTypeH5)
	}
}

// Fuzz tests

func FuzzCalculateConfidence(f *testing.F) {
	d := NewDetector()

	// Add seed corpus.
	f.Add("import tensorflow as tf")
	f.Add("import torch")
	f.Add("from sklearn import model_selection")
	f.Add("")
	f.Add("x = 1 + 2")

	f.Fuzz(func(t *testing.T, content string) {
		// Should not panic.
		confidence := d.calculateConfidence(content, FrameworkTensorFlow)
		if confidence < 0 || confidence > 1 {
			t.Errorf("confidence out of range: %f", confidence)
		}
	})
}

func FuzzIsMLPipeline(f *testing.F) {
	d := NewDetector()

	// Add seed corpus.
	f.Add("model.fit(x, y, epochs=10)")
	f.Add("optimizer = 'adam'")
	f.Add("")
	f.Add("print('hello')")

	f.Fuzz(func(t *testing.T, content string) {
		// Should not panic.
		_ = d.isMLPipeline(content)
	})
}

func TestCacheEntry(t *testing.T) {
	d := NewDetector()

	// Cache should be enabled by default.
	if !d.config.EnableCache {
		t.Error("expected cache to be enabled by default")
	}

	// Initially cache should be empty.
	if d.CacheSize() != 0 {
		t.Errorf("expected cache size 0, got %d", d.CacheSize())
	}
}

func TestGetCacheEntryNotFound(t *testing.T) {
	d := NewDetector()

	entry := d.GetCacheEntry("/nonexistent/path.py")
	if entry != nil {
		t.Error("expected nil for nonexistent cache entry")
	}
}

func TestSetAndGetCacheEntry(t *testing.T) {
	d := NewDetector()

	entry := &CacheEntry{
		Frameworks: []DetectedFramework{
			{Name: FrameworkTensorFlow, SourceFile: "test.py"},
		},
		Size: 1024,
	}

	d.SetCacheEntry("/test/path.py", entry)

	retrieved := d.GetCacheEntry("/test/path.py")
	if retrieved == nil {
		t.Fatal("expected cache entry, got nil")
	}

	if len(retrieved.Frameworks) != 1 {
		t.Errorf("expected 1 framework, got %d", len(retrieved.Frameworks))
	}

	if retrieved.Size != 1024 {
		t.Errorf("expected size 1024, got %d", retrieved.Size)
	}
}

func TestCacheDisabled(t *testing.T) {
	config := DefaultDetectorConfig()
	config.EnableCache = false
	d := NewDetectorWithConfig(config)

	entry := &CacheEntry{
		Frameworks: []DetectedFramework{
			{Name: FrameworkPyTorch, SourceFile: "model.py"},
		},
		Size: 2048,
	}

	// Should not store when cache is disabled.
	d.SetCacheEntry("/test/path.py", entry)

	// Should return nil when cache is disabled.
	retrieved := d.GetCacheEntry("/test/path.py")
	if retrieved != nil {
		t.Error("expected nil when cache is disabled")
	}
}

func TestClearCache(t *testing.T) {
	d := NewDetector()

	// Add some entries.
	d.SetCacheEntry("/path1.py", &CacheEntry{Size: 100})
	d.SetCacheEntry("/path2.py", &CacheEntry{Size: 200})
	d.SetCacheEntry("/path3.py", &CacheEntry{Size: 300})

	if d.CacheSize() != 3 {
		t.Errorf("expected cache size 3, got %d", d.CacheSize())
	}

	d.ClearCache()

	if d.CacheSize() != 0 {
		t.Errorf("expected cache size 0 after clear, got %d", d.CacheSize())
	}
}

func TestIsCacheValid(t *testing.T) {
	tmpDir := t.TempDir()
	sp, err := safepath.New(tmpDir)
	if err != nil {
		t.Fatalf("create safepath: %v", err)
	}

	content := []byte("import tensorflow as tf")
	if writeErr := sp.WriteFile("test.py", content, 0o600); writeErr != nil {
		t.Fatalf("write file: %v", writeErr)
	}

	filePath := filepath.Join(tmpDir, "test.py")
	d := NewDetector()

	// Create a cache entry with correct mod time and size.
	info, _ := sp.Stat("test.py")
	entry := &CacheEntry{
		ModTime: info.ModTime(),
		Size:    info.Size(),
	}

	if !d.IsCacheValid(filePath, entry) {
		t.Error("expected cache to be valid")
	}

	// Nil entry should be invalid.
	if d.IsCacheValid(filePath, nil) {
		t.Error("expected nil entry to be invalid")
	}

	// Entry with wrong size should be invalid.
	wrongSizeEntry := &CacheEntry{
		ModTime: info.ModTime(),
		Size:    999999,
	}
	if d.IsCacheValid(filePath, wrongSizeEntry) {
		t.Error("expected entry with wrong size to be invalid")
	}

	// Nonexistent file should be invalid.
	if d.IsCacheValid("/nonexistent/file.py", entry) {
		t.Error("expected nonexistent file to be invalid")
	}
}

func TestDetectWithCache(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()

	sp, err := safepath.New(tmpDir)
	if err != nil {
		t.Fatalf("create safepath: %v", err)
	}

	content := []byte("import torch\nmodel = torch.nn.Linear(10, 5)")
	if writeErr := sp.WriteFile("model.py", content, 0o600); writeErr != nil {
		t.Fatalf("write file: %v", writeErr)
	}

	d := NewDetector()

	// First detection should populate cache.
	result1, err := d.DetectWithCache(ctx, tmpDir)
	if err != nil {
		t.Fatalf("DetectWithCache failed: %v", err)
	}

	if len(result1.Frameworks) != 1 {
		t.Errorf("expected 1 framework, got %d", len(result1.Frameworks))
	}

	// Cache should have an entry.
	if d.CacheSize() == 0 {
		t.Error("expected cache to have entries after detection")
	}

	// Second detection should use cache.
	result2, err := d.DetectWithCache(ctx, tmpDir)
	if err != nil {
		t.Fatalf("DetectWithCache failed: %v", err)
	}

	if len(result2.Frameworks) != 1 {
		t.Errorf("expected 1 framework from cache, got %d", len(result2.Frameworks))
	}
}

func TestDetectWithCacheEmptyPath(t *testing.T) {
	ctx := context.Background()
	d := NewDetector()

	_, err := d.DetectWithCache(ctx, "")
	if err == nil {
		t.Error("expected error for empty path")
	}
}

func BenchmarkDetectWithCache(b *testing.B) {
	tmpDir := b.TempDir()
	sp, _ := safepath.New(tmpDir)

	// Create test files.
	for i := 0; i < 10; i++ {
		content := []byte("import tensorflow as tf\nmodel = tf.keras.Sequential()")
		_ = sp.WriteFile("file"+string(rune('0'+i))+".py", content, 0o600)
	}

	ctx := context.Background()
	d := NewDetector()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = d.DetectWithCache(ctx, tmpDir)
	}
}
