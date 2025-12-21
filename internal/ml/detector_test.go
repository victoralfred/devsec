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
