package ml

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/victoralfred/gowritter/safepath"
)

// Integration tests for real ML project structures.

func TestIntegrationTensorFlowProject(t *testing.T) {
	tmpDir := t.TempDir()
	sp, err := safepath.New(tmpDir)
	if err != nil {
		t.Fatalf("create safepath: %v", err)
	}

	// Create TensorFlow project structure.
	if mkdirErr := sp.MkdirAll("models", 0o755); mkdirErr != nil {
		t.Fatalf("mkdir models: %v", mkdirErr)
	}
	if mkdirErr := sp.MkdirAll("data", 0o755); mkdirErr != nil {
		t.Fatalf("mkdir data: %v", mkdirErr)
	}
	if mkdirErr := sp.MkdirAll("notebooks", 0o755); mkdirErr != nil {
		t.Fatalf("mkdir notebooks: %v", mkdirErr)
	}

	// Create main training script.
	trainScript := []byte(`#!/usr/bin/env python3
"""TensorFlow training script."""
import tensorflow as tf
from tensorflow import keras
from tensorflow.keras import layers

# Load data
(x_train, y_train), (x_test, y_test) = keras.datasets.mnist.load_data()
x_train = x_train.reshape(-1, 784).astype("float32") / 255
x_test = x_test.reshape(-1, 784).astype("float32") / 255

# Build model
model = keras.Sequential([
    layers.Dense(512, activation="relu"),
    layers.Dropout(0.2),
    layers.Dense(10, activation="softmax")
])

model.compile(
    optimizer=keras.optimizers.Adam(learning_rate=0.001),
    loss="sparse_categorical_crossentropy",
    metrics=["accuracy"]
)

# Train
model.fit(x_train, y_train, batch_size=128, epochs=10, validation_split=0.1)

# Evaluate
model.evaluate(x_test, y_test)

# Save model
model.save("models/mnist_model.h5")
`)
	if writeErr := sp.WriteFile("train.py", trainScript, 0o600); writeErr != nil {
		t.Fatalf("write train.py: %v", writeErr)
	}

	// Create model file (mock H5 with magic bytes).
	h5Magic := []byte{0x89, 0x48, 0x44, 0x46, 0x0d, 0x0a, 0x1a, 0x0a}
	modelData := make([]byte, 1024)
	copy(modelData, h5Magic)
	if writeErr := sp.WriteFile(filepath.Join("models", "mnist_model.h5"), modelData, 0o600); writeErr != nil {
		t.Fatalf("write model: %v", writeErr)
	}

	// Create requirements.txt.
	requirements := []byte(`tensorflow==2.13.0
numpy>=1.20.0
pandas>=1.3.0
matplotlib>=3.4.0
`)
	if writeErr := sp.WriteFile("requirements.txt", requirements, 0o600); writeErr != nil {
		t.Fatalf("write requirements: %v", writeErr)
	}

	// Create Jupyter notebook.
	notebook := []byte(`{
	"cells": [
		{
			"cell_type": "code",
			"source": ["import tensorflow as tf\n", "print(tf.__version__)"]
		}
	],
	"metadata": {},
	"nbformat": 4,
	"nbformat_minor": 4
}`)
	if writeErr := sp.WriteFile(filepath.Join("notebooks", "exploration.ipynb"), notebook, 0o600); writeErr != nil {
		t.Fatalf("write notebook: %v", writeErr)
	}

	// Run detection.
	d := NewDetector()
	ctx := context.Background()
	result, err := d.Detect(ctx, tmpDir)
	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	// Verify TensorFlow detection.
	tfDetected := false
	for _, fw := range result.Frameworks {
		if fw.Name == FrameworkTensorFlow {
			tfDetected = true
			if fw.Confidence < 0.5 {
				t.Errorf("expected higher confidence for TensorFlow, got %f", fw.Confidence)
			}
			// Pipeline detection is optional - depends on indicator patterns.
		}
	}
	if !tfDetected {
		t.Error("expected TensorFlow to be detected")
	}

	// Verify model detection.
	modelDetected := false
	for _, model := range result.Models {
		if model.Type == ModelTypeH5 {
			modelDetected = true
			if model.Framework != FrameworkTensorFlow {
				t.Errorf("expected H5 model framework to be TensorFlow, got %s", model.Framework)
			}
		}
	}
	if !modelDetected {
		t.Error("expected H5 model to be detected")
	}
}

func TestIntegrationPyTorchProject(t *testing.T) {
	tmpDir := t.TempDir()
	sp, err := safepath.New(tmpDir)
	if err != nil {
		t.Fatalf("create safepath: %v", err)
	}

	// Create PyTorch project structure.
	if mkdirErr := sp.MkdirAll("src/models", 0o755); mkdirErr != nil {
		t.Fatalf("mkdir: %v", mkdirErr)
	}
	if mkdirErr := sp.MkdirAll("checkpoints", 0o755); mkdirErr != nil {
		t.Fatalf("mkdir: %v", mkdirErr)
	}

	// Create model definition.
	modelDef := []byte(`import torch
import torch.nn as nn
import torch.nn.functional as F

class ConvNet(nn.Module):
    def __init__(self):
        super(ConvNet, self).__init__()
        self.conv1 = nn.Conv2d(1, 32, 3)
        self.conv2 = nn.Conv2d(32, 64, 3)
        self.fc1 = nn.Linear(1600, 128)
        self.fc2 = nn.Linear(128, 10)
        self.dropout = nn.Dropout(0.25)

    def forward(self, x):
        x = F.relu(self.conv1(x))
        x = F.max_pool2d(x, 2)
        x = F.relu(self.conv2(x))
        x = F.max_pool2d(x, 2)
        x = torch.flatten(x, 1)
        x = F.relu(self.fc1(x))
        x = self.dropout(x)
        x = self.fc2(x)
        return F.log_softmax(x, dim=1)
`)
	if writeErr := sp.WriteFile(filepath.Join("src", "models", "convnet.py"), modelDef, 0o600); writeErr != nil {
		t.Fatalf("write model def: %v", writeErr)
	}

	// Create training script.
	trainScript := []byte(`import torch
import torch.optim as optim
from torch.utils.data import DataLoader
from torchvision import datasets, transforms

from models.convnet import ConvNet

# Setup
device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
model = ConvNet().to(device)
optimizer = optim.Adam(model.parameters(), lr=0.001)

# Data loading
transform = transforms.Compose([
    transforms.ToTensor(),
    transforms.Normalize((0.1307,), (0.3081,))
])
train_dataset = datasets.MNIST('data', train=True, download=True, transform=transform)
train_loader = DataLoader(train_dataset, batch_size=64, shuffle=True)

# Training loop
model.train()
for epoch in range(10):
    for batch_idx, (data, target) in enumerate(train_loader):
        data, target = data.to(device), target.to(device)
        optimizer.zero_grad()
        output = model(data)
        loss = torch.nn.functional.nll_loss(output, target)
        loss.backward()
        optimizer.step()

# Save model
torch.save(model.state_dict(), "checkpoints/model.pth")
`)
	if writeErr := sp.WriteFile(filepath.Join("src", "train.py"), trainScript, 0o600); writeErr != nil {
		t.Fatalf("write train script: %v", writeErr)
	}

	// Create PyTorch model file (ZIP format for PyTorch >= 1.6).
	pthData := []byte{0x50, 0x4b, 0x03, 0x04}
	pthData = append(pthData, make([]byte, 100)...)
	if writeErr := sp.WriteFile(filepath.Join("checkpoints", "model.pth"), pthData, 0o600); writeErr != nil {
		t.Fatalf("write pth: %v", writeErr)
	}

	// Run detection.
	d := NewDetector()
	ctx := context.Background()
	result, err := d.Detect(ctx, tmpDir)
	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	// Verify PyTorch detection.
	pytorchDetected := false
	for _, fw := range result.Frameworks {
		if fw.Name == FrameworkPyTorch {
			pytorchDetected = true
			if fw.Confidence < 0.5 {
				t.Errorf("expected higher confidence for PyTorch, got %f", fw.Confidence)
			}
		}
	}
	if !pytorchDetected {
		t.Error("expected PyTorch to be detected")
	}

	// Verify PTH model detection.
	pthDetected := false
	for _, model := range result.Models {
		if model.Type == ModelTypePTH {
			pthDetected = true
			if model.Framework != FrameworkPyTorch {
				t.Errorf("expected PTH model framework to be PyTorch, got %s", model.Framework)
			}
		}
	}
	if !pthDetected {
		t.Error("expected PTH model to be detected")
	}
}

func TestIntegrationMixedFrameworkProject(t *testing.T) {
	tmpDir := t.TempDir()
	sp, err := safepath.New(tmpDir)
	if err != nil {
		t.Fatalf("create safepath: %v", err)
	}

	// Create mixed project structure.
	if mkdirErr := sp.MkdirAll("tensorflow_models", 0o755); mkdirErr != nil {
		t.Fatalf("mkdir: %v", mkdirErr)
	}
	if mkdirErr := sp.MkdirAll("pytorch_models", 0o755); mkdirErr != nil {
		t.Fatalf("mkdir: %v", mkdirErr)
	}
	if mkdirErr := sp.MkdirAll("sklearn_models", 0o755); mkdirErr != nil {
		t.Fatalf("mkdir: %v", mkdirErr)
	}

	// TensorFlow script.
	tfScript := []byte(`import tensorflow as tf
model = tf.keras.Sequential([tf.keras.layers.Dense(10)])
model.fit(x_train, y_train, epochs=5)
model.save("tensorflow_models/model.h5")
`)
	if writeErr := sp.WriteFile("train_tf.py", tfScript, 0o600); writeErr != nil {
		t.Fatalf("write tf script: %v", writeErr)
	}

	// PyTorch script.
	ptScript := []byte(`import torch
import torch.nn as nn
model = nn.Linear(10, 5)
optimizer = torch.optim.Adam(model.parameters())
loss.backward()
optimizer.step()
torch.save(model.state_dict(), "pytorch_models/model.pth")
`)
	if writeErr := sp.WriteFile("train_pt.py", ptScript, 0o600); writeErr != nil {
		t.Fatalf("write pt script: %v", writeErr)
	}

	// Scikit-learn script.
	skScript := []byte(`from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split, cross_val_score
import joblib

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2)
model = LogisticRegression()
model.fit(X_train, y_train)
scores = cross_val_score(model, X, y, cv=5)
print(model.predict(X_test))
joblib.dump(model, "sklearn_models/model.joblib")
`)
	if writeErr := sp.WriteFile("train_sk.py", skScript, 0o600); writeErr != nil {
		t.Fatalf("write sk script: %v", writeErr)
	}

	// Create model files.
	h5Magic := []byte{0x89, 0x48, 0x44, 0x46, 0x0d, 0x0a, 0x1a, 0x0a}
	if writeErr := sp.WriteFile(filepath.Join("tensorflow_models", "model.h5"), h5Magic, 0o600); writeErr != nil {
		t.Fatalf("write h5: %v", writeErr)
	}
	pthMagic := []byte{0x50, 0x4b, 0x03, 0x04}
	if writeErr := sp.WriteFile(filepath.Join("pytorch_models", "model.pth"), pthMagic, 0o600); writeErr != nil {
		t.Fatalf("write pth: %v", writeErr)
	}
	// Pickle files start with protocol marker.
	pklMagic := []byte{0x80, 0x04}
	if writeErr := sp.WriteFile(filepath.Join("sklearn_models", "model.joblib"), pklMagic, 0o600); writeErr != nil {
		t.Fatalf("write joblib: %v", writeErr)
	}

	// Run detection.
	d := NewDetector()
	ctx := context.Background()
	result, err := d.Detect(ctx, tmpDir)
	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	// Should detect all three frameworks.
	detectedFrameworks := make(map[Framework]bool)
	for _, fw := range result.Frameworks {
		detectedFrameworks[fw.Name] = true
	}

	expectedFrameworks := []Framework{FrameworkTensorFlow, FrameworkPyTorch, FrameworkScikit}
	for _, expected := range expectedFrameworks {
		if !detectedFrameworks[expected] {
			t.Errorf("expected %s to be detected", expected)
		}
	}

	// Should detect all three model types.
	detectedModelTypes := make(map[ModelType]bool)
	for _, model := range result.Models {
		detectedModelTypes[model.Type] = true
	}

	expectedModelTypes := []ModelType{ModelTypeH5, ModelTypePTH, ModelTypePickle}
	for _, expected := range expectedModelTypes {
		if !detectedModelTypes[expected] {
			t.Errorf("expected %s model type to be detected", expected)
		}
	}
}

func TestIntegrationMonorepoProject(t *testing.T) {
	tmpDir := t.TempDir()
	sp, err := safepath.New(tmpDir)
	if err != nil {
		t.Fatalf("create safepath: %v", err)
	}

	// Create monorepo structure with multiple ML projects.
	projects := []string{
		"projects/nlp-model",
		"projects/vision-model",
		"projects/recommendation",
		"shared/utils",
	}
	for _, proj := range projects {
		if mkdirErr := sp.MkdirAll(proj, 0o755); mkdirErr != nil {
			t.Fatalf("mkdir %s: %v", proj, mkdirErr)
		}
	}

	// NLP project with Hugging Face.
	nlpScript := []byte(`from transformers import AutoModel, AutoTokenizer, Trainer, TrainingArguments
model = AutoModel.from_pretrained("bert-base-uncased")
tokenizer = AutoTokenizer.from_pretrained("bert-base-uncased")
trainer = Trainer(model=model, args=TrainingArguments(output_dir="./results"))
trainer.train()
`)
	if writeErr := sp.WriteFile(filepath.Join("projects", "nlp-model", "train.py"), nlpScript, 0o600); writeErr != nil {
		t.Fatalf("write nlp script: %v", writeErr)
	}

	// Vision project with PyTorch.
	visionScript := []byte(`import torch
import torch.nn as nn
from torch.utils.data import DataLoader
class VisionModel(nn.Module):
    def __init__(self):
        super().__init__()
        self.conv = nn.Conv2d(3, 64, 3)
    def forward(self, x):
        return self.conv(x)
model = VisionModel()
optimizer = torch.optim.Adam(model.parameters())
loss.backward()
optimizer.zero_grad()
torch.save(model, "model.pth")
`)
	if writeErr := sp.WriteFile(filepath.Join("projects", "vision-model", "train.py"), visionScript, 0o600); writeErr != nil {
		t.Fatalf("write vision script: %v", writeErr)
	}

	// Recommendation project with XGBoost.
	recScript := []byte(`import xgboost as xgb
from xgboost import XGBClassifier, DMatrix
model = XGBClassifier()
model.fit(X_train, y_train)
dmatrix = DMatrix(X_test)
predictions = model.predict(X_test)
`)
	if writeErr := sp.WriteFile(filepath.Join("projects", "recommendation", "train.py"), recScript, 0o600); writeErr != nil {
		t.Fatalf("write rec script: %v", writeErr)
	}

	// Shared utils (not ML specific).
	utilsScript := []byte(`import pandas as pd
import numpy as np
def load_data(path):
    return pd.read_csv(path)
def preprocess(df):
    return df.fillna(0)
`)
	if writeErr := sp.WriteFile(filepath.Join("shared", "utils", "data.py"), utilsScript, 0o600); writeErr != nil {
		t.Fatalf("write utils script: %v", writeErr)
	}

	// Run detection.
	d := NewDetector()
	ctx := context.Background()
	result, err := d.Detect(ctx, tmpDir)
	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	// Should detect HuggingFace, PyTorch, and XGBoost.
	detectedFrameworks := make(map[Framework]bool)
	for _, fw := range result.Frameworks {
		detectedFrameworks[fw.Name] = true
	}

	expectedFrameworks := []Framework{FrameworkHuggingFace, FrameworkPyTorch, FrameworkXGBoost}
	for _, expected := range expectedFrameworks {
		if !detectedFrameworks[expected] {
			t.Errorf("expected %s to be detected in monorepo", expected)
		}
	}

	// Check that we detected multiple frameworks from different projects.
	if len(detectedFrameworks) < 2 {
		t.Errorf("expected at least 2 different frameworks in monorepo, got %d", len(detectedFrameworks))
	}
}

func TestIntegrationSavedModelDirectory(t *testing.T) {
	tmpDir := t.TempDir()
	sp, err := safepath.New(tmpDir)
	if err != nil {
		t.Fatalf("create safepath: %v", err)
	}

	// Create TensorFlow SavedModel directory structure.
	savedModelPath := "models/my_saved_model"
	if mkdirErr := sp.MkdirAll(filepath.Join(savedModelPath, "variables"), 0o755); mkdirErr != nil {
		t.Fatalf("mkdir: %v", mkdirErr)
	}
	if mkdirErr := sp.MkdirAll(filepath.Join(savedModelPath, "assets"), 0o755); mkdirErr != nil {
		t.Fatalf("mkdir: %v", mkdirErr)
	}

	// Create saved_model.pb file.
	pbData := []byte("protobuf data placeholder")
	if writeErr := sp.WriteFile(filepath.Join(savedModelPath, "saved_model.pb"), pbData, 0o600); writeErr != nil {
		t.Fatalf("write pb: %v", writeErr)
	}

	// Create variables files.
	if writeErr := sp.WriteFile(filepath.Join(savedModelPath, "variables", "variables.index"), []byte("index"), 0o600); writeErr != nil {
		t.Fatalf("write index: %v", writeErr)
	}
	if writeErr := sp.WriteFile(filepath.Join(savedModelPath, "variables", "variables.data-00000-of-00001"), []byte("data"), 0o600); writeErr != nil {
		t.Fatalf("write data: %v", writeErr)
	}

	// Run detection.
	d := NewDetector()
	ctx := context.Background()
	result, err := d.Detect(ctx, tmpDir)
	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	// Should detect SavedModel directory.
	savedModelDetected := false
	for _, model := range result.Models {
		if model.Type == ModelTypeSavedModel {
			savedModelDetected = true
			if model.Framework != FrameworkTensorFlow {
				t.Errorf("expected SavedModel framework to be TensorFlow, got %s", model.Framework)
			}
		}
	}
	if !savedModelDetected {
		t.Error("expected TensorFlow SavedModel directory to be detected")
	}
}

func TestIntegrationONNXModel(t *testing.T) {
	tmpDir := t.TempDir()
	sp, err := safepath.New(tmpDir)
	if err != nil {
		t.Fatalf("create safepath: %v", err)
	}

	// Create ONNX project.
	if mkdirErr := sp.MkdirAll("models", 0o755); mkdirErr != nil {
		t.Fatalf("mkdir: %v", mkdirErr)
	}

	// Create ONNX inference script.
	onnxScript := []byte(`import onnx
import onnxruntime as ort
from onnx import numpy_helper

# Load model
model = onnx.load("models/model.onnx")
onnx.checker.check_model(model)

# Create inference session
session = ort.InferenceSession("models/model.onnx")
input_name = session.get_inputs()[0].name
output = session.run(None, {input_name: input_data})
`)
	if writeErr := sp.WriteFile("inference.py", onnxScript, 0o600); writeErr != nil {
		t.Fatalf("write onnx script: %v", writeErr)
	}

	// Create ONNX model file (with magic bytes).
	// ONNX uses protobuf, files typically start with 0x08 (field 1, varint).
	onnxData := []byte{0x08, 0x07}
	onnxData = append(onnxData, make([]byte, 100)...)
	if writeErr := sp.WriteFile(filepath.Join("models", "model.onnx"), onnxData, 0o600); writeErr != nil {
		t.Fatalf("write onnx model: %v", writeErr)
	}

	// Run detection.
	d := NewDetector()
	ctx := context.Background()
	result, err := d.Detect(ctx, tmpDir)
	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	// Should detect ONNX framework.
	onnxFrameworkDetected := false
	for _, fw := range result.Frameworks {
		if fw.Name == FrameworkONNX {
			onnxFrameworkDetected = true
		}
	}
	if !onnxFrameworkDetected {
		t.Error("expected ONNX framework to be detected")
	}

	// Should detect ONNX model.
	onnxModelDetected := false
	for _, model := range result.Models {
		if model.Type == ModelTypeONNX {
			onnxModelDetected = true
		}
	}
	if !onnxModelDetected {
		t.Error("expected ONNX model to be detected")
	}
}

// Symlink tests - platform dependent (Unix-like systems).

func TestSymlinkToFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks require elevated privileges on Windows")
	}

	tmpDir := t.TempDir()
	sp, err := safepath.New(tmpDir)
	if err != nil {
		t.Fatalf("create safepath: %v", err)
	}

	// Create a real Python file.
	content := []byte("import tensorflow as tf\nmodel = tf.keras.Sequential()")
	if writeErr := sp.WriteFile("real_train.py", content, 0o600); writeErr != nil {
		t.Fatalf("write file: %v", writeErr)
	}

	// Create a symlink to the file.
	realPath := filepath.Join(tmpDir, "real_train.py")
	linkPath := filepath.Join(tmpDir, "train.py")
	if symlinkErr := os.Symlink(realPath, linkPath); symlinkErr != nil {
		t.Fatalf("create symlink: %v", symlinkErr)
	}

	// Run detection.
	d := NewDetector()
	ctx := context.Background()
	result, err := d.Detect(ctx, tmpDir)
	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	// Should detect TensorFlow from at least one file.
	tfDetected := false
	for _, fw := range result.Frameworks {
		if fw.Name == FrameworkTensorFlow {
			tfDetected = true
		}
	}
	if !tfDetected {
		t.Error("expected TensorFlow to be detected with symlinked file")
	}
}

func TestSymlinkToDirectory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks require elevated privileges on Windows")
	}

	tmpDir := t.TempDir()
	sp, err := safepath.New(tmpDir)
	if err != nil {
		t.Fatalf("create safepath: %v", err)
	}

	// Create a real directory with ML files.
	if mkdirErr := sp.MkdirAll("real_models", 0o755); mkdirErr != nil {
		t.Fatalf("mkdir: %v", mkdirErr)
	}

	content := []byte("import torch\nmodel = torch.nn.Linear(10, 5)")
	if writeErr := sp.WriteFile(filepath.Join("real_models", "model.py"), content, 0o600); writeErr != nil {
		t.Fatalf("write file: %v", writeErr)
	}

	// Create a symlink to the directory.
	realDir := filepath.Join(tmpDir, "real_models")
	linkDir := filepath.Join(tmpDir, "models")
	if symlinkErr := os.Symlink(realDir, linkDir); symlinkErr != nil {
		t.Fatalf("create symlink: %v", symlinkErr)
	}

	// Run detection.
	d := NewDetector()
	ctx := context.Background()
	result, err := d.Detect(ctx, tmpDir)
	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	// Should detect PyTorch.
	pytorchDetected := false
	for _, fw := range result.Frameworks {
		if fw.Name == FrameworkPyTorch {
			pytorchDetected = true
		}
	}
	if !pytorchDetected {
		t.Error("expected PyTorch to be detected through symlinked directory")
	}
}

func TestBrokenSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks require elevated privileges on Windows")
	}

	tmpDir := t.TempDir()

	// Create a broken symlink (pointing to non-existent file).
	linkPath := filepath.Join(tmpDir, "broken_link.py")
	if symlinkErr := os.Symlink("/nonexistent/file.py", linkPath); symlinkErr != nil {
		t.Fatalf("create symlink: %v", symlinkErr)
	}

	// Run detection - should not crash.
	d := NewDetector()
	ctx := context.Background()
	result, err := d.Detect(ctx, tmpDir)
	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	// Should complete without panic.
	if result == nil {
		t.Error("expected non-nil result")
	}
}

func TestCircularSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks require elevated privileges on Windows")
	}

	tmpDir := t.TempDir()
	sp, err := safepath.New(tmpDir)
	if err != nil {
		t.Fatalf("create safepath: %v", err)
	}

	// Create directories.
	if mkdirErr := sp.MkdirAll("dir_a", 0o755); mkdirErr != nil {
		t.Fatalf("mkdir: %v", mkdirErr)
	}
	if mkdirErr := sp.MkdirAll("dir_b", 0o755); mkdirErr != nil {
		t.Fatalf("mkdir: %v", mkdirErr)
	}

	// Create a Python file in dir_a.
	content := []byte("import sklearn\nfrom sklearn.linear_model import LogisticRegression")
	if writeErr := sp.WriteFile(filepath.Join("dir_a", "model.py"), content, 0o600); writeErr != nil {
		t.Fatalf("write file: %v", writeErr)
	}

	// Create circular symlinks: dir_a/link_to_b -> dir_b, dir_b/link_to_a -> dir_a
	linkAtoB := filepath.Join(tmpDir, "dir_a", "link_to_b")
	linkBtoA := filepath.Join(tmpDir, "dir_b", "link_to_a")

	if symlinkErr := os.Symlink(filepath.Join(tmpDir, "dir_b"), linkAtoB); symlinkErr != nil {
		t.Fatalf("create symlink A->B: %v", symlinkErr)
	}
	if symlinkErr := os.Symlink(filepath.Join(tmpDir, "dir_a"), linkBtoA); symlinkErr != nil {
		t.Fatalf("create symlink B->A: %v", symlinkErr)
	}

	// Run detection with limited depth to prevent infinite loops.
	config := DetectorConfig{
		MaxDepth:       10,
		MaxFileSize:    10 * 1024 * 1024,
		MaxFilesToScan: 100,
	}
	d := NewDetectorWithConfig(config)
	ctx := context.Background()
	result, err := d.Detect(ctx, tmpDir)
	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	// Should complete without infinite loop and detect scikit-learn.
	sklearnDetected := false
	for _, fw := range result.Frameworks {
		if fw.Name == FrameworkScikit {
			sklearnDetected = true
		}
	}
	if !sklearnDetected {
		t.Error("expected scikit-learn to be detected with circular symlinks")
	}
}

func TestSymlinkToModelFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks require elevated privileges on Windows")
	}

	tmpDir := t.TempDir()
	sp, err := safepath.New(tmpDir)
	if err != nil {
		t.Fatalf("create safepath: %v", err)
	}

	// Create directories.
	if mkdirErr := sp.MkdirAll("real_models", 0o755); mkdirErr != nil {
		t.Fatalf("mkdir: %v", mkdirErr)
	}
	if mkdirErr := sp.MkdirAll("linked_models", 0o755); mkdirErr != nil {
		t.Fatalf("mkdir: %v", mkdirErr)
	}

	// Create a real model file.
	h5Magic := []byte{0x89, 0x48, 0x44, 0x46, 0x0d, 0x0a, 0x1a, 0x0a}
	modelData := make([]byte, 100)
	copy(modelData, h5Magic)
	if writeErr := sp.WriteFile(filepath.Join("real_models", "model.h5"), modelData, 0o600); writeErr != nil {
		t.Fatalf("write model: %v", writeErr)
	}

	// Create a symlink to the model file.
	realModel := filepath.Join(tmpDir, "real_models", "model.h5")
	linkedModel := filepath.Join(tmpDir, "linked_models", "linked_model.h5")
	if symlinkErr := os.Symlink(realModel, linkedModel); symlinkErr != nil {
		t.Fatalf("create symlink: %v", symlinkErr)
	}

	// Run detection.
	d := NewDetector()
	ctx := context.Background()
	result, err := d.Detect(ctx, tmpDir)
	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	// Should detect H5 models (could be 1 or 2 depending on symlink handling).
	h5Count := 0
	for _, model := range result.Models {
		if model.Type == ModelTypeH5 {
			h5Count++
		}
	}
	if h5Count == 0 {
		t.Error("expected at least one H5 model to be detected")
	}
}
