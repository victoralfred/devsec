package ml

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/victoralfred/gowritter/safepath"
)

func TestNewModelCardGenerator(t *testing.T) {
	gen := NewModelCardGenerator()
	if gen == nil {
		t.Fatal("expected generator, got nil")
	}
	if gen.detector == nil {
		t.Error("expected detector to be initialized")
	}
}

func TestGenerateFromPath(t *testing.T) {
	ctx := context.Background()
	gen := NewModelCardGenerator()

	tmpDir := t.TempDir()
	sp, err := safepath.New(tmpDir)
	if err != nil {
		t.Fatalf("create safepath: %v", err)
	}

	// Create Python file with TensorFlow.
	pyContent := []byte(`import tensorflow as tf`)
	if writeErr := sp.WriteFile("train.py", pyContent, 0o600); writeErr != nil {
		t.Fatalf("write Python file: %v", writeErr)
	}

	card, err := gen.GenerateFromPath(ctx, tmpDir)
	if err != nil {
		t.Fatalf("GenerateFromPath failed: %v", err)
	}

	if card == nil {
		t.Fatal("expected model card, got nil")
	}

	if card.ModelDetails.Name == "" {
		t.Error("expected model name to be set")
	}

	if card.ModelDetails.DateCreated.IsZero() {
		t.Error("expected DateCreated to be set")
	}
}

func TestGenerateFromPathEmptyPath(t *testing.T) {
	ctx := context.Background()
	gen := NewModelCardGenerator()

	_, err := gen.GenerateFromPath(ctx, "")
	if err == nil {
		t.Error("expected error for empty path")
	}
}

func TestGenerateFromPathContextCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	gen := NewModelCardGenerator()
	_, err := gen.GenerateFromPath(ctx, "/tmp")
	if err == nil {
		t.Error("expected error for canceled context")
	}
}

func TestGenerateFromModel(t *testing.T) {
	ctx := context.Background()
	gen := NewModelCardGenerator()

	tmpDir := t.TempDir()
	sp, err := safepath.New(tmpDir)
	if err != nil {
		t.Fatalf("create safepath: %v", err)
	}

	if writeErr := sp.WriteFile("model.h5", []byte("dummy"), 0o600); writeErr != nil {
		t.Fatalf("write model file: %v", writeErr)
	}

	modelPath := filepath.Join(tmpDir, "model.h5")
	card, err := gen.GenerateFromModel(ctx, modelPath)
	if err != nil {
		t.Fatalf("GenerateFromModel failed: %v", err)
	}

	if card.ModelDetails.Name != "model" {
		t.Errorf("expected name 'model', got %q", card.ModelDetails.Name)
	}

	if card.ModelDetails.Framework != string(FrameworkTensorFlow) {
		t.Errorf("expected framework 'tensorflow', got %q", card.ModelDetails.Framework)
	}
}

func TestGenerateFromModelEmptyPath(t *testing.T) {
	ctx := context.Background()
	gen := NewModelCardGenerator()

	_, err := gen.GenerateFromModel(ctx, "")
	if err == nil {
		t.Error("expected error for empty path")
	}
}

func TestGenerateFromModelContextCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	gen := NewModelCardGenerator()
	_, err := gen.GenerateFromModel(ctx, "/tmp/model.h5")
	if err == nil {
		t.Error("expected error for canceled context")
	}
}

func TestModelCardToJSON(t *testing.T) {
	card := &ModelCard{
		ModelDetails: ModelDetails{
			Name:      "test-model",
			Version:   "1.0.0",
			Framework: "tensorflow",
		},
		IntendedUse: IntendedUse{
			PrimaryUses: []string{"classification"},
		},
	}

	data, err := card.ToJSON()
	if err != nil {
		t.Fatalf("ToJSON failed: %v", err)
	}

	if len(data) == 0 {
		t.Error("expected non-empty JSON")
	}

	if !strings.Contains(string(data), "test-model") {
		t.Error("expected model name in JSON")
	}
}

func TestModelCardToMarkdown(t *testing.T) {
	card := &ModelCard{
		ModelDetails: ModelDetails{
			Name:        "test-model",
			Version:     "1.0.0",
			Framework:   "tensorflow",
			Description: "A test model",
		},
		IntendedUse: IntendedUse{
			PrimaryUses:    []string{"classification", "regression"},
			PrimaryUsers:   []string{"data scientists"},
			OutOfScopeUses: []string{"production without validation"},
		},
		Metrics: Metrics{
			PerformanceMetrics: []MetricValue{
				{Name: "accuracy", Value: 0.95, Description: "Test accuracy"},
			},
		},
		TrainingData: DataInfo{
			Datasets:   []string{"MNIST"},
			Motivation: "Standard benchmark",
		},
		EthicalConsider: EthicalConsider{
			Risks:       []string{"Potential bias"},
			Mitigations: []string{"Regular audits"},
		},
		CaveatsRecommend: CaveatsRecommend{
			Caveats:         []string{"Limited to specific domain"},
			Recommendations: []string{"Validate before production use"},
		},
	}

	md := card.ToMarkdown()
	if md == "" {
		t.Error("expected non-empty markdown")
	}

	// Check for key sections.
	sections := []string{
		"# Model Card",
		"## Model Details",
		"## Intended Use",
		"## Metrics",
		"## Training Data",
		"## Ethical Considerations",
		"## Caveats and Recommendations",
	}

	for _, section := range sections {
		if !strings.Contains(md, section) {
			t.Errorf("expected section %q in markdown", section)
		}
	}
}

func TestWriteAndReadModelCard(t *testing.T) {
	ctx := context.Background()

	tmpDir := t.TempDir()
	cardPath := filepath.Join(tmpDir, "model-card.json")

	original := &ModelCard{
		ModelDetails: ModelDetails{
			Name:      "test-model",
			Version:   "1.0.0",
			Framework: "pytorch",
		},
		IntendedUse: IntendedUse{
			PrimaryUses: []string{"image classification"},
		},
	}

	// Write JSON.
	if err := WriteModelCard(ctx, cardPath, original, "json"); err != nil {
		t.Fatalf("WriteModelCard failed: %v", err)
	}

	// Read back.
	loaded, err := ReadModelCard(ctx, cardPath)
	if err != nil {
		t.Fatalf("ReadModelCard failed: %v", err)
	}

	if loaded.ModelDetails.Name != original.ModelDetails.Name {
		t.Errorf("expected name %q, got %q", original.ModelDetails.Name, loaded.ModelDetails.Name)
	}
	if loaded.ModelDetails.Framework != original.ModelDetails.Framework {
		t.Errorf("expected framework %q, got %q", original.ModelDetails.Framework, loaded.ModelDetails.Framework)
	}
}

func TestWriteModelCardMarkdown(t *testing.T) {
	ctx := context.Background()

	tmpDir := t.TempDir()
	cardPath := filepath.Join(tmpDir, "model-card.md")

	card := &ModelCard{
		ModelDetails: ModelDetails{
			Name: "test-model",
		},
	}

	if err := WriteModelCard(ctx, cardPath, card, "markdown"); err != nil {
		t.Fatalf("WriteModelCard failed: %v", err)
	}

	// Verify file exists by reading it.
	sp, err := safepath.New(tmpDir)
	if err != nil {
		t.Fatalf("create safepath: %v", err)
	}

	data, err := sp.ReadFile("model-card.md")
	if err != nil {
		t.Fatalf("read file: %v", err)
	}

	if len(data) == 0 {
		t.Error("expected non-empty file")
	}
}

func TestWriteModelCardInvalidFormat(t *testing.T) {
	ctx := context.Background()

	tmpDir := t.TempDir()
	cardPath := filepath.Join(tmpDir, "model-card.txt")

	card := &ModelCard{}

	err := WriteModelCard(ctx, cardPath, card, "invalid")
	if err == nil {
		t.Error("expected error for invalid format")
	}
}

func TestWriteModelCardNilCard(t *testing.T) {
	ctx := context.Background()

	err := WriteModelCard(ctx, "/tmp/card.json", nil, "json")
	if err == nil {
		t.Error("expected error for nil card")
	}
}

func TestWriteModelCardContextCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	card := &ModelCard{}
	err := WriteModelCard(ctx, "/tmp/card.json", card, "json")
	if err == nil {
		t.Error("expected error for canceled context")
	}
}

func TestReadModelCardNotExists(t *testing.T) {
	ctx := context.Background()

	_, err := ReadModelCard(ctx, "/nonexistent/path/card.json")
	if err == nil {
		t.Error("expected error for non-existent file")
	}
}

func TestReadModelCardContextCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := ReadModelCard(ctx, "/tmp/card.json")
	if err == nil {
		t.Error("expected error for canceled context")
	}
}

func TestInferFrameworkFromExtension(t *testing.T) {
	gen := NewModelCardGenerator()

	tests := []struct {
		ext      string
		expected Framework
	}{
		{".h5", FrameworkTensorFlow},
		{".hdf5", FrameworkTensorFlow},
		{".pb", FrameworkTensorFlow},
		{".pt", FrameworkPyTorch},
		{".pth", FrameworkPyTorch},
		{".pkl", FrameworkScikit},
		{".onnx", FrameworkONNX},
		{".safetensors", FrameworkHuggingFace},
		{".unknown", FrameworkUnknown},
	}

	for _, tt := range tests {
		result := gen.inferFrameworkFromExtension(tt.ext)
		if result != tt.expected {
			t.Errorf("inferFrameworkFromExtension(%s) = %s, want %s", tt.ext, result, tt.expected)
		}
	}
}

func TestInferModelType(t *testing.T) {
	gen := NewModelCardGenerator()

	tests := []struct {
		ext      string
		contains string
	}{
		{".h5", "Keras"},
		{".pt", "PyTorch"},
		{".pkl", "Pickled"},
		{".onnx", "ONNX"},
		{".safetensors", "Safetensors"},
		{".ckpt", "Checkpoint"},
		{".unknown", "Unknown"},
	}

	for _, tt := range tests {
		result := gen.inferModelType(tt.ext)
		if !strings.Contains(result, tt.contains) {
			t.Errorf("inferModelType(%s) = %q, expected to contain %q", tt.ext, result, tt.contains)
		}
	}
}
