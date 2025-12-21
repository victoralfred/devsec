package ml

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"testing"

	"github.com/victoralfred/gowritter/safepath"
)

func TestExtractPyTorchMetadataFromPickle(t *testing.T) {
	tmpDir := t.TempDir()
	sp, err := safepath.New(tmpDir)
	if err != nil {
		t.Fatalf("create safepath: %v", err)
	}

	// Create a simple pickle file with protocol 2 header.
	// This is a minimal pickle that represents an empty dict.
	pickleContent := []byte{
		0x80, 0x02, // Protocol 2 marker
		0x7d, // EMPTY_DICT
		0x2e, // STOP
	}
	if writeErr := sp.WriteFile("model.pkl", pickleContent, 0o600); writeErr != nil {
		t.Fatalf("write pickle file: %v", writeErr)
	}

	info, err := ExtractPyTorchMetadata(tmpDir + "/model.pkl")
	if err != nil {
		t.Fatalf("extract metadata: %v", err)
	}

	if info == nil {
		t.Fatal("expected info, got nil")
	}
	if info.Format != "Python pickle" {
		t.Errorf("expected format 'Python pickle', got %s", info.Format)
	}
}

func TestExtractPyTorchMetadataFromZIP(t *testing.T) {
	tmpDir := t.TempDir()
	sp, err := safepath.New(tmpDir)
	if err != nil {
		t.Fatalf("create safepath: %v", err)
	}

	// Create a PyTorch-like ZIP file.
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)

	// Add version file.
	vf, err := w.Create("archive/version")
	if err != nil {
		t.Fatalf("create version: %v", err)
	}
	if _, writeErr := vf.Write([]byte("3")); writeErr != nil {
		t.Fatalf("write version: %v", writeErr)
	}

	// Add data.pkl with empty dict.
	pkl, err := w.Create("archive/data.pkl")
	if err != nil {
		t.Fatalf("create data.pkl: %v", err)
	}
	if _, writeErr := pkl.Write([]byte{0x80, 0x02, 0x7d, 0x2e}); writeErr != nil {
		t.Fatalf("write data.pkl: %v", writeErr)
	}

	if closeErr := w.Close(); closeErr != nil {
		t.Fatalf("close zip: %v", closeErr)
	}

	if writeErr := sp.WriteFile("model.pt", buf.Bytes(), 0o600); writeErr != nil {
		t.Fatalf("write pt file: %v", writeErr)
	}

	info, err := ExtractPyTorchMetadata(tmpDir + "/model.pt")
	if err != nil {
		t.Fatalf("extract metadata: %v", err)
	}

	if info == nil {
		t.Fatal("expected info, got nil")
	}
	if info.Format != "PyTorch ZIP archive" {
		t.Errorf("expected format 'PyTorch ZIP archive', got %s", info.Format)
	}
}

func TestExtractLayerName(t *testing.T) {
	tests := []struct {
		key  string
		want string
	}{
		{"conv1.weight", "conv1"},
		{"fc.bias", "fc"},
		{"bn1.running_mean", "bn1"},
		{"layer1.0.conv1.weight", "layer1.0.conv1"},
		{"embedding", "embedding"},
	}

	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			got := extractLayerName(tt.key)
			if got != tt.want {
				t.Errorf("extractLayerName(%q) = %q, want %q", tt.key, got, tt.want)
			}
		})
	}
}

func TestInferModelTypeFromLayers(t *testing.T) {
	//nolint:govet // Test struct field order for readability.
	tests := []struct {
		layers []string
		want   string
	}{
		{[]string{"transformer.encoder"}, "Transformer"},
		{[]string{"bert.embeddings"}, "BERT"},
		{[]string{"gpt_model.layer"}, "GPT"},
		{[]string{"resnet.layer1"}, "ResNet"},
		{[]string{"vgg.features"}, "VGG"},
		{[]string{"conv1", "conv2"}, "CNN"},
		{[]string{"linear", "fc"}, "MLP"},
		{[]string{"lstm.weight_ih"}, "LSTM"},
		{[]string{"gru.weight_hh"}, "GRU"},
		{[]string{"unknown_layer"}, "Unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := inferModelType(tt.layers)
			if got != tt.want {
				t.Errorf("inferModelType(%v) = %q, want %q", tt.layers, got, tt.want)
			}
		})
	}
}

func TestCategorizeParameter(t *testing.T) {
	info := &PyTorchModelInfo{
		Parameters: make(map[string]string),
	}

	categorizeParameter("conv1.weight", info)
	categorizeParameter("conv1.bias", info)
	categorizeParameter("bn1.running_mean", info)
	categorizeParameter("bn1.running_var", info)

	if info.Parameters["conv1.weight"] != "weight" {
		t.Errorf("expected weight, got %s", info.Parameters["conv1.weight"])
	}
	if info.Parameters["conv1.bias"] != "bias" {
		t.Errorf("expected bias, got %s", info.Parameters["conv1.bias"])
	}
	if len(info.Buffers) != 2 {
		t.Errorf("expected 2 buffers, got %d", len(info.Buffers))
	}
}

func TestParseLayerMap(t *testing.T) {
	layerMap := map[string]any{
		"class_name": "Dense",
		"config": map[string]any{
			"name":       "dense_1",
			"units":      float64(128),
			"activation": "relu",
			"trainable":  false,
		},
	}

	info := parseLayerMap(layerMap)

	if info.ClassName != "Dense" {
		t.Errorf("expected ClassName 'Dense', got %s", info.ClassName)
	}
	if info.Name != "dense_1" {
		t.Errorf("expected Name 'dense_1', got %s", info.Name)
	}
	if info.Units != 128 {
		t.Errorf("expected Units 128, got %d", info.Units)
	}
	if info.Activation != "relu" {
		t.Errorf("expected Activation 'relu', got %s", info.Activation)
	}
	if info.Trainable {
		t.Error("expected Trainable false")
	}
}

func TestParseOptimizerConfig(t *testing.T) {
	optCfg := map[string]any{
		"class_name": "Adam",
		"config": map[string]any{
			"learning_rate": 0.001,
			"beta_1":        0.9,
			"beta_2":        0.999,
			"epsilon":       1e-7,
		},
	}

	opt := parseOptimizerConfig(optCfg)

	if opt.ClassName != "Adam" {
		t.Errorf("expected ClassName 'Adam', got %s", opt.ClassName)
	}
	if opt.LearningRate != 0.001 {
		t.Errorf("expected LearningRate 0.001, got %f", opt.LearningRate)
	}
	if opt.Beta1 != 0.9 {
		t.Errorf("expected Beta1 0.9, got %f", opt.Beta1)
	}
}

func TestParseModelConfig(t *testing.T) {
	config := &KerasModelConfig{}
	modelCfgJSON := `{
		"class_name": "Sequential",
		"config": {
			"name": "sequential_1",
			"layers": [
				{
					"class_name": "Dense",
					"config": {"name": "dense_1", "units": 64}
				},
				{
					"class_name": "Dense",
					"config": {"name": "dense_2", "units": 10}
				}
			]
		}
	}`

	parseModelConfig(modelCfgJSON, config)

	if config.ClassName != "Sequential" {
		t.Errorf("expected ClassName 'Sequential', got %s", config.ClassName)
	}
	if config.ModelName != "sequential_1" {
		t.Errorf("expected ModelName 'sequential_1', got %s", config.ModelName)
	}
	if len(config.Layers) != 2 {
		t.Errorf("expected 2 layers, got %d", len(config.Layers))
	}
}

func TestParseTrainingConfig(t *testing.T) {
	config := &KerasModelConfig{}
	trainingCfgJSON := `{
		"optimizer_config": {
			"class_name": "Adam",
			"config": {"learning_rate": 0.001}
		},
		"loss": "categorical_crossentropy",
		"metrics": ["accuracy", "precision"]
	}`

	parseTrainingConfig(trainingCfgJSON, config)

	if config.Optimizer == nil {
		t.Fatal("expected Optimizer, got nil")
	}
	if config.Optimizer.ClassName != "Adam" {
		t.Errorf("expected Optimizer.ClassName 'Adam', got %s", config.Optimizer.ClassName)
	}
	if config.LossConfig == nil {
		t.Fatal("expected LossConfig, got nil")
	}
	if config.LossConfig.ClassName != "categorical_crossentropy" {
		t.Errorf("expected loss 'categorical_crossentropy', got %s", config.LossConfig.ClassName)
	}
	if len(config.Metrics) != 2 {
		t.Errorf("expected 2 metrics, got %d", len(config.Metrics))
	}
}

func TestAttrToString(t *testing.T) {
	tests := []struct {
		name  string
		input any
		want  string
		ok    bool
	}{
		{"string", "hello", "hello", true},
		{"bytes", []byte("world"), "world", true},
		{"string slice", []string{"first", "second"}, "first", true},
		{"empty slice", []string{}, "", false},
		{"int", 42, "", false},
		{"nil", nil, "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := attrToString(tt.input)
			if ok != tt.ok {
				t.Errorf("attrToString(%v) ok = %v, want %v", tt.input, ok, tt.ok)
			}
			if got != tt.want {
				t.Errorf("attrToString(%v) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestExtractModelMetadataToMap(t *testing.T) {
	// Test with non-existent file (should return empty map).
	result := ExtractModelMetadataToMap("/nonexistent/file.h5", ModelTypeH5)
	if len(result) != 0 {
		t.Errorf("expected empty map for non-existent file, got %v", result)
	}

	result = ExtractModelMetadataToMap("/nonexistent/file.pth", ModelTypePTH)
	if len(result) != 0 {
		t.Errorf("expected empty map for non-existent file, got %v", result)
	}
}

func TestKerasModelConfigJSON(t *testing.T) {
	config := KerasModelConfig{
		ClassName: "Sequential",
		ModelName: "my_model",
		KerasVer:  "2.12.0",
		Layers: []KerasLayerInfo{
			{Name: "dense_1", ClassName: "Dense", Units: 64, Activation: "relu"},
			{Name: "dense_2", ClassName: "Dense", Units: 10, Activation: "softmax"},
		},
		Optimizer: &OptimizerConfig{
			ClassName:    "Adam",
			LearningRate: 0.001,
		},
		LossConfig: &LossConfig{
			ClassName: "categorical_crossentropy",
		},
		Metrics: []string{"accuracy"},
	}

	data, err := json.Marshal(config)
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}

	var decoded KerasModelConfig
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal config: %v", err)
	}

	if decoded.ClassName != config.ClassName {
		t.Errorf("expected ClassName %s, got %s", config.ClassName, decoded.ClassName)
	}
	if len(decoded.Layers) != len(config.Layers) {
		t.Errorf("expected %d layers, got %d", len(config.Layers), len(decoded.Layers))
	}
}

func TestPyTorchModelInfoJSON(t *testing.T) {
	info := PyTorchModelInfo{
		StateDictKeys: []string{"conv1.weight", "conv1.bias"},
		LayerNames:    []string{"conv1"},
		TensorShapes:  map[string][]int{"conv1.weight": {64, 3, 3, 3}},
		TensorCount:   2,
		ModelType:     "CNN",
		Format:        "PyTorch ZIP archive",
		Parameters:    map[string]string{"conv1.weight": "weight"},
	}

	data, err := json.Marshal(info)
	if err != nil {
		t.Fatalf("marshal info: %v", err)
	}

	var decoded PyTorchModelInfo
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal info: %v", err)
	}

	if decoded.ModelType != info.ModelType {
		t.Errorf("expected ModelType %s, got %s", info.ModelType, decoded.ModelType)
	}
	if decoded.TensorCount != info.TensorCount {
		t.Errorf("expected TensorCount %d, got %d", info.TensorCount, decoded.TensorCount)
	}
}
