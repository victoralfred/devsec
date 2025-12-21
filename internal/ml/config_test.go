package ml

import (
	"path/filepath"
	"testing"

	"github.com/victoralfred/gowritter/safepath"
)

func TestDefaultMLConfig(t *testing.T) {
	config := DefaultMLConfig()

	// Check detection defaults.
	if config.Detection.MaxFileSize != 10*1024*1024 {
		t.Errorf("expected MaxFileSize 10MB, got %d", config.Detection.MaxFileSize)
	}
	if config.Detection.MaxDepth != 50 {
		t.Errorf("expected MaxDepth 50, got %d", config.Detection.MaxDepth)
	}
	if config.Detection.MaxFilesToScan != 10000 {
		t.Errorf("expected MaxFilesToScan 10000, got %d", config.Detection.MaxFilesToScan)
	}

	// Check validation defaults.
	if config.Validation.DriftThreshold != 0.1 {
		t.Errorf("expected DriftThreshold 0.1, got %f", config.Validation.DriftThreshold)
	}

	// Check fairness defaults.
	if config.Fairness.DisparateImpactThreshold != 0.8 {
		t.Errorf("expected DisparateImpactThreshold 0.8, got %f", config.Fairness.DisparateImpactThreshold)
	}
	if config.Fairness.StatisticalParityThreshold != 0.1 {
		t.Errorf("expected StatisticalParityThreshold 0.1, got %f", config.Fairness.StatisticalParityThreshold)
	}

	// Check bias defaults.
	if config.Bias.SamplingBiasThreshold != 0.3 {
		t.Errorf("expected SamplingBiasThreshold 0.3, got %f", config.Bias.SamplingBiasThreshold)
	}
}

func TestLoadConfigJSON(t *testing.T) {
	tmpDir := t.TempDir()
	sp, err := safepath.New(tmpDir)
	if err != nil {
		t.Fatalf("create safepath: %v", err)
	}

	configContent := []byte(`{
		"detection": {
			"max_file_size": 5242880,
			"max_depth": 25,
			"max_files_to_scan": 5000
		},
		"validation": {
			"drift_threshold": 0.2
		},
		"fairness": {
			"disparate_impact_threshold": 0.9
		},
		"bias": {
			"sampling_bias_threshold": 0.4
		}
	}`)
	if writeErr := sp.WriteFile("config.json", configContent, 0o600); writeErr != nil {
		t.Fatalf("write config: %v", writeErr)
	}

	configPath := filepath.Join(tmpDir, "config.json")
	config, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	if config.Detection.MaxFileSize != 5242880 {
		t.Errorf("expected MaxFileSize 5242880, got %d", config.Detection.MaxFileSize)
	}
	if config.Detection.MaxDepth != 25 {
		t.Errorf("expected MaxDepth 25, got %d", config.Detection.MaxDepth)
	}
	if config.Validation.DriftThreshold != 0.2 {
		t.Errorf("expected DriftThreshold 0.2, got %f", config.Validation.DriftThreshold)
	}
	if config.Fairness.DisparateImpactThreshold != 0.9 {
		t.Errorf("expected DisparateImpactThreshold 0.9, got %f", config.Fairness.DisparateImpactThreshold)
	}
}

func TestLoadConfigYAML(t *testing.T) {
	tmpDir := t.TempDir()
	sp, err := safepath.New(tmpDir)
	if err != nil {
		t.Fatalf("create safepath: %v", err)
	}

	configContent := []byte(`
detection:
  max_file_size: 1048576
  max_depth: 10
validation:
  drift_threshold: 0.3
fairness:
  disparate_impact_threshold: 0.75
bias:
  sampling_bias_threshold: 0.5
`)
	if writeErr := sp.WriteFile("config.yaml", configContent, 0o600); writeErr != nil {
		t.Fatalf("write config: %v", writeErr)
	}

	configPath := filepath.Join(tmpDir, "config.yaml")
	config, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	if config.Detection.MaxFileSize != 1048576 {
		t.Errorf("expected MaxFileSize 1048576, got %d", config.Detection.MaxFileSize)
	}
	if config.Detection.MaxDepth != 10 {
		t.Errorf("expected MaxDepth 10, got %d", config.Detection.MaxDepth)
	}
	if config.Validation.DriftThreshold != 0.3 {
		t.Errorf("expected DriftThreshold 0.3, got %f", config.Validation.DriftThreshold)
	}
}

func TestLoadConfigEmptyPath(t *testing.T) {
	_, err := LoadConfig("")
	if err == nil {
		t.Error("expected error for empty path")
	}
}

func TestLoadConfigUnsupportedFormat(t *testing.T) {
	tmpDir := t.TempDir()
	sp, err := safepath.New(tmpDir)
	if err != nil {
		t.Fatalf("create safepath: %v", err)
	}

	if writeErr := sp.WriteFile("config.txt", []byte("data"), 0o600); writeErr != nil {
		t.Fatalf("write config: %v", writeErr)
	}

	configPath := filepath.Join(tmpDir, "config.txt")
	_, err = LoadConfig(configPath)
	if err == nil {
		t.Error("expected error for unsupported format")
	}
}

func TestLoadConfigFromEnv(t *testing.T) {
	// Set environment variables using t.Setenv (automatically cleaned up).
	t.Setenv("DEVSEC_ML_MAX_FILE_SIZE", "2097152")
	t.Setenv("DEVSEC_ML_DRIFT_THRESHOLD", "0.25")

	config, err := LoadConfigFromEnv("")
	if err != nil {
		t.Fatalf("LoadConfigFromEnv failed: %v", err)
	}

	if config.Detection.MaxFileSize != 2097152 {
		t.Errorf("expected MaxFileSize 2097152, got %d", config.Detection.MaxFileSize)
	}
	if config.Validation.DriftThreshold != 0.25 {
		t.Errorf("expected DriftThreshold 0.25, got %f", config.Validation.DriftThreshold)
	}
}

func TestLoadConfigFromEnvWithFile(t *testing.T) {
	tmpDir := t.TempDir()
	sp, err := safepath.New(tmpDir)
	if err != nil {
		t.Fatalf("create safepath: %v", err)
	}

	configContent := []byte(`{
		"detection": {
			"max_file_size": 1000000
		}
	}`)
	if writeErr := sp.WriteFile("config.json", configContent, 0o600); writeErr != nil {
		t.Fatalf("write config: %v", writeErr)
	}

	// Environment variable should override file value.
	t.Setenv("DEVSEC_ML_MAX_FILE_SIZE", "5000000")

	configPath := filepath.Join(tmpDir, "config.json")
	config, err := LoadConfigFromEnv(configPath)
	if err != nil {
		t.Fatalf("LoadConfigFromEnv failed: %v", err)
	}

	if config.Detection.MaxFileSize != 5000000 {
		t.Errorf("expected MaxFileSize 5000000 (from env), got %d", config.Detection.MaxFileSize)
	}
}

func TestSaveConfigJSON(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "output.json")

	config := DefaultMLConfig()
	config.Detection.MaxFileSize = 12345

	if err := SaveConfig(configPath, &config); err != nil {
		t.Fatalf("SaveConfig failed: %v", err)
	}

	// Load and verify.
	loaded, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	if loaded.Detection.MaxFileSize != 12345 {
		t.Errorf("expected MaxFileSize 12345, got %d", loaded.Detection.MaxFileSize)
	}
}

func TestSaveConfigYAML(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "output.yaml")

	config := DefaultMLConfig()
	config.Fairness.DisparateImpactThreshold = 0.85

	if err := SaveConfig(configPath, &config); err != nil {
		t.Fatalf("SaveConfig failed: %v", err)
	}

	// Load and verify.
	loaded, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	if loaded.Fairness.DisparateImpactThreshold != 0.85 {
		t.Errorf("expected DisparateImpactThreshold 0.85, got %f", loaded.Fairness.DisparateImpactThreshold)
	}
}

func TestSaveConfigEmptyPath(t *testing.T) {
	config := DefaultMLConfig()
	err := SaveConfig("", &config)
	if err == nil {
		t.Error("expected error for empty path")
	}
}

func TestSaveConfigNilConfig(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "output.json")

	err := SaveConfig(configPath, nil)
	if err == nil {
		t.Error("expected error for nil config")
	}
}

func TestToDetectorConfig(t *testing.T) {
	config := MLConfig{
		Detection: DetectionMLConfig{
			MaxFileSize:     1234567,
			MaxDepth:        42,
			MaxFilesToScan:  999,
			ExcludePatterns: []string{"*.tmp"},
		},
	}

	detectorConfig := config.ToDetectorConfig()

	if detectorConfig.MaxFileSize != 1234567 {
		t.Errorf("expected MaxFileSize 1234567, got %d", detectorConfig.MaxFileSize)
	}
	if detectorConfig.MaxDepth != 42 {
		t.Errorf("expected MaxDepth 42, got %d", detectorConfig.MaxDepth)
	}
	if detectorConfig.MaxFilesToScan != 999 {
		t.Errorf("expected MaxFilesToScan 999, got %d", detectorConfig.MaxFilesToScan)
	}
	if len(detectorConfig.ExcludePatterns) != 1 || detectorConfig.ExcludePatterns[0] != "*.tmp" {
		t.Error("expected ExcludePatterns [*.tmp]")
	}
}

func TestToFairnessThresholds(t *testing.T) {
	config := MLConfig{
		Fairness: FairnessConfig{
			DisparateImpactThreshold:   0.85,
			StatisticalParityThreshold: 0.15,
			EqualOpportunityThreshold:  0.12,
		},
	}

	thresholds := config.ToFairnessThresholds()

	if len(thresholds) != 3 {
		t.Fatalf("expected 3 thresholds, got %d", len(thresholds))
	}

	// Find disparate impact threshold.
	var di *FairnessThreshold
	for i := range thresholds {
		if thresholds[i].Metric == MetricDisparateImpact {
			di = &thresholds[i]
			break
		}
	}

	if di == nil {
		t.Fatal("expected disparate impact threshold")
	}
	if di.Threshold != 0.85 {
		t.Errorf("expected threshold 0.85, got %f", di.Threshold)
	}
	if di.Comparison != "greater" {
		t.Errorf("expected comparison 'greater', got %s", di.Comparison)
	}
}

func TestToBiasThresholds(t *testing.T) {
	config := MLConfig{
		Bias: BiasConfig{
			SelectionBiasThreshold: 0.35,
			SamplingBiasThreshold:  0.45,
			LabelBiasThreshold:     0.25,
			FeatureBiasThreshold:   0.30,
		},
	}

	thresholds := config.ToBiasThresholds()

	if thresholds[BiasSelection] != 0.35 {
		t.Errorf("expected SelectionBiasThreshold 0.35, got %f", thresholds[BiasSelection])
	}
	if thresholds[BiasSampling] != 0.45 {
		t.Errorf("expected SamplingBiasThreshold 0.45, got %f", thresholds[BiasSampling])
	}
	if thresholds[BiasLabel] != 0.25 {
		t.Errorf("expected LabelBiasThreshold 0.25, got %f", thresholds[BiasLabel])
	}
	if thresholds[BiasFeature] != 0.30 {
		t.Errorf("expected FeatureBiasThreshold 0.30, got %f", thresholds[BiasFeature])
	}
}

func TestLoadConfigInvalidJSON(t *testing.T) {
	tmpDir := t.TempDir()
	sp, err := safepath.New(tmpDir)
	if err != nil {
		t.Fatalf("create safepath: %v", err)
	}

	if writeErr := sp.WriteFile("invalid.json", []byte("{invalid}"), 0o600); writeErr != nil {
		t.Fatalf("write config: %v", writeErr)
	}

	configPath := filepath.Join(tmpDir, "invalid.json")
	_, err = LoadConfig(configPath)
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestLoadConfigInvalidYAML(t *testing.T) {
	tmpDir := t.TempDir()
	sp, err := safepath.New(tmpDir)
	if err != nil {
		t.Fatalf("create safepath: %v", err)
	}

	if writeErr := sp.WriteFile("invalid.yaml", []byte(":\ninvalid:\n  - ["), 0o600); writeErr != nil {
		t.Fatalf("write config: %v", writeErr)
	}

	configPath := filepath.Join(tmpDir, "invalid.yaml")
	_, err = LoadConfig(configPath)
	if err == nil {
		t.Error("expected error for invalid YAML")
	}
}

func TestLoadConfigYML(t *testing.T) {
	tmpDir := t.TempDir()
	sp, err := safepath.New(tmpDir)
	if err != nil {
		t.Fatalf("create safepath: %v", err)
	}

	configContent := []byte(`
detection:
  max_file_size: 2097152
`)
	if writeErr := sp.WriteFile("config.yml", configContent, 0o600); writeErr != nil {
		t.Fatalf("write config: %v", writeErr)
	}

	configPath := filepath.Join(tmpDir, "config.yml")
	config, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	if config.Detection.MaxFileSize != 2097152 {
		t.Errorf("expected MaxFileSize 2097152, got %d", config.Detection.MaxFileSize)
	}
}
