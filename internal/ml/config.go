package ml

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/victoralfred/gowritter/safepath"
	"gopkg.in/yaml.v3"
)

// MLConfig contains all ML module configuration.
// Fields ordered for optimal memory alignment.
//
//nolint:revive // MLConfig is intentionally named for clarity in external packages.
type MLConfig struct {
	Detection  DetectionMLConfig `json:"detection" yaml:"detection"`
	Validation ValidationConfig  `json:"validation" yaml:"validation"`
	Fairness   FairnessConfig    `json:"fairness" yaml:"fairness"`
	Bias       BiasConfig        `json:"bias" yaml:"bias"`
}

// DetectionMLConfig contains detector configuration.
// Fields ordered for optimal memory alignment.
type DetectionMLConfig struct {
	ExcludePatterns []string `json:"exclude_patterns" yaml:"exclude_patterns"`
	MaxFileSize     int64    `json:"max_file_size" yaml:"max_file_size"`
	MaxFilesToScan  int      `json:"max_files_to_scan" yaml:"max_files_to_scan"`
	MaxDepth        int      `json:"max_depth" yaml:"max_depth"`
}

// ValidationConfig contains validation configuration.
// Fields ordered for optimal memory alignment.
type ValidationConfig struct {
	DriftThreshold        float64 `json:"drift_threshold" yaml:"drift_threshold"`
	MissingValueThreshold float64 `json:"missing_value_threshold" yaml:"missing_value_threshold"`
	OutlierThreshold      float64 `json:"outlier_threshold" yaml:"outlier_threshold"`
}

// FairnessConfig contains fairness checking configuration.
// Fields ordered for optimal memory alignment.
type FairnessConfig struct {
	DisparateImpactThreshold   float64 `json:"disparate_impact_threshold" yaml:"disparate_impact_threshold"`
	StatisticalParityThreshold float64 `json:"statistical_parity_threshold" yaml:"statistical_parity_threshold"`
	EqualOpportunityThreshold  float64 `json:"equal_opportunity_threshold" yaml:"equal_opportunity_threshold"`
}

// BiasConfig contains bias detection configuration.
// Fields ordered for optimal memory alignment.
type BiasConfig struct {
	SelectionBiasThreshold float64 `json:"selection_bias_threshold" yaml:"selection_bias_threshold"`
	SamplingBiasThreshold  float64 `json:"sampling_bias_threshold" yaml:"sampling_bias_threshold"`
	LabelBiasThreshold     float64 `json:"label_bias_threshold" yaml:"label_bias_threshold"`
	FeatureBiasThreshold   float64 `json:"feature_bias_threshold" yaml:"feature_bias_threshold"`
	MissingValueThreshold  float64 `json:"missing_value_threshold" yaml:"missing_value_threshold"`
}

// DefaultMLConfig returns the default ML configuration.
func DefaultMLConfig() MLConfig {
	return MLConfig{
		Detection: DetectionMLConfig{
			MaxFileSize:    10 * 1024 * 1024, // 10 MB
			MaxDepth:       50,
			MaxFilesToScan: 10000,
			ExcludePatterns: []string{
				"**/node_modules/**",
				"**/.git/**",
				"**/venv/**",
				"**/__pycache__/**",
			},
		},
		Validation: ValidationConfig{
			DriftThreshold:        0.1,
			MissingValueThreshold: 0.1,
			OutlierThreshold:      3.0, // Standard deviations.
		},
		Fairness: FairnessConfig{
			DisparateImpactThreshold:   0.8,
			StatisticalParityThreshold: 0.1,
			EqualOpportunityThreshold:  0.1,
		},
		Bias: BiasConfig{
			SelectionBiasThreshold: 0.3,
			SamplingBiasThreshold:  0.3,
			LabelBiasThreshold:     0.2,
			FeatureBiasThreshold:   0.25,
			MissingValueThreshold:  0.1,
		},
	}
}

// LoadConfig loads configuration from a file.
// Supports JSON and YAML formats based on file extension.
func LoadConfig(path string) (*MLConfig, error) {
	if path == "" {
		return nil, ErrEmptyPath
	}

	dir := filepath.Dir(path)
	filename := filepath.Base(path)

	sp, err := safepath.New(dir)
	if err != nil {
		return nil, fmt.Errorf("create safepath: %w", err)
	}

	data, err := sp.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("read config file: %w", err)
	}

	config := DefaultMLConfig()
	ext := strings.ToLower(filepath.Ext(path))

	switch ext {
	case ".json":
		if err := json.Unmarshal(data, &config); err != nil {
			return nil, fmt.Errorf("parse JSON config: %w", err)
		}
	case ".yaml", ".yml":
		if err := yaml.Unmarshal(data, &config); err != nil {
			return nil, fmt.Errorf("parse YAML config: %w", err)
		}
	default:
		return nil, fmt.Errorf("%w: use .json, .yaml, or .yml", ErrUnsupportedFormat)
	}

	return &config, nil
}

// LoadConfigFromEnv loads configuration with environment variable overrides.
func LoadConfigFromEnv(path string) (*MLConfig, error) {
	var config *MLConfig
	var err error

	if path != "" {
		config, err = LoadConfig(path)
		if err != nil {
			return nil, err
		}
	} else {
		defaultConfig := DefaultMLConfig()
		config = &defaultConfig
	}

	// Apply environment variable overrides.
	applyEnvOverrides(config)

	return config, nil
}

// applyEnvOverrides applies environment variable overrides to config.
func applyEnvOverrides(config *MLConfig) {
	// Detection overrides.
	if v := os.Getenv("DEVSEC_ML_MAX_FILE_SIZE"); v != "" {
		var size int64
		if _, err := fmt.Sscanf(v, "%d", &size); err == nil && size > 0 {
			config.Detection.MaxFileSize = size
		}
	}

	if v := os.Getenv("DEVSEC_ML_MAX_DEPTH"); v != "" {
		var depth int
		if _, err := fmt.Sscanf(v, "%d", &depth); err == nil && depth > 0 {
			config.Detection.MaxDepth = depth
		}
	}

	if v := os.Getenv("DEVSEC_ML_MAX_FILES"); v != "" {
		var files int
		if _, err := fmt.Sscanf(v, "%d", &files); err == nil && files > 0 {
			config.Detection.MaxFilesToScan = files
		}
	}

	// Validation overrides.
	if v := os.Getenv("DEVSEC_ML_DRIFT_THRESHOLD"); v != "" {
		var threshold float64
		if _, err := fmt.Sscanf(v, "%f", &threshold); err == nil && threshold > 0 {
			config.Validation.DriftThreshold = threshold
		}
	}

	// Fairness overrides.
	if v := os.Getenv("DEVSEC_ML_DISPARATE_IMPACT_THRESHOLD"); v != "" {
		var threshold float64
		if _, err := fmt.Sscanf(v, "%f", &threshold); err == nil && threshold > 0 {
			config.Fairness.DisparateImpactThreshold = threshold
		}
	}

	if v := os.Getenv("DEVSEC_ML_STATISTICAL_PARITY_THRESHOLD"); v != "" {
		var threshold float64
		if _, err := fmt.Sscanf(v, "%f", &threshold); err == nil && threshold > 0 {
			config.Fairness.StatisticalParityThreshold = threshold
		}
	}

	// Bias overrides.
	if v := os.Getenv("DEVSEC_ML_SAMPLING_BIAS_THRESHOLD"); v != "" {
		var threshold float64
		if _, err := fmt.Sscanf(v, "%f", &threshold); err == nil && threshold > 0 {
			config.Bias.SamplingBiasThreshold = threshold
		}
	}
}

// SaveConfig saves configuration to a file.
func SaveConfig(path string, config *MLConfig) error {
	if path == "" {
		return ErrEmptyPath
	}

	if config == nil {
		return fmt.Errorf("config cannot be nil")
	}

	dir := filepath.Dir(path)
	filename := filepath.Base(path)

	sp, err := safepath.New(dir)
	if err != nil {
		return fmt.Errorf("create safepath: %w", err)
	}

	var data []byte
	ext := strings.ToLower(filepath.Ext(path))

	switch ext {
	case ".json":
		data, err = json.MarshalIndent(config, "", "  ")
		if err != nil {
			return fmt.Errorf("marshal JSON: %w", err)
		}
	case ".yaml", ".yml":
		data, err = yaml.Marshal(config)
		if err != nil {
			return fmt.Errorf("marshal YAML: %w", err)
		}
	default:
		return fmt.Errorf("%w: use .json, .yaml, or .yml", ErrUnsupportedFormat)
	}

	if err := sp.WriteFile(filename, data, 0o644); err != nil {
		return fmt.Errorf("write config file: %w", err)
	}

	return nil
}

// ToDetectorConfig converts MLConfig detection settings to DetectorConfig.
func (c *MLConfig) ToDetectorConfig() DetectorConfig {
	return DetectorConfig{
		MaxFileSize:     c.Detection.MaxFileSize,
		MaxDepth:        c.Detection.MaxDepth,
		MaxFilesToScan:  c.Detection.MaxFilesToScan,
		ExcludePatterns: c.Detection.ExcludePatterns,
	}
}

// ToFairnessThresholds converts MLConfig fairness settings to thresholds.
func (c *MLConfig) ToFairnessThresholds() []FairnessThreshold {
	return []FairnessThreshold{
		{
			Metric:     MetricDisparateImpact,
			Threshold:  c.Fairness.DisparateImpactThreshold,
			Comparison: "greater",
		},
		{
			Metric:     MetricStatisticalParity,
			Threshold:  c.Fairness.StatisticalParityThreshold,
			Comparison: "less",
		},
		{
			Metric:     MetricEqualOpportunity,
			Threshold:  c.Fairness.EqualOpportunityThreshold,
			Comparison: "less",
		},
	}
}

// ToBiasThresholds converts MLConfig bias settings to thresholds map.
func (c *MLConfig) ToBiasThresholds() map[BiasType]float64 {
	return map[BiasType]float64{
		BiasSelection: c.Bias.SelectionBiasThreshold,
		BiasSampling:  c.Bias.SamplingBiasThreshold,
		BiasLabel:     c.Bias.LabelBiasThreshold,
		BiasFeature:   c.Bias.FeatureBiasThreshold,
	}
}
