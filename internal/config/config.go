// Package config provides configuration loading and validation for devsec.
package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/victoralfred/gowritter/safepath"
	"gopkg.in/yaml.v3"
)

// Config represents the main configuration for devsec.
type Config struct {
	LogLevel   string          `yaml:"log_level"`
	WorkDir    string          `yaml:"work_dir"`
	ConfigPath string          `yaml:"-"`
	Reporting  ReportingConfig `yaml:"reporting"`
	Policy     PolicyConfig    `yaml:"policy"`
	Scanners   ScannersConfig  `yaml:"scanners"`
	Pipeline   PipelineConfig  `yaml:"pipeline"`
}

// ScannersConfig holds configuration for all scanners.
type ScannersConfig struct {
	Gitleaks ScannerConfig `yaml:"gitleaks"`
	Semgrep  ScannerConfig `yaml:"semgrep"`
	Trivy    ScannerConfig `yaml:"trivy"`
	Gosec    ScannerConfig `yaml:"gosec"`
}

// ScannerConfig holds configuration for a single scanner.
type ScannerConfig struct {
	Options    map[string]string `yaml:"options"`
	ConfigFile string            `yaml:"config_file"`
	Timeout    int               `yaml:"timeout"`
	Enabled    bool              `yaml:"enabled"`
}

// PolicyConfig holds configuration for policy evaluation.
type PolicyConfig struct {
	PoliciesDir    string `yaml:"policies_dir"`
	FailOnCritical bool   `yaml:"fail_on_critical"`
	FailOnHigh     bool   `yaml:"fail_on_high"`
}

// ReportingConfig holds configuration for report generation.
type ReportingConfig struct {
	OutputDir string   `yaml:"output_dir"`
	Formats   []string `yaml:"formats"`
}

// PipelineConfig holds configuration for pipeline execution.
type PipelineConfig struct {
	Parallel   bool `yaml:"parallel"`
	MaxWorkers int  `yaml:"max_workers"`
}

// DefaultConfig returns a configuration with sensible defaults.
func DefaultConfig() *Config {
	return &Config{
		LogLevel: "info",
		WorkDir:  ".",
		Scanners: ScannersConfig{
			Gitleaks: ScannerConfig{Enabled: true, Timeout: 300},
			Semgrep:  ScannerConfig{Enabled: true, Timeout: 600},
			Trivy:    ScannerConfig{Enabled: true, Timeout: 300},
			Gosec:    ScannerConfig{Enabled: true, Timeout: 300},
		},
		Policy: PolicyConfig{
			PoliciesDir:    "policies",
			FailOnCritical: true,
			FailOnHigh:     true,
		},
		Reporting: ReportingConfig{
			OutputDir: "reports",
			Formats:   []string{"json", "sarif"},
		},
		Pipeline: PipelineConfig{
			Parallel:   true,
			MaxWorkers: 4,
		},
	}
}

// Load reads configuration from a YAML file using safe path operations.
func Load(path string) (*Config, error) {
	dir := filepath.Dir(path)
	filename := filepath.Base(path)

	sp, err := safepath.New(dir)
	if err != nil {
		return nil, fmt.Errorf("failed to create safe path: %w", err)
	}

	data, err := sp.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	cfg := DefaultConfig()
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	cfg.ConfigPath = path

	if err := cfg.ApplyEnvOverrides(); err != nil {
		return nil, fmt.Errorf("failed to apply env overrides: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return cfg, nil
}

// ApplyEnvOverrides applies environment variable overrides to the config.
// Environment variables follow the pattern DEVSEC_<SECTION>_<KEY>.
func (c *Config) ApplyEnvOverrides() error {
	if v := os.Getenv("DEVSEC_LOG_LEVEL"); v != "" {
		c.LogLevel = v
	}

	if v := os.Getenv("DEVSEC_WORK_DIR"); v != "" {
		c.WorkDir = v
	}

	if v := os.Getenv("DEVSEC_POLICY_FAIL_ON_CRITICAL"); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return fmt.Errorf("invalid DEVSEC_POLICY_FAIL_ON_CRITICAL: %w", err)
		}
		c.Policy.FailOnCritical = b
	}

	if v := os.Getenv("DEVSEC_POLICY_FAIL_ON_HIGH"); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return fmt.Errorf("invalid DEVSEC_POLICY_FAIL_ON_HIGH: %w", err)
		}
		c.Policy.FailOnHigh = b
	}

	if v := os.Getenv("DEVSEC_PIPELINE_PARALLEL"); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return fmt.Errorf("invalid DEVSEC_PIPELINE_PARALLEL: %w", err)
		}
		c.Pipeline.Parallel = b
	}

	if v := os.Getenv("DEVSEC_PIPELINE_MAX_WORKERS"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return fmt.Errorf("invalid DEVSEC_PIPELINE_MAX_WORKERS: %w", err)
		}
		c.Pipeline.MaxWorkers = n
	}

	return nil
}

// Validate checks the configuration for errors.
func (c *Config) Validate() error {
	var errs []string

	validLogLevels := map[string]bool{
		"debug": true,
		"info":  true,
		"warn":  true,
		"error": true,
	}
	if !validLogLevels[strings.ToLower(c.LogLevel)] {
		errs = append(errs, fmt.Sprintf("invalid log_level: %s", c.LogLevel))
	}

	if c.Pipeline.MaxWorkers < 1 {
		errs = append(errs, "pipeline.max_workers must be at least 1")
	}

	if c.Pipeline.MaxWorkers > 32 {
		errs = append(errs, "pipeline.max_workers must not exceed 32")
	}

	for _, format := range c.Reporting.Formats {
		validFormats := map[string]bool{
			"json":     true,
			"sarif":    true,
			"markdown": true,
			"text":     true,
		}
		if !validFormats[strings.ToLower(format)] {
			errs = append(errs, fmt.Sprintf("invalid report format: %s", format))
		}
	}

	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}

	return nil
}
