package config

import (
	"path/filepath"
	"testing"

	"github.com/victoralfred/gowritter/safepath"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.LogLevel != "info" {
		t.Errorf("expected log_level 'info', got '%s'", cfg.LogLevel)
	}

	if !cfg.Scanners.Gitleaks.Enabled {
		t.Error("expected gitleaks to be enabled by default")
	}

	if cfg.Pipeline.MaxWorkers != 4 {
		t.Errorf("expected max_workers 4, got %d", cfg.Pipeline.MaxWorkers)
	}

	if !cfg.Policy.FailOnCritical {
		t.Error("expected fail_on_critical to be true by default")
	}
}

func TestConfigValidate(t *testing.T) {
	tests := []struct {
		modify  func(*Config)
		name    string
		wantErr bool
	}{
		{
			name:    "valid default config",
			modify:  func(c *Config) {},
			wantErr: false,
		},
		{
			name:    "invalid log level",
			modify:  func(c *Config) { c.LogLevel = "invalid" },
			wantErr: true,
		},
		{
			name:    "max workers too low",
			modify:  func(c *Config) { c.Pipeline.MaxWorkers = 0 },
			wantErr: true,
		},
		{
			name:    "max workers too high",
			modify:  func(c *Config) { c.Pipeline.MaxWorkers = 100 },
			wantErr: true,
		},
		{
			name:    "invalid report format",
			modify:  func(c *Config) { c.Reporting.Formats = []string{"invalid"} },
			wantErr: true,
		},
		{
			name:    "valid log level debug",
			modify:  func(c *Config) { c.LogLevel = "debug" },
			wantErr: false,
		},
		{
			name:    "valid log level warn",
			modify:  func(c *Config) { c.LogLevel = "warn" },
			wantErr: false,
		},
		{
			name:    "valid log level error",
			modify:  func(c *Config) { c.LogLevel = "error" },
			wantErr: false,
		},
		{
			name:    "valid report format markdown",
			modify:  func(c *Config) { c.Reporting.Formats = []string{"markdown"} },
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultConfig()
			tt.modify(cfg)
			err := cfg.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestApplyEnvOverrides(t *testing.T) {
	tests := []struct {
		envVars map[string]string
		check   func(*Config) bool
		name    string
		wantErr bool
	}{
		{
			name:    "override log level",
			envVars: map[string]string{"DEVSEC_LOG_LEVEL": "debug"},
			check:   func(c *Config) bool { return c.LogLevel == "debug" },
			wantErr: false,
		},
		{
			name:    "override work dir",
			envVars: map[string]string{"DEVSEC_WORK_DIR": "/tmp/test"},
			check:   func(c *Config) bool { return c.WorkDir == "/tmp/test" },
			wantErr: false,
		},
		{
			name:    "override fail on critical",
			envVars: map[string]string{"DEVSEC_POLICY_FAIL_ON_CRITICAL": "false"},
			check:   func(c *Config) bool { return !c.Policy.FailOnCritical },
			wantErr: false,
		},
		{
			name:    "override fail on high",
			envVars: map[string]string{"DEVSEC_POLICY_FAIL_ON_HIGH": "false"},
			check:   func(c *Config) bool { return !c.Policy.FailOnHigh },
			wantErr: false,
		},
		{
			name:    "override parallel",
			envVars: map[string]string{"DEVSEC_PIPELINE_PARALLEL": "false"},
			check:   func(c *Config) bool { return !c.Pipeline.Parallel },
			wantErr: false,
		},
		{
			name:    "override max workers",
			envVars: map[string]string{"DEVSEC_PIPELINE_MAX_WORKERS": "8"},
			check:   func(c *Config) bool { return c.Pipeline.MaxWorkers == 8 },
			wantErr: false,
		},
		{
			name:    "invalid bool value",
			envVars: map[string]string{"DEVSEC_POLICY_FAIL_ON_CRITICAL": "notabool"},
			check:   func(c *Config) bool { return true },
			wantErr: true,
		},
		{
			name:    "invalid int value",
			envVars: map[string]string{"DEVSEC_PIPELINE_MAX_WORKERS": "notanint"},
			check:   func(c *Config) bool { return true },
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for k, v := range tt.envVars {
				t.Setenv(k, v)
			}

			cfg := DefaultConfig()
			err := cfg.ApplyEnvOverrides()

			if (err != nil) != tt.wantErr {
				t.Errorf("ApplyEnvOverrides() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && !tt.check(cfg) {
				t.Error("ApplyEnvOverrides() did not apply expected override")
			}
		})
	}
}

func TestLoad(t *testing.T) {
	tmpDir := t.TempDir()

	sp, err := safepath.New(tmpDir)
	if err != nil {
		t.Fatalf("failed to create safe path: %v", err)
	}

	validConfig := `
log_level: debug
work_dir: /tmp/devsec
scanners:
  gitleaks:
    enabled: true
    timeout: 600
  semgrep:
    enabled: false
policy:
  fail_on_critical: true
  fail_on_high: false
reporting:
  output_dir: /tmp/reports
  formats:
    - json
    - sarif
pipeline:
  parallel: true
  max_workers: 8
`

	configPath := filepath.Join(tmpDir, "devsec.yaml")
	err = sp.WriteFile("devsec.yaml", []byte(validConfig), 0o644)
	if err != nil {
		t.Fatalf("failed to write test config: %v", err)
	}

	cfg, err := Load(configPath)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.LogLevel != "debug" {
		t.Errorf("expected log_level 'debug', got '%s'", cfg.LogLevel)
	}

	if cfg.WorkDir != "/tmp/devsec" {
		t.Errorf("expected work_dir '/tmp/devsec', got '%s'", cfg.WorkDir)
	}

	if !cfg.Scanners.Gitleaks.Enabled {
		t.Error("expected gitleaks to be enabled")
	}

	if cfg.Scanners.Gitleaks.Timeout != 600 {
		t.Errorf("expected gitleaks timeout 600, got %d", cfg.Scanners.Gitleaks.Timeout)
	}

	if cfg.Scanners.Semgrep.Enabled {
		t.Error("expected semgrep to be disabled")
	}

	if cfg.Pipeline.MaxWorkers != 8 {
		t.Errorf("expected max_workers 8, got %d", cfg.Pipeline.MaxWorkers)
	}

	if cfg.ConfigPath != configPath {
		t.Errorf("expected config_path '%s', got '%s'", configPath, cfg.ConfigPath)
	}
}

func TestLoadFileNotFound(t *testing.T) {
	_, err := Load("/nonexistent/path/config.yaml")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestLoadInvalidYAML(t *testing.T) {
	tmpDir := t.TempDir()

	sp, err := safepath.New(tmpDir)
	if err != nil {
		t.Fatalf("failed to create safe path: %v", err)
	}

	invalidYAML := `
log_level: [invalid yaml
`

	configPath := filepath.Join(tmpDir, "invalid.yaml")
	err = sp.WriteFile("invalid.yaml", []byte(invalidYAML), 0o644)
	if err != nil {
		t.Fatalf("failed to write test config: %v", err)
	}

	_, err = Load(configPath)
	if err == nil {
		t.Error("expected error for invalid YAML")
	}
}

func TestLoadInvalidConfig(t *testing.T) {
	tmpDir := t.TempDir()

	sp, err := safepath.New(tmpDir)
	if err != nil {
		t.Fatalf("failed to create safe path: %v", err)
	}

	invalidConfig := `
log_level: invalid_level
pipeline:
  max_workers: 0
`

	configPath := filepath.Join(tmpDir, "invalid_config.yaml")
	err = sp.WriteFile("invalid_config.yaml", []byte(invalidConfig), 0o644)
	if err != nil {
		t.Fatalf("failed to write test config: %v", err)
	}

	_, err = Load(configPath)
	if err == nil {
		t.Error("expected error for invalid config values")
	}
}

func TestScannerConfigDefaults(t *testing.T) {
	cfg := DefaultConfig()

	scanners := []struct {
		name    string
		scanner ScannerConfig
	}{
		{"gitleaks", cfg.Scanners.Gitleaks},
		{"semgrep", cfg.Scanners.Semgrep},
		{"trivy", cfg.Scanners.Trivy},
		{"gosec", cfg.Scanners.Gosec},
	}

	for _, s := range scanners {
		t.Run(s.name, func(t *testing.T) {
			if !s.scanner.Enabled {
				t.Errorf("%s should be enabled by default", s.name)
			}
			if s.scanner.Timeout <= 0 {
				t.Errorf("%s should have positive timeout", s.name)
			}
		})
	}
}
