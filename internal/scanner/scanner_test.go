package scanner

import (
	"testing"
)

func TestConfigDefaults(t *testing.T) {
	cfg := Config{}

	if cfg.Enabled {
		t.Error("expected Enabled to be false by default")
	}
	if cfg.Timeout != 0 {
		t.Errorf("expected Timeout to be 0 by default, got %d", cfg.Timeout)
	}
	if cfg.ConfigFile != "" {
		t.Errorf("expected ConfigFile to be empty by default, got %s", cfg.ConfigFile)
	}
	if cfg.Options != nil {
		t.Error("expected Options to be nil by default")
	}
}

func TestConfigWithValues(t *testing.T) {
	cfg := Config{
		Timeout:    300,
		Enabled:    true,
		ConfigFile: "/path/to/config.yaml",
		Options: map[string]string{
			"verbose": "true",
		},
	}

	if !cfg.Enabled {
		t.Error("expected Enabled to be true")
	}
	if cfg.Timeout != 300 {
		t.Errorf("expected Timeout to be 300, got %d", cfg.Timeout)
	}
	if cfg.ConfigFile != "/path/to/config.yaml" {
		t.Errorf("expected ConfigFile to be /path/to/config.yaml, got %s", cfg.ConfigFile)
	}
	if cfg.Options["verbose"] != "true" {
		t.Errorf("expected verbose option to be true, got %s", cfg.Options["verbose"])
	}
}
