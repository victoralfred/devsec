// Package scanner defines the interface for security scanners.
package scanner

import (
	"context"

	"github.com/victoralfred/devsec/internal/model"
)

// Scanner defines the interface that all security scanners must implement.
type Scanner interface {
	// Name returns the name of the scanner.
	Name() string
	// Scan performs a security scan on the given path and returns findings.
	Scan(ctx context.Context, path string) ([]model.Finding, error)
}

// Config holds configuration for scanner execution.
// Fields ordered for optimal memory alignment.
type Config struct {
	Options    map[string]string `yaml:"options"`
	ConfigFile string            `yaml:"config_file"`
	Timeout    int               `yaml:"timeout"`
	Enabled    bool              `yaml:"enabled"`
}
