// Package scanner defines the interface for security scanners.
package scanner

import (
	"time"

	"github.com/victoralfred/devsec/internal/scanner/gitleaks"
	"github.com/victoralfred/devsec/internal/scanner/osv"
	"github.com/victoralfred/devsec/internal/scanner/semgrep"
	"github.com/victoralfred/devsec/internal/scanner/trivy"
)

// DefaultRegistry returns a registry with all built-in scanners registered.
// Built-in scanners include: gitleaks, semgrep, trivy, osv.
func DefaultRegistry() *Registry {
	registry := NewRegistry()

	// Register gitleaks scanner.
	registry.MustRegister("gitleaks", func(timeout time.Duration) (Scanner, error) {
		return gitleaks.New(gitleaks.WithTimeout(timeout))
	})

	// Register semgrep scanner.
	registry.MustRegister("semgrep", func(timeout time.Duration) (Scanner, error) {
		return semgrep.New(semgrep.WithTimeout(timeout)), nil
	})

	// Register trivy scanner.
	registry.MustRegister("trivy", func(timeout time.Duration) (Scanner, error) {
		return trivy.New(trivy.WithTimeout(timeout)), nil
	})

	// Register osv scanner.
	registry.MustRegister("osv", func(timeout time.Duration) (Scanner, error) {
		return osv.New(osv.WithTimeout(timeout)), nil
	})

	return registry
}

// globalRegistry is the default registry used when none is specified.
var globalRegistry = DefaultRegistry()

// GlobalRegistry returns the global default scanner registry.
// This registry is initialized with all built-in scanners.
func GlobalRegistry() *Registry {
	return globalRegistry
}
