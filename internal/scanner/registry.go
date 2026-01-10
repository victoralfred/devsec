// Package scanner defines the interface for security scanners.
package scanner

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/victoralfred/devsec/internal/model"
)

// ScannerFactory creates scanner instances with the given timeout.
type ScannerFactory func(timeout time.Duration) (Scanner, error)

// ScannerRegistry manages scanner registration and creation.
// It allows consumers to register custom scanners and retrieve them by name.
type ScannerRegistry struct {
	factories map[string]ScannerFactory
	mu        sync.RWMutex
}

// NewScannerRegistry creates a new empty scanner registry.
func NewScannerRegistry() *ScannerRegistry {
	return &ScannerRegistry{
		factories: make(map[string]ScannerFactory),
	}
}

// Register adds a scanner factory to the registry.
// The name is case-insensitive and will be stored in lowercase.
// Returns an error if the name is empty or already registered.
func (r *ScannerRegistry) Register(name string, factory ScannerFactory) error {
	if name == "" {
		return fmt.Errorf("scanner name cannot be empty")
	}
	if factory == nil {
		return fmt.Errorf("scanner factory cannot be nil")
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	lowerName := toLower(name)
	if _, exists := r.factories[lowerName]; exists {
		return fmt.Errorf("scanner %q already registered", name)
	}

	r.factories[lowerName] = factory
	return nil
}

// MustRegister registers a scanner factory and panics on error.
// Useful for registering built-in scanners at package initialization.
func (r *ScannerRegistry) MustRegister(name string, factory ScannerFactory) {
	if err := r.Register(name, factory); err != nil {
		panic(fmt.Sprintf("failed to register scanner %q: %v", name, err))
	}
}

// Get returns the factory for the given scanner name.
// Returns false if the scanner is not registered.
func (r *ScannerRegistry) Get(name string) (ScannerFactory, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	factory, ok := r.factories[toLower(name)]
	return factory, ok
}

// Has checks if a scanner is registered.
func (r *ScannerRegistry) Has(name string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()

	_, ok := r.factories[toLower(name)]
	return ok
}

// Create creates a scanner instance by name with the given timeout.
// Returns an error if the scanner is not registered or creation fails.
func (r *ScannerRegistry) Create(name string, timeout time.Duration) (Scanner, error) {
	factory, ok := r.Get(name)
	if !ok {
		return nil, fmt.Errorf("unknown scanner type: %s", name)
	}

	scanner, err := factory(timeout)
	if err != nil {
		return nil, fmt.Errorf("failed to create scanner %q: %w", name, err)
	}

	return scanner, nil
}

// Names returns all registered scanner names.
func (r *ScannerRegistry) Names() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	names := make([]string, 0, len(r.factories))
	for name := range r.factories {
		names = append(names, name)
	}
	return names
}

// Unregister removes a scanner from the registry.
// Returns true if the scanner was found and removed.
func (r *ScannerRegistry) Unregister(name string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	lowerName := toLower(name)
	if _, exists := r.factories[lowerName]; exists {
		delete(r.factories, lowerName)
		return true
	}
	return false
}

// ScannerCloser extends Scanner with a Close method for cleanup.
type ScannerCloser interface {
	Scanner
	Close(ctx context.Context) error
}

// RunScanner creates a scanner, runs it, and handles cleanup.
// This is a convenience function for one-shot scanning.
func (r *ScannerRegistry) RunScanner(ctx context.Context, name, path string, timeout time.Duration) ([]model.Finding, error) {
	scanner, err := r.Create(name, timeout)
	if err != nil {
		return nil, err
	}

	// Close if scanner implements ScannerCloser.
	if closer, ok := scanner.(ScannerCloser); ok {
		defer func() { _ = closer.Close(ctx) }()
	}

	return scanner.Scan(ctx, path)
}

// toLower converts a string to lowercase without allocations for ASCII.
func toLower(s string) string {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			// Has uppercase, need to allocate.
			b := make([]byte, len(s))
			copy(b, s[:i])
			for ; i < len(s); i++ {
				c := s[i]
				if c >= 'A' && c <= 'Z' {
					c += 'a' - 'A'
				}
				b[i] = c
			}
			return string(b)
		}
	}
	return s
}
