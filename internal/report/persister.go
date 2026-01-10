// Package report provides functionality for aggregating and formatting security findings.
package report

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/victoralfred/devsec/internal/model"
	"github.com/victoralfred/gowritter/safepath"
)

// ResultsPersister defines the interface for persisting scan results.
// Implementations can store results to files, databases, cloud storage, etc.
type ResultsPersister interface {
	// Persist saves the report to storage.
	// The format parameter indicates the desired output format (e.g., "json", "sarif", "markdown").
	Persist(ctx context.Context, report *model.Report, format string) error
}

// PersisterConfig holds configuration for persistence operations.
type PersisterConfig struct {
	// OutputPath is the file path for file-based persistence.
	OutputPath string
	// Permissions for created files (default: 0644).
	Permissions os.FileMode
	// CreateDirs creates parent directories if they don't exist.
	CreateDirs bool
	// Indent enables pretty-printing for JSON output.
	Indent bool
}

// PersisterOption configures a persister.
type PersisterOption func(*PersisterConfig)

// WithOutputPath sets the output path.
func WithOutputPath(path string) PersisterOption {
	return func(c *PersisterConfig) {
		c.OutputPath = path
	}
}

// WithPermissions sets the file permissions.
func WithPermissions(perm os.FileMode) PersisterOption {
	return func(c *PersisterConfig) {
		c.Permissions = perm
	}
}

// WithCreateDirs enables creating parent directories.
func WithCreateDirs(create bool) PersisterOption {
	return func(c *PersisterConfig) {
		c.CreateDirs = create
	}
}

// WithIndent enables pretty-printing.
func WithIndent(indent bool) PersisterOption {
	return func(c *PersisterConfig) {
		c.Indent = indent
	}
}

// FilePersister persists reports to the filesystem.
type FilePersister struct {
	config     PersisterConfig
	formatters map[string]Formatter
}

// NewFilePersister creates a new file-based persister.
func NewFilePersister(opts ...PersisterOption) *FilePersister {
	config := PersisterConfig{
		Permissions: 0o644,
		CreateDirs:  true,
		Indent:      true,
	}

	for _, opt := range opts {
		opt(&config)
	}

	return &FilePersister{
		config: config,
		formatters: map[string]Formatter{
			"json":     NewJSONFormatter(config.Indent),
			"sarif":    NewSARIFFormatter(),
			"markdown": NewMarkdownFormatter(),
		},
	}
}

// RegisterFormatter adds a custom formatter for a format type.
func (p *FilePersister) RegisterFormatter(format string, formatter Formatter) {
	p.formatters[format] = formatter
}

// Persist writes the report to a file in the specified format.
func (p *FilePersister) Persist(ctx context.Context, report *model.Report, format string) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}

	if report == nil {
		return fmt.Errorf("report cannot be nil")
	}

	// Get formatter for format.
	formatter, ok := p.formatters[format]
	if !ok {
		return fmt.Errorf("unsupported format: %s", format)
	}

	// Format the report.
	data, err := formatter.Format(ctx, report)
	if err != nil {
		return fmt.Errorf("format report: %w", err)
	}

	// Determine output path.
	outputPath := p.config.OutputPath
	if outputPath == "" {
		return fmt.Errorf("output path not specified")
	}

	// Ensure extension matches format.
	ext := formatter.Extension()
	if filepath.Ext(outputPath) != ext {
		outputPath = outputPath + ext
	}

	// Create parent directories if needed.
	dir := filepath.Dir(outputPath)
	if p.config.CreateDirs {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("create directory: %w", err)
		}
	}

	// Write file using safepath.
	sp, err := safepath.New(dir)
	if err != nil {
		return fmt.Errorf("create safepath: %w", err)
	}

	filename := filepath.Base(outputPath)
	if err := sp.WriteFile(filename, data, p.config.Permissions); err != nil {
		return fmt.Errorf("write report: %w", err)
	}

	return nil
}

// GetOutputPath returns the configured output path.
func (p *FilePersister) GetOutputPath() string {
	return p.config.OutputPath
}

// NoOpPersister is a persister that does nothing.
// Useful for testing or when persistence is not needed.
type NoOpPersister struct{}

// NewNoOpPersister creates a no-op persister.
func NewNoOpPersister() *NoOpPersister {
	return &NoOpPersister{}
}

// Persist does nothing and returns nil.
func (p *NoOpPersister) Persist(ctx context.Context, report *model.Report, format string) error {
	return nil
}

// MultiPersister persists to multiple backends.
type MultiPersister struct {
	persisters []ResultsPersister
}

// NewMultiPersister creates a persister that writes to multiple backends.
func NewMultiPersister(persisters ...ResultsPersister) *MultiPersister {
	return &MultiPersister{
		persisters: persisters,
	}
}

// Add adds a persister to the chain.
func (p *MultiPersister) Add(persister ResultsPersister) {
	p.persisters = append(p.persisters, persister)
}

// Persist writes to all configured persisters.
// Returns the first error encountered, but continues to try all persisters.
func (p *MultiPersister) Persist(ctx context.Context, report *model.Report, format string) error {
	var firstErr error
	for _, persister := range p.persisters {
		if err := persister.Persist(ctx, report, format); err != nil {
			if firstErr == nil {
				firstErr = err
			}
		}
	}
	return firstErr
}
