// Package policy provides OPA-based policy evaluation for security findings.
package policy

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/victoralfred/gowritter/safepath"
)

// LoaderConfig configures the policy loader.
type LoaderConfig struct {
	Recursive    bool
	ValidateOnly bool
	MaxDepth     int
}

const (
	// MaxPolicyFiles is the maximum number of policy files to load to prevent DoS.
	MaxPolicyFiles = 1000
	// DefaultMaxDepth is the default maximum recursion depth.
	DefaultMaxDepth = 5
)

// DefaultLoaderConfig returns the default loader configuration.
func DefaultLoaderConfig() LoaderConfig {
	return LoaderConfig{
		Recursive:    true,
		ValidateOnly: false,
		MaxDepth:     DefaultMaxDepth,
	}
}

// LoadResult contains the result of loading policies from a directory.
type LoadResult struct {
	Directory string      `json:"directory"`
	Errors    []LoadError `json:"errors,omitempty"`
	Policies  []Info      `json:"policies"`
	Loaded    int         `json:"loaded"`
	Failed    int         `json:"failed"`
	Skipped   int         `json:"skipped"`
}

// LoadError represents an error loading a specific policy.
type LoadError struct {
	Path    string `json:"path"`
	Message string `json:"message"`
}

// LoadDirectory loads all Rego policies from a directory.
func (e *Engine) LoadDirectory(ctx context.Context, dirPath string, config LoaderConfig) (LoadResult, error) {
	result := LoadResult{
		Directory: dirPath,
		Policies:  make([]Info, 0),
		Errors:    make([]LoadError, 0),
	}

	// Check context at start.
	if ctxErr := ctx.Err(); ctxErr != nil {
		return result, fmt.Errorf("context canceled: %w", ctxErr)
	}

	// Validate directory path
	if dirPath == "" {
		return result, fmt.Errorf("directory path cannot be empty")
	}
	if strings.Contains(dirPath, "..") {
		return result, fmt.Errorf("directory path contains invalid characters: %s", dirPath)
	}

	absPath, err := filepath.Abs(dirPath)
	if err != nil {
		return result, fmt.Errorf("failed to resolve directory path: %w", err)
	}

	sp, err := safepath.New(absPath)
	if err != nil {
		return result, fmt.Errorf("directory not accessible: %w", err)
	}

	// List files in directory.
	entries, err := sp.ReadDir(".")
	if err != nil {
		return result, fmt.Errorf("failed to read directory: %w", err)
	}

	for _, entry := range entries {
		// Check for context cancellation.
		if ctxErr := ctx.Err(); ctxErr != nil {
			return result, fmt.Errorf("context canceled: %w", ctxErr)
		}

		// Check policy file limit
		if result.Loaded+result.Failed >= MaxPolicyFiles {
			result.Errors = append(result.Errors, LoadError{
				Path:    absPath,
				Message: fmt.Sprintf("policy file limit exceeded: %d (max %d)", result.Loaded+result.Failed, MaxPolicyFiles),
			})
			break
		}

		entryPath := filepath.Join(absPath, entry.Name())

		if entry.IsDir() {
			if config.Recursive && config.MaxDepth > 0 {
				subConfig := config
				subConfig.MaxDepth--
				subResult, subErr := e.LoadDirectory(ctx, entryPath, subConfig)
				if subErr != nil {
					result.Errors = append(result.Errors, LoadError{
						Path:    entryPath,
						Message: subErr.Error(),
					})
					result.Failed++
					continue
				}
				result.Loaded += subResult.Loaded
				result.Failed += subResult.Failed
				result.Skipped += subResult.Skipped
				result.Policies = append(result.Policies, subResult.Policies...)
				result.Errors = append(result.Errors, subResult.Errors...)
			}
			continue
		}

		// Skip non-rego files.
		if !strings.HasSuffix(entry.Name(), ".rego") {
			result.Skipped++
			continue
		}

		// Skip test files.
		if strings.HasSuffix(entry.Name(), "_test.rego") {
			result.Skipped++
			continue
		}

		// Load the policy.
		if config.ValidateOnly {
			if valErr := e.ValidateFile(ctx, entryPath); valErr != nil {
				result.Errors = append(result.Errors, LoadError{
					Path:    entryPath,
					Message: valErr.Error(),
				})
				result.Failed++
				continue
			}
		} else {
			if loadErr := e.LoadPolicy(ctx, entryPath); loadErr != nil {
				result.Errors = append(result.Errors, LoadError{
					Path:    entryPath,
					Message: loadErr.Error(),
				})
				result.Failed++
				continue
			}
		}

		result.Loaded++
		result.Policies = append(result.Policies, Info{
			Name: filepath.Base(entryPath),
			Path: entryPath,
		})
	}

	return result, nil
}

// LoadFiles loads policies from a list of file paths.
func (e *Engine) LoadFiles(ctx context.Context, paths []string) (LoadResult, error) {
	result := LoadResult{
		Policies: make([]Info, 0, len(paths)),
		Errors:   make([]LoadError, 0),
	}

	for _, path := range paths {
		// Check for context cancellation.
		if ctxErr := ctx.Err(); ctxErr != nil {
			return result, fmt.Errorf("context canceled: %w", ctxErr)
		}

		absPath, err := filepath.Abs(path)
		if err != nil {
			result.Errors = append(result.Errors, LoadError{
				Path:    path,
				Message: fmt.Sprintf("failed to resolve path: %v", err),
			})
			result.Failed++
			continue
		}

		if loadErr := e.LoadPolicy(ctx, absPath); loadErr != nil {
			result.Errors = append(result.Errors, LoadError{
				Path:    absPath,
				Message: loadErr.Error(),
			})
			result.Failed++
			continue
		}

		result.Loaded++
		result.Policies = append(result.Policies, Info{
			Name: filepath.Base(absPath),
			Path: absPath,
		})
	}

	return result, nil
}
