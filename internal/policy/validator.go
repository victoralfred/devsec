// Package policy provides OPA-based policy evaluation for security findings.
package policy

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/victoralfred/gowritter/safepath"
)

// ValidationResult contains the result of policy validation.
type ValidationResult struct {
	Path     string            `json:"path"`
	Package  string            `json:"package,omitempty"`
	Errors   []ValidationError `json:"errors,omitempty"`
	Warnings []string          `json:"warnings,omitempty"`
	Rules    []RuleInfo        `json:"rules,omitempty"`
	Valid    bool              `json:"valid"`
}

// ValidationError represents a validation error.
type ValidationError struct {
	Message  string `json:"message"`
	Severity string `json:"severity"`
	Line     int    `json:"line,omitempty"`
	Column   int    `json:"column,omitempty"`
}

// RuleInfo contains information about a rule in the policy.
type RuleInfo struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Default     bool   `json:"default"`
}

// ValidateFile validates a Rego policy file.
func (e *Engine) ValidateFile(ctx context.Context, policyPath string) error {
	result, err := e.ValidatePolicy(ctx, policyPath)
	if err != nil {
		return err
	}

	if !result.Valid {
		var msgs []string
		for _, verr := range result.Errors {
			msgs = append(msgs, verr.Message)
		}
		return fmt.Errorf("validation failed: %s", strings.Join(msgs, "; "))
	}

	return nil
}

// ValidatePolicy validates a Rego policy and returns detailed results.
func (e *Engine) ValidatePolicy(ctx context.Context, policyPath string) (ValidationResult, error) {
	result := ValidationResult{
		Path:     policyPath,
		Errors:   make([]ValidationError, 0),
		Warnings: make([]string, 0),
		Rules:    make([]RuleInfo, 0),
	}

	// Check context.
	if ctxErr := ctx.Err(); ctxErr != nil {
		return result, fmt.Errorf("context canceled: %w", ctxErr)
	}

	// Validate path
	if policyPath == "" {
		result.Errors = append(result.Errors, ValidationError{
			Message:  "policy path cannot be empty",
			Severity: "error",
		})
		return result, nil
	}
	if strings.Contains(policyPath, "..") {
		result.Errors = append(result.Errors, ValidationError{
			Message:  fmt.Sprintf("policy path contains invalid characters: %s", policyPath),
			Severity: "error",
		})
		return result, nil
	}

	// Read the policy file.
	absPath, err := filepath.Abs(policyPath)
	if err != nil {
		result.Errors = append(result.Errors, ValidationError{
			Message:  fmt.Sprintf("failed to resolve path: %v", err),
			Severity: "error",
		})
		return result, nil
	}

	dir := filepath.Dir(absPath)
	filename := filepath.Base(absPath)

	sp, spErr := safepath.New(dir)
	if spErr != nil {
		result.Errors = append(result.Errors, ValidationError{
			Message:  fmt.Sprintf("directory not accessible: %v", spErr),
			Severity: "error",
		})
		return result, nil
	}

	// Check file exists and size.
	info, statErr := sp.Stat(filename)
	if statErr != nil {
		result.Errors = append(result.Errors, ValidationError{
			Message:  fmt.Sprintf("file not found: %v", statErr),
			Severity: "error",
		})
		return result, nil
	}

	if info.Size() > MaxPolicySize {
		result.Errors = append(result.Errors, ValidationError{
			Message:  fmt.Sprintf("file too large: %d bytes (max %d)", info.Size(), MaxPolicySize),
			Severity: "error",
		})
		return result, nil
	}

	if info.Size() == 0 {
		result.Errors = append(result.Errors, ValidationError{
			Message:  "empty policy file",
			Severity: "error",
		})
		return result, nil
	}

	data, readErr := sp.ReadFile(filename)
	if readErr != nil {
		result.Errors = append(result.Errors, ValidationError{
			Message:  fmt.Sprintf("failed to read file: %v", readErr),
			Severity: "error",
		})
		return result, nil
	}

	return e.ValidatePolicyContent(ctx, absPath, string(data))
}

// ValidatePolicyContent validates Rego policy content.
func (e *Engine) ValidatePolicyContent(_ context.Context, name, content string) (ValidationResult, error) {
	result := ValidationResult{
		Path:     name,
		Errors:   make([]ValidationError, 0),
		Warnings: make([]string, 0),
		Rules:    make([]RuleInfo, 0),
	}

	// Parse the policy.
	module, parseErr := ast.ParseModule(name, content)
	if parseErr != nil {
		result.Errors = append(result.Errors, parseAstErrors(parseErr)...)
		return result, nil
	}

	// Extract package name (skip "data" prefix which is OPA internal root).
	if module.Package != nil && module.Package.Path != nil {
		parts := make([]string, 0, len(module.Package.Path))
		for _, p := range module.Package.Path {
			// Get the string value, removing quotes if present.
			val := p.Value.String()
			val = strings.Trim(val, `"`)
			// Skip the OPA "data" root reference.
			if val == "data" && len(parts) == 0 {
				continue
			}
			parts = append(parts, val)
		}
		result.Package = strings.Join(parts, ".")
	}

	// Check package is "devsec".
	if result.Package != "devsec" {
		result.Warnings = append(result.Warnings,
			fmt.Sprintf("package should be 'devsec', found '%s'", result.Package))
	}

	// Compile the policy.
	compiler := ast.NewCompiler()
	compiler.Compile(map[string]*ast.Module{name: module})
	if compiler.Failed() {
		for _, compErr := range compiler.Errors {
			result.Errors = append(result.Errors, ValidationError{
				Message:  compErr.Message,
				Line:     compErr.Location.Row,
				Column:   compErr.Location.Col,
				Severity: "error",
			})
		}
		return result, nil
	}

	// Extract rules.
	hasDecisionRule := false
	for _, rule := range module.Rules {
		ruleName := string(rule.Head.Name)
		ruleInfo := RuleInfo{
			Name:    ruleName,
			Default: rule.Default,
		}

		// Extract description from annotations.
		if len(rule.Annotations) > 0 {
			for _, ann := range rule.Annotations {
				if ann.Description != "" {
					ruleInfo.Description = ann.Description
					break
				}
			}
		}

		result.Rules = append(result.Rules, ruleInfo)

		if ruleName == "decision" {
			hasDecisionRule = true
		}
	}

	// Check for required decision rule.
	if !hasDecisionRule {
		result.Warnings = append(result.Warnings,
			"policy should define a 'decision' rule for proper integration")
	}

	// All validation passed.
	result.Valid = len(result.Errors) == 0

	return result, nil
}

// parseAstErrors converts AST parse errors to ValidationErrors.
func parseAstErrors(err error) []ValidationError {
	if err == nil {
		return nil
	}

	errors := make([]ValidationError, 0)

	// Try to extract location from ast.Errors.
	if astErrors, ok := err.(ast.Errors); ok {
		for _, astErr := range astErrors {
			verr := ValidationError{
				Message:  astErr.Message,
				Severity: "error",
			}
			if astErr.Location != nil {
				verr.Line = astErr.Location.Row
				verr.Column = astErr.Location.Col
			}
			errors = append(errors, verr)
		}
		return errors
	}

	// Fallback to generic error.
	errors = append(errors, ValidationError{
		Message:  err.Error(),
		Severity: "error",
	})

	return errors
}

// ValidateString validates a Rego policy string.
func (e *Engine) ValidateString(ctx context.Context, name, content string) (ValidationResult, error) {
	return e.ValidatePolicyContent(ctx, name, content)
}
