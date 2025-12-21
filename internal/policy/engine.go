// Package policy provides OPA-based policy evaluation for security findings.
package policy

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/victoralfred/devsec/internal/model"
	"github.com/victoralfred/gowritter/safepath"
)

// DefaultQuery is the default policy query.
const DefaultQuery = "data.devsec.decision"

// MaxPolicySize is the maximum size of a policy file (1MB).
const MaxPolicySize = 1 * 1024 * 1024

// Engine provides OPA policy evaluation.
type Engine struct {
	policies     map[string]*compiledPolicy
	defaultQuery string
	mu           sync.RWMutex
}

// compiledPolicy holds a compiled OPA policy.
type compiledPolicy struct {
	query    rego.PreparedEvalQuery
	compiler *ast.Compiler
	name     string
	path     string
}

// Option configures an Engine.
type Option func(*Engine)

// WithDefaultQuery sets a custom default query.
func WithDefaultQuery(query string) Option {
	return func(e *Engine) {
		e.defaultQuery = query
	}
}

// New creates a new policy engine.
func New(opts ...Option) *Engine {
	e := &Engine{
		policies:     make(map[string]*compiledPolicy),
		defaultQuery: DefaultQuery,
	}

	for _, opt := range opts {
		opt(e)
	}

	return e
}

// LoadPolicy loads a Rego policy from a file.
func (e *Engine) LoadPolicy(ctx context.Context, policyPath string) error {
	if policyPath == "" {
		return fmt.Errorf("policy path cannot be empty")
	}

	// Validate path to prevent path traversal
	if strings.Contains(policyPath, "..") {
		return fmt.Errorf("policy path contains invalid characters: %s", policyPath)
	}

	absPath, err := filepath.Abs(policyPath)
	if err != nil {
		return fmt.Errorf("failed to resolve policy path: %w", err)
	}

	dir := filepath.Dir(absPath)
	filename := filepath.Base(absPath)

	sp, err := safepath.New(dir)
	if err != nil {
		return fmt.Errorf("policy directory not accessible: %w", err)
	}

	// Check file size.
	info, err := sp.Stat(filename)
	if err != nil {
		return fmt.Errorf("failed to stat policy file: %w", err)
	}
	if info.Size() > MaxPolicySize {
		return fmt.Errorf("policy file too large: %d bytes (max %d)", info.Size(), MaxPolicySize)
	}

	// Check for context cancellation.
	if ctxErr := ctx.Err(); ctxErr != nil {
		return fmt.Errorf("context canceled: %w", ctxErr)
	}

	data, err := sp.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("failed to read policy file: %w", err)
	}

	return e.loadPolicyFromContent(ctx, absPath, string(data))
}

// loadPolicyFromContent loads a policy from content string.
func (e *Engine) loadPolicyFromContent(ctx context.Context, path, content string) error {
	// Check for context cancellation.
	if ctxErr := ctx.Err(); ctxErr != nil {
		return fmt.Errorf("context canceled: %w", ctxErr)
	}

	// Parse the policy.
	module, err := ast.ParseModule(path, content)
	if err != nil {
		return fmt.Errorf("failed to parse policy: %w", err)
	}

	// Compile the policy.
	compiler := ast.NewCompiler()
	compiler.Compile(map[string]*ast.Module{path: module})
	if compiler.Failed() {
		return fmt.Errorf("failed to compile policy: %v", compiler.Errors)
	}

	// Prepare the query.
	query, err := rego.New(
		rego.Query(e.defaultQuery),
		rego.Compiler(compiler),
	).PrepareForEval(ctx)
	if err != nil {
		return fmt.Errorf("failed to prepare query: %w", err)
	}

	// Extract policy name from module package.
	name := extractPolicyName(module)

	e.mu.Lock()
	e.policies[path] = &compiledPolicy{
		name:     name,
		path:     path,
		query:    query,
		compiler: compiler,
	}
	e.mu.Unlock()

	return nil
}

// LoadPolicyFromString loads a policy from a string (for testing).
func (e *Engine) LoadPolicyFromString(ctx context.Context, name, content string) error {
	return e.loadPolicyFromContent(ctx, name, content)
}

// Evaluate evaluates all loaded policies against the given findings.
func (e *Engine) Evaluate(ctx context.Context, findings []model.Finding) ([]EvaluationResult, error) {
	e.mu.RLock()
	policyCount := len(e.policies)
	if policyCount == 0 {
		e.mu.RUnlock()
		return nil, fmt.Errorf("no policies loaded")
	}

	// Copy policies for safe iteration
	policies := make([]*compiledPolicy, 0, policyCount)
	for _, p := range e.policies {
		policies = append(policies, p)
	}
	e.mu.RUnlock()

	results := make([]EvaluationResult, 0, policyCount)

	for _, policy := range policies {
		// Check for context cancellation.
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, fmt.Errorf("context canceled: %w", ctxErr)
		}

		result, err := e.evaluatePolicy(ctx, policy, findings)
		if err != nil {
			return nil, fmt.Errorf("failed to evaluate policy %s: %w", policy.name, err)
		}

		results = append(results, result)
	}

	return results, nil
}

// EvaluateSingle evaluates a specific policy by path.
func (e *Engine) EvaluateSingle(ctx context.Context, policyPath string, findings []model.Finding) (EvaluationResult, error) {
	e.mu.RLock()
	policy, ok := e.policies[policyPath]
	e.mu.RUnlock()
	if !ok {
		return EvaluationResult{}, fmt.Errorf("policy not found: %s", policyPath)
	}

	return e.evaluatePolicy(ctx, policy, findings)
}

// evaluatePolicy evaluates a single policy.
func (e *Engine) evaluatePolicy(ctx context.Context, policy *compiledPolicy, findings []model.Finding) (EvaluationResult, error) {
	start := time.Now()

	input := EvaluationInput{
		Findings: findings,
		Metadata: make(map[string]string),
	}

	// Evaluate the query.
	rs, err := policy.query.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		return EvaluationResult{}, fmt.Errorf("evaluation failed: %w", err)
	}

	evalTime := time.Since(start).Milliseconds()

	decision := parseDecision(rs)
	failedCount := countFailedFindings(findings, decision)

	return EvaluationResult{
		Decision:    decision,
		PolicyName:  policy.name,
		PolicyPath:  policy.path,
		EvalTimeMs:  evalTime,
		TotalCount:  len(findings),
		FailedCount: failedCount,
	}, nil
}

// parseDecision extracts a Decision from rego results.
func parseDecision(rs rego.ResultSet) Decision {
	decision := Decision{
		Allow:    true,
		Deny:     false,
		Metadata: make(map[string]string),
	}

	if len(rs) == 0 || len(rs[0].Expressions) == 0 {
		return decision
	}

	// Try to parse the result as a map.
	result, ok := rs[0].Expressions[0].Value.(map[string]interface{})
	if !ok {
		// If it's a boolean, use it directly.
		if boolVal, isBool := rs[0].Expressions[0].Value.(bool); isBool {
			decision.Allow = boolVal
			decision.Deny = !boolVal
			return decision
		}
		return decision
	}

	// Parse allow field.
	if allow, ok := result["allow"].(bool); ok {
		decision.Allow = allow
	}

	// Parse deny field.
	if deny, ok := result["deny"].(bool); ok {
		decision.Deny = deny
	}

	// Parse warnings.
	if warnings, ok := result["warnings"].([]interface{}); ok {
		for _, w := range warnings {
			if wStr, ok := w.(string); ok {
				decision.Warnings = append(decision.Warnings, wStr)
			}
		}
	}

	// Parse metadata.
	if metadata, ok := result["metadata"].(map[string]interface{}); ok {
		for k, v := range metadata {
			if vStr, ok := v.(string); ok {
				decision.Metadata[k] = vStr
			}
		}
	}

	return decision
}

// countFailedFindings counts findings that would cause policy failure.
func countFailedFindings(findings []model.Finding, decision Decision) int {
	if decision.Allow && !decision.Deny {
		return 0
	}

	// Count critical and high severity findings.
	count := 0
	for i := range findings {
		f := &findings[i]
		if f.Severity == model.SeverityCritical || f.Severity == model.SeverityHigh {
			count++
		}
	}

	return count
}

// extractPolicyName extracts the policy name from the module.
func extractPolicyName(module *ast.Module) string {
	if module.Package != nil && module.Package.Path != nil {
		parts := make([]string, 0, len(module.Package.Path))
		for _, p := range module.Package.Path {
			parts = append(parts, p.Value.String())
		}
		return strings.Join(parts, ".")
	}
	return "unknown"
}

// ListPolicies returns information about all loaded policies.
func (e *Engine) ListPolicies() []Info {
	e.mu.RLock()
	defer e.mu.RUnlock()

	infos := make([]Info, 0, len(e.policies))
	for _, p := range e.policies {
		info := Info{
			Name: p.name,
			Path: p.path,
		}
		infos = append(infos, info)
	}

	return infos
}

// PolicyCount returns the number of loaded policies.
func (e *Engine) PolicyCount() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.policies)
}

// Close releases resources (no-op for now).
func (e *Engine) Close(_ context.Context) error {
	return nil
}
