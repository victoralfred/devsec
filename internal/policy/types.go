// Package policy provides OPA-based policy evaluation for security findings.
package policy

import "github.com/victoralfred/devsec/internal/model"

// Decision represents the result of policy evaluation.
type Decision struct {
	Metadata map[string]string `json:"metadata,omitempty"`
	Warnings []string          `json:"warnings,omitempty"`
	Allow    bool              `json:"allow"`
	Deny     bool              `json:"deny"`
}

// EvaluationInput represents the input data for policy evaluation.
type EvaluationInput struct {
	Metadata map[string]string `json:"metadata,omitempty"`
	Findings []model.Finding   `json:"findings"`
}

// EvaluationResult represents the complete result of policy evaluation.
type EvaluationResult struct {
	PolicyName  string   `json:"policy_name"`
	PolicyPath  string   `json:"policy_path"`
	Decision    Decision `json:"decision"`
	EvalTimeMs  int64    `json:"eval_time_ms"`
	TotalCount  int      `json:"total_findings"`
	FailedCount int      `json:"failed_findings"`
}

// Info contains metadata about a loaded policy.
type Info struct {
	Name        string   `json:"name"`
	Path        string   `json:"path"`
	Description string   `json:"description,omitempty"`
	Version     string   `json:"version,omitempty"`
	Rules       []string `json:"rules,omitempty"`
}
