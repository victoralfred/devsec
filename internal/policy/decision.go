// Package policy provides OPA-based policy evaluation for security findings.
package policy

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/victoralfred/devsec/internal/model"
	"github.com/victoralfred/devsec/internal/policy/defaults"
)

// DefaultPolicyName is the name used for the default policy.
const DefaultPolicyName = "default-security-policy"

// DecisionPoint provides pass/fail policy decisions for security findings.
type DecisionPoint struct {
	engine     *Engine
	policyName string
	strictMode bool
}

// DecisionPointOption configures a DecisionPoint.
type DecisionPointOption func(*DecisionPoint)

// WithStrictMode enables strict mode (block high and critical).
func WithStrictMode(strict bool) DecisionPointOption {
	return func(dp *DecisionPoint) {
		dp.strictMode = strict
	}
}

// WithPolicyName sets a custom policy name.
func WithPolicyName(name string) DecisionPointOption {
	return func(dp *DecisionPoint) {
		dp.policyName = name
	}
}

// NewDecisionPoint creates a new decision point with default policies.
func NewDecisionPoint(ctx context.Context, opts ...DecisionPointOption) (*DecisionPoint, error) {
	dp := &DecisionPoint{
		engine:     New(),
		policyName: DefaultPolicyName,
		strictMode: false,
	}

	for _, opt := range opts {
		opt(dp)
	}

	// Load appropriate default policy based on mode.
	var policyContent string
	if dp.strictMode {
		policyContent = defaults.StrictSecurity
	} else {
		policyContent = defaults.BlockHighAndCritical
	}

	if err := dp.engine.LoadPolicyFromString(ctx, dp.policyName, policyContent); err != nil {
		return nil, fmt.Errorf("failed to load default policy: %w", err)
	}

	return dp, nil
}

// NewDecisionPointWithPolicy creates a decision point with a custom policy.
func NewDecisionPointWithPolicy(ctx context.Context, policyPath string) (*DecisionPoint, error) {
	dp := &DecisionPoint{
		engine:     New(),
		policyName: policyPath,
	}

	if err := dp.engine.LoadPolicy(ctx, policyPath); err != nil {
		return nil, fmt.Errorf("failed to load policy: %w", err)
	}

	return dp, nil
}

// CheckResult represents the result of a policy check.
// Fields ordered for optimal memory alignment.
type CheckResult struct {
	Metadata    map[string]string `json:"metadata,omitempty"`
	Summary     string            `json:"summary"`
	PolicyName  string            `json:"policy_name"`
	Violations  []Violation       `json:"violations,omitempty"`
	Warnings    []string          `json:"warnings,omitempty"`
	CheckTimeMs int64             `json:"check_time_ms"`
	TotalCount  int               `json:"total_findings"`
	Passed      bool              `json:"passed"`
}

// Violation represents a policy violation.
// Fields ordered for optimal memory alignment.
type Violation struct {
	Reason   string        `json:"reason"`
	Severity string        `json:"severity"`
	Finding  model.Finding `json:"finding"`
}

// Check evaluates findings against the loaded policy.
func (dp *DecisionPoint) Check(ctx context.Context, findings []model.Finding) (CheckResult, error) {
	// Validate inputs
	if dp == nil {
		return CheckResult{}, fmt.Errorf("decision point cannot be nil")
	}
	if dp.engine == nil {
		return CheckResult{}, fmt.Errorf("policy engine cannot be nil")
	}

	start := time.Now()

	results, err := dp.engine.Evaluate(ctx, findings)
	if err != nil {
		return CheckResult{}, fmt.Errorf("policy evaluation failed: %w", err)
	}

	if len(results) == 0 {
		return CheckResult{}, fmt.Errorf("no policy results returned")
	}

	// Use the first result (we only have one policy loaded).
	if results[0].PolicyName == "" {
		return CheckResult{}, fmt.Errorf("invalid policy result: missing policy name")
	}
	evalResult := results[0]
	decision := evalResult.Decision

	checkResult := CheckResult{
		Passed:      decision.Allow && !decision.Deny,
		Warnings:    decision.Warnings,
		Metadata:    decision.Metadata,
		PolicyName:  evalResult.PolicyName,
		CheckTimeMs: time.Since(start).Milliseconds(),
		TotalCount:  len(findings),
	}

	// Generate violations if policy denied.
	if !checkResult.Passed {
		checkResult.Violations = dp.generateViolations(findings, decision)
	}

	// Generate summary.
	checkResult.Summary = dp.generateSummary(checkResult, findings)

	return checkResult, nil
}

// generateViolations creates violation entries for blocking findings.
func (dp *DecisionPoint) generateViolations(findings []model.Finding, decision Decision) []Violation {
	var violations []Violation

	blockedBy := decision.Metadata["blocked_by"]

	for i := range findings {
		f := &findings[i]
		var reason string
		var include bool

		switch blockedBy {
		case "critical_findings", "critical":
			if f.Severity == model.SeverityCritical {
				reason = "Critical severity finding blocked by policy"
				include = true
			}
		case "high_critical_findings", "high":
			if f.Severity == model.SeverityCritical || f.Severity == model.SeverityHigh {
				reason = fmt.Sprintf("%s severity finding blocked by policy", f.Severity)
				include = true
			}
		default:
			// Default: include high and critical.
			if f.Severity == model.SeverityCritical || f.Severity == model.SeverityHigh {
				reason = fmt.Sprintf("%s severity finding blocked by policy", f.Severity)
				include = true
			}
		}

		if include {
			violations = append(violations, Violation{
				Finding:  *f,
				Reason:   reason,
				Severity: string(f.Severity),
			})
		}
	}

	return violations
}

// generateSummary creates a human-readable summary.
func (dp *DecisionPoint) generateSummary(result CheckResult, findings []model.Finding) string {
	var builder strings.Builder
	builder.Grow(512) // Increased capacity for better performance

	if result.Passed {
		builder.WriteString("Policy check PASSED. ")
	} else {
		builder.WriteString("Policy check FAILED. ")
	}

	builder.WriteString(fmt.Sprintf("Evaluated %d finding(s). ", len(findings)))

	if len(result.Violations) > 0 {
		builder.WriteString(fmt.Sprintf("%d violation(s) found. ", len(result.Violations)))
	}

	if len(result.Warnings) > 0 {
		builder.WriteString(fmt.Sprintf("%d warning(s). ", len(result.Warnings)))
	}

	return strings.TrimSpace(builder.String())
}

// ViolationReport generates a detailed violation report.
// Fields ordered for optimal memory alignment.
type ViolationReport struct {
	GeneratedAt     time.Time   `json:"generated_at"`
	Title           string      `json:"title"`
	Summary         string      `json:"summary"`
	Violations      []Violation `json:"violations"`
	Warnings        []string    `json:"warnings"`
	Recommendations []string    `json:"recommendations,omitempty"`
	Passed          bool        `json:"passed"`
}

// GenerateReport creates a detailed violation report from check results.
func (dp *DecisionPoint) GenerateReport(result CheckResult) ViolationReport {
	report := ViolationReport{
		Title:       "Security Policy Violation Report",
		Summary:     result.Summary,
		Passed:      result.Passed,
		Violations:  result.Violations,
		Warnings:    result.Warnings,
		GeneratedAt: time.Now().UTC(),
	}

	// Generate recommendations.
	if !result.Passed {
		report.Recommendations = dp.generateRecommendations(result)
	}

	return report
}

// generateRecommendations creates fix recommendations based on violations.
func (dp *DecisionPoint) generateRecommendations(result CheckResult) []string {
	recommendations := make([]string, 0, len(result.Violations))
	seen := make(map[string]bool)

	for i := range result.Violations {
		v := &result.Violations[i]
		rec := dp.getRecommendation(v)
		if rec != "" && !seen[rec] {
			recommendations = append(recommendations, rec)
			seen[rec] = true
		}
	}

	return recommendations
}

// getRecommendation returns a recommendation for a violation.
func (dp *DecisionPoint) getRecommendation(v *Violation) string {
	switch v.Finding.Scanner {
	case "gitleaks":
		return "Remove or rotate exposed secrets and credentials"
	case "semgrep":
		return "Review and fix code security issues identified by SAST"
	case "trivy":
		return "Update vulnerable dependencies to patched versions"
	case "osv":
		return "Upgrade packages to versions without known vulnerabilities"
	default:
		if v.Finding.Severity == model.SeverityCritical {
			return "Immediately address all critical severity findings"
		}
		return "Review and remediate security findings before deployment"
	}
}

// FormatViolationReport formats a report as a string.
func FormatViolationReport(report ViolationReport) string {
	var builder strings.Builder
	builder.Grow(1024)

	builder.WriteString("=" + strings.Repeat("=", 59) + "\n")
	builder.WriteString(report.Title + "\n")
	builder.WriteString("=" + strings.Repeat("=", 59) + "\n\n")

	if report.Passed {
		builder.WriteString("Status: PASSED\n\n")
	} else {
		builder.WriteString("Status: FAILED\n\n")
	}

	builder.WriteString("Summary: " + report.Summary + "\n\n")

	if len(report.Violations) > 0 {
		builder.WriteString("VIOLATIONS:\n")
		builder.WriteString("-" + strings.Repeat("-", 39) + "\n")
		for i := range report.Violations {
			v := &report.Violations[i]
			builder.WriteString(fmt.Sprintf("%d. [%s] %s\n", i+1, v.Severity, v.Finding.Title))
			builder.WriteString(fmt.Sprintf("   Scanner: %s\n", v.Finding.Scanner))
			builder.WriteString(fmt.Sprintf("   File: %s\n", v.Finding.Location.File))
			builder.WriteString(fmt.Sprintf("   Reason: %s\n\n", v.Reason))
		}
	}

	if len(report.Warnings) > 0 {
		builder.WriteString("WARNINGS:\n")
		builder.WriteString("-" + strings.Repeat("-", 39) + "\n")
		for _, w := range report.Warnings {
			builder.WriteString("  - " + w + "\n")
		}
		builder.WriteString("\n")
	}

	if len(report.Recommendations) > 0 {
		builder.WriteString("RECOMMENDATIONS:\n")
		builder.WriteString("-" + strings.Repeat("-", 39) + "\n")
		for i, r := range report.Recommendations {
			builder.WriteString(fmt.Sprintf("%d. %s\n", i+1, r))
		}
		builder.WriteString("\n")
	}

	builder.WriteString("Generated at: " + report.GeneratedAt.Format(time.RFC3339) + "\n")

	return builder.String()
}

// Close releases resources.
func (dp *DecisionPoint) Close(ctx context.Context) error {
	return dp.engine.Close(ctx)
}
