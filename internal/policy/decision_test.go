package policy

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/victoralfred/devsec/internal/model"
	"github.com/victoralfred/gowritter/safepath"
)

// containsString checks if a string contains a substring.
func containsString(s, substr string) bool {
	return strings.Contains(s, substr)
}

func TestNewDecisionPoint(t *testing.T) {
	ctx := context.Background()

	dp, err := NewDecisionPoint(ctx)
	if err != nil {
		t.Fatalf("NewDecisionPoint() error = %v", err)
	}
	defer func() {
		_ = dp.Close(ctx)
	}()

	if dp.policyName != DefaultPolicyName {
		t.Errorf("expected policy name %s, got %s", DefaultPolicyName, dp.policyName)
	}
}

func TestNewDecisionPointWithStrictMode(t *testing.T) {
	ctx := context.Background()

	dp, err := NewDecisionPoint(ctx, WithStrictMode(true))
	if err != nil {
		t.Fatalf("NewDecisionPoint() error = %v", err)
	}
	defer func() {
		_ = dp.Close(ctx)
	}()

	if !dp.strictMode {
		t.Error("expected strict mode to be enabled")
	}
}

func TestDecisionPointCheckPass(t *testing.T) {
	ctx := context.Background()

	dp, err := NewDecisionPoint(ctx)
	if err != nil {
		t.Fatalf("NewDecisionPoint() error = %v", err)
	}
	defer func() {
		_ = dp.Close(ctx)
	}()

	// Low severity findings should pass.
	findings := []model.Finding{
		{
			ID:       "1",
			Severity: model.SeverityLow,
			Title:    "Low severity issue",
			Scanner:  "test",
		},
		{
			ID:       "2",
			Severity: model.SeverityMedium,
			Title:    "Medium severity issue",
			Scanner:  "test",
		},
	}

	result, err := dp.Check(ctx, findings)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}

	if !result.Passed {
		t.Error("expected check to pass for low/medium findings")
	}

	if len(result.Violations) != 0 {
		t.Errorf("expected 0 violations, got %d", len(result.Violations))
	}
}

func TestDecisionPointCheckFailCritical(t *testing.T) {
	ctx := context.Background()

	dp, err := NewDecisionPoint(ctx)
	if err != nil {
		t.Fatalf("NewDecisionPoint() error = %v", err)
	}
	defer func() {
		_ = dp.Close(ctx)
	}()

	findings := []model.Finding{
		{
			ID:       "1",
			Severity: model.SeverityCritical,
			Title:    "Critical vulnerability",
			Scanner:  "trivy",
			Location: model.Location{File: "go.mod"},
		},
	}

	result, err := dp.Check(ctx, findings)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}

	if result.Passed {
		t.Error("expected check to fail for critical finding")
	}

	if len(result.Violations) != 1 {
		t.Errorf("expected 1 violation, got %d", len(result.Violations))
	}
}

func TestDecisionPointCheckFailHigh(t *testing.T) {
	ctx := context.Background()

	dp, err := NewDecisionPoint(ctx)
	if err != nil {
		t.Fatalf("NewDecisionPoint() error = %v", err)
	}
	defer func() {
		_ = dp.Close(ctx)
	}()

	findings := []model.Finding{
		{
			ID:       "1",
			Severity: model.SeverityHigh,
			Title:    "High severity issue",
			Scanner:  "semgrep",
			Location: model.Location{File: "main.go"},
		},
	}

	result, err := dp.Check(ctx, findings)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}

	if result.Passed {
		t.Error("expected check to fail for high finding")
	}
}

func TestDecisionPointStrictModeWarnings(t *testing.T) {
	ctx := context.Background()

	dp, err := NewDecisionPoint(ctx, WithStrictMode(true))
	if err != nil {
		t.Fatalf("NewDecisionPoint() error = %v", err)
	}
	defer func() {
		_ = dp.Close(ctx)
	}()

	// Medium findings should pass but generate warnings in strict mode.
	findings := []model.Finding{
		{
			ID:       "1",
			Severity: model.SeverityMedium,
			Title:    "Medium severity issue",
			Scanner:  "semgrep",
		},
	}

	result, err := dp.Check(ctx, findings)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}

	if !result.Passed {
		t.Error("expected check to pass for medium findings in strict mode")
	}

	if len(result.Warnings) == 0 {
		t.Error("expected warnings for medium findings in strict mode")
	}
}

func TestDecisionPointEmptyFindings(t *testing.T) {
	ctx := context.Background()

	dp, err := NewDecisionPoint(ctx)
	if err != nil {
		t.Fatalf("NewDecisionPoint() error = %v", err)
	}
	defer func() {
		_ = dp.Close(ctx)
	}()

	result, err := dp.Check(ctx, []model.Finding{})
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}

	if !result.Passed {
		t.Error("expected check to pass for empty findings")
	}

	if result.TotalCount != 0 {
		t.Errorf("expected TotalCount 0, got %d", result.TotalCount)
	}
}

func TestDecisionPointWithCustomPolicy(t *testing.T) {
	ctx := context.Background()

	// Create temp policy file.
	tmpDir := "/tmp"
	policyFile := "test-custom-policy.rego"

	sp, err := safepath.New(tmpDir)
	if err != nil {
		t.Fatalf("failed to create safe path: %v", err)
	}

	customPolicy := `
package devsec

default decision := {"allow": true, "deny": false, "warnings": []}
`

	writeErr := sp.WriteFile(policyFile, []byte(customPolicy), 0o600)
	if writeErr != nil {
		t.Fatalf("failed to write policy: %v", writeErr)
	}
	defer func() {
		_ = sp.Remove(policyFile)
	}()

	policyPath := filepath.Join(tmpDir, policyFile)
	dp, dpErr := NewDecisionPointWithPolicy(ctx, policyPath)
	if dpErr != nil {
		t.Fatalf("NewDecisionPointWithPolicy() error = %v", dpErr)
	}
	defer func() {
		_ = dp.Close(ctx)
	}()

	// Should pass even with critical findings due to custom policy.
	findings := []model.Finding{
		{ID: "1", Severity: model.SeverityCritical},
	}

	result, checkErr := dp.Check(ctx, findings)
	if checkErr != nil {
		t.Fatalf("Check() error = %v", checkErr)
	}

	if !result.Passed {
		t.Error("expected check to pass with allow-all custom policy")
	}
}

func TestGenerateReport(t *testing.T) {
	ctx := context.Background()

	dp, err := NewDecisionPoint(ctx)
	if err != nil {
		t.Fatalf("NewDecisionPoint() error = %v", err)
	}
	defer func() {
		_ = dp.Close(ctx)
	}()

	findings := []model.Finding{
		{
			ID:       "1",
			Severity: model.SeverityCritical,
			Title:    "SQL Injection",
			Scanner:  "semgrep",
			Location: model.Location{File: "db.go", StartLine: 42},
		},
		{
			ID:       "2",
			Severity: model.SeverityHigh,
			Title:    "Exposed Secret",
			Scanner:  "gitleaks",
			Location: model.Location{File: ".env", StartLine: 5},
		},
	}

	result, err := dp.Check(ctx, findings)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}

	report := dp.GenerateReport(result)

	if report.Passed {
		t.Error("expected report to show failed")
	}

	if len(report.Violations) != 2 {
		t.Errorf("expected 2 violations, got %d", len(report.Violations))
	}

	if len(report.Recommendations) == 0 {
		t.Error("expected recommendations in report")
	}

	if report.GeneratedAt.IsZero() {
		t.Error("expected GeneratedAt to be set")
	}
}

func TestFormatViolationReport(t *testing.T) {
	ctx := context.Background()

	dp, err := NewDecisionPoint(ctx)
	if err != nil {
		t.Fatalf("NewDecisionPoint() error = %v", err)
	}
	defer func() {
		_ = dp.Close(ctx)
	}()

	findings := []model.Finding{
		{
			ID:       "1",
			Severity: model.SeverityCritical,
			Title:    "Critical Issue",
			Scanner:  "trivy",
			Location: model.Location{File: "package.json"},
		},
	}

	result, err := dp.Check(ctx, findings)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}

	report := dp.GenerateReport(result)
	formatted := FormatViolationReport(report)

	if formatted == "" {
		t.Error("expected non-empty formatted report")
	}

	// Check for expected sections.
	expectedStrings := []string{
		"Security Policy Violation Report",
		"Status: FAILED",
		"VIOLATIONS:",
		"Critical Issue",
		"RECOMMENDATIONS:",
	}

	for _, expected := range expectedStrings {
		if !containsString(formatted, expected) {
			t.Errorf("formatted report should contain %q", expected)
		}
	}
}

func TestCheckResultSummary(t *testing.T) {
	ctx := context.Background()

	dp, err := NewDecisionPoint(ctx)
	if err != nil {
		t.Fatalf("NewDecisionPoint() error = %v", err)
	}
	defer func() {
		_ = dp.Close(ctx)
	}()

	findings := []model.Finding{
		{ID: "1", Severity: model.SeverityLow},
	}

	result, err := dp.Check(ctx, findings)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}

	if result.Summary == "" {
		t.Error("expected non-empty summary")
	}

	if !containsString(result.Summary, "PASSED") {
		t.Error("summary should contain PASSED")
	}
}

func TestDecisionPointClose(t *testing.T) {
	ctx := context.Background()

	dp, err := NewDecisionPoint(ctx)
	if err != nil {
		t.Fatalf("NewDecisionPoint() error = %v", err)
	}

	closeErr := dp.Close(ctx)
	if closeErr != nil {
		t.Errorf("Close() error = %v", closeErr)
	}
}

func TestRecommendationsByScanner(t *testing.T) {
	ctx := context.Background()

	dp, err := NewDecisionPoint(ctx)
	if err != nil {
		t.Fatalf("NewDecisionPoint() error = %v", err)
	}
	defer func() {
		_ = dp.Close(ctx)
	}()

	scanners := []struct {
		name            string
		scanner         string
		expectedContain string
	}{
		{"gitleaks", "gitleaks", "secrets"},
		{"semgrep", "semgrep", "SAST"},
		{"trivy", "trivy", "dependencies"},
		{"osv", "osv", "packages"},
	}

	for _, tc := range scanners {
		t.Run(tc.name, func(t *testing.T) {
			findings := []model.Finding{
				{
					ID:       "1",
					Severity: model.SeverityCritical,
					Scanner:  tc.scanner,
				},
			}

			result, checkErr := dp.Check(ctx, findings)
			if checkErr != nil {
				t.Fatalf("Check() error = %v", checkErr)
			}

			report := dp.GenerateReport(result)

			found := false
			for _, rec := range report.Recommendations {
				if containsString(rec, tc.expectedContain) {
					found = true
					break
				}
			}

			if !found {
				t.Errorf("expected recommendation containing %q for scanner %s", tc.expectedContain, tc.scanner)
			}
		})
	}
}
