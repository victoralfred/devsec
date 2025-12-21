package policy

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/victoralfred/devsec/internal/model"
	"github.com/victoralfred/gowritter/safepath"
)

const testPolicyAllow = `
package devsec

default decision = {"allow": true, "deny": false}
`

const testPolicyDeny = `
package devsec

default decision = {"allow": false, "deny": true}
`

const testPolicySeverityCheck = `
package devsec

default decision := {"allow": true, "deny": false, "warnings": []}

decision := d if {
	critical_count := count([f | some f in input.findings; f.severity == "critical"])
	high_count := count([f | some f in input.findings; f.severity == "high"])

	critical_count == 0
	high_count == 0
	d := {"allow": true, "deny": false, "warnings": []}
}

decision := d if {
	critical_count := count([f | some f in input.findings; f.severity == "critical"])
	critical_count > 0
	d := {"allow": false, "deny": true, "warnings": ["Critical vulnerabilities found"]}
}

decision := d if {
	critical_count := count([f | some f in input.findings; f.severity == "critical"])
	high_count := count([f | some f in input.findings; f.severity == "high"])

	critical_count == 0
	high_count > 0
	d := {"allow": false, "deny": true, "warnings": ["High severity vulnerabilities found"]}
}
`

func TestNew(t *testing.T) {
	engine := New()

	if engine.defaultQuery != DefaultQuery {
		t.Errorf("expected default query %s, got %s", DefaultQuery, engine.defaultQuery)
	}

	if engine.PolicyCount() != 0 {
		t.Errorf("expected 0 policies, got %d", engine.PolicyCount())
	}
}

func TestNewWithOptions(t *testing.T) {
	customQuery := "data.custom.result"
	engine := New(WithDefaultQuery(customQuery))

	if engine.defaultQuery != customQuery {
		t.Errorf("expected default query %s, got %s", customQuery, engine.defaultQuery)
	}
}

func TestLoadPolicyFromString(t *testing.T) {
	engine := New()
	ctx := context.Background()

	err := engine.LoadPolicyFromString(ctx, "test-policy", testPolicyAllow)
	if err != nil {
		t.Fatalf("LoadPolicyFromString() error = %v", err)
	}

	if engine.PolicyCount() != 1 {
		t.Errorf("expected 1 policy, got %d", engine.PolicyCount())
	}
}

func TestLoadPolicyFromStringInvalid(t *testing.T) {
	engine := New()
	ctx := context.Background()

	err := engine.LoadPolicyFromString(ctx, "invalid", "this is not valid rego {{{")
	if err == nil {
		t.Fatal("expected error for invalid policy")
	}
}

func TestLoadPolicy(t *testing.T) {
	// Create temp policy file.
	tmpDir := "/tmp"
	policyFile := "test-policy.rego"

	sp, err := safepath.New(tmpDir)
	if err != nil {
		t.Fatalf("failed to create safe path: %v", err)
	}

	writeErr := sp.WriteFile(policyFile, []byte(testPolicyAllow), 0o600)
	if writeErr != nil {
		t.Fatalf("failed to write policy file: %v", writeErr)
	}
	defer func() {
		_ = sp.Remove(policyFile)
	}()

	engine := New()
	ctx := context.Background()

	policyPath := filepath.Join(tmpDir, policyFile)
	loadErr := engine.LoadPolicy(ctx, policyPath)
	if loadErr != nil {
		t.Fatalf("LoadPolicy() error = %v", loadErr)
	}

	if engine.PolicyCount() != 1 {
		t.Errorf("expected 1 policy, got %d", engine.PolicyCount())
	}
}

func TestLoadPolicyEmptyPath(t *testing.T) {
	engine := New()
	ctx := context.Background()

	err := engine.LoadPolicy(ctx, "")
	if err == nil {
		t.Fatal("expected error for empty path")
	}
}

func TestLoadPolicyNotFound(t *testing.T) {
	engine := New()
	ctx := context.Background()

	err := engine.LoadPolicy(ctx, "/nonexistent/path/policy.rego")
	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}
}

func TestEvaluateAllow(t *testing.T) {
	engine := New()
	ctx := context.Background()

	err := engine.LoadPolicyFromString(ctx, "allow-policy", testPolicyAllow)
	if err != nil {
		t.Fatalf("failed to load policy: %v", err)
	}

	findings := []model.Finding{
		{
			ID:       "test-1",
			Severity: model.SeverityLow,
			Title:    "Test finding",
		},
	}

	results, err := engine.Evaluate(ctx, findings)
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	if !results[0].Decision.Allow {
		t.Error("expected decision to allow")
	}

	if results[0].Decision.Deny {
		t.Error("expected decision not to deny")
	}
}

func TestEvaluateDeny(t *testing.T) {
	engine := New()
	ctx := context.Background()

	err := engine.LoadPolicyFromString(ctx, "deny-policy", testPolicyDeny)
	if err != nil {
		t.Fatalf("failed to load policy: %v", err)
	}

	findings := []model.Finding{
		{
			ID:       "test-1",
			Severity: model.SeverityCritical,
			Title:    "Critical finding",
		},
	}

	results, err := engine.Evaluate(ctx, findings)
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	if results[0].Decision.Allow {
		t.Error("expected decision not to allow")
	}

	if !results[0].Decision.Deny {
		t.Error("expected decision to deny")
	}
}

func TestEvaluateSeverityPolicy(t *testing.T) {
	engine := New()
	ctx := context.Background()

	err := engine.LoadPolicyFromString(ctx, "severity-policy", testPolicySeverityCheck)
	if err != nil {
		t.Fatalf("failed to load policy: %v", err)
	}

	tests := []struct {
		name        string
		findings    []model.Finding
		expectAllow bool
		expectDeny  bool
		expectWarn  bool
	}{
		{
			name:        "no findings",
			findings:    []model.Finding{},
			expectAllow: true,
			expectDeny:  false,
			expectWarn:  false,
		},
		{
			name: "low severity only",
			findings: []model.Finding{
				{ID: "1", Severity: model.SeverityLow},
				{ID: "2", Severity: model.SeverityMedium},
			},
			expectAllow: true,
			expectDeny:  false,
			expectWarn:  false,
		},
		{
			name: "critical finding",
			findings: []model.Finding{
				{ID: "1", Severity: model.SeverityCritical},
			},
			expectAllow: false,
			expectDeny:  true,
			expectWarn:  true,
		},
		{
			name: "high finding",
			findings: []model.Finding{
				{ID: "1", Severity: model.SeverityHigh},
			},
			expectAllow: false,
			expectDeny:  true,
			expectWarn:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results, err := engine.Evaluate(ctx, tt.findings)
			if err != nil {
				t.Fatalf("Evaluate() error = %v", err)
			}

			if len(results) != 1 {
				t.Fatalf("expected 1 result, got %d", len(results))
			}

			r := results[0]
			if r.Decision.Allow != tt.expectAllow {
				t.Errorf("expected allow=%v, got %v", tt.expectAllow, r.Decision.Allow)
			}
			if r.Decision.Deny != tt.expectDeny {
				t.Errorf("expected deny=%v, got %v", tt.expectDeny, r.Decision.Deny)
			}
			if tt.expectWarn && len(r.Decision.Warnings) == 0 {
				t.Error("expected warnings but got none")
			}
		})
	}
}

func TestEvaluateNoPolicies(t *testing.T) {
	engine := New()
	ctx := context.Background()

	_, err := engine.Evaluate(ctx, []model.Finding{})
	if err == nil {
		t.Fatal("expected error when no policies loaded")
	}
}

func TestEvaluateSingle(t *testing.T) {
	engine := New()
	ctx := context.Background()

	// Create temp policy file.
	tmpDir := "/tmp"
	policyFile := "test-single-policy.rego"

	sp, spErr := safepath.New(tmpDir)
	if spErr != nil {
		t.Fatalf("failed to create safe path: %v", spErr)
	}

	writeErr := sp.WriteFile(policyFile, []byte(testPolicyAllow), 0o600)
	if writeErr != nil {
		t.Fatalf("failed to write policy file: %v", writeErr)
	}
	defer func() {
		_ = sp.Remove(policyFile)
	}()

	policyPath := filepath.Join(tmpDir, policyFile)
	loadErr := engine.LoadPolicy(ctx, policyPath)
	if loadErr != nil {
		t.Fatalf("LoadPolicy() error = %v", loadErr)
	}

	result, err := engine.EvaluateSingle(ctx, policyPath, []model.Finding{})
	if err != nil {
		t.Fatalf("EvaluateSingle() error = %v", err)
	}

	if !result.Decision.Allow {
		t.Error("expected decision to allow")
	}
}

func TestEvaluateSingleNotFound(t *testing.T) {
	engine := New()
	ctx := context.Background()

	_, err := engine.EvaluateSingle(ctx, "/nonexistent", []model.Finding{})
	if err == nil {
		t.Fatal("expected error for nonexistent policy")
	}
}

func TestListPolicies(t *testing.T) {
	engine := New()
	ctx := context.Background()

	// Load two policies.
	err := engine.LoadPolicyFromString(ctx, "policy1", testPolicyAllow)
	if err != nil {
		t.Fatalf("failed to load policy1: %v", err)
	}

	err = engine.LoadPolicyFromString(ctx, "policy2", testPolicyDeny)
	if err != nil {
		t.Fatalf("failed to load policy2: %v", err)
	}

	policies := engine.ListPolicies()
	if len(policies) != 2 {
		t.Errorf("expected 2 policies, got %d", len(policies))
	}
}

func TestContextCancellation(t *testing.T) {
	engine := New()
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately.

	err := engine.LoadPolicy(ctx, "/some/path.rego")
	if err == nil {
		t.Fatal("expected error for canceled context")
	}
}

func TestClose(t *testing.T) {
	engine := New()
	ctx := context.Background()

	err := engine.Close(ctx)
	if err != nil {
		t.Errorf("Close() error = %v", err)
	}
}

func TestParseDecisionBoolean(t *testing.T) {
	engine := New()
	ctx := context.Background()

	boolPolicy := `
package devsec

decision = true
`

	err := engine.LoadPolicyFromString(ctx, "bool-policy", boolPolicy)
	if err != nil {
		t.Fatalf("failed to load policy: %v", err)
	}

	results, err := engine.Evaluate(ctx, []model.Finding{})
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}

	if !results[0].Decision.Allow {
		t.Error("expected decision to allow for boolean true")
	}
}

func TestEvaluationResult(t *testing.T) {
	engine := New()
	ctx := context.Background()

	err := engine.LoadPolicyFromString(ctx, "test-policy", testPolicyAllow)
	if err != nil {
		t.Fatalf("failed to load policy: %v", err)
	}

	findings := []model.Finding{
		{ID: "1", Severity: model.SeverityLow},
		{ID: "2", Severity: model.SeverityMedium},
	}

	results, err := engine.Evaluate(ctx, findings)
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}

	r := results[0]
	if r.TotalCount != 2 {
		t.Errorf("expected TotalCount 2, got %d", r.TotalCount)
	}

	if r.EvalTimeMs < 0 {
		t.Error("expected non-negative eval time")
	}

	if r.PolicyName == "" {
		t.Error("expected non-empty policy name")
	}
}
