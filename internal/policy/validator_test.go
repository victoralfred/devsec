package policy

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/victoralfred/gowritter/safepath"
)

func TestValidateFile(t *testing.T) {
	tmpDir := t.TempDir()
	sp, err := safepath.New(tmpDir)
	if err != nil {
		t.Fatalf("failed to create safe path: %v", err)
	}

	validPolicy := `package devsec
default decision = {"allow": true, "deny": false}`

	err = sp.WriteFile("valid.rego", []byte(validPolicy), 0o644)
	if err != nil {
		t.Fatalf("failed to write policy: %v", err)
	}

	engine := New()
	ctx := context.Background()

	err = engine.ValidateFile(ctx, filepath.Join(tmpDir, "valid.rego"))
	if err != nil {
		t.Fatalf("ValidateFile() error = %v", err)
	}
}

func TestValidateFileInvalidPolicy(t *testing.T) {
	tmpDir := t.TempDir()
	sp, err := safepath.New(tmpDir)
	if err != nil {
		t.Fatalf("failed to create safe path: %v", err)
	}

	invalidPolicy := `package devsec
invalid syntax {{{`

	err = sp.WriteFile("invalid.rego", []byte(invalidPolicy), 0o644)
	if err != nil {
		t.Fatalf("failed to write policy: %v", err)
	}

	engine := New()
	ctx := context.Background()

	err = engine.ValidateFile(ctx, filepath.Join(tmpDir, "invalid.rego"))
	if err == nil {
		t.Error("expected error for invalid policy")
	}
}

func TestValidatePolicy(t *testing.T) {
	tmpDir := t.TempDir()
	sp, err := safepath.New(tmpDir)
	if err != nil {
		t.Fatalf("failed to create safe path: %v", err)
	}

	validPolicy := `package devsec
default decision = {"allow": true, "deny": false}`

	err = sp.WriteFile("valid.rego", []byte(validPolicy), 0o644)
	if err != nil {
		t.Fatalf("failed to write policy: %v", err)
	}

	engine := New()
	ctx := context.Background()

	result, err := engine.ValidatePolicy(ctx, filepath.Join(tmpDir, "valid.rego"))
	if err != nil {
		t.Fatalf("ValidatePolicy() error = %v", err)
	}

	if !result.Valid {
		t.Error("expected policy to be valid")
	}
	if result.Package != "devsec" {
		t.Errorf("expected package 'devsec', got '%s'", result.Package)
	}
}

func TestValidatePolicyContent(t *testing.T) {
	engine := New()
	ctx := context.Background()

	validPolicy := `package devsec
default decision = {"allow": true, "deny": false}`

	result, err := engine.ValidatePolicyContent(ctx, "test-policy", validPolicy)
	if err != nil {
		t.Fatalf("ValidatePolicyContent() error = %v", err)
	}

	if !result.Valid {
		t.Error("expected policy to be valid")
	}
}

func TestValidatePolicyContentInvalid(t *testing.T) {
	engine := New()
	ctx := context.Background()

	invalidPolicy := `package devsec
invalid syntax {{{`

	result, err := engine.ValidatePolicyContent(ctx, "test-policy", invalidPolicy)
	if err != nil {
		t.Fatalf("ValidatePolicyContent() error = %v", err)
	}

	if result.Valid {
		t.Error("expected policy to be invalid")
	}
	if len(result.Errors) == 0 {
		t.Error("expected validation errors")
	}
}

func TestValidatePolicyContentWrongPackage(t *testing.T) {
	engine := New()
	ctx := context.Background()

	wrongPackagePolicy := `package wrong
default decision = {"allow": true, "deny": false}`

	result, err := engine.ValidatePolicyContent(ctx, "test-policy", wrongPackagePolicy)
	if err != nil {
		t.Fatalf("ValidatePolicyContent() error = %v", err)
	}

	if !result.Valid {
		t.Error("expected policy to be valid (wrong package is a warning)")
	}
	if len(result.Warnings) == 0 {
		t.Error("expected warning for wrong package")
	}
}

func TestValidatePolicyContentMissingDecisionRule(t *testing.T) {
	engine := New()
	ctx := context.Background()

	noDecisionPolicy := `package devsec
some_other_rule = true`

	result, err := engine.ValidatePolicyContent(ctx, "test-policy", noDecisionPolicy)
	if err != nil {
		t.Fatalf("ValidatePolicyContent() error = %v", err)
	}

	if !result.Valid {
		t.Error("expected policy to be valid (missing decision is a warning)")
	}
	if len(result.Warnings) == 0 {
		t.Error("expected warning for missing decision rule")
	}
}

func TestValidateString(t *testing.T) {
	engine := New()
	ctx := context.Background()

	validPolicy := `package devsec
default decision = {"allow": true, "deny": false}`

	result, err := engine.ValidateString(ctx, "test-policy", validPolicy)
	if err != nil {
		t.Fatalf("ValidateString() error = %v", err)
	}

	if !result.Valid {
		t.Error("expected policy to be valid")
	}
}

func TestValidatePolicyEmptyFile(t *testing.T) {
	tmpDir := t.TempDir()
	sp, err := safepath.New(tmpDir)
	if err != nil {
		t.Fatalf("failed to create safe path: %v", err)
	}

	err = sp.WriteFile("empty.rego", []byte{}, 0o644)
	if err != nil {
		t.Fatalf("failed to write empty file: %v", err)
	}

	engine := New()
	ctx := context.Background()

	result, err := engine.ValidatePolicy(ctx, filepath.Join(tmpDir, "empty.rego"))
	if err != nil {
		t.Fatalf("ValidatePolicy() error = %v", err)
	}

	if result.Valid {
		t.Error("expected policy to be invalid (empty file)")
	}
	if len(result.Errors) == 0 {
		t.Error("expected validation errors for empty file")
	}
}

func TestValidatePolicyFileNotFound(t *testing.T) {
	engine := New()
	ctx := context.Background()

	result, err := engine.ValidatePolicy(ctx, "/nonexistent/path/policy.rego")
	if err != nil {
		t.Fatalf("ValidatePolicy() error = %v", err)
	}

	if result.Valid {
		t.Error("expected policy to be invalid (file not found)")
	}
	if len(result.Errors) == 0 {
		t.Error("expected validation errors for missing file")
	}
}

func TestValidatePolicyContextCancellation(t *testing.T) {
	engine := New()
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, err := engine.ValidatePolicy(ctx, "/tmp/policy.rego")
	if err == nil {
		t.Error("expected error for canceled context")
	}
}

func TestValidatePolicyLargeFile(t *testing.T) {
	tmpDir := t.TempDir()
	sp, err := safepath.New(tmpDir)
	if err != nil {
		t.Fatalf("failed to create safe path: %v", err)
	}

	// Create a file larger than MaxPolicySize
	largeData := make([]byte, MaxPolicySize+1)
	for i := range largeData {
		largeData[i] = byte(i % 256)
	}

	err = sp.WriteFile("large.rego", largeData, 0o644)
	if err != nil {
		t.Fatalf("failed to write large file: %v", err)
	}

	engine := New()
	ctx := context.Background()

	result, err := engine.ValidatePolicy(ctx, filepath.Join(tmpDir, "large.rego"))
	if err != nil {
		t.Fatalf("ValidatePolicy() error = %v", err)
	}

	if result.Valid {
		t.Error("expected policy to be invalid (file too large)")
	}
	if len(result.Errors) == 0 {
		t.Error("expected validation errors for large file")
	}
}

func TestParseAstErrors(t *testing.T) {
	// Test that parseAstErrors handles different error types
	tests := []struct {
		err  error
		name string
	}{
		{name: "nil error", err: nil},
		{name: "generic error", err: &testError{msg: "test error"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errors := parseAstErrors(tt.err)
			if tt.err == nil && len(errors) > 0 {
				t.Error("expected no errors for nil input")
			}
			if tt.err != nil && len(errors) == 0 {
				t.Error("expected errors for non-nil input")
			}
		})
	}
}

type testError struct {
	msg string
}

func (e *testError) Error() string {
	return e.msg
}
