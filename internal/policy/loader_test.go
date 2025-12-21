package policy

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/victoralfred/gowritter/safepath"
)

func TestLoadDirectory(t *testing.T) {
	tmpDir := t.TempDir()
	sp, err := safepath.New(tmpDir)
	if err != nil {
		t.Fatalf("failed to create safe path: %v", err)
	}

	// Create test policies
	policy1 := `package devsec
default decision = {"allow": true, "deny": false}`
	policy2 := `package devsec
default decision = {"allow": false, "deny": true}`

	err = sp.WriteFile("policy1.rego", []byte(policy1), 0o644)
	if err != nil {
		t.Fatalf("failed to write policy1: %v", err)
	}

	err = sp.WriteFile("policy2.rego", []byte(policy2), 0o644)
	if err != nil {
		t.Fatalf("failed to write policy2: %v", err)
	}

	// Create subdirectory with policy
	subDir := filepath.Join(tmpDir, "subdir")
	subSp, err := safepath.New(tmpDir)
	if err != nil {
		t.Fatalf("failed to create safe path: %v", err)
	}
	err = subSp.MkdirAll("subdir", 0o755)
	if err != nil {
		t.Fatalf("failed to create subdir: %v", err)
	}

	subSp2, err := safepath.New(subDir)
	if err != nil {
		t.Fatalf("failed to create safe path for subdir: %v", err)
	}
	err = subSp2.WriteFile("policy3.rego", []byte(policy1), 0o644)
	if err != nil {
		t.Fatalf("failed to write policy3: %v", err)
	}

	engine := New()
	ctx := context.Background()

	config := DefaultLoaderConfig()
	result, err := engine.LoadDirectory(ctx, tmpDir, config)
	if err != nil {
		t.Fatalf("LoadDirectory() error = %v", err)
	}

	if result.Loaded < 3 {
		t.Errorf("expected at least 3 policies loaded, got %d", result.Loaded)
	}
}

func TestLoadDirectoryNonRecursive(t *testing.T) {
	tmpDir := t.TempDir()
	sp, err := safepath.New(tmpDir)
	if err != nil {
		t.Fatalf("failed to create safe path: %v", err)
	}

	policy1 := `package devsec
default decision = {"allow": true, "deny": false}`

	err = sp.WriteFile("policy1.rego", []byte(policy1), 0o644)
	if err != nil {
		t.Fatalf("failed to write policy1: %v", err)
	}

	engine := New()
	ctx := context.Background()

	config := DefaultLoaderConfig()
	config.Recursive = false
	result, err := engine.LoadDirectory(ctx, tmpDir, config)
	if err != nil {
		t.Fatalf("LoadDirectory() error = %v", err)
	}

	if result.Loaded != 1 {
		t.Errorf("expected 1 policy loaded, got %d", result.Loaded)
	}
}

func TestLoadDirectoryWithMaxDepth(t *testing.T) {
	tmpDir := t.TempDir()
	sp, err := safepath.New(tmpDir)
	if err != nil {
		t.Fatalf("failed to create safe path: %v", err)
	}

	policy1 := `package devsec
default decision = {"allow": true, "deny": false}`

	err = sp.WriteFile("policy1.rego", []byte(policy1), 0o644)
	if err != nil {
		t.Fatalf("failed to write policy1: %v", err)
	}

	engine := New()
	ctx := context.Background()

	config := DefaultLoaderConfig()
	config.MaxDepth = 0 // No recursion
	result, err := engine.LoadDirectory(ctx, tmpDir, config)
	if err != nil {
		t.Fatalf("LoadDirectory() error = %v", err)
	}

	if result.Loaded != 1 {
		t.Errorf("expected 1 policy loaded, got %d", result.Loaded)
	}
}

func TestLoadDirectorySkipTestFiles(t *testing.T) {
	tmpDir := t.TempDir()
	sp, err := safepath.New(tmpDir)
	if err != nil {
		t.Fatalf("failed to create safe path: %v", err)
	}

	policy1 := `package devsec
default decision = {"allow": true, "deny": false}`
	testPolicy := `package devsec
test_decision = true`

	err = sp.WriteFile("policy1.rego", []byte(policy1), 0o644)
	if err != nil {
		t.Fatalf("failed to write policy1: %v", err)
	}

	err = sp.WriteFile("policy_test.rego", []byte(testPolicy), 0o644)
	if err != nil {
		t.Fatalf("failed to write test policy: %v", err)
	}

	engine := New()
	ctx := context.Background()

	config := DefaultLoaderConfig()
	result, err := engine.LoadDirectory(ctx, tmpDir, config)
	if err != nil {
		t.Fatalf("LoadDirectory() error = %v", err)
	}

	if result.Loaded != 1 {
		t.Errorf("expected 1 policy loaded (test file skipped), got %d", result.Loaded)
	}
	if result.Skipped < 1 {
		t.Errorf("expected at least 1 skipped file, got %d", result.Skipped)
	}
}

func TestLoadFiles(t *testing.T) {
	tmpDir := t.TempDir()
	sp, err := safepath.New(tmpDir)
	if err != nil {
		t.Fatalf("failed to create safe path: %v", err)
	}

	policy1 := `package devsec
default decision = {"allow": true, "deny": false}`
	policy2 := `package devsec
default decision = {"allow": false, "deny": true}`

	err = sp.WriteFile("policy1.rego", []byte(policy1), 0o644)
	if err != nil {
		t.Fatalf("failed to write policy1: %v", err)
	}

	err = sp.WriteFile("policy2.rego", []byte(policy2), 0o644)
	if err != nil {
		t.Fatalf("failed to write policy2: %v", err)
	}

	engine := New()
	ctx := context.Background()

	paths := []string{
		filepath.Join(tmpDir, "policy1.rego"),
		filepath.Join(tmpDir, "policy2.rego"),
	}

	result, err := engine.LoadFiles(ctx, paths)
	if err != nil {
		t.Fatalf("LoadFiles() error = %v", err)
	}

	if result.Loaded != 2 {
		t.Errorf("expected 2 policies loaded, got %d", result.Loaded)
	}
}

func TestLoadFilesWithInvalidPath(t *testing.T) {
	engine := New()
	ctx := context.Background()

	paths := []string{
		"/nonexistent/path/policy.rego",
	}

	result, err := engine.LoadFiles(ctx, paths)
	if err != nil {
		t.Fatalf("LoadFiles() error = %v", err)
	}

	if result.Loaded != 0 {
		t.Errorf("expected 0 policies loaded, got %d", result.Loaded)
	}
	if result.Failed != 1 {
		t.Errorf("expected 1 failed load, got %d", result.Failed)
	}
	if len(result.Errors) != 1 {
		t.Errorf("expected 1 error, got %d", len(result.Errors))
	}
}

func TestLoadDirectoryContextCancellation(t *testing.T) {
	tmpDir := t.TempDir()
	engine := New()
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	config := DefaultLoaderConfig()
	_, err := engine.LoadDirectory(ctx, tmpDir, config)
	if err == nil {
		t.Error("expected error for canceled context")
	}
}

func TestLoadFilesContextCancellation(t *testing.T) {
	engine := New()
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	paths := []string{"/tmp/policy.rego"}
	_, err := engine.LoadFiles(ctx, paths)
	if err == nil {
		t.Error("expected error for canceled context")
	}
}

func TestLoadDirectoryEmptyDirectory(t *testing.T) {
	tmpDir := t.TempDir()
	engine := New()
	ctx := context.Background()

	config := DefaultLoaderConfig()
	result, err := engine.LoadDirectory(ctx, tmpDir, config)
	if err != nil {
		t.Fatalf("LoadDirectory() error = %v", err)
	}

	if result.Loaded != 0 {
		t.Errorf("expected 0 policies loaded, got %d", result.Loaded)
	}
}

func TestLoadDirectoryNonRegoFiles(t *testing.T) {
	tmpDir := t.TempDir()
	sp, err := safepath.New(tmpDir)
	if err != nil {
		t.Fatalf("failed to create safe path: %v", err)
	}

	err = sp.WriteFile("not-a-policy.txt", []byte("not a policy"), 0o644)
	if err != nil {
		t.Fatalf("failed to write text file: %v", err)
	}

	engine := New()
	ctx := context.Background()

	config := DefaultLoaderConfig()
	result, err := engine.LoadDirectory(ctx, tmpDir, config)
	if err != nil {
		t.Fatalf("LoadDirectory() error = %v", err)
	}

	if result.Loaded != 0 {
		t.Errorf("expected 0 policies loaded, got %d", result.Loaded)
	}
	if result.Skipped < 1 {
		t.Errorf("expected at least 1 skipped file, got %d", result.Skipped)
	}
}
