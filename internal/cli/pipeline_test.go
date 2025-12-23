package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/victoralfred/devsec/internal/pipeline"
)

func TestNewPipelineCmd(t *testing.T) {
	cmd := NewPipelineCmd()

	if cmd.Use != "pipeline" {
		t.Errorf("Use = %v, want pipeline", cmd.Use)
	}

	if cmd.Short == "" {
		t.Error("Short description is empty")
	}

	// Check subcommands.
	subcommands := cmd.Commands()
	if len(subcommands) != 3 {
		t.Errorf("expected 3 subcommands, got %d", len(subcommands))
	}

	expectedSubcommands := map[string]bool{
		"run":      false,
		"validate": false,
		"generate": false,
	}

	for _, sub := range subcommands {
		if _, ok := expectedSubcommands[sub.Name()]; ok {
			expectedSubcommands[sub.Name()] = true
		}
	}

	for name, found := range expectedSubcommands {
		if !found {
			t.Errorf("expected subcommand %q not found", name)
		}
	}
}

func TestNewPipelineRunCmd(t *testing.T) {
	cmd := NewPipelineRunCmd()

	if cmd.Use != "run [pipeline-file] [path]" {
		t.Errorf("Use = %v, want 'run [pipeline-file] [path]'", cmd.Use)
	}

	// Check flags.
	flags := []string{"output", "format", "timeout", "parallel", "dry-run"}
	for _, flag := range flags {
		if cmd.Flags().Lookup(flag) == nil {
			t.Errorf("flag %q not found", flag)
		}
	}
}

func TestNewPipelineValidateCmd(t *testing.T) {
	cmd := NewPipelineValidateCmd()

	if cmd.Use != "validate [pipeline-file]" {
		t.Errorf("Use = %v, want 'validate [pipeline-file]'", cmd.Use)
	}

	// Check flags.
	flags := []string{"output", "format"}
	for _, flag := range flags {
		if cmd.Flags().Lookup(flag) == nil {
			t.Errorf("flag %q not found", flag)
		}
	}
}

func TestNewPipelineGenerateCmd(t *testing.T) {
	cmd := NewPipelineGenerateCmd()

	if cmd.Use != "generate [template]" {
		t.Errorf("Use = %v, want 'generate [template]'", cmd.Use)
	}

	// Check flags.
	flags := []string{"output", "template"}
	for _, flag := range flags {
		if cmd.Flags().Lookup(flag) == nil {
			t.Errorf("flag %q not found", flag)
		}
	}
}

func TestIsPipelineFile(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"pipeline.yaml", true},
		{"pipeline.yml", true},
		{"devsec.YAML", true},
		{".devsec.yml", true},
		{"pipeline.json", false},
		{"README.md", false},
		{"pipeline", false},
		{"src/main.go", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			if got := isPipelineFile(tt.path); got != tt.want {
				t.Errorf("isPipelineFile(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

func TestGeneratePipelineTemplate(t *testing.T) {
	tests := []struct {
		template    string
		wantName    string
		wantVersion string
		wantStages  int
		wantErr     bool
	}{
		{
			template:    "basic",
			wantErr:     false,
			wantName:    "security-scan",
			wantStages:  3,
			wantVersion: "1.0.0",
		},
		{
			template:    "full",
			wantErr:     false,
			wantName:    "full-security-pipeline",
			wantStages:  7,
			wantVersion: "1.0.0",
		},
		{
			template:    "parallel",
			wantErr:     false,
			wantName:    "parallel-scan",
			wantStages:  5,
			wantVersion: "1.0.0",
		},
		{
			template:    "cicd",
			wantErr:     false,
			wantName:    "cicd-security-check",
			wantStages:  3,
			wantVersion: "1.0.0",
		},
		{
			template: "unknown",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.template, func(t *testing.T) {
			p, err := generatePipelineTemplate(tt.template)

			if (err != nil) != tt.wantErr {
				t.Errorf("generatePipelineTemplate(%q) error = %v, wantErr %v", tt.template, err, tt.wantErr)
				return
			}

			if err != nil {
				return
			}

			if p.Name != tt.wantName {
				t.Errorf("Name = %v, want %v", p.Name, tt.wantName)
			}
			if len(p.Stages) != tt.wantStages {
				t.Errorf("Stages = %d, want %d", len(p.Stages), tt.wantStages)
			}
			if p.Version != tt.wantVersion {
				t.Errorf("Version = %v, want %v", p.Version, tt.wantVersion)
			}

			// Validate the generated pipeline.
			if err := p.Validate(); err != nil {
				t.Errorf("generated pipeline is invalid: %v", err)
			}
		})
	}
}

func TestGetStatusIcon(t *testing.T) {
	tests := []struct {
		status pipeline.StageStatus
		want   string
	}{
		{pipeline.StageStatusSuccess, "[OK]"},
		{pipeline.StageStatusFailed, "[FAIL]"},
		{pipeline.StageStatusSkipped, "[SKIP]"},
		{pipeline.StageStatusCanceled, "[CANCEL]"},
		{pipeline.StageStatusRunning, "[RUN]"},
		{pipeline.StageStatusPending, "[?]"},
	}

	for _, tt := range tests {
		t.Run(string(tt.status), func(t *testing.T) {
			if got := getStatusIcon(tt.status); got != tt.want {
				t.Errorf("getStatusIcon(%v) = %v, want %v", tt.status, got, tt.want)
			}
		})
	}
}

func TestFormatPipelineResultText(t *testing.T) {
	result := pipeline.PipelineResult{
		Name:      "test-pipeline",
		Status:    pipeline.StageStatusSuccess,
		Duration:  5 * time.Second,
		StartTime: time.Now().Add(-5 * time.Second),
		EndTime:   time.Now(),
		Stages: []pipeline.StageResult{
			{
				Name:     "stage1",
				Status:   pipeline.StageStatusSuccess,
				Duration: 2 * time.Second,
			},
			{
				Name:     "stage2",
				Status:   pipeline.StageStatusSuccess,
				Duration: 3 * time.Second,
			},
		},
	}

	output := formatPipelineResultText(result)

	// Check for expected content.
	expectedStrings := []string{
		"Pipeline Execution Results",
		"test-pipeline",
		"SUCCESS",
		"stage1",
		"stage2",
		"Total Stages: 2",
		"Successful: 2",
	}

	for _, expected := range expectedStrings {
		if !bytes.Contains([]byte(output), []byte(expected)) {
			t.Errorf("output missing expected string: %q", expected)
		}
	}
}

func TestFormatPipelineResultMarkdown(t *testing.T) {
	result := pipeline.PipelineResult{
		Name:      "test-pipeline",
		Status:    pipeline.StageStatusFailed,
		Duration:  10 * time.Second,
		StartTime: time.Now().Add(-10 * time.Second),
		EndTime:   time.Now(),
		Error:     "stage failed",
		Stages: []pipeline.StageResult{
			{
				Name:     "stage1",
				Status:   pipeline.StageStatusSuccess,
				Duration: 5 * time.Second,
			},
			{
				Name:     "stage2",
				Status:   pipeline.StageStatusFailed,
				Duration: 5 * time.Second,
				Error:    "execution error",
			},
		},
	}

	output := formatPipelineResultMarkdown(result)

	// Check for expected markdown content.
	expectedStrings := []string{
		"# Pipeline Execution Results",
		"**Pipeline**: test-pipeline",
		"**Status**: `FAILED`",
		"**Error**: stage failed",
		"## Summary",
		"| Stage | Status | Duration | Error |",
		"stage1",
		"stage2",
		"execution error",
	}

	for _, expected := range expectedStrings {
		if !bytes.Contains([]byte(output), []byte(expected)) {
			t.Errorf("output missing expected string: %q", expected)
		}
	}
}

func TestFormatPipelineValidationResult(t *testing.T) {
	tests := []struct {
		name   string
		want   []string
		result pipelineValidationResult
	}{
		{
			name: "valid pipeline",
			result: pipelineValidationResult{
				File:     "pipeline.yaml",
				Pipeline: "test-pipeline",
				Version:  "1.0.0",
				Stages:   3,
				Valid:    true,
			},
			want: []string{
				"Pipeline Validation",
				"pipeline.yaml",
				"test-pipeline",
				"1.0.0",
				"Stages: 3",
				"Status: VALID",
			},
		},
		{
			name: "invalid pipeline",
			result: pipelineValidationResult{
				File:   "bad.yaml",
				Valid:  false,
				Errors: []string{"invalid YAML", "missing name"},
			},
			want: []string{
				"Pipeline Validation",
				"bad.yaml",
				"Status: INVALID",
				"Errors:",
				"invalid YAML",
				"missing name",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output := formatPipelineValidationResult(tt.result)

			for _, expected := range tt.want {
				if !bytes.Contains([]byte(output), []byte(expected)) {
					t.Errorf("output missing expected string: %q", expected)
				}
			}
		})
	}
}

func TestPipelineGenerate_Integration(t *testing.T) {
	// Create temp directory.
	tmpDir, err := os.MkdirTemp("", "pipeline-test-*")
	if err != nil {
		t.Fatalf("create temp dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(tmpDir) })

	genOutputFile := filepath.Join(tmpDir, "test-pipeline.yaml")

	// Set up command.
	cmd := NewPipelineGenerateCmd()
	cmd.SetArgs([]string{"basic"})

	// Set output flag.
	if setErr := cmd.Flags().Set("output", genOutputFile); setErr != nil {
		t.Fatalf("set output flag: %v", setErr)
	}

	// Execute.
	if execErr := cmd.Execute(); execErr != nil {
		t.Fatalf("execute: %v", execErr)
	}

	// Verify file was created.
	if _, statErr := os.Stat(genOutputFile); os.IsNotExist(statErr) {
		t.Error("output file was not created")
	}

	// Load and validate the generated file.
	loader := pipeline.NewLoader()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	p, loadErr := loader.Load(ctx, genOutputFile)
	if loadErr != nil {
		t.Fatalf("load generated pipeline: %v", loadErr)
	}

	if p.Name != "security-scan" {
		t.Errorf("Name = %v, want security-scan", p.Name)
	}
}

func TestPipelineValidate_Integration(t *testing.T) {
	// Create temp directory.
	tmpDir, err := os.MkdirTemp("", "pipeline-test-*")
	if err != nil {
		t.Fatalf("create temp dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(tmpDir) })

	// Create a valid pipeline file.
	pipelineFile := filepath.Join(tmpDir, "valid.yaml")
	pipelineContent := `
name: test-pipeline
version: "1.0.0"
stages:
  - name: test
    kind: scan
    config:
      scanner: gitleaks
`
	if writeErr := os.WriteFile(pipelineFile, []byte(pipelineContent), 0o600); writeErr != nil {
		t.Fatalf("write pipeline file: %v", writeErr)
	}

	// Set up command.
	cmd := NewPipelineValidateCmd()
	cmd.SetArgs([]string{pipelineFile})

	var stdout bytes.Buffer
	cmd.SetOut(&stdout)

	// Execute.
	if execErr := cmd.Execute(); execErr != nil {
		t.Fatalf("execute: %v", execErr)
	}

	output := stdout.String()
	if !bytes.Contains([]byte(output), []byte("VALID")) {
		t.Error("expected output to contain 'VALID'")
	}
}

func TestPipelineValidate_InvalidPipeline(t *testing.T) {
	// Create temp directory.
	tmpDir, err := os.MkdirTemp("", "pipeline-test-*")
	if err != nil {
		t.Fatalf("create temp dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(tmpDir) })

	// Create an invalid pipeline file.
	pipelineFile := filepath.Join(tmpDir, "invalid.yaml")
	pipelineContent := `
name: ""
stages: []
`
	if writeErr := os.WriteFile(pipelineFile, []byte(pipelineContent), 0o600); writeErr != nil {
		t.Fatalf("write pipeline file: %v", writeErr)
	}

	// Set up command.
	cmd := NewPipelineValidateCmd()
	cmd.SetArgs([]string{pipelineFile})

	var stdout bytes.Buffer
	cmd.SetOut(&stdout)

	// Execute - should fail.
	execErr := cmd.Execute()
	if execErr == nil {
		t.Error("expected error for invalid pipeline")
	}

	output := stdout.String()
	if !bytes.Contains([]byte(output), []byte("INVALID")) {
		t.Error("expected output to contain 'INVALID'")
	}
}

func TestShowExecutionPlan(t *testing.T) {
	p := &pipeline.Pipeline{
		Name:    "test-pipeline",
		Version: "1.0.0",
		Stages: []pipeline.Stage{
			{
				Name: "stage1",
				Kind: pipeline.StageKindScan,
				Config: map[string]string{
					"scanner": "gitleaks",
				},
			},
			{
				Name:      "stage2",
				Kind:      pipeline.StageKindScan,
				DependsOn: []string{"stage1"},
				Timeout:   5 * time.Minute,
			},
		},
		Timeout:  30 * time.Minute,
		Parallel: true,
		FailFast: true,
	}

	cmd := NewPipelineRunCmd()
	var stdout bytes.Buffer
	cmd.SetOut(&stdout)

	executor := pipeline.NewExecutor()

	if err := showExecutionPlan(cmd, p, executor); err != nil {
		t.Fatalf("showExecutionPlan: %v", err)
	}

	output := stdout.String()
	expectedStrings := []string{
		"Pipeline: test-pipeline",
		"v1.0.0",
		"Parallel: true",
		"Fail Fast: true",
		"Stages: 2",
		"Execution Order:",
		"stage1",
		"stage2",
		"depends on: stage1",
		"Validation: PASSED",
	}

	for _, expected := range expectedStrings {
		if !bytes.Contains([]byte(output), []byte(expected)) {
			t.Errorf("output missing expected string: %q", expected)
		}
	}
}
