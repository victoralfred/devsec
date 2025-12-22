package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/victoralfred/devsec/internal/pipeline"
	"github.com/victoralfred/gowritter/safepath"
)

var (
	pipelineRunOutput   string
	pipelineRunFormat   string
	pipelineRunTimeout  time.Duration
	pipelineRunParallel int
	pipelineRunDryRun   bool

	pipelineValidateOutput string
	pipelineValidateFormat string

	pipelineGenerateOutput   string
	pipelineGenerateTemplate string
)

// NewPipelineCmd creates the pipeline command.
func NewPipelineCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "pipeline",
		Short: "Pipeline orchestration commands",
		Long: `Pipeline orchestration for security scans, policy checks, and compliance.

Provides:
  - Execute YAML-defined pipelines
  - Validate pipeline definitions
  - Generate pipeline templates

Pipelines support:
  - Sequential and parallel stage execution
  - Stage dependencies with automatic ordering
  - Fail-fast and continue-on-failure modes
  - Multiple stage types: scan, policy, report, compliance, custom`,
	}

	cmd.AddCommand(NewPipelineRunCmd())
	cmd.AddCommand(NewPipelineValidateCmd())
	cmd.AddCommand(NewPipelineGenerateCmd())

	return cmd
}

// NewPipelineRunCmd creates the pipeline run subcommand.
func NewPipelineRunCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "run [pipeline-file] [path]",
		Short: "Execute a pipeline",
		Long: `Execute a security pipeline on the specified path.

The pipeline file should be a YAML file defining stages to execute.
If no pipeline file is specified, searches for default pipeline files:
  - devsec.yaml, devsec.yml
  - pipeline.yaml, pipeline.yml
  - .devsec.yaml, .devsec.yml

If no path is specified, the current directory is used.

Example pipeline.yaml:
  name: security-pipeline
  stages:
    - name: secrets
      kind: scan
      config:
        scanner: gitleaks
    - name: sast
      kind: scan
      config:
        scanner: semgrep
      depends_on: [secrets]
    - name: policy
      kind: policy
      depends_on: [secrets, sast]`,
		Args: cobra.MaximumNArgs(2),
		RunE: runPipelineRun,
	}

	cmd.Flags().StringVarP(&pipelineRunOutput, "output", "o", "", "output file for results (default: stdout)")
	cmd.Flags().StringVarP(&pipelineRunFormat, "format", "f", "text", "output format (text, json, markdown)")
	cmd.Flags().DurationVarP(&pipelineRunTimeout, "timeout", "t", 30*time.Minute, "pipeline execution timeout")
	cmd.Flags().IntVarP(&pipelineRunParallel, "parallel", "p", 0, "max parallel stages (0 = auto)")
	cmd.Flags().BoolVar(&pipelineRunDryRun, "dry-run", false, "validate and show execution plan without running")

	return cmd
}

func runPipelineRun(cmd *cobra.Command, args []string) error {
	var pipelineFile string
	var targetPath string

	switch len(args) {
	case 0:
		targetPath = "."
	case 1:
		// Could be pipeline file or target path.
		if isPipelineFile(args[0]) {
			pipelineFile = args[0]
			targetPath = "."
		} else {
			targetPath = args[0]
		}
	case 2:
		pipelineFile = args[0]
		targetPath = args[1]
	}

	absPath, err := filepath.Abs(targetPath)
	if err != nil {
		return fmt.Errorf("resolve path: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), pipelineRunTimeout)
	defer cancel()

	// Load pipeline.
	loader := pipeline.NewLoader()

	var p *pipeline.Pipeline
	if pipelineFile != "" {
		p, err = loader.Load(ctx, pipelineFile)
		if err != nil {
			return fmt.Errorf("load pipeline: %w", err)
		}
	} else {
		// Search for pipeline file.
		pipelineFile, err = loader.FindPipeline(ctx, targetPath)
		if err != nil {
			return fmt.Errorf("find pipeline: %w", err)
		}
		p, err = loader.Load(ctx, pipelineFile)
		if err != nil {
			return fmt.Errorf("load pipeline: %w", err)
		}
	}

	if verbose {
		cmd.Printf("Loading pipeline: %s\n", pipelineFile)
		cmd.Printf("Target path: %s\n", absPath)
		cmd.Printf("Stages: %d\n", len(p.Stages))
	}

	// Create executor.
	executor := pipeline.NewExecutor()

	// Build execution options.
	opts := pipeline.ExecuteOptions{
		WorkDir:     absPath,
		MaxParallel: pipelineRunParallel,
		DryRun:      pipelineRunDryRun,
		Verbose:     verbose,
	}

	if pipelineRunDryRun {
		cmd.Println("Dry run mode - validating and showing execution plan:")
		return showExecutionPlan(cmd, p, executor)
	}

	// Execute pipeline.
	if verbose {
		cmd.Printf("Executing pipeline: %s\n", p.Name)
	}

	result, err := executor.Execute(ctx, *p, opts)

	// Output results even if there's an error.
	if outputErr := outputPipelineResults(cmd, result); outputErr != nil {
		if err != nil {
			return fmt.Errorf("execution failed: %w (output error: %v)", err, outputErr)
		}
		return fmt.Errorf("output results: %w", outputErr)
	}

	if err != nil {
		return fmt.Errorf("pipeline execution failed: %w", err)
	}

	if result.Status == pipeline.StageStatusFailed {
		return fmt.Errorf("pipeline completed with failures")
	}

	return nil
}

func isPipelineFile(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	return ext == ".yaml" || ext == ".yml"
}

func showExecutionPlan(cmd *cobra.Command, p *pipeline.Pipeline, executor *pipeline.DefaultExecutor) error {
	// Validate pipeline.
	if err := executor.Validate(*p); err != nil {
		return fmt.Errorf("validation failed: %w", err)
	}

	cmd.Printf("\nPipeline: %s", p.Name)
	if p.Version != "" {
		cmd.Printf(" (v%s)", p.Version)
	}
	cmd.Println()
	cmd.Println(strings.Repeat("-", 40))

	cmd.Printf("Timeout: %s\n", p.GetTimeout())
	cmd.Printf("Parallel: %v\n", p.Parallel)
	cmd.Printf("Fail Fast: %v\n", p.FailFast)
	cmd.Printf("Stages: %d\n\n", len(p.Stages))

	cmd.Println("Execution Order:")
	for i := range p.Stages {
		stage := &p.Stages[i]
		cmd.Printf("  %d. %s (%s)\n", i+1, stage.Name, stage.Kind)
		if len(stage.DependsOn) > 0 {
			cmd.Printf("     depends on: %s\n", strings.Join(stage.DependsOn, ", "))
		}
		if stage.Timeout > 0 {
			cmd.Printf("     timeout: %s\n", stage.Timeout)
		}
	}

	cmd.Println("\nValidation: PASSED")
	return nil
}

func outputPipelineResults(cmd *cobra.Command, result pipeline.PipelineResult) error {
	var output []byte
	var err error

	switch pipelineRunFormat {
	case "json":
		output, err = json.MarshalIndent(result, "", "  ")
		if err != nil {
			return fmt.Errorf("marshal JSON: %w", err)
		}
	case "markdown", "md":
		output = []byte(formatPipelineResultMarkdown(result))
	default:
		output = []byte(formatPipelineResultText(result))
	}

	return writePipelineOutput(cmd, output, pipelineRunOutput)
}

func formatPipelineResultText(result pipeline.PipelineResult) string {
	var sb strings.Builder

	sb.WriteString("Pipeline Execution Results\n")
	sb.WriteString("==========================\n\n")

	fmt.Fprintf(&sb, "Pipeline: %s\n", result.Name)
	fmt.Fprintf(&sb, "Status: %s\n", strings.ToUpper(string(result.Status)))
	fmt.Fprintf(&sb, "Duration: %s\n", result.Duration.Round(time.Millisecond))
	fmt.Fprintf(&sb, "Started: %s\n", result.StartTime.Format(time.RFC3339))
	fmt.Fprintf(&sb, "Ended: %s\n\n", result.EndTime.Format(time.RFC3339))

	if result.Error != "" {
		fmt.Fprintf(&sb, "Error: %s\n\n", result.Error)
	}

	summary := result.Summarize()
	sb.WriteString("Summary:\n")
	fmt.Fprintf(&sb, "  Total Stages: %d\n", summary.TotalStages)
	fmt.Fprintf(&sb, "  Successful: %d\n", summary.SuccessCount)
	fmt.Fprintf(&sb, "  Failed: %d\n", summary.FailedCount)
	fmt.Fprintf(&sb, "  Skipped: %d\n", summary.SkippedCount)
	fmt.Fprintf(&sb, "  Canceled: %d\n\n", summary.CanceledCount)

	sb.WriteString("Stage Results:\n")
	sb.WriteString("--------------\n")

	for i := range result.Stages {
		stage := &result.Stages[i]
		statusIcon := getStatusIcon(stage.Status)
		fmt.Fprintf(&sb, "\n%s %s\n", statusIcon, stage.Name)
		fmt.Fprintf(&sb, "   Status: %s\n", stage.Status)
		fmt.Fprintf(&sb, "   Duration: %s\n", stage.Duration.Round(time.Millisecond))
		if stage.Error != "" {
			fmt.Fprintf(&sb, "   Error: %s\n", stage.Error)
		}
	}

	return sb.String()
}

func formatPipelineResultMarkdown(result pipeline.PipelineResult) string {
	var sb strings.Builder

	sb.WriteString("# Pipeline Execution Results\n\n")

	fmt.Fprintf(&sb, "**Pipeline**: %s\n\n", result.Name)
	fmt.Fprintf(&sb, "**Status**: `%s`\n\n", strings.ToUpper(string(result.Status)))
	fmt.Fprintf(&sb, "**Duration**: %s\n\n", result.Duration.Round(time.Millisecond))

	if result.Error != "" {
		fmt.Fprintf(&sb, "**Error**: %s\n\n", result.Error)
	}

	summary := result.Summarize()
	sb.WriteString("## Summary\n\n")
	sb.WriteString("| Metric | Count |\n")
	sb.WriteString("|--------|-------|\n")
	fmt.Fprintf(&sb, "| Total Stages | %d |\n", summary.TotalStages)
	fmt.Fprintf(&sb, "| Successful | %d |\n", summary.SuccessCount)
	fmt.Fprintf(&sb, "| Failed | %d |\n", summary.FailedCount)
	fmt.Fprintf(&sb, "| Skipped | %d |\n", summary.SkippedCount)
	fmt.Fprintf(&sb, "| Canceled | %d |\n\n", summary.CanceledCount)

	sb.WriteString("## Stage Results\n\n")
	sb.WriteString("| Stage | Status | Duration | Error |\n")
	sb.WriteString("|-------|--------|----------|-------|\n")

	for i := range result.Stages {
		stage := &result.Stages[i]
		errStr := "-"
		if stage.Error != "" {
			errStr = stage.Error
		}
		fmt.Fprintf(&sb, "| %s | %s | %s | %s |\n",
			stage.Name,
			stage.Status,
			stage.Duration.Round(time.Millisecond),
			errStr,
		)
	}

	return sb.String()
}

func getStatusIcon(status pipeline.StageStatus) string {
	switch status {
	case pipeline.StageStatusSuccess:
		return "[OK]"
	case pipeline.StageStatusFailed:
		return "[FAIL]"
	case pipeline.StageStatusSkipped:
		return "[SKIP]"
	case pipeline.StageStatusCanceled:
		return "[CANCEL]"
	case pipeline.StageStatusRunning:
		return "[RUN]"
	default:
		return "[?]"
	}
}

// NewPipelineValidateCmd creates the pipeline validate subcommand.
func NewPipelineValidateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "validate [pipeline-file]",
		Short: "Validate a pipeline definition",
		Long: `Validate a pipeline definition file.

Checks:
  - YAML syntax
  - Required fields (name, stages)
  - Valid stage kinds
  - Dependency references
  - Circular dependency detection
  - Configuration limits`,
		Args: cobra.ExactArgs(1),
		RunE: runPipelineValidate,
	}

	cmd.Flags().StringVarP(&pipelineValidateOutput, "output", "o", "", "output file for validation results")
	cmd.Flags().StringVarP(&pipelineValidateFormat, "format", "f", "text", "output format (text, json)")

	return cmd
}

func runPipelineValidate(cmd *cobra.Command, args []string) error {
	pipelineFile := args[0]

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	loader := pipeline.NewLoader()
	executor := pipeline.NewExecutor()

	// Load pipeline.
	p, loadErr := loader.Load(ctx, pipelineFile)

	result := pipelineValidationResult{
		File:   pipelineFile,
		Valid:  loadErr == nil,
		Stages: 0,
	}

	if loadErr != nil {
		result.Errors = append(result.Errors, loadErr.Error())
	} else {
		result.Pipeline = p.Name
		result.Version = p.Version
		result.Stages = len(p.Stages)

		// Additional validation.
		if err := executor.Validate(*p); err != nil {
			result.Valid = false
			result.Errors = append(result.Errors, err.Error())
		}
	}

	// Format output.
	var output []byte
	var err error

	switch pipelineValidateFormat {
	case "json":
		output, err = json.MarshalIndent(result, "", "  ")
		if err != nil {
			return fmt.Errorf("marshal JSON: %w", err)
		}
	default:
		output = []byte(formatPipelineValidationResult(result))
	}

	if err := writePipelineOutput(cmd, output, pipelineValidateOutput); err != nil {
		return err
	}

	if !result.Valid {
		return fmt.Errorf("validation failed")
	}

	return nil
}

type pipelineValidationResult struct {
	File     string   `json:"file"`
	Pipeline string   `json:"pipeline,omitempty"`
	Version  string   `json:"version,omitempty"`
	Errors   []string `json:"errors,omitempty"`
	Stages   int      `json:"stages"`
	Valid    bool     `json:"valid"`
}

func formatPipelineValidationResult(result pipelineValidationResult) string {
	var sb strings.Builder

	sb.WriteString("Pipeline Validation\n")
	sb.WriteString("===================\n\n")

	fmt.Fprintf(&sb, "File: %s\n", result.File)

	if result.Valid {
		fmt.Fprintf(&sb, "Pipeline: %s\n", result.Pipeline)
		if result.Version != "" {
			fmt.Fprintf(&sb, "Version: %s\n", result.Version)
		}
		fmt.Fprintf(&sb, "Stages: %d\n\n", result.Stages)
		sb.WriteString("Status: VALID\n")
	} else {
		sb.WriteString("\nStatus: INVALID\n\n")
		sb.WriteString("Errors:\n")
		for _, err := range result.Errors {
			fmt.Fprintf(&sb, "  - %s\n", err)
		}
	}

	return sb.String()
}

// NewPipelineGenerateCmd creates the pipeline generate subcommand.
func NewPipelineGenerateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "generate [template]",
		Short: "Generate a pipeline template",
		Long: `Generate a pipeline template file.

Available templates:
  - basic: Simple sequential pipeline with scan stages
  - full: Complete pipeline with all stage types
  - parallel: Pipeline with parallel execution
  - cicd: Pipeline optimized for CI/CD integration

If no template is specified, 'basic' is used.`,
		Args: cobra.MaximumNArgs(1),
		RunE: runPipelineGenerate,
	}

	cmd.Flags().StringVarP(&pipelineGenerateOutput, "output", "o", "devsec.yaml", "output file")
	cmd.Flags().StringVarP(&pipelineGenerateTemplate, "template", "T", "basic", "template type")

	return cmd
}

func runPipelineGenerate(cmd *cobra.Command, args []string) error {
	template := pipelineGenerateTemplate
	if len(args) > 0 {
		template = args[0]
	}

	p, err := generatePipelineTemplate(template)
	if err != nil {
		return fmt.Errorf("generate template: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Save pipeline.
	loader := pipeline.NewLoader()
	if err := loader.Save(ctx, p, pipelineGenerateOutput); err != nil {
		return fmt.Errorf("save pipeline: %w", err)
	}

	cmd.Printf("Generated pipeline template: %s\n", pipelineGenerateOutput)

	if verbose {
		cmd.Printf("Template: %s\n", template)
		cmd.Printf("Stages: %d\n", len(p.Stages))
	}

	return nil
}

func generatePipelineTemplate(template string) (*pipeline.Pipeline, error) {
	switch strings.ToLower(template) {
	case "basic":
		return generateBasicPipeline(), nil
	case "full":
		return generateFullPipeline(), nil
	case "parallel":
		return generateParallelPipeline(), nil
	case "cicd":
		return generateCICDPipeline(), nil
	default:
		return nil, fmt.Errorf("unknown template: %s (available: basic, full, parallel, cicd)", template)
	}
}

func generateBasicPipeline() *pipeline.Pipeline {
	return &pipeline.Pipeline{
		Name:    "security-scan",
		Version: "1.0.0",
		Stages: []pipeline.Stage{
			{
				Name: "secrets",
				Kind: pipeline.StageKindScan,
				Config: map[string]string{
					"scanner": "gitleaks",
				},
			},
			{
				Name: "sast",
				Kind: pipeline.StageKindScan,
				Config: map[string]string{
					"scanner": "semgrep",
				},
				DependsOn: []string{"secrets"},
			},
			{
				Name: "vulnerabilities",
				Kind: pipeline.StageKindScan,
				Config: map[string]string{
					"scanner": "trivy",
				},
				DependsOn: []string{"sast"},
			},
		},
		Timeout:  30 * time.Minute,
		FailFast: true,
	}
}

func generateFullPipeline() *pipeline.Pipeline {
	return &pipeline.Pipeline{
		Name:    "full-security-pipeline",
		Version: "1.0.0",
		Metadata: map[string]string{
			"description": "Complete security pipeline with all stages",
			"author":      "devsec",
		},
		Stages: []pipeline.Stage{
			{
				Name: "secrets",
				Kind: pipeline.StageKindScan,
				Config: map[string]string{
					"scanner": "gitleaks",
				},
				Timeout: 5 * time.Minute,
			},
			{
				Name: "sast",
				Kind: pipeline.StageKindScan,
				Config: map[string]string{
					"scanner": "semgrep",
				},
				DependsOn: []string{"secrets"},
				Timeout:   10 * time.Minute,
			},
			{
				Name: "vulnerabilities",
				Kind: pipeline.StageKindScan,
				Config: map[string]string{
					"scanner": "trivy",
				},
				DependsOn: []string{"secrets"},
				Timeout:   10 * time.Minute,
			},
			{
				Name: "dependencies",
				Kind: pipeline.StageKindScan,
				Config: map[string]string{
					"scanner": "osv",
				},
				DependsOn: []string{"secrets"},
				Timeout:   5 * time.Minute,
			},
			{
				Name: "policy-check",
				Kind: pipeline.StageKindPolicy,
				Config: map[string]string{
					"policy_dir": "policies",
					"fail_on":    "high",
				},
				DependsOn: []string{"sast", "vulnerabilities", "dependencies"},
			},
			{
				Name: "compliance",
				Kind: pipeline.StageKindCompliance,
				Config: map[string]string{
					"frameworks": "soc2,iso27001",
				},
				DependsOn: []string{"policy-check"},
			},
			{
				Name: "report",
				Kind: pipeline.StageKindReport,
				Config: map[string]string{
					"format": "markdown",
					"output": "security-report.md",
				},
				DependsOn:  []string{"compliance"},
				ContinueOn: pipeline.ContinueAlways,
			},
		},
		Timeout:  60 * time.Minute,
		FailFast: true,
	}
}

func generateParallelPipeline() *pipeline.Pipeline {
	return &pipeline.Pipeline{
		Name:     "parallel-scan",
		Version:  "1.0.0",
		Parallel: true,
		Stages: []pipeline.Stage{
			{
				Name: "secrets",
				Kind: pipeline.StageKindScan,
				Config: map[string]string{
					"scanner": "gitleaks",
				},
			},
			{
				Name: "sast",
				Kind: pipeline.StageKindScan,
				Config: map[string]string{
					"scanner": "semgrep",
				},
			},
			{
				Name: "vulnerabilities",
				Kind: pipeline.StageKindScan,
				Config: map[string]string{
					"scanner": "trivy",
				},
			},
			{
				Name: "dependencies",
				Kind: pipeline.StageKindScan,
				Config: map[string]string{
					"scanner": "osv",
				},
			},
			{
				Name: "aggregate",
				Kind: pipeline.StageKindReport,
				Config: map[string]string{
					"format": "json",
					"output": "scan-results.json",
				},
				DependsOn: []string{"secrets", "sast", "vulnerabilities", "dependencies"},
			},
		},
		Timeout:  30 * time.Minute,
		FailFast: false,
	}
}

func generateCICDPipeline() *pipeline.Pipeline {
	return &pipeline.Pipeline{
		Name:    "cicd-security-check",
		Version: "1.0.0",
		Metadata: map[string]string{
			"description": "Security checks for CI/CD pipelines",
			"trigger":     "pull_request",
		},
		Stages: []pipeline.Stage{
			{
				Name: "quick-scan",
				Kind: pipeline.StageKindScan,
				Config: map[string]string{
					"scanner": "gitleaks",
				},
				Timeout:  2 * time.Minute,
				FailFast: true,
			},
			{
				Name: "security-check",
				Kind: pipeline.StageKindScan,
				Config: map[string]string{
					"scanner": "semgrep",
				},
				DependsOn: []string{"quick-scan"},
				Timeout:   5 * time.Minute,
			},
			{
				Name: "policy-gate",
				Kind: pipeline.StageKindPolicy,
				Config: map[string]string{
					"fail_on": "critical",
				},
				DependsOn: []string{"security-check"},
			},
		},
		Timeout:  15 * time.Minute,
		FailFast: true,
	}
}

func writePipelineOutput(cmd *cobra.Command, output []byte, outputPath string) error {
	if outputPath != "" {
		absOutput, err := filepath.Abs(outputPath)
		if err != nil {
			return fmt.Errorf("resolve output path: %w", err)
		}

		dir := filepath.Dir(absOutput)
		filename := filepath.Base(absOutput)

		sp, err := safepath.New(dir)
		if err != nil {
			return fmt.Errorf("create safepath: %w", err)
		}

		if err := sp.WriteFile(filename, output, 0o644); err != nil {
			return fmt.Errorf("write output: %w", err)
		}

		cmd.Printf("Results written to: %s\n", absOutput)
	} else {
		cmd.Println(string(output))
	}

	return nil
}
