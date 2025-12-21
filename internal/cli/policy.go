package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"
	"github.com/victoralfred/devsec/internal/model"
	"github.com/victoralfred/devsec/internal/policy"
	"github.com/victoralfred/gowritter/safepath"
)

var (
	policyFile   string
	strictMode   bool
	findingsFile string
)

// ErrPolicyViolation is returned when policy check fails.
var ErrPolicyViolation = errors.New("policy violation")

// NewPolicyCmd creates the policy command.
func NewPolicyCmd() *cobra.Command {
	policyCmd := &cobra.Command{
		Use:   "policy",
		Short: "Policy management commands",
		Long:  `Commands for managing and evaluating security policies.`,
	}

	policyCmd.AddCommand(NewPolicyCheckCmd())

	return policyCmd
}

// NewPolicyCheckCmd creates the policy check subcommand.
func NewPolicyCheckCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "check",
		Short: "Check findings against security policy",
		Long: `Evaluate security findings against a policy and report violations.

By default, uses the built-in policy that blocks high and critical findings.
Use --strict for stricter checking that also warns on medium findings.
Use --policy to specify a custom Rego policy file.

The findings can be provided via --findings flag pointing to a JSON file
containing an array of findings from previous scans.`,
		RunE: runPolicyCheck,
	}

	cmd.Flags().StringVarP(&policyFile, "policy", "p", "", "custom Rego policy file")
	cmd.Flags().BoolVarP(&strictMode, "strict", "s", false, "enable strict mode (warn on medium)")
	cmd.Flags().StringVarP(&findingsFile, "findings", "i", "", "JSON file with findings to check")
	cmd.Flags().StringVarP(&outputFormat, "format", "f", "text", "output format (text, json)")
	cmd.Flags().StringVarP(&outputFile, "output", "o", "", "output file (default is stdout)")

	return cmd
}

func runPolicyCheck(cmd *cobra.Command, _ []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// Load findings.
	findings, err := loadFindings(ctx, findingsFile)
	if err != nil {
		return fmt.Errorf("failed to load findings: %w", err)
	}

	// Create decision point.
	var dp *policy.DecisionPoint
	if policyFile != "" {
		absPath, pathErr := filepath.Abs(policyFile)
		if pathErr != nil {
			return fmt.Errorf("failed to resolve policy path: %w", pathErr)
		}
		dp, err = policy.NewDecisionPointWithPolicy(ctx, absPath)
	} else {
		dp, err = policy.NewDecisionPoint(ctx,
			policy.WithStrictMode(strictMode),
		)
	}
	if err != nil {
		return fmt.Errorf("failed to create policy decision point: %w", err)
	}

	cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cleanupCancel()
	defer func() {
		_ = dp.Close(cleanupCtx)
	}()

	if verbose {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Checking %d finding(s) against policy...\n", len(findings))
	}

	// Run policy check.
	result, err := dp.Check(ctx, findings)
	if err != nil {
		return fmt.Errorf("policy check failed: %w", err)
	}

	// Output results.
	if err := outputPolicyResult(cmd, result, dp); err != nil {
		return fmt.Errorf("failed to output results: %w", err)
	}

	if !result.Passed {
		return ErrPolicyViolation
	}

	return nil
}

func loadFindings(ctx context.Context, filePath string) ([]model.Finding, error) {
	if filePath == "" {
		// Return empty findings if no file specified.
		return []model.Finding{}, nil
	}

	// Check context.
	if ctxErr := ctx.Err(); ctxErr != nil {
		return nil, fmt.Errorf("context canceled: %w", ctxErr)
	}

	absPath, err := filepath.Abs(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve path: %w", err)
	}

	dir := filepath.Dir(absPath)
	filename := filepath.Base(absPath)

	sp, err := safepath.New(dir)
	if err != nil {
		return nil, fmt.Errorf("path not accessible: %w", err)
	}

	// Check file size.
	info, err := sp.Stat(filename)
	if err != nil {
		return nil, fmt.Errorf("file not found: %w", err)
	}

	const maxSize = 50 * 1024 * 1024 // 50MB
	if info.Size() > maxSize {
		return nil, fmt.Errorf("file too large: %d bytes", info.Size())
	}

	data, err := sp.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	var findings []model.Finding
	if err := json.Unmarshal(data, &findings); err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %w", err)
	}

	return findings, nil
}

func outputPolicyResult(cmd *cobra.Command, result policy.CheckResult, dp *policy.DecisionPoint) error {
	switch outputFormat {
	case "json":
		return outputPolicyJSON(cmd, result, dp)
	case "text":
		return outputPolicyText(cmd, result, dp)
	default:
		return fmt.Errorf("unknown format: %s", outputFormat)
	}
}

func outputPolicyJSON(cmd *cobra.Command, result policy.CheckResult, dp *policy.DecisionPoint) error {
	report := dp.GenerateReport(result)

	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}

	if outputFile != "" {
		return writeToFile(outputFile, data)
	}

	_, _ = fmt.Fprintln(cmd.OutOrStdout(), string(data))
	return nil
}

func outputPolicyText(cmd *cobra.Command, result policy.CheckResult, dp *policy.DecisionPoint) error {
	report := dp.GenerateReport(result)
	formatted := policy.FormatViolationReport(report)

	_, _ = fmt.Fprint(cmd.OutOrStdout(), formatted)

	if outputFile != "" {
		return writeToFile(outputFile, []byte(formatted))
	}

	return nil
}
