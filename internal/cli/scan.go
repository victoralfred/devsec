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
	"github.com/victoralfred/devsec/internal/scanner/gitleaks"
	"github.com/victoralfred/devsec/internal/scanner/semgrep"
	"github.com/victoralfred/gowritter/safepath"
)

var (
	outputFormat string
	outputFile   string
	timeout      time.Duration
)

// ErrSecretsFound is returned when secrets are found during a scan.
var ErrSecretsFound = errors.New("secrets found")

// ErrVulnerabilitiesFound is returned when vulnerabilities are found during a scan.
var ErrVulnerabilitiesFound = errors.New("vulnerabilities found")

// NewScanCmd creates the scan command.
func NewScanCmd() *cobra.Command {
	scanCmd := &cobra.Command{
		Use:   "scan",
		Short: "Run security scans",
		Long:  `Run security scans on the target directory.`,
	}

	scanCmd.AddCommand(NewScanSecretsCmd())
	scanCmd.AddCommand(NewScanSastCmd())

	return scanCmd
}

// NewScanSecretsCmd creates the scan secrets subcommand.
func NewScanSecretsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "secrets [path]",
		Short: "Scan for secrets using Gitleaks",
		Long: `Scan the specified directory for secrets and credentials
using Gitleaks secret detection.

If no path is specified, the current directory is scanned.`,
		Args: cobra.MaximumNArgs(1),
		RunE: runScanSecrets,
	}

	cmd.Flags().StringVarP(&outputFormat, "format", "f", "text", "output format (text, json)")
	cmd.Flags().StringVarP(&outputFile, "output", "o", "", "output file (default is stdout)")
	cmd.Flags().DurationVarP(&timeout, "timeout", "t", 5*time.Minute, "scan timeout")

	return cmd
}

func runScanSecrets(cmd *cobra.Command, args []string) error {
	targetPath := "."
	if len(args) > 0 {
		targetPath = args[0]
	}

	absPath, err := filepath.Abs(targetPath)
	if err != nil {
		return fmt.Errorf("failed to resolve path: %w", err)
	}

	scanner, err := gitleaks.New(
		gitleaks.WithTimeout(timeout),
	)
	if err != nil {
		return fmt.Errorf("failed to create scanner: %w", err)
	}
	defer func() {
		closeErr := scanner.Close(context.Background())
		_ = closeErr
	}()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	if verbose {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Scanning %s for secrets...\n", absPath)
	}

	findings, err := scanner.Scan(ctx, absPath)
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}

	if err := outputResults(cmd, findings); err != nil {
		return fmt.Errorf("failed to output results: %w", err)
	}

	if len(findings) > 0 {
		return ErrSecretsFound
	}

	return nil
}

func outputResults(cmd *cobra.Command, findings []model.Finding) error {
	switch outputFormat {
	case "json":
		return outputJSON(cmd, findings)
	case "text":
		return outputText(cmd, findings)
	default:
		return fmt.Errorf("unknown format: %s", outputFormat)
	}
}

func outputJSON(cmd *cobra.Command, findings []model.Finding) error {
	data, err := json.MarshalIndent(findings, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}

	if outputFile != "" {
		return writeToFile(outputFile, data)
	}

	_, _ = fmt.Fprintln(cmd.OutOrStdout(), string(data))
	return nil
}

func outputText(cmd *cobra.Command, findings []model.Finding) error {
	out := cmd.OutOrStdout()

	if len(findings) == 0 {
		_, _ = fmt.Fprintln(out, "No secrets found.")
		return nil
	}

	_, _ = fmt.Fprintf(out, "Found %d secret(s):\n\n", len(findings))

	for i := range findings {
		f := &findings[i]
		_, _ = fmt.Fprintf(out, "[%d] %s\n", i+1, f.Title)
		_, _ = fmt.Fprintf(out, "    Rule:     %s\n", f.Rule)
		_, _ = fmt.Fprintf(out, "    Severity: %s\n", f.Severity)
		_, _ = fmt.Fprintf(out, "    File:     %s:%d\n", f.Location.File, f.Location.StartLine)
		if f.Description != "" {
			_, _ = fmt.Fprintf(out, "    Details:  %s\n", f.Description)
		}
		_, _ = fmt.Fprintln(out)
	}

	if outputFile != "" {
		var textOutput string
		textOutput = fmt.Sprintf("Found %d secret(s):\n\n", len(findings))
		for i := range findings {
			f := &findings[i]
			textOutput += fmt.Sprintf("[%d] %s\n", i+1, f.Title)
			textOutput += fmt.Sprintf("    Rule:     %s\n", f.Rule)
			textOutput += fmt.Sprintf("    Severity: %s\n", f.Severity)
			textOutput += fmt.Sprintf("    File:     %s:%d\n", f.Location.File, f.Location.StartLine)
			if f.Description != "" {
				textOutput += fmt.Sprintf("    Details:  %s\n", f.Description)
			}
			textOutput += "\n"
		}
		return writeToFile(outputFile, []byte(textOutput))
	}

	return nil
}

func writeToFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	filename := filepath.Base(path)

	sp, err := safepath.New(dir)
	if err != nil {
		return fmt.Errorf("failed to create safe path: %w", err)
	}

	if err := sp.WriteFile(filename, data, 0o644); err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	return nil
}

// NewScanSastCmd creates the scan sast subcommand.
func NewScanSastCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "sast [path]",
		Short: "Scan for security issues using Semgrep",
		Long: `Scan the specified directory for security vulnerabilities
using Semgrep static application security testing (SAST).

If no path is specified, the current directory is scanned.`,
		Args: cobra.MaximumNArgs(1),
		RunE: runScanSast,
	}

	cmd.Flags().StringVarP(&outputFormat, "format", "f", "text", "output format (text, json)")
	cmd.Flags().StringVarP(&outputFile, "output", "o", "", "output file (default is stdout)")
	cmd.Flags().DurationVarP(&timeout, "timeout", "t", 10*time.Minute, "scan timeout")

	return cmd
}

func runScanSast(cmd *cobra.Command, args []string) error {
	targetPath := "."
	if len(args) > 0 {
		targetPath = args[0]
	}

	absPath, err := filepath.Abs(targetPath)
	if err != nil {
		return fmt.Errorf("failed to resolve path: %w", err)
	}

	scanner := semgrep.New(
		semgrep.WithTimeout(timeout),
	)
	defer func() {
		closeErr := scanner.Close(context.Background())
		_ = closeErr
	}()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	if verbose {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Scanning %s for vulnerabilities...\n", absPath)
	}

	findings, err := scanner.Scan(ctx, absPath)
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}

	if err := outputResults(cmd, findings); err != nil {
		return fmt.Errorf("failed to output results: %w", err)
	}

	if len(findings) > 0 {
		return ErrVulnerabilitiesFound
	}

	return nil
}
