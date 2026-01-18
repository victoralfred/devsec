package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/victoralfred/devsec/internal/model"
	"github.com/victoralfred/devsec/internal/progress"
	"github.com/victoralfred/devsec/internal/scanner/gitleaks"
	"github.com/victoralfred/devsec/internal/scanner/osv"
	"github.com/victoralfred/devsec/internal/scanner/semgrep"
	"github.com/victoralfred/devsec/internal/scanner/trivy"
	"github.com/victoralfred/devsec/internal/tui"
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
	scanCmd.AddCommand(NewScanVulnerabilitiesCmd())
	scanCmd.AddCommand(NewScanDependenciesCmd())

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
		Args:         cobra.MaximumNArgs(1),
		RunE:         runScanSecrets,
		SilenceUsage: true,
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

	// Create context with timeout for cleanup
	cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cleanupCancel()

	defer func() {
		closeErr := scanner.Close(cleanupCtx)
		if closeErr != nil {
			// Log but don't fail on cleanup error
			_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "warning: failed to close scanner: %v\n", closeErr)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// Check if TUI progress is enabled.
	if IsProgressEnabled() {
		return runScanWithTUI(ctx, cmd, "secrets", absPath, scanner, outputResults, ErrSecretsFound)
	}

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

	if cmd != nil {
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), string(data))
	} else {
		// If command is nil, we cannot safely output without os package
		// This should not happen in normal operation, but we handle it gracefully
		// by returning an error rather than using os package
		return fmt.Errorf("cannot output JSON: command is nil")
	}
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
		// Use strings.Builder for efficient string building
		var builder strings.Builder
		builder.Grow(len(findings) * 200) // Pre-allocate estimated capacity

		_, _ = fmt.Fprintf(&builder, "Found %d secret(s):\n\n", len(findings))
		for i := range findings {
			f := &findings[i]
			_, _ = fmt.Fprintf(&builder, "[%d] %s\n", i+1, f.Title)
			_, _ = fmt.Fprintf(&builder, "    Rule:     %s\n", f.Rule)
			_, _ = fmt.Fprintf(&builder, "    Severity: %s\n", f.Severity)
			_, _ = fmt.Fprintf(&builder, "    File:     %s:%d\n", f.Location.File, f.Location.StartLine)
			if f.Description != "" {
				_, _ = fmt.Fprintf(&builder, "    Details:  %s\n", f.Description)
			}
			_, _ = fmt.Fprintln(&builder)
		}
		return writeToFile(outputFile, []byte(builder.String()))
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
		Args:         cobra.MaximumNArgs(1),
		RunE:         runScanSast,
		SilenceUsage: true,
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

	// Create context with timeout for cleanup
	cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cleanupCancel()

	defer func() {
		closeErr := scanner.Close(cleanupCtx)
		if closeErr != nil {
			// Log but don't fail on cleanup error
			_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "warning: failed to close scanner: %v\n", closeErr)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// Check if TUI progress is enabled.
	if IsProgressEnabled() {
		return runScanWithTUI(ctx, cmd, "sast", absPath, scanner, outputResults, ErrVulnerabilitiesFound)
	}

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

// NewScanVulnerabilitiesCmd creates the scan vulnerabilities subcommand.
func NewScanVulnerabilitiesCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "vulnerabilities [path]",
		Short: "Scan for vulnerabilities using Trivy",
		Long: `Scan the specified directory for dependency and container vulnerabilities
using Trivy vulnerability scanner.

If no path is specified, the current directory is scanned.`,
		Args:         cobra.MaximumNArgs(1),
		RunE:         runScanVulnerabilities,
		SilenceUsage: true,
	}

	cmd.Flags().StringVarP(&outputFormat, "format", "f", "text", "output format (text, json)")
	cmd.Flags().StringVarP(&outputFile, "output", "o", "", "output file (default is stdout)")
	cmd.Flags().DurationVarP(&timeout, "timeout", "t", 10*time.Minute, "scan timeout")

	return cmd
}

func runScanVulnerabilities(cmd *cobra.Command, args []string) error {
	targetPath := "."
	if len(args) > 0 {
		targetPath = args[0]
	}

	absPath, err := filepath.Abs(targetPath)
	if err != nil {
		return fmt.Errorf("failed to resolve path: %w", err)
	}

	scanner := trivy.New(
		trivy.WithTimeout(timeout),
	)

	// Create context with timeout for cleanup
	cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cleanupCancel()

	defer func() {
		closeErr := scanner.Close(cleanupCtx)
		if closeErr != nil {
			// Log but don't fail on cleanup error
			_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "warning: failed to close scanner: %v\n", closeErr)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// Check if TUI progress is enabled.
	if IsProgressEnabled() {
		return runScanWithTUI(ctx, cmd, "vulnerabilities", absPath, scanner, outputVulnerabilityResults, ErrVulnerabilitiesFound)
	}

	if verbose {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Scanning %s for dependency vulnerabilities...\n", absPath)
	}

	findings, err := scanner.Scan(ctx, absPath)
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}

	if err := outputVulnerabilityResults(cmd, findings); err != nil {
		return fmt.Errorf("failed to output results: %w", err)
	}

	if len(findings) > 0 {
		return ErrVulnerabilitiesFound
	}

	return nil
}

func outputVulnerabilityResults(cmd *cobra.Command, findings []model.Finding) error {
	switch outputFormat {
	case "json":
		return outputJSON(cmd, findings)
	case "text":
		return outputVulnerabilityText(cmd, findings)
	default:
		return fmt.Errorf("unknown format: %s", outputFormat)
	}
}

func outputVulnerabilityText(cmd *cobra.Command, findings []model.Finding) error {
	out := cmd.OutOrStdout()

	if len(findings) == 0 {
		_, _ = fmt.Fprintln(out, "No vulnerabilities found.")
		return nil
	}

	_, _ = fmt.Fprintf(out, "Found %d vulnerability(ies):\n\n", len(findings))

	for i := range findings {
		f := &findings[i]
		_, _ = fmt.Fprintf(out, "[%d] %s\n", i+1, f.Title)
		_, _ = fmt.Fprintf(out, "    CVE:      %s\n", f.Rule)
		_, _ = fmt.Fprintf(out, "    Severity: %s\n", f.Severity)
		_, _ = fmt.Fprintf(out, "    File:     %s\n", f.Location.File)
		if f.Description != "" {
			_, _ = fmt.Fprintf(out, "    Details:  %s\n", f.Description)
		}
		_, _ = fmt.Fprintln(out)
	}

	if outputFile != "" {
		var builder strings.Builder
		builder.Grow(len(findings) * 250)

		_, _ = fmt.Fprintf(&builder, "Found %d vulnerability(ies):\n\n", len(findings))
		for i := range findings {
			f := &findings[i]
			_, _ = fmt.Fprintf(&builder, "[%d] %s\n", i+1, f.Title)
			_, _ = fmt.Fprintf(&builder, "    CVE:      %s\n", f.Rule)
			_, _ = fmt.Fprintf(&builder, "    Severity: %s\n", f.Severity)
			_, _ = fmt.Fprintf(&builder, "    File:     %s\n", f.Location.File)
			if f.Description != "" {
				_, _ = fmt.Fprintf(&builder, "    Details:  %s\n", f.Description)
			}
			_, _ = fmt.Fprintln(&builder)
		}
		return writeToFile(outputFile, []byte(builder.String()))
	}

	return nil
}

// NewScanDependenciesCmd creates the scan dependencies subcommand.
func NewScanDependenciesCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "dependencies [path]",
		Short: "Scan for dependency vulnerabilities using OSV",
		Long: `Scan the specified directory for dependency vulnerabilities
using the OSV (Open Source Vulnerabilities) database.

Supports: go.mod, package.json, requirements.txt

If no path is specified, the current directory is scanned.`,
		Args:         cobra.MaximumNArgs(1),
		RunE:         runScanDependencies,
		SilenceUsage: true,
	}

	cmd.Flags().StringVarP(&outputFormat, "format", "f", "text", "output format (text, json)")
	cmd.Flags().StringVarP(&outputFile, "output", "o", "", "output file (default is stdout)")
	cmd.Flags().DurationVarP(&timeout, "timeout", "t", 2*time.Minute, "scan timeout")

	return cmd
}

func runScanDependencies(cmd *cobra.Command, args []string) error {
	targetPath := "."
	if len(args) > 0 {
		targetPath = args[0]
	}

	absPath, err := filepath.Abs(targetPath)
	if err != nil {
		return fmt.Errorf("failed to resolve path: %w", err)
	}

	scanner := osv.New(
		osv.WithTimeout(timeout),
	)

	// Create context with timeout for cleanup.
	cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cleanupCancel()

	defer func() {
		closeErr := scanner.Close(cleanupCtx)
		if closeErr != nil {
			_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "warning: failed to close scanner: %v\n", closeErr)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// Check if TUI progress is enabled.
	if IsProgressEnabled() {
		return runScanWithTUI(ctx, cmd, "dependencies", absPath, scanner, outputDependencyResults, ErrVulnerabilitiesFound)
	}

	if verbose {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Scanning %s for dependency vulnerabilities...\n", absPath)
	}

	findings, err := scanner.Scan(ctx, absPath)
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}

	if err := outputDependencyResults(cmd, findings); err != nil {
		return fmt.Errorf("failed to output results: %w", err)
	}

	if len(findings) > 0 {
		return ErrVulnerabilitiesFound
	}

	return nil
}

func outputDependencyResults(cmd *cobra.Command, findings []model.Finding) error {
	switch outputFormat {
	case "json":
		return outputJSON(cmd, findings)
	case "text":
		return outputDependencyText(cmd, findings)
	default:
		return fmt.Errorf("unknown format: %s", outputFormat)
	}
}

func outputDependencyText(cmd *cobra.Command, findings []model.Finding) error {
	out := cmd.OutOrStdout()

	if len(findings) == 0 {
		_, _ = fmt.Fprintln(out, "No dependency vulnerabilities found.")
		return nil
	}

	_, _ = fmt.Fprintf(out, "Found %d dependency vulnerability(ies):\n\n", len(findings))

	for i := range findings {
		f := &findings[i]
		_, _ = fmt.Fprintf(out, "[%d] %s\n", i+1, f.Title)
		_, _ = fmt.Fprintf(out, "    ID:       %s\n", f.Rule)
		_, _ = fmt.Fprintf(out, "    Severity: %s\n", f.Severity)
		_, _ = fmt.Fprintf(out, "    File:     %s\n", f.Location.File)
		if f.Description != "" {
			_, _ = fmt.Fprintf(out, "    Details:  %s\n", f.Description)
		}
		_, _ = fmt.Fprintln(out)
	}

	if outputFile != "" {
		var builder strings.Builder
		builder.Grow(len(findings) * 300)

		_, _ = fmt.Fprintf(&builder, "Found %d dependency vulnerability(ies):\n\n", len(findings))
		for i := range findings {
			f := &findings[i]
			_, _ = fmt.Fprintf(&builder, "[%d] %s\n", i+1, f.Title)
			_, _ = fmt.Fprintf(&builder, "    ID:       %s\n", f.Rule)
			_, _ = fmt.Fprintf(&builder, "    Severity: %s\n", f.Severity)
			_, _ = fmt.Fprintf(&builder, "    File:     %s\n", f.Location.File)
			if f.Description != "" {
				_, _ = fmt.Fprintf(&builder, "    Details:  %s\n", f.Description)
			}
			_, _ = fmt.Fprintln(&builder)
		}
		return writeToFile(outputFile, []byte(builder.String()))
	}

	return nil
}

// Scanner is an interface for security scanners.
type Scanner interface {
	Scan(ctx context.Context, path string) ([]model.Finding, error)
	Close(ctx context.Context) error
}

// runScanWithTUI executes a scan with TUI progress display.
func runScanWithTUI(
	ctx context.Context,
	cmd *cobra.Command,
	scannerName string,
	absPath string,
	scanner Scanner,
	outputFn func(*cobra.Command, []model.Finding) error,
	errType error,
) error {
	// Create channel reporter for progress events.
	reporter, events := progress.NewChannelReporter(100)

	// Create TUI model for single stage scan.
	tuiModel := tui.NewModel(tui.Config{
		CommandName: scannerName,
		CommandType: tui.CommandTypeScan,
		Events:      events,
		Stages:      []string{scannerName},
	})

	// Get terminal size.
	width, height, err := tui.GetTerminalSize()
	if err != nil {
		width, height = 80, 24
	}
	tuiModel.SetSize(width, height)

	// Result channel.
	type scanResult struct {
		err      error
		findings []model.Finding
	}
	resultChan := make(chan scanResult, 1)

	// Execute scan in background.
	go func() {
		reporter.ReportStageStarted(scannerName)

		startTime := time.Now()
		findings, scanErr := scanner.Scan(ctx, absPath)
		duration := time.Since(startTime)

		// Report finding counts.
		if len(findings) > 0 {
			count := countScanFindings(findings)
			reporter.ReportFindingCount(count)
		}

		// Report completion.
		status := progress.StatusSuccess
		if scanErr != nil {
			status = progress.StatusFailed
		}
		reporter.ReportStageCompleted(scannerName, status, duration)
		reporter.ReportCompleted(findings, scanErr)
		reporter.Close()

		resultChan <- scanResult{findings: findings, err: scanErr}
	}()

	// Run TUI.
	if tuiErr := tui.Run(tuiModel); tuiErr != nil {
		res := <-resultChan
		if res.err != nil {
			return fmt.Errorf("scan failed: %w", res.err)
		}
		return fmt.Errorf("TUI error: %w", tuiErr)
	}

	// Get scan result.
	res := <-resultChan

	if res.err != nil {
		return fmt.Errorf("scan failed: %w", res.err)
	}

	// Output results after TUI exits.
	if err := outputFn(cmd, res.findings); err != nil {
		return fmt.Errorf("failed to output results: %w", err)
	}

	if len(res.findings) > 0 {
		return errType
	}

	return nil
}

// countScanFindings counts findings by severity.
func countScanFindings(findings []model.Finding) progress.FindingCount {
	var count progress.FindingCount
	for i := range findings {
		switch findings[i].Severity {
		case model.SeverityCritical:
			count.Critical++
		case model.SeverityHigh:
			count.High++
		case model.SeverityMedium:
			count.Medium++
		case model.SeverityLow:
			count.Low++
		default:
			count.Info++
		}
	}
	return count
}
