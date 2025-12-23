// Package cli provides the command-line interface for devsec.
package cli

import (
	"github.com/spf13/cobra"
	"github.com/victoralfred/devsec/internal/tui"
)

var (
	cfgFile    string
	verbose    bool
	progressUI bool
)

// NewRootCmd creates the root command for devsec CLI.
func NewRootCmd() *cobra.Command {
	rootCmd := &cobra.Command{
		Use:   "devsec",
		Short: "MLSecOps pipeline tool for security scanning and compliance",
		Long: `devsec is an MLSecOps pipeline tool that validates source code
against security, compliance, and quality standards.

It provides automated security scanning, policy enforcement,
and compliance reporting for CI/CD pipelines.`,
	}

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is ./devsec.yaml)")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "verbose output")
	rootCmd.PersistentFlags().BoolVarP(&progressUI, "progress", "P", false, "enable interactive TUI progress dashboard")

	rootCmd.AddCommand(NewScanCmd())
	rootCmd.AddCommand(NewVersionCmd())
	rootCmd.AddCommand(NewPolicyCmd())
	rootCmd.AddCommand(NewSBOMCmd())
	rootCmd.AddCommand(NewSignCmd())
	rootCmd.AddCommand(NewAttestationCmd())
	rootCmd.AddCommand(NewMLCmd())
	rootCmd.AddCommand(NewComplianceCmd())
	rootCmd.AddCommand(NewPipelineCmd())

	return rootCmd
}

// Execute runs the root command.
func Execute() error {
	return NewRootCmd().Execute()
}

// IsProgressEnabled returns true if the TUI progress dashboard should be shown.
func IsProgressEnabled() bool {
	return tui.IsTUIEnabled(progressUI)
}

// IsVerbose returns true if verbose output is enabled.
func IsVerbose() bool {
	return verbose
}
