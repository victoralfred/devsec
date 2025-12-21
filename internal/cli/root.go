// Package cli provides the command-line interface for devsec.
package cli

import (
	"github.com/spf13/cobra"
)

var (
	cfgFile string
	verbose bool
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

	rootCmd.AddCommand(NewScanCmd())
	rootCmd.AddCommand(NewVersionCmd())
	rootCmd.AddCommand(NewPolicyCmd())

	return rootCmd
}

// Execute runs the root command.
func Execute() error {
	return NewRootCmd().Execute()
}
