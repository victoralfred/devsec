package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

// Version information set at build time.
var (
	Version   = "dev"
	GitCommit = "unknown"
	BuildDate = "unknown"
)

// NewVersionCmd creates the version command.
func NewVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Run: func(cmd *cobra.Command, args []string) {
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "devsec version %s\n", Version)
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  Git commit: %s\n", GitCommit)
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  Build date: %s\n", BuildDate)
		},
	}
}
