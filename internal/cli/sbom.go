package cli

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/victoralfred/devsec/internal/sbom"
)

var (
	sbomFormat  string
	sbomOutput  string
	sbomTimeout time.Duration
)

// NewSBOMCmd creates the sbom command.
func NewSBOMCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "sbom [path]",
		Short: "Generate Software Bill of Materials",
		Long: `Generate a Software Bill of Materials (SBOM) for the specified directory.

Supports multiple formats:
  - SPDX (Software Package Data Exchange) 2.3
  - CycloneDX 1.5

The SBOM includes dependencies from:
  - Go (go.mod)
  - Node.js (package.json)
  - Python (requirements.txt)

If no path is specified, the current directory is scanned.`,
		Args: cobra.MaximumNArgs(1),
		RunE: runSBOMGenerate,
	}

	cmd.Flags().StringVarP(&sbomFormat, "format", "f", "spdx", "output format (spdx, cyclonedx)")
	cmd.Flags().StringVarP(&sbomOutput, "output", "o", "", "output file (default is stdout)")
	cmd.Flags().DurationVarP(&sbomTimeout, "timeout", "t", 2*time.Minute, "generation timeout")

	return cmd
}

func runSBOMGenerate(cmd *cobra.Command, args []string) error {
	targetPath := "."
	if len(args) > 0 {
		targetPath = args[0]
	}

	absPath, err := filepath.Abs(targetPath)
	if err != nil {
		return fmt.Errorf("failed to resolve path: %w", err)
	}

	// Determine format.
	var format sbom.Format
	switch strings.ToLower(sbomFormat) {
	case "spdx":
		format = sbom.FormatSPDX
	case "cyclonedx", "cdx":
		format = sbom.FormatCycloneDX
	default:
		return fmt.Errorf("unsupported format: %s (use spdx or cyclonedx)", sbomFormat)
	}

	// Create generator.
	gen := sbom.NewGenerator(Version)

	// Create context with timeout.
	ctx, cancel := context.WithTimeout(context.Background(), sbomTimeout)
	defer cancel()

	// Generate SBOM.
	result, err := gen.Generate(ctx, absPath, format)
	if err != nil {
		return fmt.Errorf("failed to generate SBOM: %w", err)
	}

	// Format output.
	data, err := result.Marshal()
	if err != nil {
		return fmt.Errorf("failed to format SBOM: %w", err)
	}

	// Write output.
	if sbomOutput != "" {
		if err := result.WriteToFile(sbomOutput); err != nil {
			return fmt.Errorf("failed to write output: %w", err)
		}
		cmd.Printf("SBOM written to %s\n", sbomOutput)
	} else {
		cmd.Println(string(data))
	}

	return nil
}
