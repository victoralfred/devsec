package cli

import (
	"context"
	"fmt"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"
	"github.com/victoralfred/devsec/internal/ml"
	"github.com/victoralfred/gowritter/safepath"
)

var (
	mlDetectOutput  string
	mlDetectFormat  string
	mlDetectTimeout time.Duration

	mlModelCardOutput  string
	mlModelCardFormat  string
	mlModelCardTimeout time.Duration
)

// NewMLCmd creates the ml command.
func NewMLCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ml",
		Short: "ML-specific validation and analysis",
		Long: `ML-specific validation and analysis tools.

Provides:
  - ML framework detection (TensorFlow, PyTorch, scikit-learn, etc.)
  - Model file identification
  - Model card generation
  - Data validation and drift detection (interfaces)
  - Fairness and bias analysis (interfaces)`,
	}

	cmd.AddCommand(NewMLDetectCmd())
	cmd.AddCommand(NewMLModelCardCmd())

	return cmd
}

// NewMLDetectCmd creates the ml detect subcommand.
func NewMLDetectCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "detect [path]",
		Short: "Detect ML frameworks and model files",
		Long: `Detect ML frameworks and model files in a project.

Scans the project for:
  - Python files with ML framework imports
  - Model files (.h5, .pt, .onnx, etc.)
  - TensorFlow SavedModel directories

Supported frameworks:
  - TensorFlow/Keras
  - PyTorch
  - scikit-learn
  - ONNX
  - Hugging Face Transformers
  - XGBoost
  - LightGBM`,
		Args: cobra.MaximumNArgs(1),
		RunE: runMLDetect,
	}

	cmd.Flags().StringVarP(&mlDetectOutput, "output", "o", "", "output file (default: stdout)")
	cmd.Flags().StringVarP(&mlDetectFormat, "format", "f", "text", "output format (text, json)")
	cmd.Flags().DurationVarP(&mlDetectTimeout, "timeout", "t", 2*time.Minute, "detection timeout")

	return cmd
}

func runMLDetect(cmd *cobra.Command, args []string) error {
	path := "."
	if len(args) > 0 {
		path = args[0]
	}

	absPath, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("resolve path: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), mlDetectTimeout)
	defer cancel()

	detector := ml.NewDetector()
	result, err := detector.Detect(ctx, absPath)
	if err != nil {
		return fmt.Errorf("detect: %w", err)
	}

	// Format output.
	var output []byte
	switch mlDetectFormat {
	case "json":
		output, err = result.ToJSON()
		if err != nil {
			return fmt.Errorf("marshal JSON: %w", err)
		}
	default:
		output = []byte(result.Summary())
	}

	// Write output.
	if mlDetectOutput != "" {
		absOutput, absErr := filepath.Abs(mlDetectOutput)
		if absErr != nil {
			return fmt.Errorf("resolve output path: %w", absErr)
		}

		dir := filepath.Dir(absOutput)
		filename := filepath.Base(absOutput)

		sp, spErr := safepath.New(dir)
		if spErr != nil {
			return fmt.Errorf("create safepath: %w", spErr)
		}

		if writeErr := sp.WriteFile(filename, output, 0o644); writeErr != nil {
			return fmt.Errorf("write output: %w", writeErr)
		}

		cmd.Printf("Detection results written to: %s\n", absOutput)
	} else {
		cmd.Println(string(output))
	}

	return nil
}

// NewMLModelCardCmd creates the ml model-card subcommand.
func NewMLModelCardCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "model-card [path]",
		Short: "Generate a model card template",
		Long: `Generate a model card template for ML models.

A model card documents:
  - Model details (name, version, framework)
  - Intended use cases
  - Performance metrics
  - Training and evaluation data
  - Ethical considerations
  - Caveats and recommendations

The template includes placeholders for information that
should be filled in by the model developer.`,
		Args: cobra.MaximumNArgs(1),
		RunE: runMLModelCard,
	}

	cmd.Flags().StringVarP(&mlModelCardOutput, "output", "o", "", "output file (required)")
	cmd.Flags().StringVarP(&mlModelCardFormat, "format", "f", "markdown", "output format (markdown, json)")
	cmd.Flags().DurationVarP(&mlModelCardTimeout, "timeout", "t", 1*time.Minute, "generation timeout")

	_ = cmd.MarkFlagRequired("output")

	return cmd
}

func runMLModelCard(cmd *cobra.Command, args []string) error {
	path := "."
	if len(args) > 0 {
		path = args[0]
	}

	absPath, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("resolve path: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), mlModelCardTimeout)
	defer cancel()

	generator := ml.NewModelCardGenerator()
	card, err := generator.GenerateFromPath(ctx, absPath)
	if err != nil {
		return fmt.Errorf("generate model card: %w", err)
	}

	// Determine output path.
	absOutput, err := filepath.Abs(mlModelCardOutput)
	if err != nil {
		return fmt.Errorf("resolve output path: %w", err)
	}

	// Write model card.
	if writeErr := ml.WriteModelCard(ctx, absOutput, card, mlModelCardFormat); writeErr != nil {
		return fmt.Errorf("write model card: %w", writeErr)
	}

	cmd.Printf("Model card generated: %s\n", absOutput)
	cmd.Printf("Format: %s\n", mlModelCardFormat)

	return nil
}
