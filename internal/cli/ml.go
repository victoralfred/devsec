package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
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

	mlValidateSchema  string
	mlValidateOutput  string
	mlValidateFormat  string
	mlValidateTimeout time.Duration

	mlDriftThreshold float64
	mlDriftOutput    string
	mlDriftFormat    string
	mlDriftTimeout   time.Duration

	mlFairnessProtected string
	mlFairnessOutput    string
	mlFairnessFormat    string
	mlFairnessTimeout   time.Duration

	mlBiasAttributes string
	mlBiasOutput     string
	mlBiasFormat     string
	mlBiasTimeout    time.Duration
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
	cmd.AddCommand(NewMLValidateCmd())
	cmd.AddCommand(NewMLDriftCmd())
	cmd.AddCommand(NewMLFairnessCmd())
	cmd.AddCommand(NewMLBiasCmd())

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

// NewMLValidateCmd creates the ml validate subcommand.
func NewMLValidateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "validate [data-file]",
		Short: "Validate ML data against a schema",
		Long: `Validate ML data against a JSON schema.

Validates data files for:
  - Required fields
  - Data types (string, integer, float, boolean)
  - Value ranges (min/max)
  - Categorical values
  - Null handling

Schema format (JSON):
  {
    "name": "schema-name",
    "columns": [
      {"name": "age", "type": "integer", "required": true, "min": 0, "max": 150}
    ]
  }`,
		Args: cobra.ExactArgs(1),
		RunE: runMLValidate,
	}

	cmd.Flags().StringVarP(&mlValidateSchema, "schema", "s", "", "schema file (required)")
	cmd.Flags().StringVarP(&mlValidateOutput, "output", "o", "", "output file (default: stdout)")
	cmd.Flags().StringVarP(&mlValidateFormat, "format", "f", "text", "output format (text, json)")
	cmd.Flags().DurationVarP(&mlValidateTimeout, "timeout", "t", 2*time.Minute, "validation timeout")

	_ = cmd.MarkFlagRequired("schema")

	return cmd
}

func runMLValidate(cmd *cobra.Command, args []string) error {
	dataPath := args[0]

	absDataPath, err := filepath.Abs(dataPath)
	if err != nil {
		return fmt.Errorf("resolve data path: %w", err)
	}

	absSchemaPath, err := filepath.Abs(mlValidateSchema)
	if err != nil {
		return fmt.Errorf("resolve schema path: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), mlValidateTimeout)
	defer cancel()

	// Read schema file.
	schemaDir := filepath.Dir(absSchemaPath)
	schemaFile := filepath.Base(absSchemaPath)

	sp, err := safepath.New(schemaDir)
	if err != nil {
		return fmt.Errorf("create safepath for schema: %w", err)
	}

	schemaBytes, err := sp.ReadFile(schemaFile)
	if err != nil {
		return fmt.Errorf("read schema: %w", err)
	}

	var schema ml.DataSchema
	if unmarshalErr := json.Unmarshal(schemaBytes, &schema); unmarshalErr != nil {
		return fmt.Errorf("parse schema: %w", unmarshalErr)
	}

	// Read data file.
	dataDir := filepath.Dir(absDataPath)
	dataFile := filepath.Base(absDataPath)

	spData, err := safepath.New(dataDir)
	if err != nil {
		return fmt.Errorf("create safepath for data: %w", err)
	}

	dataBytes, err := spData.ReadFile(dataFile)
	if err != nil {
		return fmt.Errorf("read data: %w", err)
	}

	var data []map[string]interface{}
	if unmarshalErr := json.Unmarshal(dataBytes, &data); unmarshalErr != nil {
		return fmt.Errorf("parse data: %w", unmarshalErr)
	}

	// Validate.
	validator := ml.NewDataValidator(&schema)
	result, err := validator.Validate(ctx, data)
	if err != nil {
		return fmt.Errorf("validate: %w", err)
	}

	// Format output.
	var output []byte
	switch mlValidateFormat {
	case "json":
		output, err = json.MarshalIndent(result, "", "  ")
		if err != nil {
			return fmt.Errorf("marshal JSON: %w", err)
		}
	default:
		output = []byte(formatValidationResult(result))
	}

	return writeOutput(cmd, output, mlValidateOutput)
}

func formatValidationResult(result *ml.ValidationResult) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("Validation Result for: %s\n", result.SchemaName))
	sb.WriteString(fmt.Sprintf("Valid: %v\n", result.Valid))
	sb.WriteString(fmt.Sprintf("Total Rows: %d\n", result.Statistics.TotalRows))
	sb.WriteString(fmt.Sprintf("Valid Rows: %d\n", result.Statistics.ValidRows))
	sb.WriteString(fmt.Sprintf("Invalid Rows: %d\n", result.Statistics.InvalidRows))

	if len(result.Errors) > 0 {
		sb.WriteString("\nErrors:\n")
		for _, e := range result.Errors {
			sb.WriteString(fmt.Sprintf("  [Row %d] %s: %s\n", e.Row, e.Column, e.Message))
		}
	}

	return sb.String()
}

// NewMLDriftCmd creates the ml drift subcommand.
func NewMLDriftCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "drift [baseline-file] [current-file]",
		Short: "Detect data drift between datasets",
		Long: `Detect data drift between baseline and current datasets.

Compares statistical properties of numeric columns:
  - Mean shift detection
  - Standard deviation changes
  - Per-column drift scores

Use cases:
  - Monitor training vs production data
  - Detect feature distribution changes
  - Identify potential model degradation`,
		Args: cobra.ExactArgs(2),
		RunE: runMLDrift,
	}

	cmd.Flags().Float64VarP(&mlDriftThreshold, "threshold", "T", 0.1, "drift detection threshold (0.0-1.0)")
	cmd.Flags().StringVarP(&mlDriftOutput, "output", "o", "", "output file (default: stdout)")
	cmd.Flags().StringVarP(&mlDriftFormat, "format", "f", "text", "output format (text, json)")
	cmd.Flags().DurationVarP(&mlDriftTimeout, "timeout", "t", 2*time.Minute, "detection timeout")

	return cmd
}

func runMLDrift(cmd *cobra.Command, args []string) error {
	baselinePath := args[0]
	currentPath := args[1]

	absBaselinePath, err := filepath.Abs(baselinePath)
	if err != nil {
		return fmt.Errorf("resolve baseline path: %w", err)
	}

	absCurrentPath, err := filepath.Abs(currentPath)
	if err != nil {
		return fmt.Errorf("resolve current path: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), mlDriftTimeout)
	defer cancel()

	// Read baseline file.
	baseline, err := readJSONData(absBaselinePath)
	if err != nil {
		return fmt.Errorf("read baseline: %w", err)
	}

	// Read current file.
	current, err := readJSONData(absCurrentPath)
	if err != nil {
		return fmt.Errorf("read current: %w", err)
	}

	// Detect drift.
	detector := ml.NewDriftDetector(mlDriftThreshold)
	result, err := detector.DetectDrift(ctx, baseline, current)
	if err != nil {
		return fmt.Errorf("detect drift: %w", err)
	}

	// Format output.
	var output []byte
	switch mlDriftFormat {
	case "json":
		output, err = result.ToJSON()
		if err != nil {
			return fmt.Errorf("marshal JSON: %w", err)
		}
	default:
		output = []byte(result.Summary())
	}

	return writeOutput(cmd, output, mlDriftOutput)
}

// NewMLFairnessCmd creates the ml fairness subcommand.
func NewMLFairnessCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "fairness [data-file]",
		Short: "Analyze model fairness across groups",
		Long: `Analyze model fairness for protected attributes.

Calculates fairness metrics:
  - Disparate Impact (ratio of positive rates)
  - Statistical Parity (difference in positive rates)
  - Equal Opportunity (difference in TPR)

Data format (JSON array with predictions, labels, groups):
  [
    {"prediction": true, "label": true, "group": "A"},
    {"prediction": false, "label": false, "group": "B"}
  ]`,
		Args: cobra.ExactArgs(1),
		RunE: runMLFairness,
	}

	cmd.Flags().StringVarP(&mlFairnessProtected, "protected", "p", "group", "protected attribute column name")
	cmd.Flags().StringVarP(&mlFairnessOutput, "output", "o", "", "output file (default: stdout)")
	cmd.Flags().StringVarP(&mlFairnessFormat, "format", "f", "text", "output format (text, json)")
	cmd.Flags().DurationVarP(&mlFairnessTimeout, "timeout", "t", 2*time.Minute, "analysis timeout")

	return cmd
}

func runMLFairness(cmd *cobra.Command, args []string) error {
	dataPath := args[0]

	absDataPath, err := filepath.Abs(dataPath)
	if err != nil {
		return fmt.Errorf("resolve data path: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), mlFairnessTimeout)
	defer cancel()

	// Read data file.
	records, err := readJSONData(absDataPath)
	if err != nil {
		return fmt.Errorf("read data: %w", err)
	}

	// Extract predictions, labels, and groups.
	predictions := make([]interface{}, len(records))
	labels := make([]interface{}, len(records))
	groups := make([]interface{}, len(records))

	for i, record := range records {
		predictions[i] = record["prediction"]
		labels[i] = record["label"]
		groups[i] = record[mlFairnessProtected]
	}

	// Check fairness.
	checker := ml.NewFairnessChecker(mlFairnessProtected)
	result, err := checker.CheckFairness(ctx, predictions, labels, groups)
	if err != nil {
		return fmt.Errorf("check fairness: %w", err)
	}

	// Format output.
	var output []byte
	switch mlFairnessFormat {
	case "json":
		output, err = result.ToJSON()
		if err != nil {
			return fmt.Errorf("marshal JSON: %w", err)
		}
	default:
		output = []byte(result.Summary())
	}

	return writeOutput(cmd, output, mlFairnessOutput)
}

// NewMLBiasCmd creates the ml bias subcommand.
func NewMLBiasCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "bias [data-file]",
		Short: "Detect potential biases in data",
		Long: `Detect potential biases in ML training data.

Analyzes:
  - Class imbalance in protected attributes
  - Missing value patterns
  - Selection bias indicators
  - Sampling bias indicators

Data format (JSON array):
  [
    {"gender": "M", "age": 25, "income": 50000},
    {"gender": "F", "age": 30, "income": 60000}
  ]`,
		Args: cobra.ExactArgs(1),
		RunE: runMLBias,
	}

	cmd.Flags().StringVarP(&mlBiasAttributes, "attributes", "a", "", "protected attributes (comma-separated, required)")
	cmd.Flags().StringVarP(&mlBiasOutput, "output", "o", "", "output file (default: stdout)")
	cmd.Flags().StringVarP(&mlBiasFormat, "format", "f", "text", "output format (text, json)")
	cmd.Flags().DurationVarP(&mlBiasTimeout, "timeout", "t", 2*time.Minute, "analysis timeout")

	_ = cmd.MarkFlagRequired("attributes")

	return cmd
}

func runMLBias(cmd *cobra.Command, args []string) error {
	dataPath := args[0]

	absDataPath, err := filepath.Abs(dataPath)
	if err != nil {
		return fmt.Errorf("resolve data path: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), mlBiasTimeout)
	defer cancel()

	// Read data file.
	records, err := readJSONData(absDataPath)
	if err != nil {
		return fmt.Errorf("read data: %w", err)
	}

	// Parse protected attributes.
	attributes := strings.Split(mlBiasAttributes, ",")
	for i := range attributes {
		attributes[i] = strings.TrimSpace(attributes[i])
	}

	// Detect bias.
	detector := ml.NewBiasDetector()
	result, err := detector.DetectBias(ctx, records, attributes)
	if err != nil {
		return fmt.Errorf("detect bias: %w", err)
	}

	// Format output.
	var output []byte
	switch mlBiasFormat {
	case "json":
		output, err = result.ToJSON()
		if err != nil {
			return fmt.Errorf("marshal JSON: %w", err)
		}
	default:
		output = []byte(result.Summary())
	}

	return writeOutput(cmd, output, mlBiasOutput)
}

// readJSONData reads a JSON file and returns records.
func readJSONData(path string) ([]map[string]interface{}, error) {
	dir := filepath.Dir(path)
	file := filepath.Base(path)

	sp, err := safepath.New(dir)
	if err != nil {
		return nil, fmt.Errorf("create safepath: %w", err)
	}

	data, err := sp.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("read file: %w", err)
	}

	var records []map[string]interface{}
	if err := json.Unmarshal(data, &records); err != nil {
		return nil, fmt.Errorf("parse JSON: %w", err)
	}

	return records, nil
}

// writeOutput writes output to file or stdout.
func writeOutput(cmd *cobra.Command, output []byte, outputPath string) error {
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
