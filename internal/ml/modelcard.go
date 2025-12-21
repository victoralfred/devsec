package ml

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/victoralfred/gowritter/safepath"
)

// ModelCard represents a model card document.
// Fields ordered for optimal memory alignment.
type ModelCard struct {
	ModelDetails     ModelDetails     `json:"model_details"`
	IntendedUse      IntendedUse      `json:"intended_use"`
	Factors          Factors          `json:"factors,omitempty"`
	Metrics          Metrics          `json:"metrics,omitempty"`
	TrainingData     DataInfo         `json:"training_data,omitempty"`
	EvaluationData   DataInfo         `json:"evaluation_data,omitempty"`
	EthicalConsider  EthicalConsider  `json:"ethical_considerations,omitempty"`
	CaveatsRecommend CaveatsRecommend `json:"caveats_and_recommendations,omitempty"`
}

// ModelDetails contains model identification information.
// Fields ordered for optimal memory alignment.
type ModelDetails struct {
	DateCreated  time.Time `json:"date_created,omitempty"`
	DateModified time.Time `json:"date_modified,omitempty"`
	Name         string    `json:"name"`
	Version      string    `json:"version,omitempty"`
	Type         string    `json:"type,omitempty"`
	Framework    string    `json:"framework,omitempty"`
	License      string    `json:"license,omitempty"`
	Description  string    `json:"description,omitempty"`
	Developers   []string  `json:"developers,omitempty"`
	References   []string  `json:"references,omitempty"`
	Citations    []string  `json:"citations,omitempty"`
}

// IntendedUse describes the intended use cases.
// Fields ordered for optimal memory alignment.
type IntendedUse struct {
	PrimaryUses    []string `json:"primary_uses,omitempty"`
	PrimaryUsers   []string `json:"primary_users,omitempty"`
	OutOfScopeUses []string `json:"out_of_scope_uses,omitempty"`
}

// Factors describes relevant factors for model performance.
// Fields ordered for optimal memory alignment.
type Factors struct {
	RelevantFactors   []string `json:"relevant_factors,omitempty"`
	EvaluationFactors []string `json:"evaluation_factors,omitempty"`
}

// Metrics contains performance metrics.
// Fields ordered for optimal memory alignment.
type Metrics struct {
	PerformanceMetrics []MetricValue `json:"performance_metrics,omitempty"`
	DecisionThresholds []MetricValue `json:"decision_thresholds,omitempty"`
}

// MetricValue represents a single metric.
// Fields ordered for optimal memory alignment.
type MetricValue struct {
	Name        string  `json:"name"`
	Description string  `json:"description,omitempty"`
	Value       float64 `json:"value"`
	Confidence  float64 `json:"confidence,omitempty"`
}

// DataInfo describes training or evaluation data.
// Fields ordered for optimal memory alignment.
type DataInfo struct {
	Motivation    string   `json:"motivation,omitempty"`
	Datasets      []string `json:"datasets,omitempty"`
	Preprocessing []string `json:"preprocessing,omitempty"`
}

// EthicalConsider contains ethical considerations.
// Fields ordered for optimal memory alignment.
type EthicalConsider struct {
	Risks           []string `json:"risks,omitempty"`
	Mitigations     []string `json:"mitigations,omitempty"`
	UseCasesToAvoid []string `json:"use_cases_to_avoid,omitempty"`
}

// CaveatsRecommend contains caveats and recommendations.
// Fields ordered for optimal memory alignment.
type CaveatsRecommend struct {
	Caveats         []string `json:"caveats,omitempty"`
	Recommendations []string `json:"recommendations,omitempty"`
}

// ModelCardGenerator generates model cards.
type ModelCardGenerator struct {
	detector *Detector
}

// NewModelCardGenerator creates a new model card generator.
func NewModelCardGenerator() *ModelCardGenerator {
	return &ModelCardGenerator{
		detector: NewDetector(),
	}
}

// GenerateFromPath generates a model card template from a project path.
func (g *ModelCardGenerator) GenerateFromPath(ctx context.Context, projectPath string) (*ModelCard, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	if projectPath == "" {
		return nil, ErrEmptyPath
	}

	// Detect ML frameworks and models.
	detection, err := g.detector.Detect(ctx, projectPath)
	if err != nil {
		return nil, fmt.Errorf("detect ML components: %w", err)
	}

	card := g.createTemplateCard(detection, projectPath)
	return card, nil
}

// GenerateFromModel generates a model card for a specific model file.
func (g *ModelCardGenerator) GenerateFromModel(ctx context.Context, modelPath string) (*ModelCard, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	if modelPath == "" {
		return nil, ErrEmptyPath
	}

	modelName := filepath.Base(modelPath)
	ext := strings.ToLower(filepath.Ext(modelPath))

	card := &ModelCard{
		ModelDetails: ModelDetails{
			Name:         strings.TrimSuffix(modelName, ext),
			DateCreated:  time.Now().UTC(),
			DateModified: time.Now().UTC(),
		},
		IntendedUse: IntendedUse{
			PrimaryUses:    []string{"[Describe primary use cases]"},
			PrimaryUsers:   []string{"[Describe target users]"},
			OutOfScopeUses: []string{"[Describe inappropriate uses]"},
		},
		EthicalConsider: EthicalConsider{
			Risks:           []string{"[List potential risks]"},
			Mitigations:     []string{"[Describe risk mitigations]"},
			UseCasesToAvoid: []string{"[List use cases to avoid]"},
		},
		CaveatsRecommend: CaveatsRecommend{
			Caveats:         []string{"[Document known limitations]"},
			Recommendations: []string{"[Provide usage recommendations]"},
		},
	}

	// Infer framework from extension.
	card.ModelDetails.Framework = string(g.inferFrameworkFromExtension(ext))
	card.ModelDetails.Type = g.inferModelType(ext)

	return card, nil
}

// createTemplateCard creates a model card template from detection results.
func (g *ModelCardGenerator) createTemplateCard(detection *DetectionResult, projectPath string) *ModelCard {
	card := &ModelCard{
		ModelDetails: ModelDetails{
			Name:         filepath.Base(projectPath),
			DateCreated:  time.Now().UTC(),
			DateModified: time.Now().UTC(),
			Description:  "[Provide a brief description of the model]",
		},
		IntendedUse: IntendedUse{
			PrimaryUses:    []string{"[Describe the primary intended use cases]"},
			PrimaryUsers:   []string{"[Describe the target users]"},
			OutOfScopeUses: []string{"[Describe use cases that are out of scope or inappropriate]"},
		},
		Factors: Factors{
			RelevantFactors:   []string{"[List factors that may affect model performance]"},
			EvaluationFactors: []string{"[List factors considered during evaluation]"},
		},
		Metrics: Metrics{
			PerformanceMetrics: []MetricValue{
				{Name: "accuracy", Description: "[Describe how accuracy is measured]"},
				{Name: "precision", Description: "[Describe precision metric]"},
				{Name: "recall", Description: "[Describe recall metric]"},
			},
		},
		TrainingData: DataInfo{
			Datasets:      []string{"[List training datasets]"},
			Preprocessing: []string{"[Describe preprocessing steps]"},
			Motivation:    "[Explain choice of training data]",
		},
		EvaluationData: DataInfo{
			Datasets:      []string{"[List evaluation datasets]"},
			Preprocessing: []string{"[Describe evaluation preprocessing]"},
			Motivation:    "[Explain choice of evaluation data]",
		},
		EthicalConsider: EthicalConsider{
			Risks:           []string{"[List potential ethical risks and concerns]"},
			Mitigations:     []string{"[Describe steps taken to mitigate risks]"},
			UseCasesToAvoid: []string{"[List use cases that should be avoided]"},
		},
		CaveatsRecommend: CaveatsRecommend{
			Caveats:         []string{"[Document known limitations and caveats]"},
			Recommendations: []string{"[Provide recommendations for safe use]"},
		},
	}

	// Add detected frameworks.
	if len(detection.Frameworks) > 0 {
		seen := make(map[Framework]bool)
		var frameworks []string
		for _, f := range detection.Frameworks {
			if !seen[f.Name] {
				seen[f.Name] = true
				frameworks = append(frameworks, string(f.Name))
			}
		}
		card.ModelDetails.Framework = strings.Join(frameworks, ", ")
	}

	// Add model information if detected.
	if len(detection.Models) > 0 {
		card.ModelDetails.Type = string(detection.Models[0].Type)
	}

	return card
}

// inferFrameworkFromExtension infers framework from file extension.
func (g *ModelCardGenerator) inferFrameworkFromExtension(ext string) Framework {
	switch ext {
	case ".h5", ".hdf5", ".pb":
		return FrameworkTensorFlow
	case ".pt", ".pth":
		return FrameworkPyTorch
	case ".pkl", ".pickle", ".joblib":
		return FrameworkScikit
	case ".onnx":
		return FrameworkONNX
	case ".safetensors":
		return FrameworkHuggingFace
	default:
		return FrameworkUnknown
	}
}

// inferModelType infers model type from file extension.
func (g *ModelCardGenerator) inferModelType(ext string) string {
	switch ext {
	case ".h5", ".hdf5":
		return "Keras/TensorFlow model"
	case ".pb":
		return "TensorFlow SavedModel"
	case ".pt", ".pth":
		return "PyTorch model"
	case ".pkl", ".pickle":
		return "Pickled model"
	case ".joblib":
		return "Joblib serialized model"
	case ".onnx":
		return "ONNX model"
	case ".safetensors":
		return "Safetensors model"
	case ".ckpt":
		return "Checkpoint"
	default:
		return "Unknown model type"
	}
}

// ToJSON converts model card to JSON.
func (c *ModelCard) ToJSON() ([]byte, error) {
	return json.MarshalIndent(c, "", "  ")
}

// ToMarkdown converts model card to Markdown format.
func (c *ModelCard) ToMarkdown() string {
	var sb strings.Builder

	sb.WriteString("# Model Card\n\n")

	// Model Details.
	sb.WriteString("## Model Details\n\n")
	sb.WriteString(fmt.Sprintf("- **Name**: %s\n", c.ModelDetails.Name))
	if c.ModelDetails.Version != "" {
		sb.WriteString(fmt.Sprintf("- **Version**: %s\n", c.ModelDetails.Version))
	}
	if c.ModelDetails.Type != "" {
		sb.WriteString(fmt.Sprintf("- **Type**: %s\n", c.ModelDetails.Type))
	}
	if c.ModelDetails.Framework != "" {
		sb.WriteString(fmt.Sprintf("- **Framework**: %s\n", c.ModelDetails.Framework))
	}
	if c.ModelDetails.License != "" {
		sb.WriteString(fmt.Sprintf("- **License**: %s\n", c.ModelDetails.License))
	}
	if c.ModelDetails.Description != "" {
		sb.WriteString(fmt.Sprintf("\n%s\n", c.ModelDetails.Description))
	}
	if len(c.ModelDetails.Developers) > 0 {
		sb.WriteString(fmt.Sprintf("- **Developers**: %s\n", strings.Join(c.ModelDetails.Developers, ", ")))
	}
	sb.WriteString("\n")

	// Intended Use.
	sb.WriteString("## Intended Use\n\n")
	if len(c.IntendedUse.PrimaryUses) > 0 {
		sb.WriteString("### Primary Uses\n")
		for _, use := range c.IntendedUse.PrimaryUses {
			sb.WriteString(fmt.Sprintf("- %s\n", use))
		}
		sb.WriteString("\n")
	}
	if len(c.IntendedUse.PrimaryUsers) > 0 {
		sb.WriteString("### Primary Users\n")
		for _, user := range c.IntendedUse.PrimaryUsers {
			sb.WriteString(fmt.Sprintf("- %s\n", user))
		}
		sb.WriteString("\n")
	}
	if len(c.IntendedUse.OutOfScopeUses) > 0 {
		sb.WriteString("### Out-of-Scope Uses\n")
		for _, use := range c.IntendedUse.OutOfScopeUses {
			sb.WriteString(fmt.Sprintf("- %s\n", use))
		}
		sb.WriteString("\n")
	}

	// Factors.
	if len(c.Factors.RelevantFactors) > 0 || len(c.Factors.EvaluationFactors) > 0 {
		sb.WriteString("## Factors\n\n")
		if len(c.Factors.RelevantFactors) > 0 {
			sb.WriteString("### Relevant Factors\n")
			for _, factor := range c.Factors.RelevantFactors {
				sb.WriteString(fmt.Sprintf("- %s\n", factor))
			}
			sb.WriteString("\n")
		}
		if len(c.Factors.EvaluationFactors) > 0 {
			sb.WriteString("### Evaluation Factors\n")
			for _, factor := range c.Factors.EvaluationFactors {
				sb.WriteString(fmt.Sprintf("- %s\n", factor))
			}
			sb.WriteString("\n")
		}
	}

	// Metrics.
	if len(c.Metrics.PerformanceMetrics) > 0 {
		sb.WriteString("## Metrics\n\n")
		sb.WriteString("### Performance Metrics\n")
		sb.WriteString("| Metric | Value | Description |\n")
		sb.WriteString("|--------|-------|-------------|\n")
		for _, m := range c.Metrics.PerformanceMetrics {
			sb.WriteString(fmt.Sprintf("| %s | %.4f | %s |\n", m.Name, m.Value, m.Description))
		}
		sb.WriteString("\n")
	}

	// Training Data.
	if len(c.TrainingData.Datasets) > 0 || c.TrainingData.Motivation != "" {
		sb.WriteString("## Training Data\n\n")
		if len(c.TrainingData.Datasets) > 0 {
			sb.WriteString("### Datasets\n")
			for _, ds := range c.TrainingData.Datasets {
				sb.WriteString(fmt.Sprintf("- %s\n", ds))
			}
			sb.WriteString("\n")
		}
		if c.TrainingData.Motivation != "" {
			sb.WriteString(fmt.Sprintf("**Motivation**: %s\n\n", c.TrainingData.Motivation))
		}
	}

	// Evaluation Data.
	if len(c.EvaluationData.Datasets) > 0 || c.EvaluationData.Motivation != "" {
		sb.WriteString("## Evaluation Data\n\n")
		if len(c.EvaluationData.Datasets) > 0 {
			sb.WriteString("### Datasets\n")
			for _, ds := range c.EvaluationData.Datasets {
				sb.WriteString(fmt.Sprintf("- %s\n", ds))
			}
			sb.WriteString("\n")
		}
	}

	// Ethical Considerations.
	if len(c.EthicalConsider.Risks) > 0 || len(c.EthicalConsider.Mitigations) > 0 {
		sb.WriteString("## Ethical Considerations\n\n")
		if len(c.EthicalConsider.Risks) > 0 {
			sb.WriteString("### Risks\n")
			for _, risk := range c.EthicalConsider.Risks {
				sb.WriteString(fmt.Sprintf("- %s\n", risk))
			}
			sb.WriteString("\n")
		}
		if len(c.EthicalConsider.Mitigations) > 0 {
			sb.WriteString("### Mitigations\n")
			for _, m := range c.EthicalConsider.Mitigations {
				sb.WriteString(fmt.Sprintf("- %s\n", m))
			}
			sb.WriteString("\n")
		}
		if len(c.EthicalConsider.UseCasesToAvoid) > 0 {
			sb.WriteString("### Use Cases to Avoid\n")
			for _, uc := range c.EthicalConsider.UseCasesToAvoid {
				sb.WriteString(fmt.Sprintf("- %s\n", uc))
			}
			sb.WriteString("\n")
		}
	}

	// Caveats and Recommendations.
	if len(c.CaveatsRecommend.Caveats) > 0 || len(c.CaveatsRecommend.Recommendations) > 0 {
		sb.WriteString("## Caveats and Recommendations\n\n")
		if len(c.CaveatsRecommend.Caveats) > 0 {
			sb.WriteString("### Caveats\n")
			for _, caveat := range c.CaveatsRecommend.Caveats {
				sb.WriteString(fmt.Sprintf("- %s\n", caveat))
			}
			sb.WriteString("\n")
		}
		if len(c.CaveatsRecommend.Recommendations) > 0 {
			sb.WriteString("### Recommendations\n")
			for _, rec := range c.CaveatsRecommend.Recommendations {
				sb.WriteString(fmt.Sprintf("- %s\n", rec))
			}
			sb.WriteString("\n")
		}
	}

	return sb.String()
}

// WriteModelCard writes a model card to a file.
func WriteModelCard(ctx context.Context, path string, card *ModelCard, format string) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}

	if card == nil {
		return ErrNilModelCard
	}

	var content []byte
	var err error

	switch strings.ToLower(format) {
	case "json":
		content, err = card.ToJSON()
		if err != nil {
			return fmt.Errorf("marshal to JSON: %w", err)
		}
	case "markdown", "md":
		content = []byte(card.ToMarkdown())
	default:
		return fmt.Errorf("%w: %s (use 'json' or 'markdown')", ErrUnsupportedFormat, format)
	}

	dir := filepath.Dir(path)
	filename := filepath.Base(path)

	sp, err := safepath.New(dir)
	if err != nil {
		return fmt.Errorf("create safepath: %w", err)
	}

	return sp.WriteFile(filename, content, 0o644)
}

// ReadModelCard reads a model card from a JSON file.
func ReadModelCard(ctx context.Context, path string) (*ModelCard, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	dir := filepath.Dir(path)
	filename := filepath.Base(path)

	sp, err := safepath.New(dir)
	if err != nil {
		return nil, fmt.Errorf("create safepath: %w", err)
	}

	data, err := sp.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("read file: %w", err)
	}

	var card ModelCard
	if err := json.Unmarshal(data, &card); err != nil {
		return nil, fmt.Errorf("unmarshal model card: %w", err)
	}

	return &card, nil
}
