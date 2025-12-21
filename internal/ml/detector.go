// Package ml provides ML-specific validation and detection capabilities.
package ml

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/victoralfred/gowritter/safepath"
)

// Framework represents a detected ML framework.
type Framework string

const (
	// FrameworkTensorFlow represents TensorFlow/Keras.
	FrameworkTensorFlow Framework = "tensorflow"
	// FrameworkPyTorch represents PyTorch.
	FrameworkPyTorch Framework = "pytorch"
	// FrameworkScikit represents scikit-learn.
	FrameworkScikit Framework = "scikit-learn"
	// FrameworkONNX represents ONNX runtime.
	FrameworkONNX Framework = "onnx"
	// FrameworkHuggingFace represents Hugging Face Transformers.
	FrameworkHuggingFace Framework = "huggingface"
	// FrameworkXGBoost represents XGBoost.
	FrameworkXGBoost Framework = "xgboost"
	// FrameworkLightGBM represents LightGBM.
	FrameworkLightGBM Framework = "lightgbm"
	// FrameworkUnknown represents an unknown framework.
	FrameworkUnknown Framework = "unknown"
)

// ModelType represents the type of ML model file.
type ModelType string

const (
	// ModelTypeSavedModel represents TensorFlow SavedModel.
	ModelTypeSavedModel ModelType = "saved_model"
	// ModelTypeH5 represents Keras H5 format.
	ModelTypeH5 ModelType = "h5"
	// ModelTypePTH represents PyTorch model file.
	ModelTypePTH ModelType = "pth"
	// ModelTypePickle represents pickled model.
	ModelTypePickle ModelType = "pickle"
	// ModelTypeONNX represents ONNX model.
	ModelTypeONNX ModelType = "onnx"
	// ModelTypePMML represents PMML model.
	ModelTypePMML ModelType = "pmml"
	// ModelTypeSafetensors represents safetensors format.
	ModelTypeSafetensors ModelType = "safetensors"
	// ModelTypeCheckpoint represents checkpoint file.
	ModelTypeCheckpoint ModelType = "checkpoint"
	// ModelTypeUnknown represents unknown model type.
	ModelTypeUnknown ModelType = "unknown"
)

// DetectedFramework contains information about a detected framework.
// Fields ordered for optimal memory alignment.
type DetectedFramework struct {
	Name         Framework `json:"name"`
	Version      string    `json:"version,omitempty"`
	SourceFile   string    `json:"source_file"`
	Imports      []string  `json:"imports,omitempty"`
	Confidence   float64   `json:"confidence"`
	IsMLPipeline bool      `json:"is_ml_pipeline"`
}

// DetectedModel contains information about a detected model file.
// Fields ordered for optimal memory alignment.
type DetectedModel struct {
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
	Path        string                 `json:"path"`
	Name        string                 `json:"name"`
	Framework   Framework              `json:"framework"`
	Type        ModelType              `json:"type"`
	SizeBytes   int64                  `json:"size_bytes"`
	IsTrainable bool                   `json:"is_trainable"`
}

// DetectionResult contains the complete detection results.
// Fields ordered for optimal memory alignment.
type DetectionResult struct {
	Frameworks []DetectedFramework `json:"frameworks"`
	Models     []DetectedModel     `json:"models"`
	Errors     []string            `json:"errors,omitempty"`
}

// DetectorConfig contains configuration for the ML detector.
// Fields ordered for optimal memory alignment.
type DetectorConfig struct {
	ExcludePatterns []string `json:"exclude_patterns,omitempty"`
	MaxFileSize     int64    `json:"max_file_size"`
	MaxFilesToScan  int      `json:"max_files_to_scan"`
	MaxDepth        int      `json:"max_depth"`
}

// DefaultDetectorConfig returns the default detector configuration.
func DefaultDetectorConfig() DetectorConfig {
	return DetectorConfig{
		MaxFileSize:    10 * 1024 * 1024, // 10 MB
		MaxDepth:       50,
		MaxFilesToScan: 10000,
		ExcludePatterns: []string{
			"**/node_modules/**",
			"**/.git/**",
			"**/venv/**",
			"**/__pycache__/**",
			"**/dist/**",
			"**/build/**",
		},
	}
}

// Detector detects ML frameworks and model files in a project.
type Detector struct {
	frameworkPatterns  map[Framework]*regexp.Regexp
	confidencePatterns map[Framework][]*regexp.Regexp
	pipelineIndicators []*regexp.Regexp
	modelExtensions    map[string]ModelType
	config             DetectorConfig
	filesScanned       int
}

// NewDetector creates a new ML detector with default configuration.
func NewDetector() *Detector {
	return NewDetectorWithConfig(DefaultDetectorConfig())
}

// NewDetectorWithConfig creates a new ML detector with custom configuration.
func NewDetectorWithConfig(config DetectorConfig) *Detector {
	return &Detector{
		config: config,
		frameworkPatterns: map[Framework]*regexp.Regexp{
			FrameworkTensorFlow:  regexp.MustCompile(`(?:import\s+tensorflow|from\s+tensorflow|import\s+keras|from\s+keras)`),
			FrameworkPyTorch:     regexp.MustCompile(`(?:import\s+torch|from\s+torch)`),
			FrameworkScikit:      regexp.MustCompile(`(?:import\s+sklearn|from\s+sklearn|import\s+scikit)`),
			FrameworkONNX:        regexp.MustCompile(`(?:import\s+onnx|from\s+onnx|import\s+onnxruntime)`),
			FrameworkHuggingFace: regexp.MustCompile(`(?:import\s+transformers|from\s+transformers|from\s+huggingface)`),
			FrameworkXGBoost:     regexp.MustCompile(`(?:import\s+xgboost|from\s+xgboost)`),
			FrameworkLightGBM:    regexp.MustCompile(`(?:import\s+lightgbm|from\s+lightgbm)`),
		},
		// Pre-compiled confidence patterns for each framework.
		confidencePatterns: map[Framework][]*regexp.Regexp{
			FrameworkTensorFlow: {
				regexp.MustCompile(`tf\.keras`),
				regexp.MustCompile(`model\.fit`),
				regexp.MustCompile(`model\.compile`),
				regexp.MustCompile(`tf\.data`),
				regexp.MustCompile(`tf\.function`),
			},
			FrameworkPyTorch: {
				regexp.MustCompile(`torch\.nn`),
				regexp.MustCompile(`torch\.optim`),
				regexp.MustCompile(`DataLoader`),
				regexp.MustCompile(`\.backward\(\)`),
				regexp.MustCompile(`\.zero_grad\(\)`),
			},
			FrameworkScikit: {
				regexp.MustCompile(`\.fit\(`),
				regexp.MustCompile(`\.predict\(`),
				regexp.MustCompile(`train_test_split`),
				regexp.MustCompile(`cross_val_score`),
				regexp.MustCompile(`Pipeline`),
			},
			FrameworkHuggingFace: {
				regexp.MustCompile(`AutoModel`),
				regexp.MustCompile(`AutoTokenizer`),
				regexp.MustCompile(`Trainer`),
				regexp.MustCompile(`TrainingArguments`),
				regexp.MustCompile(`pipeline\(`),
			},
			FrameworkXGBoost: {
				regexp.MustCompile(`XGBClassifier`),
				regexp.MustCompile(`XGBRegressor`),
				regexp.MustCompile(`xgb\.train`),
				regexp.MustCompile(`DMatrix`),
			},
			FrameworkLightGBM: {
				regexp.MustCompile(`LGBMClassifier`),
				regexp.MustCompile(`LGBMRegressor`),
				regexp.MustCompile(`lgb\.train`),
				regexp.MustCompile(`Dataset`),
			},
		},
		// Pre-compiled pipeline indicators.
		pipelineIndicators: []*regexp.Regexp{
			regexp.MustCompile(`\.fit\(`),
			regexp.MustCompile(`\.train\(`),
			regexp.MustCompile(`epochs?\s*=`),
			regexp.MustCompile(`batch_size\s*=`),
			regexp.MustCompile(`learning_rate\s*=`),
			regexp.MustCompile(`optimizer`),
			regexp.MustCompile(`loss\s*=`),
			regexp.MustCompile(`model\.save`),
			regexp.MustCompile(`torch\.save`),
			regexp.MustCompile(`checkpoint`),
		},
		modelExtensions: map[string]ModelType{
			".h5":          ModelTypeH5,
			".hdf5":        ModelTypeH5,
			".pt":          ModelTypePTH,
			".pth":         ModelTypePTH,
			".pkl":         ModelTypePickle,
			".pickle":      ModelTypePickle,
			".joblib":      ModelTypePickle,
			".onnx":        ModelTypeONNX,
			".pmml":        ModelTypePMML,
			".safetensors": ModelTypeSafetensors,
			".ckpt":        ModelTypeCheckpoint,
		},
		filesScanned: 0,
	}
}

// Config returns the detector configuration.
func (d *Detector) Config() DetectorConfig {
	return d.config
}

// Detect scans a directory for ML frameworks and model files.
func (d *Detector) Detect(ctx context.Context, rootPath string) (*DetectionResult, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	if rootPath == "" {
		return nil, ErrEmptyPath
	}

	// Reset file counter for each scan.
	d.filesScanned = 0

	result := &DetectionResult{
		Frameworks: make([]DetectedFramework, 0),
		Models:     make([]DetectedModel, 0),
		Errors:     make([]string, 0),
	}

	// Scan for frameworks in Python files.
	if err := d.scanForFrameworks(ctx, rootPath, result); err != nil {
		return nil, fmt.Errorf("scan frameworks: %w", err)
	}

	// Scan for model files.
	if err := d.scanForModels(ctx, rootPath, result); err != nil {
		return nil, fmt.Errorf("scan models: %w", err)
	}

	return result, nil
}

// scanForFrameworks scans Python files for ML framework imports.
func (d *Detector) scanForFrameworks(ctx context.Context, rootPath string, result *DetectionResult) error {
	pythonExts := []string{".py", ".pyx", ".pyw"}

	return d.walkDirectory(ctx, rootPath, func(path string, isDir bool, size int64) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		if isDir {
			return nil
		}

		ext := strings.ToLower(filepath.Ext(path))

		// Check for Jupyter notebook.
		if ext == ".ipynb" {
			content, err := d.parseNotebook(path)
			if err != nil {
				result.Errors = append(result.Errors, fmt.Sprintf("parse notebook %s: %v", path, err))
				return nil
			}
			if content != "" {
				d.detectFrameworksInContent(content, path, result)
			}
			return nil
		}

		// Check for Python files.
		isPython := false
		for _, pyExt := range pythonExts {
			if ext == pyExt {
				isPython = true
				break
			}
		}
		if !isPython {
			return nil
		}

		// Read file content.
		content, err := d.readFile(path)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("read %s: %v", path, err))
			return nil
		}

		// Detect frameworks.
		d.detectFrameworksInContent(string(content), path, result)
		return nil
	})
}

// detectFrameworksInContent detects ML frameworks in file content.
func (d *Detector) detectFrameworksInContent(content, filePath string, result *DetectionResult) {
	for framework, pattern := range d.frameworkPatterns {
		matches := pattern.FindAllString(content, -1)
		if len(matches) > 0 {
			detected := DetectedFramework{
				Name:       framework,
				SourceFile: filePath,
				Imports:    d.uniqueStrings(matches),
				Confidence: d.calculateConfidence(content, framework),
			}

			// Check if this is an ML pipeline (training script).
			detected.IsMLPipeline = d.isMLPipeline(content)

			result.Frameworks = append(result.Frameworks, detected)
		}
	}
}

// calculateConfidence calculates detection confidence based on content analysis.
// Uses pre-compiled regex patterns for performance.
func (d *Detector) calculateConfidence(content string, framework Framework) float64 {
	confidence := 0.5 // Base confidence for import detection.

	// Use pre-compiled patterns from detector.
	patterns, ok := d.confidencePatterns[framework]
	if ok {
		for _, p := range patterns {
			if p.MatchString(content) {
				confidence += 0.1
			}
		}
	}

	// Cap at 1.0.
	if confidence > 1.0 {
		confidence = 1.0
	}

	return confidence
}

// isMLPipeline checks if content appears to be an ML training pipeline.
// Uses pre-compiled regex patterns for performance.
func (d *Detector) isMLPipeline(content string) bool {
	matches := 0
	for _, indicator := range d.pipelineIndicators {
		if indicator.MatchString(content) {
			matches++
		}
	}

	return matches >= 3
}

// scanForModels scans for model files in the directory.
func (d *Detector) scanForModels(ctx context.Context, rootPath string, result *DetectionResult) error {
	return d.walkDirectory(ctx, rootPath, func(path string, isDir bool, size int64) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		if isDir {
			// Check for TensorFlow SavedModel directory.
			if d.isSavedModelDir(path) {
				model := DetectedModel{
					Path:      path,
					Name:      filepath.Base(path),
					Type:      ModelTypeSavedModel,
					Framework: FrameworkTensorFlow,
					SizeBytes: size,
				}
				result.Models = append(result.Models, model)
			}
			return nil
		}

		ext := strings.ToLower(filepath.Ext(path))
		modelType, isModel := d.modelExtensions[ext]
		if !isModel {
			return nil
		}

		model := DetectedModel{
			Path:      path,
			Name:      filepath.Base(path),
			Type:      modelType,
			Framework: d.inferFramework(modelType),
			SizeBytes: size,
		}

		// Try to extract metadata for certain formats.
		if metadata := d.extractMetadata(path, modelType); metadata != nil {
			model.Metadata = metadata
		}

		result.Models = append(result.Models, model)
		return nil
	})
}

// isSavedModelDir checks if a directory is a TensorFlow SavedModel.
func (d *Detector) isSavedModelDir(dirPath string) bool {
	// SavedModel directories contain saved_model.pb or saved_model.pbtxt.
	sp, err := safepath.New(dirPath)
	if err != nil {
		return false
	}

	entries, err := sp.ReadDir(".")
	if err != nil {
		return false
	}

	for _, entry := range entries {
		name := entry.Name()
		if name == "saved_model.pb" || name == "saved_model.pbtxt" {
			return true
		}
	}
	return false
}

// inferFramework infers the framework from model type.
func (d *Detector) inferFramework(modelType ModelType) Framework {
	switch modelType {
	case ModelTypeH5, ModelTypeSavedModel:
		return FrameworkTensorFlow
	case ModelTypePTH:
		return FrameworkPyTorch
	case ModelTypePickle:
		return FrameworkScikit // Could also be other frameworks.
	case ModelTypeONNX:
		return FrameworkONNX
	case ModelTypeSafetensors:
		return FrameworkHuggingFace
	default:
		return FrameworkUnknown
	}
}

// extractMetadata extracts metadata from model files.
func (d *Detector) extractMetadata(path string, modelType ModelType) map[string]interface{} {
	// For now, return basic file info.
	// More sophisticated metadata extraction can be added later.
	return map[string]interface{}{
		"model_type": string(modelType),
		"path":       path,
	}
}

// walkDirectory walks a directory tree using safepath.
func (d *Detector) walkDirectory(ctx context.Context, rootPath string, fn func(path string, isDir bool, size int64) error) error {
	sp, err := safepath.New(rootPath)
	if err != nil {
		return fmt.Errorf("create safepath: %w", err)
	}

	return d.walkRecursive(ctx, sp, rootPath, "", 0, fn)
}

// walkRecursive recursively walks directories with depth tracking.
func (d *Detector) walkRecursive(ctx context.Context, sp *safepath.SafePath, rootPath, relativePath string, depth int, fn func(path string, isDir bool, size int64) error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}

	// Check depth limit - stop scanning this branch but don't fail.
	if d.config.MaxDepth > 0 && depth > d.config.MaxDepth {
		return nil
	}

	// Check file count limit - stop scanning but don't fail.
	if d.config.MaxFilesToScan > 0 && d.filesScanned >= d.config.MaxFilesToScan {
		return nil
	}

	dirToRead := "."
	if relativePath != "" {
		dirToRead = relativePath
	}

	entries, readErr := sp.ReadDir(dirToRead)
	if readErr != nil {
		// Skip unreadable directories silently.
		return nil //nolint:nilerr // Intentionally skipping unreadable directories.
	}

	for _, entry := range entries {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		// Check file count limit for each iteration - stop scanning but don't fail.
		if d.config.MaxFilesToScan > 0 && d.filesScanned >= d.config.MaxFilesToScan {
			return nil
		}

		name := entry.Name()
		// Skip hidden files and common non-essential directories.
		if strings.HasPrefix(name, ".") || name == "node_modules" || name == "__pycache__" || name == "venv" || name == ".git" {
			continue
		}

		var entryPath string
		if relativePath == "" {
			entryPath = name
		} else {
			entryPath = filepath.Join(relativePath, name)
		}
		fullPath := filepath.Join(rootPath, entryPath)

		info, infoErr := entry.Info()
		var size int64
		if infoErr == nil {
			size = info.Size()
		}

		// Check file size limit for non-directories.
		if !entry.IsDir() && d.config.MaxFileSize > 0 && size > d.config.MaxFileSize {
			// Skip files that exceed size limit, but don't fail.
			continue
		}

		// Increment file counter for non-directories.
		if !entry.IsDir() {
			d.filesScanned++
		}

		if err := fn(fullPath, entry.IsDir(), size); err != nil {
			return err
		}

		if entry.IsDir() {
			if err := d.walkRecursive(ctx, sp, rootPath, entryPath, depth+1, fn); err != nil {
				return err
			}
		}
	}

	return nil
}

// readFile reads a file using safepath.
func (d *Detector) readFile(path string) ([]byte, error) {
	dir := filepath.Dir(path)
	filename := filepath.Base(path)

	sp, err := safepath.New(dir)
	if err != nil {
		return nil, fmt.Errorf("create safepath: %w", err)
	}

	return sp.ReadFile(filename)
}

// notebookCell represents a cell in a Jupyter notebook.
type notebookCell struct {
	CellType string   `json:"cell_type"`
	Source   []string `json:"source"`
}

// notebook represents a Jupyter notebook structure.
type notebook struct {
	Cells []notebookCell `json:"cells"`
}

// parseNotebook parses a Jupyter notebook and extracts code from code cells.
func (d *Detector) parseNotebook(path string) (string, error) {
	data, err := d.readFile(path)
	if err != nil {
		return "", fmt.Errorf("read notebook: %w", err)
	}

	var nb notebook
	if err := json.Unmarshal(data, &nb); err != nil {
		return "", fmt.Errorf("parse notebook JSON: %w", err)
	}

	var codeBuilder strings.Builder
	for _, cell := range nb.Cells {
		// Only process code cells, skip markdown, raw cells.
		if cell.CellType != "code" {
			continue
		}

		// Source is an array of lines.
		for _, line := range cell.Source {
			codeBuilder.WriteString(line)
		}
		codeBuilder.WriteString("\n")
	}

	return codeBuilder.String(), nil
}

// uniqueStrings returns unique strings from a slice.
func (d *Detector) uniqueStrings(items []string) []string {
	seen := make(map[string]bool)
	result := make([]string, 0, len(items))

	for _, item := range items {
		if !seen[item] {
			seen[item] = true
			result = append(result, item)
		}
	}

	return result
}

// DetectFromRequirements detects frameworks from requirements.txt.
func (d *Detector) DetectFromRequirements(ctx context.Context, path string) ([]DetectedFramework, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	content, err := d.readFile(path)
	if err != nil {
		return nil, fmt.Errorf("read requirements: %w", err)
	}

	frameworks := make([]DetectedFramework, 0)
	lines := strings.Split(string(content), "\n")

	packageFrameworks := map[string]Framework{
		"tensorflow":   FrameworkTensorFlow,
		"keras":        FrameworkTensorFlow,
		"torch":        FrameworkPyTorch,
		"torchvision":  FrameworkPyTorch,
		"scikit-learn": FrameworkScikit,
		"sklearn":      FrameworkScikit,
		"onnx":         FrameworkONNX,
		"onnxruntime":  FrameworkONNX,
		"transformers": FrameworkHuggingFace,
		"xgboost":      FrameworkXGBoost,
		"lightgbm":     FrameworkLightGBM,
	}

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Parse package name and version.
		parts := regexp.MustCompile(`[<>=!~\[]`).Split(line, 2)
		pkgName := strings.ToLower(strings.TrimSpace(parts[0]))

		if framework, ok := packageFrameworks[pkgName]; ok {
			version := ""
			if len(parts) > 1 {
				version = strings.TrimSpace(parts[1])
			}

			frameworks = append(frameworks, DetectedFramework{
				Name:       framework,
				Version:    version,
				SourceFile: path,
				Confidence: 1.0,
			})
		}
	}

	return frameworks, nil
}

// ToJSON converts detection result to JSON.
func (r *DetectionResult) ToJSON() ([]byte, error) {
	return json.MarshalIndent(r, "", "  ")
}

// Summary returns a summary of detection results.
func (r *DetectionResult) Summary() string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("Detected %d framework(s) and %d model file(s)\n", len(r.Frameworks), len(r.Models)))

	if len(r.Frameworks) > 0 {
		sb.WriteString("\nFrameworks:\n")
		seen := make(map[Framework]bool)
		for _, f := range r.Frameworks {
			if !seen[f.Name] {
				seen[f.Name] = true
				sb.WriteString(fmt.Sprintf("  - %s (confidence: %.0f%%)\n", f.Name, f.Confidence*100))
			}
		}
	}

	if len(r.Models) > 0 {
		sb.WriteString("\nModel Files:\n")
		for _, m := range r.Models {
			sb.WriteString(fmt.Sprintf("  - %s (%s, %s)\n", m.Name, m.Type, m.Framework))
		}
	}

	if len(r.Errors) > 0 {
		sb.WriteString(fmt.Sprintf("\nErrors: %d\n", len(r.Errors)))
	}

	return sb.String()
}
