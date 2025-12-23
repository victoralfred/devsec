// Package ml provides ML-specific validation and detection capabilities.
package ml

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"

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

// Resource limits to prevent DoS and memory exhaustion.
const (
	// MaxCacheEntries is the maximum number of cache entries to prevent unbounded growth.
	MaxCacheEntries = 10000
	// MaxFrameworks is the maximum number of frameworks that can be detected.
	MaxFrameworks = 1000
	// MaxModels is the maximum number of models that can be detected.
	MaxModels = 5000
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
	CellNumber   int       `json:"cell_number,omitempty"` // 0 for non-notebook files, 1-indexed for notebooks
	IsMLPipeline bool      `json:"is_ml_pipeline"`
}

// CellImport tracks an import statement with its cell location.
type CellImport struct {
	Import     string `json:"import"`
	CellNumber int    `json:"cell_number"` // 1-indexed cell number
	LineInCell int    `json:"line_in_cell"`
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
	ExcludePatterns        []string      `json:"exclude_patterns,omitempty"`
	FileTimeout            time.Duration `json:"file_timeout"`
	MaxFileSize            int64         `json:"max_file_size"`
	MaxFilesToScan         int           `json:"max_files_to_scan"`
	MaxDepth               int           `json:"max_depth"`
	WorkerCount            int           `json:"worker_count"`
	EnableCache            bool          `json:"enable_cache"`
	EnableHashVerification bool          `json:"enable_hash_verification"`
}

// CacheEntry represents a cached file detection result.
// Fields ordered for optimal memory alignment.
type CacheEntry struct {
	ModTime    time.Time           `json:"mod_time"`
	Frameworks []DetectedFramework `json:"frameworks,omitempty"`
	Models     []DetectedModel     `json:"models,omitempty"`
	Size       int64               `json:"size"`
}

// DefaultDetectorConfig returns the default detector configuration.
func DefaultDetectorConfig() DetectorConfig {
	workerCount := runtime.NumCPU()
	if workerCount < 2 {
		workerCount = 2
	}
	if workerCount > 8 {
		workerCount = 8
	}

	return DetectorConfig{
		MaxFileSize:            10 * 1024 * 1024, // 10 MB
		MaxDepth:               50,
		MaxFilesToScan:         10000,
		WorkerCount:            workerCount,
		FileTimeout:            5 * time.Second, // Per-file processing timeout
		EnableCache:            true,
		EnableHashVerification: true, // Calculate SHA256 hashes for model files
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
	cache              sync.Map // map[string]*CacheEntry
	frameworkPatterns  map[Framework]*regexp.Regexp
	confidencePatterns map[Framework][]*regexp.Regexp
	pipelineIndicators []*regexp.Regexp
	modelExtensions    map[string]ModelType
	config             DetectorConfig
	filesScanned       int
	filesScannedMu     sync.RWMutex // Protects filesScanned from race conditions
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

// fileContext creates a context with per-file timeout if configured.
// Returns the context and a cancel function that must be called.
func (d *Detector) fileContext(parent context.Context) (context.Context, context.CancelFunc) {
	if d.config.FileTimeout > 0 {
		return context.WithTimeout(parent, d.config.FileTimeout)
	}
	return parent, func() {} // No-op cancel function
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
	d.filesScannedMu.Lock()
	d.filesScanned = 0
	d.filesScannedMu.Unlock()

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

		// Check for Jupyter notebook with per-file timeout and cell tracking.
		if ext == ".ipynb" {
			fileCtx, cancel := d.fileContext(ctx)
			nbResult, err := d.parseNotebookWithCellsContext(fileCtx, path)
			cancel()
			if err != nil {
				if fileCtx.Err() == context.DeadlineExceeded {
					result.Errors = append(result.Errors, fmt.Sprintf("timeout parsing notebook %s", path))
				} else {
					result.Errors = append(result.Errors, fmt.Sprintf("parse notebook %s: %v", path, err))
				}
				return nil
			}
			if nbResult != nil && nbResult.Code != "" {
				d.detectFrameworksInNotebook(nbResult, path, result)
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

		// Read file content with per-file timeout.
		fileCtx, cancel := d.fileContext(ctx)
		content, err := d.readFileWithContext(fileCtx, path)
		cancel()
		if err != nil {
			if fileCtx.Err() == context.DeadlineExceeded {
				result.Errors = append(result.Errors, fmt.Sprintf("timeout reading %s", path))
			} else {
				result.Errors = append(result.Errors, fmt.Sprintf("read %s: %v", path, err))
			}
			return nil
		}

		// Detect frameworks.
		d.detectFrameworksInContent(string(content), path, result)
		return nil
	})
}

// detectFrameworksInContent detects ML frameworks in file content.
func (d *Detector) detectFrameworksInContent(content, filePath string, result *DetectionResult) {
	// Check limit to prevent DoS.
	if len(result.Frameworks) >= MaxFrameworks {
		return
	}

	for framework, pattern := range d.frameworkPatterns {
		// Check limit in loop to prevent exceeding.
		if len(result.Frameworks) >= MaxFrameworks {
			break
		}

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

// detectFrameworksInNotebookResult detects frameworks with cell tracking and returns them.
func (d *Detector) detectFrameworksInNotebookResult(nbResult *NotebookParseResult, filePath string) []DetectedFramework {
	// Group imports by framework and cell.
	//nolint:govet // Local struct with minimal allocations.
	type cellFramework struct {
		imports    []string
		framework  Framework
		cellNumber int
	}

	cellFrameworks := make(map[string]*cellFramework) // key: "framework:cell"

	for _, ci := range nbResult.CellImports {
		for framework, pattern := range d.frameworkPatterns {
			if pattern.MatchString(ci.Import) {
				key := fmt.Sprintf("%s:%d", framework, ci.CellNumber)
				if cf, exists := cellFrameworks[key]; exists {
					cf.imports = append(cf.imports, ci.Import)
				} else {
					cellFrameworks[key] = &cellFramework{
						framework:  framework,
						cellNumber: ci.CellNumber,
						imports:    []string{ci.Import},
					}
				}
			}
		}
	}

	// Create DetectedFramework for each cell-framework combination.
	result := make([]DetectedFramework, 0, len(cellFrameworks))
	for _, cf := range cellFrameworks {
		detected := DetectedFramework{
			Name:         cf.framework,
			SourceFile:   filePath,
			Imports:      d.uniqueStrings(cf.imports),
			CellNumber:   cf.cellNumber,
			Confidence:   d.calculateConfidence(nbResult.Code, cf.framework),
			IsMLPipeline: d.isMLPipeline(nbResult.Code),
		}
		result = append(result, detected)
	}

	return result
}

// detectFrameworksInNotebook detects frameworks with cell tracking for notebooks.
func (d *Detector) detectFrameworksInNotebook(nbResult *NotebookParseResult, filePath string, result *DetectionResult) {
	frameworks := d.detectFrameworksInNotebookResult(nbResult, filePath)
	// Check limit to prevent DoS.
	remaining := MaxFrameworks - len(result.Frameworks)
	if remaining > 0 && len(frameworks) > remaining {
		frameworks = frameworks[:remaining]
	}
	result.Frameworks = append(result.Frameworks, frameworks...)
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

		// Check limit to prevent DoS.
		if len(result.Models) >= MaxModels {
			return nil
		}

		model := DetectedModel{
			Path:      path,
			Name:      filepath.Base(path),
			Type:      modelType,
			Framework: d.inferFramework(modelType),
			SizeBytes: size,
		}

		// Try to extract metadata for certain formats with per-file timeout.
		fileCtx, cancel := d.fileContext(ctx)
		if metadata := d.extractMetadataWithContext(fileCtx, path, modelType); metadata != nil {
			model.Metadata = metadata
		}
		cancel()

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

// calculateSHA256 calculates the SHA256 hash of data and returns it as a hex string.
func calculateSHA256(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

// VerifyModelHash verifies that a model file matches an expected SHA256 hash.
// Returns true if the hash matches, false otherwise.
func (d *Detector) VerifyModelHash(path, expectedHash string) (bool, error) {
	data, err := d.readFile(path)
	if err != nil {
		return false, fmt.Errorf("read file: %w", err)
	}

	actualHash := calculateSHA256(data)
	return actualHash == expectedHash, nil
}

// GetModelHash calculates and returns the SHA256 hash of a model file.
func (d *Detector) GetModelHash(path string) (string, error) {
	data, err := d.readFile(path)
	if err != nil {
		return "", fmt.Errorf("read file: %w", err)
	}

	return calculateSHA256(data), nil
}

// extractMetadata extracts metadata from model files.
func (d *Detector) extractMetadata(path string, modelType ModelType) map[string]interface{} {
	metadata := map[string]interface{}{
		"model_type": string(modelType),
		"path":       path,
	}

	// Read file header for format-specific metadata.
	data, err := d.readFile(path)
	if err != nil {
		return metadata
	}

	// Limit data read for metadata extraction.
	const maxHeaderSize = 4096
	headerData := data
	if len(data) > maxHeaderSize {
		headerData = data[:maxHeaderSize]
	}

	metadata["file_size"] = len(data)

	// Calculate SHA256 hash if enabled.
	if d.config.EnableHashVerification {
		metadata["sha256"] = calculateSHA256(data)
	}

	switch modelType {
	case ModelTypeH5:
		d.extractH5Metadata(headerData, metadata)
	case ModelTypePTH:
		d.extractPyTorchMetadata(headerData, metadata)
	case ModelTypeONNX:
		d.extractONNXMetadata(headerData, metadata)
	case ModelTypePickle:
		d.extractPickleMetadata(headerData, metadata)
	case ModelTypeSafetensors:
		d.extractSafetensorsMetadata(headerData, metadata)
	}

	return metadata
}

// extractMetadataWithContext extracts metadata with context timeout support.
func (d *Detector) extractMetadataWithContext(ctx context.Context, path string, modelType ModelType) map[string]interface{} {
	if ctx.Err() != nil {
		return nil
	}

	metadata := map[string]interface{}{
		"model_type": string(modelType),
		"path":       path,
	}

	// Read file header with context timeout.
	data, err := d.readFileWithContext(ctx, path)
	if err != nil {
		return metadata
	}

	// Check context after file read.
	if ctx.Err() != nil {
		return metadata
	}

	// Limit data read for metadata extraction.
	const maxHeaderSize = 4096
	headerData := data
	if len(data) > maxHeaderSize {
		headerData = data[:maxHeaderSize]
	}

	metadata["file_size"] = len(data)

	// Calculate SHA256 hash if enabled.
	if d.config.EnableHashVerification {
		metadata["sha256"] = calculateSHA256(data)
	}

	switch modelType {
	case ModelTypeH5:
		d.extractH5Metadata(headerData, metadata)
	case ModelTypePTH:
		d.extractPyTorchMetadata(headerData, metadata)
	case ModelTypeONNX:
		d.extractONNXMetadata(headerData, metadata)
	case ModelTypePickle:
		d.extractPickleMetadata(headerData, metadata)
	case ModelTypeSafetensors:
		d.extractSafetensorsMetadata(headerData, metadata)
	}

	return metadata
}

// extractH5Metadata extracts metadata from HDF5/Keras model files.
func (d *Detector) extractH5Metadata(data []byte, metadata map[string]interface{}) {
	if len(data) < 8 {
		return
	}

	// HDF5 magic bytes: 0x89 0x48 0x44 0x46 0x0d 0x0a 0x1a 0x0a
	h5Magic := []byte{0x89, 0x48, 0x44, 0x46, 0x0d, 0x0a, 0x1a, 0x0a}
	if len(data) >= 8 && bytes.Equal(data[:8], h5Magic) {
		metadata["format"] = "HDF5"
		metadata["is_valid_hdf5"] = true

		// Parse HDF5 superblock for version info.
		d.extractH5SuperblockInfo(data, metadata)
	} else {
		metadata["is_valid_hdf5"] = false
	}
}

// extractH5SuperblockInfo extracts info from HDF5 superblock.
func (d *Detector) extractH5SuperblockInfo(data []byte, metadata map[string]interface{}) {
	if len(data) < 16 {
		return
	}

	// After 8-byte signature, superblock starts.
	// Byte 8: superblock version (0, 1, 2, or 3).
	superblockVersion := int(data[8])
	metadata["superblock_version"] = superblockVersion

	// Parse based on superblock version.
	switch superblockVersion {
	case 0, 1:
		// Version 0/1 superblock layout.
		if len(data) >= 13 {
			// Byte 9: Free-space storage version.
			// Byte 10: Root group symbol table entry version.
			// Byte 11: Reserved (zero).
			// Byte 12: Shared header message format version.
			metadata["free_space_version"] = int(data[9])
			metadata["root_group_version"] = int(data[10])

			if len(data) >= 14 {
				// Byte 13: Size of offsets.
				metadata["offset_size"] = int(data[13])
			}
			if len(data) >= 15 {
				// Byte 14: Size of lengths.
				metadata["length_size"] = int(data[14])
			}
		}

	case 2, 3:
		// Version 2/3 superblock layout (more compact).
		if len(data) >= 10 {
			// Byte 9: Size of offsets.
			metadata["offset_size"] = int(data[9])
		}
		if len(data) >= 11 {
			// Byte 10: Size of lengths.
			metadata["length_size"] = int(data[10])
		}
	}

	// Try to detect Keras model by looking for common attribute names.
	d.detectKerasModelHints(data, metadata)
}

// detectKerasModelHints tries to identify Keras-specific content in HDF5.
func (d *Detector) detectKerasModelHints(data []byte, metadata map[string]interface{}) {
	// Search for common Keras strings in the file.
	kerasHints := []string{
		"keras_version",
		"model_config",
		"model_weights",
		"optimizer_weights",
		"training_config",
		"backend",
	}

	foundHints := make([]string, 0)
	dataStr := string(data)

	for _, hint := range kerasHints {
		if strings.Contains(dataStr, hint) {
			foundHints = append(foundHints, hint)
		}
	}

	if len(foundHints) > 0 {
		metadata["keras_hints"] = foundHints
		metadata["is_keras_model"] = true

		// Try to extract keras version if present.
		if idx := strings.Index(dataStr, "keras_version"); idx != -1 {
			// Look for version string nearby (format varies).
			searchArea := dataStr[idx:min(idx+100, len(dataStr))]
			// Common version patterns.
			for _, prefix := range []string{"2.", "3."} {
				if vIdx := strings.Index(searchArea, prefix); vIdx != -1 {
					// Extract version-like string.
					end := vIdx + 1
					for end < len(searchArea) && (searchArea[end] == '.' || (searchArea[end] >= '0' && searchArea[end] <= '9')) {
						end++
					}
					if end > vIdx+2 {
						metadata["keras_version_hint"] = searchArea[vIdx:end]
						break
					}
				}
			}
		}
	}
}

// extractPyTorchMetadata extracts metadata from PyTorch model files.
func (d *Detector) extractPyTorchMetadata(data []byte, metadata map[string]interface{}) {
	if len(data) < 2 {
		return
	}

	// Check for ZIP archive (PyTorch >= 1.6 uses ZIP format).
	if len(data) >= 4 && data[0] == 0x50 && data[1] == 0x4b && data[2] == 0x03 && data[3] == 0x04 {
		metadata["format"] = "PyTorch ZIP archive"
		metadata["pytorch_version"] = ">=1.6"

		// Parse ZIP to extract more details.
		d.extractPyTorchZIPDetails(data, metadata)
	} else if len(data) >= 2 && data[0] == 0x80 {
		// Pickle protocol marker.
		protocol := int(data[1])
		metadata["format"] = "PyTorch pickle"
		metadata["pickle_protocol"] = protocol
		if protocol >= 4 {
			metadata["pytorch_version"] = ">=1.0"
		}
	}
}

// extractPyTorchZIPDetails extracts detailed info from PyTorch ZIP archives.
func (d *Detector) extractPyTorchZIPDetails(data []byte, metadata map[string]interface{}) {
	reader := bytes.NewReader(data)
	zipReader, err := zip.NewReader(reader, int64(len(data)))
	if err != nil {
		return
	}

	files := make([]string, 0, len(zipReader.File))
	var hasDataPkl, hasVersion, hasModelPy, hasConstants bool
	var tensorCount int

	for _, f := range zipReader.File {
		name := f.Name
		files = append(files, name)

		// Check for known PyTorch archive files.
		baseName := filepath.Base(name)
		switch {
		case baseName == "data.pkl":
			hasDataPkl = true
		case baseName == "version":
			hasVersion = true
			// Try to read version.
			if rc, openErr := f.Open(); openErr == nil {
				versionData := make([]byte, 32)
				n, readErr := rc.Read(versionData)
				// Accept EOF for short version files.
				if n > 0 && (readErr == nil || readErr.Error() == "EOF") {
					version := strings.TrimSpace(string(versionData[:n]))
					if version != "" {
						metadata["pytorch_archive_version"] = version
					}
				}
				_ = rc.Close()
			}
		case baseName == "model.py":
			hasModelPy = true
		case baseName == "constants.pkl":
			hasConstants = true
		case strings.HasSuffix(name, ".storage"):
			tensorCount++
		}
	}

	metadata["archive_files"] = files
	metadata["has_data_pkl"] = hasDataPkl
	metadata["has_version"] = hasVersion
	metadata["has_model_py"] = hasModelPy
	metadata["has_constants"] = hasConstants
	metadata["tensor_storage_count"] = tensorCount

	// Infer model type based on archive structure.
	if hasModelPy {
		metadata["model_type_hint"] = "TorchScript"
	} else if hasDataPkl {
		metadata["model_type_hint"] = "state_dict or full model"
	}
}

// extractONNXMetadata extracts metadata from ONNX model files.
func (d *Detector) extractONNXMetadata(data []byte, metadata map[string]interface{}) {
	if len(data) < 10 {
		return
	}

	// ONNX files are protobuf format.
	// ModelProto fields (from onnx.proto):
	// 1: ir_version (int64)
	// 2: producer_name (string)
	// 3: producer_version (string)
	// 4: domain (string)
	// 5: model_version (int64)
	// 6: doc_string (string)
	// 8: opset_import (repeated OpSetId)

	metadata["format"] = "ONNX protobuf"

	// Parse protobuf fields.
	pos := 0
	for pos < len(data) && pos < 4096 { // Limit parsing to first 4KB
		if pos >= len(data) {
			break
		}

		// Read field tag (varint).
		fieldTag, n := d.readVarint(data[pos:])
		if n == 0 {
			break
		}
		pos += n

		fieldNumber := fieldTag >> 3
		wireType := fieldTag & 0x7

		switch wireType {
		case 0: // Varint
			value, vn := d.readVarint(data[pos:])
			if vn == 0 {
				return
			}
			pos += vn

			switch fieldNumber {
			case 1:
				metadata["ir_version"] = value
			case 5:
				metadata["model_version"] = value
			}

		case 2: // Length-delimited
			length, ln := d.readVarint(data[pos:])
			if ln == 0 {
				return
			}
			pos += ln

			if pos+int(length) > len(data) {
				return
			}

			strData := data[pos : pos+int(length)]
			pos += int(length)

			switch fieldNumber {
			case 2:
				if isValidUTF8(strData) {
					metadata["producer_name"] = string(strData)
				}
			case 3:
				if isValidUTF8(strData) {
					metadata["producer_version"] = string(strData)
				}
			case 4:
				if isValidUTF8(strData) {
					metadata["domain"] = string(strData)
				}
			case 6:
				if isValidUTF8(strData) && len(strData) < 500 {
					metadata["doc_string"] = string(strData)
				}
			case 8:
				// opset_import - parse nested message for opset version.
				d.parseONNXOpsetImport(strData, metadata)
			}

		default:
			// Skip unknown wire types.
			return
		}
	}
}

// parseONNXOpsetImport parses an OpSetId message from ONNX.
func (d *Detector) parseONNXOpsetImport(data []byte, metadata map[string]interface{}) {
	// OpSetId fields:
	// 1: domain (string)
	// 2: version (int64)

	pos := 0
	var domain string
	var version int64

	for pos < len(data) {
		fieldTag, n := d.readVarint(data[pos:])
		if n == 0 {
			break
		}
		pos += n

		fieldNumber := fieldTag >> 3
		wireType := fieldTag & 0x7

		switch wireType {
		case 0: // Varint
			value, vn := d.readVarint(data[pos:])
			if vn == 0 {
				return
			}
			pos += vn

			if fieldNumber == 2 {
				version = value
			}

		case 2: // Length-delimited
			length, ln := d.readVarint(data[pos:])
			if ln == 0 {
				return
			}
			pos += ln

			if pos+int(length) > len(data) {
				return
			}

			if fieldNumber == 1 {
				domain = string(data[pos : pos+int(length)])
			}
			pos += int(length)

		default:
			return
		}
	}

	// Store opset info.
	if domain == "" || domain == "ai.onnx" {
		metadata["opset_version"] = version
	}
	if domain != "" && domain != "ai.onnx" {
		if existing, ok := metadata["custom_domains"].([]string); ok {
			metadata["custom_domains"] = append(existing, domain)
		} else {
			metadata["custom_domains"] = []string{domain}
		}
	}
}

// readVarint reads a protobuf varint from data.
func (d *Detector) readVarint(data []byte) (value int64, bytesRead int) {
	if len(data) == 0 {
		return 0, 0
	}

	var result int64
	var shift uint

	for i := 0; i < len(data) && i < 10; i++ {
		b := data[i]
		result |= int64(b&0x7F) << shift
		if b < 0x80 {
			return result, i + 1
		}
		shift += 7
	}

	return 0, 0
}

// isValidUTF8 checks if data is valid UTF-8 and printable.
func isValidUTF8(data []byte) bool {
	for _, b := range data {
		if b < 0x20 && b != '\n' && b != '\r' && b != '\t' {
			return false
		}
	}
	return true
}

// extractPickleMetadata extracts metadata from pickle files.
func (d *Detector) extractPickleMetadata(data []byte, metadata map[string]interface{}) {
	if len(data) < 2 {
		return
	}

	// Check pickle protocol.
	switch data[0] {
	case 0x80:
		protocol := int(data[1])
		metadata["pickle_protocol"] = protocol
		metadata["format"] = "Python pickle"
	case '(', ']', '}':
		// Protocol 0 (ASCII).
		metadata["pickle_protocol"] = 0
		metadata["format"] = "Python pickle (ASCII)"
	}
}

// extractSafetensorsMetadata extracts metadata from safetensors files.
func (d *Detector) extractSafetensorsMetadata(data []byte, metadata map[string]interface{}) {
	if len(data) < 8 {
		return
	}

	// Safetensors format: 8-byte header size (little-endian) followed by JSON header.
	headerSize := uint64(data[0]) |
		uint64(data[1])<<8 |
		uint64(data[2])<<16 |
		uint64(data[3])<<24 |
		uint64(data[4])<<32 |
		uint64(data[5])<<40 |
		uint64(data[6])<<48 |
		uint64(data[7])<<56

	metadata["format"] = "safetensors"

	// Validate header size is reasonable and fits in int.
	dataLen := uint64(len(data))
	const maxHeaderSize = 1 << 30 // 1GB max header, reasonable limit.
	if headerSize > 0 && headerSize < maxHeaderSize && headerSize < dataLen-8 {
		metadata["header_size"] = headerSize
		// Try to parse JSON header for tensor count.
		// Safe conversion since we validated headerSize < maxHeaderSize.
		headerEnd := 8 + int(headerSize) //nolint:gosec // headerSize validated above.
		if headerEnd <= len(data) {
			headerJSON := string(data[8:headerEnd])
			tensorCount := strings.Count(headerJSON, "\"dtype\"")
			if tensorCount > 0 {
				metadata["tensor_count"] = tensorCount
			}
		}
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
	d.filesScannedMu.RLock()
	filesScanned := d.filesScanned
	d.filesScannedMu.RUnlock()
	if d.config.MaxFilesToScan > 0 && filesScanned >= d.config.MaxFilesToScan {
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
		d.filesScannedMu.RLock()
		filesScanned = d.filesScanned
		d.filesScannedMu.RUnlock()
		if d.config.MaxFilesToScan > 0 && filesScanned >= d.config.MaxFilesToScan {
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
			d.filesScannedMu.Lock()
			d.filesScanned++
			d.filesScannedMu.Unlock()
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

// readFileWithContext reads a file with context timeout support.
func (d *Detector) readFileWithContext(ctx context.Context, path string) ([]byte, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	// Perform the file read. Since file I/O is blocking, we check context
	// before starting. For very large files, the caller's context timeout
	// provides the actual deadline enforcement.
	return d.readFile(path)
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

// NotebookParseResult contains cell-aware parsing results.
type NotebookParseResult struct {
	Code        string       // Concatenated code from all cells
	CellImports []CellImport // Imports with cell locations
	CellCount   int          // Total number of code cells
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
	codeBuilder.Grow(4096) // Pre-allocate capacity for notebook code
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

// parseNotebookWithContext parses a notebook with context timeout support.
func (d *Detector) parseNotebookWithContext(ctx context.Context, path string) (string, error) {
	if ctx.Err() != nil {
		return "", ctx.Err()
	}

	// Read file with context check.
	data, err := d.readFileWithContext(ctx, path)
	if err != nil {
		return "", fmt.Errorf("read notebook: %w", err)
	}

	// Check context before parsing.
	if ctx.Err() != nil {
		return "", ctx.Err()
	}

	var nb notebook
	if err := json.Unmarshal(data, &nb); err != nil {
		return "", fmt.Errorf("parse notebook JSON: %w", err)
	}

	var codeBuilder strings.Builder
	codeBuilder.Grow(4096) // Pre-allocate capacity for notebook code
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

// parseNotebookWithCells parses a notebook and tracks cell locations for imports.
func (d *Detector) parseNotebookWithCells(path string) (*NotebookParseResult, error) {
	data, err := d.readFile(path)
	if err != nil {
		return nil, fmt.Errorf("read notebook: %w", err)
	}

	var nb notebook
	if err := json.Unmarshal(data, &nb); err != nil {
		return nil, fmt.Errorf("parse notebook JSON: %w", err)
	}

	result := &NotebookParseResult{
		CellImports: make([]CellImport, 0),
	}

	var codeBuilder strings.Builder
	codeBuilder.Grow(4096) // Pre-allocate capacity for notebook code
	codeCellIndex := 0

	for _, cell := range nb.Cells {
		// Only process code cells, skip markdown, raw cells.
		if cell.CellType != "code" {
			continue
		}

		codeCellIndex++

		// Process each line in the cell.
		for lineNum, line := range cell.Source {
			codeBuilder.WriteString(line)

			// Check for import statements.
			trimmedLine := strings.TrimSpace(line)
			if strings.HasPrefix(trimmedLine, "import ") || strings.HasPrefix(trimmedLine, "from ") {
				result.CellImports = append(result.CellImports, CellImport{
					Import:     trimmedLine,
					CellNumber: codeCellIndex,
					LineInCell: lineNum + 1, // 1-indexed
				})
			}
		}
		codeBuilder.WriteString("\n")
	}

	result.Code = codeBuilder.String()
	result.CellCount = codeCellIndex

	return result, nil
}

// parseNotebookWithCellsContext parses a notebook with context and tracks cell locations.
func (d *Detector) parseNotebookWithCellsContext(ctx context.Context, path string) (*NotebookParseResult, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	data, err := d.readFileWithContext(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("read notebook: %w", err)
	}

	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	var nb notebook
	if err := json.Unmarshal(data, &nb); err != nil {
		return nil, fmt.Errorf("parse notebook JSON: %w", err)
	}

	result := &NotebookParseResult{
		CellImports: make([]CellImport, 0),
	}

	var codeBuilder strings.Builder
	codeBuilder.Grow(4096) // Pre-allocate capacity for notebook code
	codeCellIndex := 0

	for _, cell := range nb.Cells {
		// Only process code cells, skip markdown, raw cells.
		if cell.CellType != "code" {
			continue
		}

		codeCellIndex++

		// Process each line in the cell.
		for lineNum, line := range cell.Source {
			codeBuilder.WriteString(line)

			// Check for import statements.
			trimmedLine := strings.TrimSpace(line)
			if strings.HasPrefix(trimmedLine, "import ") || strings.HasPrefix(trimmedLine, "from ") {
				result.CellImports = append(result.CellImports, CellImport{
					Import:     trimmedLine,
					CellNumber: codeCellIndex,
					LineInCell: lineNum + 1, // 1-indexed
				})
			}
		}
		codeBuilder.WriteString("\n")
	}

	result.Code = codeBuilder.String()
	result.CellCount = codeCellIndex

	return result, nil
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
	sb.Grow(512) // Pre-allocate capacity for better performance

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

// fileTask represents a file to be processed by the worker pool.
type fileTask struct {
	path  string
	isDir bool
	size  int64
}

// concurrentResult holds thread-safe detection results.
// Fields ordered for optimal memory alignment.
type concurrentResult struct {
	frameworks []DetectedFramework
	models     []DetectedModel
	errors     []string
	mu         sync.Mutex
}

func (r *concurrentResult) addFramework(f DetectedFramework) {
	r.mu.Lock()
	r.frameworks = append(r.frameworks, f)
	r.mu.Unlock()
}

func (r *concurrentResult) addModel(m DetectedModel) {
	r.mu.Lock()
	r.models = append(r.models, m)
	r.mu.Unlock()
}

func (r *concurrentResult) addError(err string) {
	r.mu.Lock()
	r.errors = append(r.errors, err)
	r.mu.Unlock()
}

// DetectConcurrent scans a directory for ML frameworks and model files using concurrent workers.
func (d *Detector) DetectConcurrent(ctx context.Context, rootPath string) (*DetectionResult, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	if rootPath == "" {
		return nil, ErrEmptyPath
	}

	// Reset file counter for each scan.
	d.filesScannedMu.Lock()
	d.filesScanned = 0
	d.filesScannedMu.Unlock()

	// Process tasks concurrently using streaming approach to avoid loading all tasks into memory.
	result := &concurrentResult{
		frameworks: make([]DetectedFramework, 0),
		models:     make([]DetectedModel, 0),
		errors:     make([]string, 0),
	}

	workerCount := d.config.WorkerCount
	if workerCount <= 0 {
		workerCount = 4
	}

	// Use buffered channel for streaming tasks (avoids loading all into memory).
	const taskBufferSize = 1000
	taskChan := make(chan fileTask, taskBufferSize)

	// Start workers that process tasks as they arrive.
	var wg sync.WaitGroup
	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			d.worker(ctx, taskChan, result)
		}()
	}

	// Stream tasks from directory walk directly to workers.
	walkErr := d.walkDirectory(ctx, rootPath, func(path string, isDir bool, size int64) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case taskChan <- fileTask{path: path, isDir: isDir, size: size}:
			return nil
		}
	})

	// Close channel and wait for workers to finish.
	close(taskChan)
	wg.Wait()

	if walkErr != nil && walkErr != context.Canceled {
		result.addError(fmt.Sprintf("walk directory: %v", walkErr))
	}

	return &DetectionResult{
		Frameworks: result.frameworks,
		Models:     result.models,
		Errors:     result.errors,
	}, nil
}

// worker processes file tasks from the channel.
func (d *Detector) worker(ctx context.Context, tasks <-chan fileTask, result *concurrentResult) {
	pythonExts := map[string]bool{".py": true, ".pyx": true, ".pyw": true}

	for task := range tasks {
		if ctx.Err() != nil {
			return
		}

		if task.isDir {
			// Check for TensorFlow SavedModel directory.
			if d.isSavedModelDir(task.path) {
				// Check limit to prevent DoS.
				result.mu.Lock()
				canAdd := len(result.models) < MaxModels
				result.mu.Unlock()
				if canAdd {
					result.addModel(DetectedModel{
						Path:      task.path,
						Name:      filepath.Base(task.path),
						Type:      ModelTypeSavedModel,
						Framework: FrameworkTensorFlow,
						SizeBytes: task.size,
					})
				}
			}
			continue
		}

		ext := strings.ToLower(filepath.Ext(task.path))

		// Check for Jupyter notebook with cell tracking.
		if ext == ".ipynb" {
			nbResult, err := d.parseNotebookWithCells(task.path)
			if err != nil {
				result.addError(fmt.Sprintf("parse notebook %s: %v", task.path, err))
				continue
			}
			if nbResult != nil && nbResult.Code != "" {
				d.detectFrameworksInNotebookConcurrent(nbResult, task.path, result)
			}
			continue
		}

		// Check for Python files.
		if pythonExts[ext] {
			content, err := d.readFile(task.path)
			if err != nil {
				result.addError(fmt.Sprintf("read %s: %v", task.path, err))
				continue
			}
			d.detectFrameworksInContentConcurrent(string(content), task.path, result)
			continue
		}

		// Check for model files.
		modelType, isModel := d.modelExtensions[ext]
		if isModel {
			// Check limit to prevent DoS.
			result.mu.Lock()
			canAdd := len(result.models) < MaxModels
			result.mu.Unlock()
			if canAdd {
				model := DetectedModel{
					Path:      task.path,
					Name:      filepath.Base(task.path),
					Type:      modelType,
					Framework: d.inferFramework(modelType),
					SizeBytes: task.size,
				}

				if metadata := d.extractMetadata(task.path, modelType); metadata != nil {
					model.Metadata = metadata
				}

				result.addModel(model)
			}
		}
	}
}

// detectFrameworksInContentConcurrent detects ML frameworks and adds to concurrent result.
func (d *Detector) detectFrameworksInContentConcurrent(content, filePath string, result *concurrentResult) {
	result.mu.Lock()
	currentCount := len(result.frameworks)
	result.mu.Unlock()

	// Check limit to prevent DoS.
	if currentCount >= MaxFrameworks {
		return
	}

	for framework, pattern := range d.frameworkPatterns {
		result.mu.Lock()
		currentCount = len(result.frameworks)
		result.mu.Unlock()

		// Check limit in loop to prevent exceeding.
		if currentCount >= MaxFrameworks {
			break
		}

		matches := pattern.FindAllString(content, -1)
		if len(matches) > 0 {
			detected := DetectedFramework{
				Name:         framework,
				SourceFile:   filePath,
				Imports:      d.uniqueStrings(matches),
				Confidence:   d.calculateConfidence(content, framework),
				IsMLPipeline: d.isMLPipeline(content),
			}
			result.addFramework(detected)
		}
	}
}

// detectFrameworksInNotebookConcurrent detects ML frameworks with cell tracking for concurrent result.
func (d *Detector) detectFrameworksInNotebookConcurrent(nbResult *NotebookParseResult, filePath string, result *concurrentResult) {
	frameworks := d.detectFrameworksInNotebookResult(nbResult, filePath)

	result.mu.Lock()
	currentCount := len(result.frameworks)
	remaining := MaxFrameworks - currentCount
	result.mu.Unlock()

	// Check limit to prevent DoS.
	if remaining > 0 && len(frameworks) > remaining {
		frameworks = frameworks[:remaining]
	}

	for _, fw := range frameworks {
		result.addFramework(fw)
	}
}

// GetCacheEntry retrieves a cached entry for a file path.
// Returns nil if not found or if cache is disabled.
func (d *Detector) GetCacheEntry(path string) *CacheEntry {
	if !d.config.EnableCache {
		return nil
	}

	if entry, ok := d.cache.Load(path); ok {
		if ce, valid := entry.(*CacheEntry); valid {
			return ce
		}
	}
	return nil
}

// SetCacheEntry stores a cache entry for a file path.
func (d *Detector) SetCacheEntry(path string, entry *CacheEntry) {
	if !d.config.EnableCache {
		return
	}

	// Check cache size and evict oldest entry if needed.
	if d.CacheSize() >= MaxCacheEntries {
		d.evictOldestCacheEntry()
	}

	d.cache.Store(path, entry)
}

// IsCacheValid checks if a cache entry is still valid for the given file.
func (d *Detector) IsCacheValid(path string, entry *CacheEntry) bool {
	if entry == nil {
		return false
	}

	// Use safepath instead of os.Stat for compliance.
	dir := filepath.Dir(path)
	filename := filepath.Base(path)
	sp, err := safepath.New(dir)
	if err != nil {
		return false
	}

	info, err := sp.Stat(filename)
	if err != nil {
		return false
	}

	// Cache is valid if file modification time and size match.
	return info.ModTime().Equal(entry.ModTime) && info.Size() == entry.Size
}

// ClearCache clears all cached entries.
func (d *Detector) ClearCache() {
	d.cache.Range(func(key, _ interface{}) bool {
		d.cache.Delete(key)
		return true
	})
}

// CacheSize returns the number of entries in the cache.
func (d *Detector) CacheSize() int {
	count := 0
	d.cache.Range(func(_, _ interface{}) bool {
		count++
		return true
	})
	return count
}

// evictOldestCacheEntry removes the oldest cache entry to make room for new ones.
// This is a simple FIFO eviction strategy.
func (d *Detector) evictOldestCacheEntry() {
	var oldestKey interface{}
	var oldestTime time.Time
	first := true

	d.cache.Range(func(key, value interface{}) bool {
		if entry, ok := value.(*CacheEntry); ok {
			if first || entry.ModTime.Before(oldestTime) {
				oldestKey = key
				oldestTime = entry.ModTime
				first = false
			}
		}
		return true
	})

	if oldestKey != nil {
		d.cache.Delete(oldestKey)
	}
}

// DetectWithCache detects ML frameworks and model files, using cache when possible.
func (d *Detector) DetectWithCache(ctx context.Context, rootPath string) (*DetectionResult, error) {
	if rootPath == "" {
		return nil, ErrEmptyPath
	}

	absPath, err := filepath.Abs(rootPath)
	if err != nil {
		return nil, fmt.Errorf("resolve path: %w", err)
	}

	result := &DetectionResult{
		Frameworks: make([]DetectedFramework, 0),
		Models:     make([]DetectedModel, 0),
		Errors:     make([]string, 0),
	}

	d.filesScannedMu.Lock()
	d.filesScanned = 0
	d.filesScannedMu.Unlock()

	walkErr := d.walkDirectory(ctx, absPath, func(path string, isDir bool, size int64) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		if isDir {
			// Check for TensorFlow SavedModel.
			if filepath.Base(path) == "saved_model.pb" {
				// Check limit to prevent DoS.
				if len(result.Models) < MaxModels {
					result.Models = append(result.Models, DetectedModel{
						Path:      filepath.Dir(path),
						Name:      "saved_model",
						Type:      ModelTypeSavedModel,
						Framework: FrameworkTensorFlow,
					})
				}
			}
			return nil
		}

		ext := strings.ToLower(filepath.Ext(path))

		// Check for model files.
		if modelType, ok := d.modelExtensions[ext]; ok {
			// Check limit to prevent DoS.
			if len(result.Models) >= MaxModels {
				return nil
			}

			// Use safepath instead of os.Stat for compliance.
			dir := filepath.Dir(path)
			filename := filepath.Base(path)
			sp, spErr := safepath.New(dir)
			if spErr == nil {
				info, statErr := sp.Stat(filename)
				if statErr == nil {
					result.Models = append(result.Models, DetectedModel{
						Path:      path,
						Name:      filepath.Base(path),
						Type:      modelType,
						Framework: d.inferFramework(modelType),
						SizeBytes: info.Size(),
						Metadata:  d.extractMetadata(path, modelType),
					})
				}
			}
		}

		// Check for Python files using cache.
		if ext == ".py" || ext == ".pyx" || ext == ".pyw" || ext == ".ipynb" {
			// Try to use cache.
			if d.config.EnableCache {
				if cached := d.GetCacheEntry(path); cached != nil && d.IsCacheValid(path, cached) {
					result.Frameworks = append(result.Frameworks, cached.Frameworks...)
					return nil
				}
			}

			var detectedFrameworks []DetectedFramework

			if ext == ".ipynb" {
				// Use cell-aware parsing for notebooks.
				nbResult, readErr := d.parseNotebookWithCells(path)
				if readErr != nil {
					result.Errors = append(result.Errors, fmt.Sprintf("read %s: %v", path, readErr))
					return nil
				}

				detectedFrameworks = d.detectFrameworksInNotebookResult(nbResult, path)
			} else {
				data, readErr := d.readFile(path)
				if readErr != nil {
					result.Errors = append(result.Errors, fmt.Sprintf("read %s: %v", path, readErr))
					return nil
				}
				content := string(data)

				detectedFrameworks = make([]DetectedFramework, 0, 8) // Pre-allocate for common frameworks
				for framework, pattern := range d.frameworkPatterns {
					// Check limit to prevent DoS.
					if len(detectedFrameworks) >= MaxFrameworks {
						break
					}

					matches := pattern.FindAllString(content, -1)
					if len(matches) > 0 {
						detected := DetectedFramework{
							Name:         framework,
							SourceFile:   path,
							Imports:      d.uniqueStrings(matches),
							Confidence:   d.calculateConfidence(content, framework),
							IsMLPipeline: d.isMLPipeline(content),
						}
						detectedFrameworks = append(detectedFrameworks, detected)
					}
				}
			}

			result.Frameworks = append(result.Frameworks, detectedFrameworks...)

			// Cache the result.
			if d.config.EnableCache && len(detectedFrameworks) > 0 {
				// Use safepath instead of os.Stat for compliance.
				dir := filepath.Dir(path)
				filename := filepath.Base(path)
				sp, spErr := safepath.New(dir)
				if spErr == nil {
					info, statErr := sp.Stat(filename)
					if statErr == nil {
						d.SetCacheEntry(path, &CacheEntry{
							Frameworks: detectedFrameworks,
							ModTime:    info.ModTime(),
							Size:       info.Size(),
						})
					}
				}
			}
		}

		return nil
	})

	if walkErr != nil && walkErr != context.Canceled {
		result.Errors = append(result.Errors, walkErr.Error())
	}

	return result, nil
}
