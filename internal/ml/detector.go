// Package ml provides ML-specific validation and detection capabilities.
package ml

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
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

		// Check for Jupyter notebook with per-file timeout.
		if ext == ".ipynb" {
			fileCtx, cancel := d.fileContext(ctx)
			content, err := d.parseNotebookWithContext(fileCtx, path)
			cancel()
			if err != nil {
				if fileCtx.Err() == context.DeadlineExceeded {
					result.Errors = append(result.Errors, fmt.Sprintf("timeout parsing notebook %s", path))
				} else {
					result.Errors = append(result.Errors, fmt.Sprintf("parse notebook %s: %v", path, err))
				}
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
	if len(data) >= 8 && bytesEqual(data[:8], h5Magic) {
		metadata["format"] = "HDF5"
		metadata["is_valid_hdf5"] = true
	} else {
		metadata["is_valid_hdf5"] = false
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

// extractONNXMetadata extracts metadata from ONNX model files.
func (d *Detector) extractONNXMetadata(data []byte, metadata map[string]interface{}) {
	if len(data) < 10 {
		return
	}

	// ONNX files are protobuf format.
	// Check for protobuf wire type (field 1, type 2 = length-delimited for ir_version).
	if data[0] == 0x08 {
		metadata["format"] = "ONNX protobuf"
		// Try to extract IR version (varint after field tag).
		if len(data) > 1 {
			irVersion := int(data[1])
			if irVersion > 0 && irVersion < 20 {
				metadata["ir_version"] = irVersion
			}
		}
	}
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
			tensorCount := countOccurrences(headerJSON, "\"dtype\"")
			if tensorCount > 0 {
				metadata["tensor_count"] = tensorCount
			}
		}
	}
}

// bytesEqual compares two byte slices for equality.
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// countOccurrences counts the number of times a substring appears in a string.
func countOccurrences(s, substr string) int {
	count := 0
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			count++
		}
	}
	return count
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
	d.filesScanned = 0

	// Collect all file tasks.
	tasks := make([]fileTask, 0, 1000)
	if err := d.collectFileTasks(ctx, rootPath, &tasks); err != nil {
		return nil, fmt.Errorf("collect file tasks: %w", err)
	}

	// Process tasks concurrently.
	result := &concurrentResult{
		frameworks: make([]DetectedFramework, 0),
		models:     make([]DetectedModel, 0),
		errors:     make([]string, 0),
	}

	workerCount := d.config.WorkerCount
	if workerCount <= 0 {
		workerCount = 4
	}

	d.processTasksConcurrently(ctx, tasks, result, workerCount)

	return &DetectionResult{
		Frameworks: result.frameworks,
		Models:     result.models,
		Errors:     result.errors,
	}, nil
}

// collectFileTasks collects all file tasks from the directory tree.
func (d *Detector) collectFileTasks(ctx context.Context, rootPath string, tasks *[]fileTask) error {
	return d.walkDirectory(ctx, rootPath, func(path string, isDir bool, size int64) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		*tasks = append(*tasks, fileTask{
			path:  path,
			isDir: isDir,
			size:  size,
		})
		return nil
	})
}

// processTasksConcurrently processes file tasks using a worker pool.
func (d *Detector) processTasksConcurrently(ctx context.Context, tasks []fileTask, result *concurrentResult, workerCount int) {
	taskChan := make(chan fileTask, len(tasks))
	var wg sync.WaitGroup

	// Start workers.
	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			d.worker(ctx, taskChan, result)
		}()
	}

	// Send tasks to workers.
	for _, task := range tasks {
		select {
		case <-ctx.Done():
			close(taskChan)
			wg.Wait()
			return
		case taskChan <- task:
		}
	}
	close(taskChan)

	// Wait for all workers to complete.
	wg.Wait()
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
				result.addModel(DetectedModel{
					Path:      task.path,
					Name:      filepath.Base(task.path),
					Type:      ModelTypeSavedModel,
					Framework: FrameworkTensorFlow,
					SizeBytes: task.size,
				})
			}
			continue
		}

		ext := strings.ToLower(filepath.Ext(task.path))

		// Check for Jupyter notebook.
		if ext == ".ipynb" {
			content, err := d.parseNotebook(task.path)
			if err != nil {
				result.addError(fmt.Sprintf("parse notebook %s: %v", task.path, err))
				continue
			}
			if content != "" {
				d.detectFrameworksInContentConcurrent(content, task.path, result)
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

// detectFrameworksInContentConcurrent detects ML frameworks and adds to concurrent result.
func (d *Detector) detectFrameworksInContentConcurrent(content, filePath string, result *concurrentResult) {
	for framework, pattern := range d.frameworkPatterns {
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
	d.cache.Store(path, entry)
}

// IsCacheValid checks if a cache entry is still valid for the given file.
func (d *Detector) IsCacheValid(path string, entry *CacheEntry) bool {
	if entry == nil {
		return false
	}

	info, err := os.Stat(path)
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

	d.filesScanned = 0

	walkErr := d.walkDirectory(ctx, absPath, func(path string, isDir bool, size int64) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		if isDir {
			// Check for TensorFlow SavedModel.
			if filepath.Base(path) == "saved_model.pb" {
				result.Models = append(result.Models, DetectedModel{
					Path:      filepath.Dir(path),
					Name:      "saved_model",
					Type:      ModelTypeSavedModel,
					Framework: FrameworkTensorFlow,
				})
			}
			return nil
		}

		ext := strings.ToLower(filepath.Ext(path))

		// Check for model files.
		if modelType, ok := d.modelExtensions[ext]; ok {
			info, statErr := os.Stat(path)
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

		// Check for Python files using cache.
		if ext == ".py" || ext == ".pyx" || ext == ".pyw" || ext == ".ipynb" {
			// Try to use cache.
			if d.config.EnableCache {
				if cached := d.GetCacheEntry(path); cached != nil && d.IsCacheValid(path, cached) {
					result.Frameworks = append(result.Frameworks, cached.Frameworks...)
					return nil
				}
			}

			var content string
			var readErr error

			if ext == ".ipynb" {
				content, readErr = d.parseNotebook(path)
			} else {
				var data []byte
				data, readErr = d.readFile(path)
				content = string(data)
			}

			if readErr != nil {
				result.Errors = append(result.Errors, fmt.Sprintf("read %s: %v", path, readErr))
				return nil
			}

			detectedFrameworks := make([]DetectedFramework, 0)
			for framework, pattern := range d.frameworkPatterns {
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

			result.Frameworks = append(result.Frameworks, detectedFrameworks...)

			// Cache the result.
			if d.config.EnableCache && len(detectedFrameworks) > 0 {
				info, statErr := os.Stat(path)
				if statErr == nil {
					d.SetCacheEntry(path, &CacheEntry{
						Frameworks: detectedFrameworks,
						ModTime:    info.ModTime(),
						Size:       info.Size(),
					})
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
