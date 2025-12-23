// Package ml provides ML-specific validation and detection capabilities.
package ml

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/nlpodyssey/gopickle/pickle"
	"github.com/nlpodyssey/gopickle/pytorch"
	"github.com/nlpodyssey/gopickle/types"
	"github.com/scigolib/hdf5"
)

// KerasModelConfig represents parsed Keras model configuration.
type KerasModelConfig struct {
	ClassName   string           `json:"class_name"`
	Config      map[string]any   `json:"config"`
	Layers      []KerasLayerInfo `json:"layers,omitempty"`
	Optimizer   *OptimizerConfig `json:"optimizer,omitempty"`
	LossConfig  *LossConfig      `json:"loss,omitempty"`
	Metrics     []string         `json:"metrics,omitempty"`
	ModelName   string           `json:"model_name,omitempty"`
	KerasVer    string           `json:"keras_version,omitempty"`
	TFVersion   string           `json:"tensorflow_version,omitempty"`
	InputShape  []int            `json:"input_shape,omitempty"`
	OutputShape []int            `json:"output_shape,omitempty"`
}

// KerasLayerInfo contains information about a Keras layer.
type KerasLayerInfo struct {
	Config     map[string]any `json:"config,omitempty"`
	Name       string         `json:"name"`
	ClassName  string         `json:"class_name"`
	Activation string         `json:"activation,omitempty"`
	InputShape []int          `json:"input_shape,omitempty"`
	Units      int            `json:"units,omitempty"`
	Trainable  bool           `json:"trainable"`
}

// OptimizerConfig contains optimizer configuration.
type OptimizerConfig struct {
	ClassName    string  `json:"class_name"`
	LearningRate float64 `json:"learning_rate,omitempty"`
	Momentum     float64 `json:"momentum,omitempty"`
	Beta1        float64 `json:"beta_1,omitempty"`
	Beta2        float64 `json:"beta_2,omitempty"`
	Epsilon      float64 `json:"epsilon,omitempty"`
	Decay        float64 `json:"decay,omitempty"`
}

// LossConfig contains loss function configuration.
type LossConfig struct {
	Config    map[string]any `json:"config,omitempty"`
	ClassName string         `json:"class_name"`
}

// PyTorchModelInfo contains information about a PyTorch model.
//
//nolint:govet // Struct field order optimized for JSON serialization readability.
type PyTorchModelInfo struct {
	StateDictKeys []string          `json:"state_dict_keys,omitempty"`
	LayerNames    []string          `json:"layer_names,omitempty"`
	Buffers       []string          `json:"buffers,omitempty"`
	TensorShapes  map[string][]int  `json:"tensor_shapes,omitempty"`
	Parameters    map[string]string `json:"parameters,omitempty"`
	ModelType     string            `json:"model_type,omitempty"`
	Format        string            `json:"format"`
	PyTorchVer    string            `json:"pytorch_version,omitempty"`
	TensorCount   int               `json:"tensor_count"`
}

// ExtractKerasMetadata extracts full metadata from a Keras HDF5 model file.
func ExtractKerasMetadata(filePath string) (*KerasModelConfig, error) {
	file, err := hdf5.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("open hdf5 file: %w", err)
	}
	defer func() { _ = file.Close() }()

	config := &KerasModelConfig{}

	// Walk the file to find model configuration and weights.
	file.Walk(func(path string, obj hdf5.Object) {
		switch v := obj.(type) {
		case *hdf5.Group:
			// Check for model_config attribute in root group.
			if path == "/" {
				extractRootAttributes(v, config)
			}
			// Check for layer groups.
			if strings.HasPrefix(path, "/model_weights/") || strings.HasPrefix(path, "/layers/") {
				extractLayerInfo(v, path, config)
			}
		case *hdf5.Dataset:
			// Check for optimizer weights.
			if strings.Contains(path, "optimizer_weights") {
				extractOptimizerInfo(v, path, config)
			}
		}
	})

	return config, nil
}

// extractRootAttributes extracts model configuration from root group attributes.
func extractRootAttributes(group *hdf5.Group, config *KerasModelConfig) {
	attrs, err := group.Attributes()
	if err != nil {
		return
	}
	for _, attr := range attrs {
		name := attr.Name
		value, readErr := attr.ReadValue()
		if readErr != nil {
			continue
		}
		switch name {
		case "model_config":
			parseModelConfig(value, config)
		case "keras_version":
			if s, ok := attrToString(value); ok {
				config.KerasVer = s
			}
		case "backend":
			// TensorFlow backend info.
			if s, ok := attrToString(value); ok && s == "tensorflow" {
				config.TFVersion = "tensorflow"
			}
		case "training_config":
			parseTrainingConfig(value, config)
		}
	}
}

// parseModelConfig parses the model_config JSON attribute.
func parseModelConfig(attr any, config *KerasModelConfig) {
	jsonStr, ok := attrToString(attr)
	if !ok {
		return
	}

	var modelCfg map[string]any
	if err := json.Unmarshal([]byte(jsonStr), &modelCfg); err != nil {
		return
	}

	if className, ok := modelCfg["class_name"].(string); ok {
		config.ClassName = className
	}

	if cfg, ok := modelCfg["config"].(map[string]any); ok {
		config.Config = cfg
		if name, ok := cfg["name"].(string); ok {
			config.ModelName = name
		}
		// Extract layers from config.
		if layers, ok := cfg["layers"].([]any); ok {
			for _, layer := range layers {
				if layerMap, ok := layer.(map[string]any); ok {
					info := parseLayerMap(layerMap)
					config.Layers = append(config.Layers, info)
				}
			}
		}
	}
}

// parseLayerMap parses a single layer configuration map.
func parseLayerMap(layerMap map[string]any) KerasLayerInfo {
	info := KerasLayerInfo{
		Trainable: true, // Default.
	}

	if className, ok := layerMap["class_name"].(string); ok {
		info.ClassName = className
	}

	if cfg, ok := layerMap["config"].(map[string]any); ok {
		info.Config = cfg
		if name, ok := cfg["name"].(string); ok {
			info.Name = name
		}
		if units, ok := cfg["units"].(float64); ok {
			info.Units = int(units)
		}
		if activation, ok := cfg["activation"].(string); ok {
			info.Activation = activation
		}
		if trainable, ok := cfg["trainable"].(bool); ok {
			info.Trainable = trainable
		}
	}

	return info
}

// parseTrainingConfig parses the training_config JSON attribute.
func parseTrainingConfig(attr any, config *KerasModelConfig) {
	jsonStr, ok := attrToString(attr)
	if !ok {
		return
	}

	var trainingCfg map[string]any
	if err := json.Unmarshal([]byte(jsonStr), &trainingCfg); err != nil {
		return
	}

	// Extract optimizer.
	if optCfg, ok := trainingCfg["optimizer_config"].(map[string]any); ok {
		config.Optimizer = parseOptimizerConfig(optCfg)
	}

	// Extract loss.
	switch loss := trainingCfg["loss"].(type) {
	case map[string]any:
		config.LossConfig = &LossConfig{
			Config: loss,
		}
		if className, ok := loss["class_name"].(string); ok {
			config.LossConfig.ClassName = className
		}
	case string:
		config.LossConfig = &LossConfig{
			ClassName: loss,
		}
	}

	// Extract metrics.
	if metrics, ok := trainingCfg["metrics"].([]any); ok {
		for _, m := range metrics {
			switch metric := m.(type) {
			case string:
				config.Metrics = append(config.Metrics, metric)
			case map[string]any:
				if className, ok := metric["class_name"].(string); ok {
					config.Metrics = append(config.Metrics, className)
				}
			}
		}
	}
}

// parseOptimizerConfig parses optimizer configuration.
func parseOptimizerConfig(optCfg map[string]any) *OptimizerConfig {
	opt := &OptimizerConfig{}

	if className, ok := optCfg["class_name"].(string); ok {
		opt.ClassName = className
	}

	if cfg, ok := optCfg["config"].(map[string]any); ok {
		if lr, ok := cfg["learning_rate"].(float64); ok {
			opt.LearningRate = lr
		}
		if momentum, ok := cfg["momentum"].(float64); ok {
			opt.Momentum = momentum
		}
		if beta1, ok := cfg["beta_1"].(float64); ok {
			opt.Beta1 = beta1
		}
		if beta2, ok := cfg["beta_2"].(float64); ok {
			opt.Beta2 = beta2
		}
		if epsilon, ok := cfg["epsilon"].(float64); ok {
			opt.Epsilon = epsilon
		}
		if decay, ok := cfg["decay"].(float64); ok {
			opt.Decay = decay
		}
	}

	return opt
}

// extractLayerInfo extracts layer information from a group.
func extractLayerInfo(_ *hdf5.Group, path string, config *KerasModelConfig) {
	// Extract layer name from path.
	parts := strings.Split(path, "/")
	if len(parts) > 0 {
		layerName := parts[len(parts)-1]
		// Check if this layer is already in the config.
		for i := range config.Layers {
			if config.Layers[i].Name == layerName {
				// Layer already exists from model_config.
				return
			}
		}
		// Add basic layer info from weights structure.
		config.Layers = append(config.Layers, KerasLayerInfo{
			Name:      layerName,
			Trainable: true,
		})
	}
}

// extractOptimizerInfo extracts optimizer information from a dataset.
func extractOptimizerInfo(_ *hdf5.Dataset, path string, config *KerasModelConfig) {
	if config.Optimizer == nil {
		config.Optimizer = &OptimizerConfig{}
	}
	// Extract optimizer type from path if possible.
	switch {
	case strings.Contains(path, "Adam"):
		config.Optimizer.ClassName = "Adam"
	case strings.Contains(path, "SGD"):
		config.Optimizer.ClassName = "SGD"
	case strings.Contains(path, "RMSprop"):
		config.Optimizer.ClassName = "RMSprop"
	}
}

// attrToString converts an HDF5 attribute value to string.
func attrToString(attr any) (string, bool) {
	switch v := attr.(type) {
	case string:
		return v, true
	case []byte:
		return string(v), true
	case []string:
		if len(v) > 0 {
			return v[0], true
		}
	}
	return "", false
}

// ExtractPyTorchMetadata extracts full metadata from a PyTorch model file.
func ExtractPyTorchMetadata(filePath string) (*PyTorchModelInfo, error) {
	info := &PyTorchModelInfo{
		TensorShapes: make(map[string][]int),
		Parameters:   make(map[string]string),
	}

	// Try to load as a PyTorch module first.
	model, err := pytorch.Load(filePath)
	if err == nil {
		return extractFromPyTorchModel(model, info)
	}

	// Fall back to raw pickle loading.
	data, err := pickle.Load(filePath)
	if err != nil {
		return nil, fmt.Errorf("load pickle: %w", err)
	}

	return extractFromPickleData(data, info)
}

// extractFromPyTorchModel extracts metadata from a loaded PyTorch model.
func extractFromPyTorchModel(model any, info *PyTorchModelInfo) (*PyTorchModelInfo, error) {
	info.Format = "PyTorch ZIP archive"

	// Handle different return types from pytorch.Load.
	switch v := model.(type) {
	case *types.Dict:
		return extractFromDict(v, info)
	case *types.OrderedDict:
		return extractFromOrderedDict(v, info)
	case map[string]any:
		return extractFromMap(v, info)
	default:
		// Try to extract tensors from the model.
		extractTensorsFromAny(model, "", info)
	}

	sort.Strings(info.StateDictKeys)
	info.TensorCount = len(info.StateDictKeys)

	return info, nil
}

// extractFromDict extracts metadata from a gopickle Dict.
func extractFromDict(d *types.Dict, info *PyTorchModelInfo) (*PyTorchModelInfo, error) {
	layerSet := make(map[string]struct{})

	for _, entry := range *d {
		key, ok := entry.Key.(string)
		if !ok {
			continue
		}
		info.StateDictKeys = append(info.StateDictKeys, key)

		// Check if value is a tensor.
		if tensor, ok := entry.Value.(*pytorch.Tensor); ok {
			info.TensorShapes[key] = tensor.Size
		}

		// Extract layer name.
		layerName := extractLayerName(key)
		if layerName != "" {
			layerSet[layerName] = struct{}{}
		}

		// Categorize parameter type.
		categorizeParameter(key, info)
	}

	for layer := range layerSet {
		info.LayerNames = append(info.LayerNames, layer)
	}

	sort.Strings(info.StateDictKeys)
	sort.Strings(info.LayerNames)
	info.TensorCount = len(info.StateDictKeys)
	info.ModelType = inferModelType(info.LayerNames)

	return info, nil
}

// extractFromOrderedDict extracts metadata from a gopickle OrderedDict.
func extractFromOrderedDict(d *types.OrderedDict, info *PyTorchModelInfo) (*PyTorchModelInfo, error) {
	layerSet := make(map[string]struct{})

	for _, entry := range d.Map {
		key, ok := entry.Key.(string)
		if !ok {
			continue
		}
		info.StateDictKeys = append(info.StateDictKeys, key)

		// Check if value is a tensor.
		if tensor, ok := entry.Value.(*pytorch.Tensor); ok {
			info.TensorShapes[key] = tensor.Size
		}

		// Extract layer name.
		layerName := extractLayerName(key)
		if layerName != "" {
			layerSet[layerName] = struct{}{}
		}

		// Categorize parameter type.
		categorizeParameter(key, info)
	}

	for layer := range layerSet {
		info.LayerNames = append(info.LayerNames, layer)
	}

	sort.Strings(info.StateDictKeys)
	sort.Strings(info.LayerNames)
	info.TensorCount = len(info.StateDictKeys)
	info.ModelType = inferModelType(info.LayerNames)

	return info, nil
}

// extractFromMap extracts metadata from a map.
func extractFromMap(m map[string]any, info *PyTorchModelInfo) (*PyTorchModelInfo, error) {
	layerSet := make(map[string]struct{})

	for key, value := range m {
		info.StateDictKeys = append(info.StateDictKeys, key)

		// Check if value is a tensor.
		if tensor, ok := value.(*pytorch.Tensor); ok {
			info.TensorShapes[key] = tensor.Size
		}

		// Extract layer name.
		layerName := extractLayerName(key)
		if layerName != "" {
			layerSet[layerName] = struct{}{}
		}

		// Categorize parameter type.
		categorizeParameter(key, info)
	}

	for layer := range layerSet {
		info.LayerNames = append(info.LayerNames, layer)
	}

	sort.Strings(info.StateDictKeys)
	sort.Strings(info.LayerNames)
	info.TensorCount = len(info.StateDictKeys)
	info.ModelType = inferModelType(info.LayerNames)

	return info, nil
}

// extractTensorsFromAny recursively extracts tensor information from any type.
func extractTensorsFromAny(v any, prefix string, info *PyTorchModelInfo) {
	switch val := v.(type) {
	case *pytorch.Tensor:
		key := prefix
		if key == "" {
			key = "tensor"
		}
		info.StateDictKeys = append(info.StateDictKeys, key)
		info.TensorShapes[key] = val.Size
	case *types.Dict:
		for _, entry := range *val {
			if key, ok := entry.Key.(string); ok {
				newPrefix := key
				if prefix != "" {
					newPrefix = prefix + "." + key
				}
				extractTensorsFromAny(entry.Value, newPrefix, info)
			}
		}
	case *types.OrderedDict:
		for _, entry := range val.Map {
			if key, ok := entry.Key.(string); ok {
				newPrefix := key
				if prefix != "" {
					newPrefix = prefix + "." + key
				}
				extractTensorsFromAny(entry.Value, newPrefix, info)
			}
		}
	case map[string]any:
		for key, value := range val {
			newPrefix := key
			if prefix != "" {
				newPrefix = prefix + "." + key
			}
			extractTensorsFromAny(value, newPrefix, info)
		}
	}
}

// categorizeParameter categorizes a parameter key.
func categorizeParameter(key string, info *PyTorchModelInfo) {
	switch {
	case strings.HasSuffix(key, ".weight"):
		info.Parameters[key] = "weight"
	case strings.HasSuffix(key, ".bias"):
		info.Parameters[key] = "bias"
	case strings.Contains(key, "running_mean"), strings.Contains(key, "running_var"):
		info.Buffers = append(info.Buffers, key)
	}
}

// extractFromPickleData extracts metadata from raw pickle data.
func extractFromPickleData(data any, info *PyTorchModelInfo) (*PyTorchModelInfo, error) {
	info.Format = "Python pickle"

	// Try to extract state_dict keys.
	switch v := data.(type) {
	case *types.Dict:
		return extractFromDict(v, info)
	case map[string]any:
		return extractFromMap(v, info)
	case *types.OrderedDict:
		return extractFromOrderedDict(v, info)
	}

	return info, nil
}

// extractLayerName extracts the layer name from a parameter key.
func extractLayerName(key string) string {
	// Remove common suffixes.
	suffixes := []string{".weight", ".bias", ".running_mean", ".running_var", ".num_batches_tracked"}
	for _, suffix := range suffixes {
		key = strings.TrimSuffix(key, suffix)
	}
	return key
}

// inferModelType infers the model architecture type from layer names.
func inferModelType(layerNames []string) string {
	for _, name := range layerNames {
		lower := strings.ToLower(name)
		switch {
		case strings.Contains(lower, "transformer"):
			return "Transformer"
		case strings.Contains(lower, "bert"):
			return "BERT"
		case strings.Contains(lower, "gpt"):
			return "GPT"
		case strings.Contains(lower, "resnet"):
			return "ResNet"
		case strings.Contains(lower, "vgg"):
			return "VGG"
		case strings.Contains(lower, "inception"):
			return "Inception"
		case strings.Contains(lower, "efficientnet"):
			return "EfficientNet"
		case strings.Contains(lower, "mobilenet"):
			return "MobileNet"
		case strings.Contains(lower, "densenet"):
			return "DenseNet"
		case strings.Contains(lower, "lstm"):
			return "LSTM"
		case strings.Contains(lower, "gru"):
			return "GRU"
		case strings.Contains(lower, "conv"):
			return "CNN"
		case strings.Contains(lower, "linear") || strings.Contains(lower, "fc"):
			return "MLP"
		}
	}
	return "Unknown"
}

// ExtractModelMetadataToMap converts metadata to a map for integration with existing code.
func ExtractModelMetadataToMap(filePath string, modelType ModelType) map[string]any {
	result := make(map[string]any)

	switch modelType {
	case ModelTypeH5:
		kerasCfg, err := ExtractKerasMetadata(filePath)
		if err == nil && kerasCfg != nil {
			result["keras_class"] = kerasCfg.ClassName
			result["keras_version"] = kerasCfg.KerasVer
			result["model_name"] = kerasCfg.ModelName
			result["layer_count"] = len(kerasCfg.Layers)

			if len(kerasCfg.Layers) > 0 {
				layerNames := make([]string, 0, len(kerasCfg.Layers))
				layerTypes := make([]string, 0, len(kerasCfg.Layers))
				for _, l := range kerasCfg.Layers {
					layerNames = append(layerNames, l.Name)
					layerTypes = append(layerTypes, l.ClassName)
				}
				result["layer_names"] = layerNames
				result["layer_types"] = layerTypes
			}

			if kerasCfg.Optimizer != nil {
				result["optimizer"] = kerasCfg.Optimizer.ClassName
				result["learning_rate"] = kerasCfg.Optimizer.LearningRate
			}

			if kerasCfg.LossConfig != nil {
				result["loss_function"] = kerasCfg.LossConfig.ClassName
			}

			if len(kerasCfg.Metrics) > 0 {
				result["metrics"] = kerasCfg.Metrics
			}
		}

	case ModelTypePTH:
		pytorchInfo, err := ExtractPyTorchMetadata(filePath)
		if err == nil && pytorchInfo != nil {
			result["format"] = pytorchInfo.Format
			result["tensor_count"] = pytorchInfo.TensorCount
			result["model_type"] = pytorchInfo.ModelType

			if len(pytorchInfo.StateDictKeys) > 0 {
				result["state_dict_keys"] = pytorchInfo.StateDictKeys
			}

			if len(pytorchInfo.LayerNames) > 0 {
				result["layer_names"] = pytorchInfo.LayerNames
			}

			if len(pytorchInfo.TensorShapes) > 0 {
				result["tensor_shapes"] = pytorchInfo.TensorShapes
			}

			if len(pytorchInfo.Buffers) > 0 {
				result["buffers"] = pytorchInfo.Buffers
			}
		}
	}

	return result
}
