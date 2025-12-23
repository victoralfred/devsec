package helm

import (
	"context"
	"path/filepath"
	"strings"

	"github.com/victoralfred/gowritter/safepath"
	"helm.sh/helm/v3/pkg/action"
	"sigs.k8s.io/yaml"
)

// defaultValuesClient implements ValuesClient.
type defaultValuesClient struct {
	actionConfig *action.Configuration
}

// Get retrieves current values for a release.
func (v *defaultValuesClient) Get(ctx context.Context, namespace, release string) (map[string]interface{}, error) {
	if ctx == nil {
		return nil, ErrNilContext
	}
	if namespace == "" {
		return nil, ErrEmptyNamespace
	}
	if release == "" {
		return nil, ErrEmptyReleaseName
	}

	getValues := action.NewGetValues(v.actionConfig)
	getValues.AllValues = true

	values, err := getValues.Run(release)
	if err != nil {
		if isReleaseNotFoundError(err) {
			return nil, NewHelmError("get values", namespace, release, ErrReleaseNotFound)
		}
		return nil, NewHelmError("get values", namespace, release, err)
	}

	return values, nil
}

// Merge merges multiple value sources with later sources taking precedence.
func (v *defaultValuesClient) Merge(base map[string]interface{}, overlays ...map[string]interface{}) map[string]interface{} {
	result := copyMap(base)

	for _, overlay := range overlays {
		result = mergeMaps(result, overlay)
	}

	return result
}

// LoadFromFile loads values from a YAML file using safepath.
func (v *defaultValuesClient) LoadFromFile(ctx context.Context, path string) (map[string]interface{}, error) {
	if ctx == nil {
		return nil, ErrNilContext
	}
	if path == "" {
		return nil, ErrValuesLoadFailed
	}

	// Use safepath for secure file access.
	dir := filepath.Dir(path)
	filename := filepath.Base(path)

	sp, err := safepath.New(dir)
	if err != nil {
		return nil, NewHelmError("load values", "", "", ErrValuesLoadFailed)
	}

	data, err := sp.ReadFile(filename)
	if err != nil {
		return nil, NewHelmError("load values", "", "", ErrValuesLoadFailed)
	}

	var values map[string]interface{}
	if err := yaml.Unmarshal(data, &values); err != nil {
		return nil, NewHelmError("parse values", "", "", ErrValuesLoadFailed)
	}

	return values, nil
}

// copyMap creates a shallow copy of a map.
func copyMap(src map[string]interface{}) map[string]interface{} {
	if src == nil {
		return make(map[string]interface{})
	}

	dst := make(map[string]interface{}, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

// mergeMaps recursively merges src into dst.
func mergeMaps(dst, src map[string]interface{}) map[string]interface{} {
	if dst == nil {
		dst = make(map[string]interface{})
	}

	for key, srcVal := range src {
		if dstVal, exists := dst[key]; exists {
			// If both are maps, merge recursively.
			srcMap, srcIsMap := srcVal.(map[string]interface{})
			dstMap, dstIsMap := dstVal.(map[string]interface{})
			if srcIsMap && dstIsMap {
				dst[key] = mergeMaps(dstMap, srcMap)
				continue
			}
		}
		// Otherwise, replace with source value.
		dst[key] = srcVal
	}

	return dst
}

// isReleaseNotFoundError checks if the error indicates release not found.
func isReleaseNotFoundError(err error) bool {
	if err == nil {
		return false
	}
	// Helm returns a specific error message pattern for release not found.
	errStr := err.Error()
	return strings.Contains(errStr, "not found") || strings.Contains(errStr, "release: not found")
}
