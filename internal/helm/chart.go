package helm

import (
	"context"
	"strings"

	"helm.sh/helm/v3/pkg/action"
	"helm.sh/helm/v3/pkg/chart"
	"helm.sh/helm/v3/pkg/chart/loader"
	"helm.sh/helm/v3/pkg/chartutil"
	"helm.sh/helm/v3/pkg/cli"
)

// defaultChartClient implements ChartClient.
type defaultChartClient struct {
	settings *cli.EnvSettings
}

// Get retrieves chart metadata.
func (c *defaultChartClient) Get(ctx context.Context, chartRef string) (*ChartInfo, error) {
	if ctx == nil {
		return nil, ErrNilContext
	}
	if chartRef == "" {
		return nil, ErrEmptyChartRef
	}

	// Load the chart.
	ch, err := c.loadChart(chartRef)
	if err != nil {
		return nil, err
	}

	return mapChartToInfo(ch), nil
}

// Validate validates chart structure.
func (c *defaultChartClient) Validate(ctx context.Context, chartPath string) error {
	if ctx == nil {
		return ErrNilContext
	}
	if chartPath == "" {
		return ErrEmptyChartRef
	}

	// Load the chart to validate its structure.
	ch, err := c.loadChart(chartPath)
	if err != nil {
		return err
	}

	// Validate the chart using chartutil.
	if err := ch.Validate(); err != nil {
		return NewHelmError("validate chart", "", "", ErrChartInvalid)
	}

	return nil
}

// Template renders chart templates without installing.
func (c *defaultChartClient) Template(ctx context.Context, name, chartRef string, values map[string]interface{}) (string, error) {
	if ctx == nil {
		return "", ErrNilContext
	}
	if name == "" {
		return "", ErrEmptyReleaseName
	}
	if chartRef == "" {
		return "", ErrEmptyChartRef
	}

	// Load the chart.
	ch, err := c.loadChart(chartRef)
	if err != nil {
		return "", err
	}

	// Create action configuration for templating.
	actionConfig := new(action.Configuration)

	// Create install action for templating (dry run).
	install := action.NewInstall(actionConfig)
	install.DryRun = true
	install.ReleaseName = name
	install.Replace = true
	install.ClientOnly = true
	install.IncludeCRDs = false

	// Merge values with chart defaults.
	chartValues := ch.Values
	if values != nil {
		chartValues = mergeMaps(chartValues, values)
	}

	// Run the install (which in dry-run mode just renders templates).
	rel, err := install.Run(ch, chartValues)
	if err != nil {
		return "", NewHelmError("template chart", "", name, err)
	}

	return rel.Manifest, nil
}

// loadChart loads a chart from a path or reference.
func (c *defaultChartClient) loadChart(chartRef string) (*chart.Chart, error) {
	// Try to load as a local path first.
	ch, err := loader.Load(chartRef)
	if err != nil {
		// Check if it's a chart not found error.
		if isChartNotFoundError(err) {
			return nil, NewHelmError("load chart", "", "", ErrChartNotFound)
		}
		return nil, NewHelmError("load chart", "", "", ErrChartLoadFailed)
	}

	return ch, nil
}

// mapChartToInfo converts a Helm chart to ChartInfo.
func mapChartToInfo(ch *chart.Chart) *ChartInfo {
	if ch == nil || ch.Metadata == nil {
		return &ChartInfo{}
	}

	meta := ch.Metadata
	return &ChartInfo{
		Name:        meta.Name,
		Version:     meta.Version,
		AppVersion:  meta.AppVersion,
		Description: meta.Description,
		Home:        meta.Home,
		Icon:        meta.Icon,
		Deprecated:  meta.Deprecated,
	}
}

// isChartNotFoundError checks if the error indicates chart not found.
func isChartNotFoundError(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	return strings.Contains(errStr, "not found") ||
		strings.Contains(errStr, "no such file") ||
		strings.Contains(errStr, "does not exist")
}

// RenderValues renders template values for a chart.
func RenderValues(ch *chart.Chart, values map[string]interface{}) (chartutil.Values, error) {
	options := chartutil.ReleaseOptions{
		Name:      "release-name",
		Namespace: "default",
		IsInstall: true,
	}

	caps := chartutil.DefaultCapabilities

	return chartutil.ToRenderValues(ch, values, options, caps)
}

// GetChartDependencies returns the dependencies of a chart.
func GetChartDependencies(ch *chart.Chart) []ChartInfo {
	if ch == nil || ch.Metadata == nil || len(ch.Metadata.Dependencies) == 0 {
		return nil
	}

	deps := make([]ChartInfo, 0, len(ch.Metadata.Dependencies))
	for _, dep := range ch.Metadata.Dependencies {
		deps = append(deps, ChartInfo{
			Name:    dep.Name,
			Version: dep.Version,
		})
	}

	return deps
}

// PackageChart packages a chart into a .tgz archive.
func PackageChart(chartPath, destination string) (string, error) {
	ch, err := loader.Load(chartPath)
	if err != nil {
		return "", NewHelmError("package chart", "", "", ErrChartLoadFailed)
	}

	if validateErr := ch.Validate(); validateErr != nil {
		return "", NewHelmError("validate chart", "", "", ErrChartInvalid)
	}

	name, err := chartutil.Save(ch, destination)
	if err != nil {
		return "", NewHelmError("save chart", "", "", err)
	}

	return name, nil
}
