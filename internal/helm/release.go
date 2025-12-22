package helm

import (
	"context"
	"time"

	"helm.sh/helm/v3/pkg/action"
	"helm.sh/helm/v3/pkg/chart/loader"
	"helm.sh/helm/v3/pkg/cli"
	"helm.sh/helm/v3/pkg/release"
)

// DefaultPollInterval is the default polling interval for wait operations.
const DefaultPollInterval = 2 * time.Second

// defaultReleaseClient implements ReleaseClient.
type defaultReleaseClient struct {
	actionConfig *action.Configuration
	settings     *cli.EnvSettings
	namespace    string
	timeout      time.Duration
}

// Install installs a Helm chart.
func (r *defaultReleaseClient) Install(ctx context.Context, name, chartRef string, opts InstallOptions) (*Release, error) {
	if ctx == nil {
		return nil, ErrNilContext
	}
	if name == "" {
		return nil, ErrEmptyReleaseName
	}
	if chartRef == "" {
		return nil, ErrEmptyChartRef
	}

	// Load the chart.
	ch, err := loader.Load(chartRef)
	if err != nil {
		if isChartNotFoundError(err) {
			return nil, NewHelmError("install", r.namespace, name, ErrChartNotFound)
		}
		return nil, NewHelmError("install", r.namespace, name, ErrChartLoadFailed)
	}

	// Create install action.
	install := action.NewInstall(r.actionConfig)
	install.ReleaseName = name
	install.Namespace = r.namespace
	install.CreateNamespace = opts.CreateNamespace
	install.Wait = opts.Wait
	install.Atomic = opts.Atomic
	install.DryRun = opts.DryRun

	if opts.Timeout > 0 {
		install.Timeout = opts.Timeout
	} else if r.timeout > 0 {
		install.Timeout = r.timeout
	}

	if opts.ChartVersion != "" {
		install.Version = opts.ChartVersion
	}

	// Run the installation.
	rel, err := install.Run(ch, opts.Values)
	if err != nil {
		if isReleaseExistsError(err) {
			return nil, NewHelmError("install", r.namespace, name, ErrReleaseExists)
		}
		return nil, NewHelmError("install", r.namespace, name, ErrInstallFailed)
	}

	return mapHelmRelease(rel), nil
}

// Upgrade upgrades an existing release.
func (r *defaultReleaseClient) Upgrade(ctx context.Context, name, chartRef string, opts UpgradeOptions) (*Release, error) {
	if ctx == nil {
		return nil, ErrNilContext
	}
	if name == "" {
		return nil, ErrEmptyReleaseName
	}
	if chartRef == "" {
		return nil, ErrEmptyChartRef
	}

	// Load the chart.
	ch, err := loader.Load(chartRef)
	if err != nil {
		if isChartNotFoundError(err) {
			return nil, NewHelmError("upgrade", r.namespace, name, ErrChartNotFound)
		}
		return nil, NewHelmError("upgrade", r.namespace, name, ErrChartLoadFailed)
	}

	// Create upgrade action.
	upgrade := action.NewUpgrade(r.actionConfig)
	upgrade.Namespace = r.namespace
	upgrade.Wait = opts.Wait
	upgrade.Atomic = opts.Atomic
	upgrade.Force = opts.Force
	upgrade.DryRun = opts.DryRun
	upgrade.ResetValues = opts.ResetValues
	upgrade.ReuseValues = opts.ReuseValues

	if opts.Timeout > 0 {
		upgrade.Timeout = opts.Timeout
	} else if r.timeout > 0 {
		upgrade.Timeout = r.timeout
	}

	if opts.ChartVersion != "" {
		upgrade.Version = opts.ChartVersion
	}

	// Run the upgrade.
	rel, err := upgrade.Run(name, ch, opts.Values)
	if err != nil {
		if isReleaseNotFoundError(err) {
			return nil, NewHelmError("upgrade", r.namespace, name, ErrReleaseNotFound)
		}
		return nil, NewHelmError("upgrade", r.namespace, name, ErrUpgradeFailed)
	}

	return mapHelmRelease(rel), nil
}

// Get retrieves release information.
func (r *defaultReleaseClient) Get(ctx context.Context, name string) (*Release, error) {
	if ctx == nil {
		return nil, ErrNilContext
	}
	if name == "" {
		return nil, ErrEmptyReleaseName
	}

	get := action.NewGet(r.actionConfig)

	rel, err := get.Run(name)
	if err != nil {
		if isReleaseNotFoundError(err) {
			return nil, NewHelmError("get", r.namespace, name, ErrReleaseNotFound)
		}
		return nil, NewHelmError("get", r.namespace, name, err)
	}

	return mapHelmRelease(rel), nil
}

// List lists releases.
func (r *defaultReleaseClient) List(ctx context.Context, opts ListOptions) ([]Release, error) {
	if ctx == nil {
		return nil, ErrNilContext
	}

	list := action.NewList(r.actionConfig)
	list.AllNamespaces = opts.AllNamespaces
	list.Deployed = opts.Deployed
	list.Failed = opts.Failed
	list.Pending = opts.Pending
	list.Uninstalled = opts.Uninstalled

	if opts.Limit > 0 {
		list.Limit = opts.Limit
	}

	releases, err := list.Run()
	if err != nil {
		return nil, NewHelmError("list", r.namespace, "", err)
	}

	result := make([]Release, 0, len(releases))
	for _, rel := range releases {
		result = append(result, *mapHelmRelease(rel))
	}

	return result, nil
}

// Uninstall removes a release.
func (r *defaultReleaseClient) Uninstall(ctx context.Context, name string) error {
	if ctx == nil {
		return ErrNilContext
	}
	if name == "" {
		return ErrEmptyReleaseName
	}

	uninstall := action.NewUninstall(r.actionConfig)

	_, err := uninstall.Run(name)
	if err != nil {
		if isReleaseNotFoundError(err) {
			return NewHelmError("uninstall", r.namespace, name, ErrReleaseNotFound)
		}
		return NewHelmError("uninstall", r.namespace, name, ErrUninstallFailed)
	}

	return nil
}

// Rollback rolls back to a previous revision.
func (r *defaultReleaseClient) Rollback(ctx context.Context, name string, revision int) error {
	if ctx == nil {
		return ErrNilContext
	}
	if name == "" {
		return ErrEmptyReleaseName
	}

	rollback := action.NewRollback(r.actionConfig)
	rollback.Version = revision

	if r.timeout > 0 {
		rollback.Timeout = r.timeout
	}

	if err := rollback.Run(name); err != nil {
		if isReleaseNotFoundError(err) {
			return NewHelmError("rollback", r.namespace, name, ErrReleaseNotFound)
		}
		if isRevisionNotFoundError(err) {
			return NewHelmError("rollback", r.namespace, name, ErrRevisionNotFound)
		}
		return NewHelmError("rollback", r.namespace, name, ErrRollbackFailed)
	}

	return nil
}

// GetHistory retrieves release history.
func (r *defaultReleaseClient) GetHistory(ctx context.Context, name string) ([]ReleaseRevision, error) {
	if ctx == nil {
		return nil, ErrNilContext
	}
	if name == "" {
		return nil, ErrEmptyReleaseName
	}

	history := action.NewHistory(r.actionConfig)
	history.Max = 256 // Get all history.

	releases, err := history.Run(name)
	if err != nil {
		if isReleaseNotFoundError(err) {
			return nil, NewHelmError("history", r.namespace, name, ErrReleaseNotFound)
		}
		return nil, NewHelmError("history", r.namespace, name, err)
	}

	result := make([]ReleaseRevision, 0, len(releases))
	for _, rel := range releases {
		result = append(result, mapHelmReleaseToRevision(rel))
	}

	return result, nil
}

// GetStatus gets current release status.
func (r *defaultReleaseClient) GetStatus(ctx context.Context, name string) (*ReleaseStatus, error) {
	if ctx == nil {
		return nil, ErrNilContext
	}
	if name == "" {
		return nil, ErrEmptyReleaseName
	}

	status := action.NewStatus(r.actionConfig)

	rel, err := status.Run(name)
	if err != nil {
		if isReleaseNotFoundError(err) {
			return nil, NewHelmError("status", r.namespace, name, ErrReleaseNotFound)
		}
		return nil, NewHelmError("status", r.namespace, name, err)
	}

	return mapHelmReleaseToStatus(rel), nil
}

// WaitForReady waits until release reaches ready state.
func (r *defaultReleaseClient) WaitForReady(ctx context.Context, name string, timeout time.Duration) error {
	if ctx == nil {
		return ErrNilContext
	}
	if name == "" {
		return ErrEmptyReleaseName
	}

	timeoutCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	ticker := time.NewTicker(DefaultPollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-timeoutCtx.Done():
			return NewHelmError("wait for ready", r.namespace, name, ErrTimeout)
		case <-ticker.C:
			status, err := r.GetStatus(ctx, name)
			if err != nil {
				continue // Keep trying on transient errors.
			}
			if status.Status.IsSuccess() {
				return nil
			}
			if status.Status == StatusFailed {
				return NewHelmError("wait for ready", r.namespace, name, ErrReleaseFailed)
			}
		}
	}
}

// mapHelmRelease converts a Helm release to our Release type.
func mapHelmRelease(rel *release.Release) *Release {
	if rel == nil {
		return &Release{}
	}

	r := &Release{
		Name:        rel.Name,
		Namespace:   rel.Namespace,
		Revision:    rel.Version,
		Description: rel.Info.Description,
		Status:      mapHelmStatus(rel.Info.Status),
	}

	if rel.Chart != nil && rel.Chart.Metadata != nil {
		r.Chart = rel.Chart.Metadata.Name
		r.ChartVersion = rel.Chart.Metadata.Version
		r.AppVersion = rel.Chart.Metadata.AppVersion
	}

	if !rel.Info.FirstDeployed.IsZero() {
		r.FirstDeployedAt = rel.Info.FirstDeployed.Time
	}
	if !rel.Info.LastDeployed.IsZero() {
		r.LastDeployedAt = rel.Info.LastDeployed.Time
	}

	r.Values = rel.Config

	return r
}

// mapHelmReleaseToRevision converts a Helm release to ReleaseRevision.
func mapHelmReleaseToRevision(rel *release.Release) ReleaseRevision {
	rev := ReleaseRevision{
		Revision:    rel.Version,
		Description: rel.Info.Description,
		Status:      mapHelmStatus(rel.Info.Status),
	}

	if rel.Chart != nil && rel.Chart.Metadata != nil {
		rev.Chart = rel.Chart.Metadata.Name
		rev.AppVersion = rel.Chart.Metadata.AppVersion
	}

	if !rel.Info.LastDeployed.IsZero() {
		rev.UpdatedAt = rel.Info.LastDeployed.Time
	}

	return rev
}

// mapHelmReleaseToStatus converts a Helm release to ReleaseStatus.
func mapHelmReleaseToStatus(rel *release.Release) *ReleaseStatus {
	if rel == nil {
		return &ReleaseStatus{}
	}

	s := &ReleaseStatus{
		Revision:    rel.Version,
		Description: rel.Info.Description,
		Notes:       rel.Info.Notes,
		Status:      mapHelmStatus(rel.Info.Status),
	}

	if !rel.Info.LastDeployed.IsZero() {
		s.LastDeployedAt = rel.Info.LastDeployed.Time
	}

	return s
}

// mapHelmStatus maps Helm release status to our ReleaseStatusType.
func mapHelmStatus(status release.Status) ReleaseStatusType {
	switch status {
	case release.StatusDeployed:
		return StatusDeployed
	case release.StatusUninstalled:
		return StatusUninstalled
	case release.StatusSuperseded:
		return StatusSuperseded
	case release.StatusFailed:
		return StatusFailed
	case release.StatusUninstalling:
		return StatusUninstalling
	case release.StatusPendingInstall:
		return StatusPendingInstall
	case release.StatusPendingUpgrade:
		return StatusPendingUpgrade
	case release.StatusPendingRollback:
		return StatusPendingRollback
	default:
		return StatusUnknown
	}
}

// isReleaseExistsError checks if the error indicates release already exists.
func isReleaseExistsError(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	return contains(errStr, "already exists") || contains(errStr, "cannot re-use")
}

// isRevisionNotFoundError checks if the error indicates revision not found.
func isRevisionNotFoundError(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	return contains(errStr, "revision") && contains(errStr, "not found")
}
