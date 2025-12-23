package helm

import (
	"context"
	"log"
	"os"
	"time"

	"helm.sh/helm/v3/pkg/action"
	"helm.sh/helm/v3/pkg/cli"
	"helm.sh/helm/v3/pkg/storage"
	"helm.sh/helm/v3/pkg/storage/driver"
)

// Client provides Helm operations for chart deployment.
type Client interface {
	// Release returns a ReleaseClient for release operations.
	Release(namespace string) ReleaseClient

	// Chart returns a ChartClient for chart operations.
	Chart() ChartClient

	// Values returns a ValuesClient for values management.
	Values() ValuesClient

	// Close releases resources held by the client.
	Close() error
}

// ReleaseClient provides release-specific operations.
type ReleaseClient interface {
	// Install installs a Helm chart.
	Install(ctx context.Context, name, chart string, opts InstallOptions) (*Release, error)

	// Upgrade upgrades an existing release.
	Upgrade(ctx context.Context, name, chart string, opts UpgradeOptions) (*Release, error)

	// Get retrieves release information.
	Get(ctx context.Context, name string) (*Release, error)

	// List lists releases.
	List(ctx context.Context, opts ListOptions) ([]Release, error)

	// Uninstall removes a release.
	Uninstall(ctx context.Context, name string) error

	// Rollback rolls back to a previous revision.
	Rollback(ctx context.Context, name string, revision int) error

	// GetHistory retrieves release history.
	GetHistory(ctx context.Context, name string) ([]ReleaseRevision, error)

	// GetStatus gets current release status.
	GetStatus(ctx context.Context, name string) (*ReleaseStatus, error)

	// WaitForReady waits until release reaches ready state.
	WaitForReady(ctx context.Context, name string, timeout time.Duration) error
}

// ChartClient provides chart-specific operations.
type ChartClient interface {
	// Get retrieves chart metadata.
	Get(ctx context.Context, chartRef string) (*ChartInfo, error)

	// Validate validates chart structure.
	Validate(ctx context.Context, chartPath string) error

	// Template renders chart templates without installing.
	Template(ctx context.Context, name, chartRef string, values map[string]interface{}) (string, error)
}

// ValuesClient provides values management.
type ValuesClient interface {
	// Get retrieves current values for a release.
	Get(ctx context.Context, namespace, release string) (map[string]interface{}, error)

	// Merge merges multiple value sources.
	Merge(base map[string]interface{}, overlays ...map[string]interface{}) map[string]interface{}

	// LoadFromFile loads values from a YAML file.
	LoadFromFile(ctx context.Context, path string) (map[string]interface{}, error)
}

// ReleaseStatusType represents release status.
type ReleaseStatusType string

// Release status constants.
const (
	StatusDeployed        ReleaseStatusType = "deployed"
	StatusUninstalled     ReleaseStatusType = "uninstalled"
	StatusSuperseded      ReleaseStatusType = "superseded"
	StatusFailed          ReleaseStatusType = "failed"
	StatusUninstalling    ReleaseStatusType = "uninstalling"
	StatusPendingInstall  ReleaseStatusType = "pending-install"
	StatusPendingUpgrade  ReleaseStatusType = "pending-upgrade"
	StatusPendingRollback ReleaseStatusType = "pending-rollback"
	StatusUnknown         ReleaseStatusType = "unknown"
)

// IsValid returns true if the status is valid.
func (s ReleaseStatusType) IsValid() bool {
	switch s {
	case StatusDeployed, StatusUninstalled, StatusSuperseded, StatusFailed,
		StatusUninstalling, StatusPendingInstall, StatusPendingUpgrade,
		StatusPendingRollback, StatusUnknown:
		return true
	}
	return false
}

// IsTerminal returns true if the status is a terminal state.
func (s ReleaseStatusType) IsTerminal() bool {
	return s == StatusDeployed || s == StatusFailed ||
		s == StatusUninstalled || s == StatusSuperseded
}

// IsSuccess returns true if the status indicates success.
func (s ReleaseStatusType) IsSuccess() bool {
	return s == StatusDeployed
}

// Release represents a Helm release.
// Fields are ordered for optimal memory alignment.
type Release struct {
	FirstDeployedAt time.Time              `json:"first_deployed_at"`
	LastDeployedAt  time.Time              `json:"last_deployed_at"`
	Values          map[string]interface{} `json:"values,omitempty"`
	Name            string                 `json:"name"`
	Namespace       string                 `json:"namespace"`
	Chart           string                 `json:"chart"`
	ChartVersion    string                 `json:"chart_version"`
	AppVersion      string                 `json:"app_version"`
	Description     string                 `json:"description"`
	Status          ReleaseStatusType      `json:"status"`
	Revision        int                    `json:"revision"`
}

// ReleaseRevision represents a release revision in history.
// Fields are ordered for optimal memory alignment.
type ReleaseRevision struct {
	UpdatedAt   time.Time         `json:"updated_at"`
	Chart       string            `json:"chart"`
	AppVersion  string            `json:"app_version"`
	Description string            `json:"description"`
	Status      ReleaseStatusType `json:"status"`
	Revision    int               `json:"revision"`
}

// ReleaseStatus contains detailed status info.
// Fields are ordered for optimal memory alignment.
type ReleaseStatus struct {
	LastDeployedAt time.Time         `json:"last_deployed_at"`
	Description    string            `json:"description"`
	Notes          string            `json:"notes"`
	Status         ReleaseStatusType `json:"status"`
	Revision       int               `json:"revision"`
}

// ChartInfo contains chart metadata.
// Fields are ordered for optimal memory alignment.
type ChartInfo struct {
	Created     time.Time `json:"created"`
	Name        string    `json:"name"`
	Version     string    `json:"version"`
	AppVersion  string    `json:"app_version"`
	Description string    `json:"description"`
	Home        string    `json:"home,omitempty"`
	Icon        string    `json:"icon,omitempty"`
	Deprecated  bool      `json:"deprecated"`
}

// DefaultClient implements the Client interface.
// Fields are ordered for optimal memory alignment.
type DefaultClient struct {
	actionConfig *action.Configuration
	settings     *cli.EnvSettings
	cfg          HelmConfig
}

// NewClient creates a new Helm client.
func NewClient(opts ...HelmOption) (*DefaultClient, error) {
	cfg := DefaultHelmConfig()
	for _, opt := range opts {
		opt(&cfg)
	}

	settings := cli.New()
	if cfg.Kubeconfig != "" {
		settings.KubeConfig = cfg.Kubeconfig
	}
	if cfg.Context != "" {
		settings.KubeContext = cfg.Context
	}
	if cfg.Namespace != "" {
		settings.SetNamespace(cfg.Namespace)
	}
	if cfg.Debug {
		settings.Debug = true
	}

	actionConfig := new(action.Configuration)

	// Initialize with the namespace from settings.
	if err := actionConfig.Init(settings.RESTClientGetter(), cfg.Namespace, os.Getenv("HELM_DRIVER"), debugLog(cfg.Debug)); err != nil {
		return nil, NewHelmError("init client", "", "", err)
	}

	return &DefaultClient{
		actionConfig: actionConfig,
		settings:     settings,
		cfg:          cfg,
	}, nil
}

// NewClientWithActionConfig creates a DefaultClient with an injected action.Configuration.
// This is primarily useful for testing.
func NewClientWithActionConfig(actionCfg *action.Configuration, cfg HelmConfig) *DefaultClient {
	settings := cli.New()
	if cfg.Namespace != "" {
		settings.SetNamespace(cfg.Namespace)
	}

	return &DefaultClient{
		actionConfig: actionCfg,
		settings:     settings,
		cfg:          cfg,
	}
}

// NewTestClient creates a client for testing with an in-memory storage driver.
func NewTestClient(cfg HelmConfig) *DefaultClient {
	actionCfg := new(action.Configuration)
	actionCfg.Releases = storage.Init(driver.NewMemory())

	settings := cli.New()
	if cfg.Namespace != "" {
		settings.SetNamespace(cfg.Namespace)
	}

	return &DefaultClient{
		actionConfig: actionCfg,
		settings:     settings,
		cfg:          cfg,
	}
}

// Release returns a ReleaseClient for the namespace.
func (c *DefaultClient) Release(namespace string) ReleaseClient {
	if namespace == "" {
		namespace = c.cfg.Namespace
	}
	return &defaultReleaseClient{
		actionConfig: c.actionConfig,
		settings:     c.settings,
		namespace:    namespace,
		timeout:      c.cfg.Timeout,
	}
}

// Chart returns a ChartClient.
func (c *DefaultClient) Chart() ChartClient {
	return &defaultChartClient{
		settings: c.settings,
	}
}

// Values returns a ValuesClient.
func (c *DefaultClient) Values() ValuesClient {
	return &defaultValuesClient{
		actionConfig: c.actionConfig,
	}
}

// Close releases resources held by the client.
func (c *DefaultClient) Close() error {
	// Helm client doesn't require explicit cleanup.
	return nil
}

// Config returns the client configuration.
func (c *DefaultClient) Config() HelmConfig {
	return c.cfg
}

// ActionConfig returns the underlying action.Configuration.
// This is useful for advanced operations.
func (c *DefaultClient) ActionConfig() *action.Configuration {
	return c.actionConfig
}

// debugLog returns a debug log function based on the debug flag.
func debugLog(debug bool) func(format string, v ...interface{}) {
	if debug {
		return func(format string, v ...interface{}) {
			log.Printf("[HELM DEBUG] "+format, v...)
		}
	}
	return func(format string, v ...interface{}) {}
}
