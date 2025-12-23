package helm

import (
	"time"
)

// Default configuration values.
const (
	DefaultNamespace = "default"
	DefaultTimeout   = 5 * time.Minute
)

// HelmConfig holds Helm client configuration.
// Fields are ordered for optimal memory alignment.
//
//nolint:revive // HelmConfig is intentionally named for clarity.
type HelmConfig struct {
	Kubeconfig  string
	Context     string
	Namespace   string
	RegistryURL string
	Timeout     time.Duration
	Debug       bool
}

// DefaultHelmConfig returns the default Helm configuration.
func DefaultHelmConfig() HelmConfig {
	return HelmConfig{
		Namespace: DefaultNamespace,
		Timeout:   DefaultTimeout,
	}
}

// HelmOption configures a HelmConfig.
//
//nolint:revive // HelmOption is intentionally named for clarity.
type HelmOption func(*HelmConfig)

// WithKubeconfig sets the kubeconfig path.
func WithKubeconfig(path string) HelmOption {
	return func(c *HelmConfig) {
		c.Kubeconfig = path
	}
}

// WithContext sets the kubeconfig context.
func WithContext(ctx string) HelmOption {
	return func(c *HelmConfig) {
		c.Context = ctx
	}
}

// WithNamespace sets the default namespace.
func WithNamespace(ns string) HelmOption {
	return func(c *HelmConfig) {
		c.Namespace = ns
	}
}

// WithTimeout sets the default timeout.
func WithTimeout(timeout time.Duration) HelmOption {
	return func(c *HelmConfig) {
		c.Timeout = timeout
	}
}

// WithRegistryURL sets the OCI registry URL.
func WithRegistryURL(url string) HelmOption {
	return func(c *HelmConfig) {
		c.RegistryURL = url
	}
}

// WithDebug enables debug mode.
func WithDebug(debug bool) HelmOption {
	return func(c *HelmConfig) {
		c.Debug = debug
	}
}

// InstallOptions configures chart installation.
// Fields are ordered for optimal memory alignment.
type InstallOptions struct {
	Values          map[string]interface{}
	ChartVersion    string
	Timeout         time.Duration
	Wait            bool
	Atomic          bool
	CreateNamespace bool
	DryRun          bool
}

// UpgradeOptions configures chart upgrade.
// Fields are ordered for optimal memory alignment.
type UpgradeOptions struct {
	Values       map[string]interface{}
	ChartVersion string
	Timeout      time.Duration
	Wait         bool
	Atomic       bool
	Force        bool
	DryRun       bool
	ResetValues  bool
	ReuseValues  bool
}

// ListOptions filters releases.
// Fields are ordered for optimal memory alignment.
type ListOptions struct {
	Limit         int
	AllNamespaces bool
	Deployed      bool
	Failed        bool
	Pending       bool
	Uninstalled   bool
}

// RollbackOptions configures rollback operations.
// Fields are ordered for optimal memory alignment.
type RollbackOptions struct {
	Timeout       time.Duration
	Wait          bool
	Force         bool
	CleanupOnFail bool
	DisableHooks  bool
	Recreate      bool
	MaxHistory    int
}
