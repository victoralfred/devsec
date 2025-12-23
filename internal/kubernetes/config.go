package kubernetes

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// Default configuration values.
const (
	DefaultNamespace = "default"
	DefaultTimeout   = 30 * time.Second
	DefaultQPS       = 50.0
	DefaultBurst     = 100
)

// TLSConfig holds TLS configuration for the Kubernetes client.
// Fields are ordered for optimal memory alignment.
type TLSConfig struct {
	CAFile   string `json:"ca_file,omitempty"`
	CertFile string `json:"cert_file,omitempty"`
	KeyFile  string `json:"key_file,omitempty"`
	Insecure bool   `json:"insecure,omitempty"`
}

// ClientConfig holds configuration for the Kubernetes client.
// Fields are ordered for optimal memory alignment.
type ClientConfig struct {
	TLSConfig   *TLSConfig    `json:"tls_config,omitempty"`
	Kubeconfig  string        `json:"kubeconfig,omitempty"`
	Context     string        `json:"context,omitempty"`
	Namespace   string        `json:"namespace,omitempty"`
	APIServer   string        `json:"api_server,omitempty"`
	BearerToken string        `json:"bearer_token,omitempty"`
	Timeout     time.Duration `json:"timeout,omitempty"`
	Burst       int           `json:"burst,omitempty"`
	QPS         float32       `json:"qps,omitempty"`
	InCluster   bool          `json:"in_cluster,omitempty"`
}

// DefaultClientConfig returns a ClientConfig with sensible defaults.
func DefaultClientConfig() ClientConfig {
	return ClientConfig{
		Namespace: DefaultNamespace,
		Timeout:   DefaultTimeout,
		QPS:       DefaultQPS,
		Burst:     DefaultBurst,
	}
}

// ClientOption configures a Kubernetes client.
type ClientOption func(*ClientConfig)

// WithKubeconfig sets the kubeconfig path.
func WithKubeconfig(path string) ClientOption {
	return func(c *ClientConfig) {
		c.Kubeconfig = path
	}
}

// WithContext sets the kubeconfig context.
func WithContext(ctx string) ClientOption {
	return func(c *ClientConfig) {
		c.Context = ctx
	}
}

// WithNamespace sets the default namespace.
func WithNamespace(ns string) ClientOption {
	return func(c *ClientConfig) {
		c.Namespace = ns
	}
}

// WithTimeout sets the request timeout.
func WithTimeout(timeout time.Duration) ClientOption {
	return func(c *ClientConfig) {
		c.Timeout = timeout
	}
}

// WithInCluster forces in-cluster configuration.
func WithInCluster() ClientOption {
	return func(c *ClientConfig) {
		c.InCluster = true
	}
}

// WithQPS sets the QPS limit for the client.
func WithQPS(qps float32) ClientOption {
	return func(c *ClientConfig) {
		c.QPS = qps
	}
}

// WithBurst sets the burst limit for the client.
func WithBurst(burst int) ClientOption {
	return func(c *ClientConfig) {
		c.Burst = burst
	}
}

// WithAPIServer sets the API server URL.
func WithAPIServer(url string) ClientOption {
	return func(c *ClientConfig) {
		c.APIServer = url
	}
}

// WithBearerToken sets the bearer token for authentication.
func WithBearerToken(token string) ClientOption {
	return func(c *ClientConfig) {
		c.BearerToken = token
	}
}

// WithTLSConfig sets the TLS configuration.
func WithTLSConfig(tls *TLSConfig) ClientOption {
	return func(c *ClientConfig) {
		c.TLSConfig = tls
	}
}

// buildRestConfig creates a rest.Config from ClientConfig.
func buildRestConfig(cfg ClientConfig) (*rest.Config, error) {
	// Try in-cluster first if explicitly requested.
	if cfg.InCluster {
		config, err := rest.InClusterConfig()
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrNotInCluster, err)
		}
		return config, nil
	}

	// Try explicit kubeconfig path.
	if cfg.Kubeconfig != "" {
		return loadKubeconfig(cfg.Kubeconfig, cfg.Context)
	}

	// Try KUBECONFIG environment variable.
	if kubeconfigEnv := os.Getenv("KUBECONFIG"); kubeconfigEnv != "" {
		return loadKubeconfig(kubeconfigEnv, cfg.Context)
	}

	// Try in-cluster config (auto-detect).
	if config, err := rest.InClusterConfig(); err == nil {
		return config, nil
	}

	// Try default kubeconfig location.
	home, err := os.UserHomeDir()
	if err == nil {
		defaultPath := filepath.Join(home, ".kube", "config")
		if _, statErr := os.Stat(defaultPath); statErr == nil {
			return loadKubeconfig(defaultPath, cfg.Context)
		}
	}

	return nil, ErrKubeconfigNotFound
}

// loadKubeconfig loads a kubeconfig file.
func loadKubeconfig(path, context string) (*rest.Config, error) {
	loadingRules := &clientcmd.ClientConfigLoadingRules{
		ExplicitPath: path,
	}

	configOverrides := &clientcmd.ConfigOverrides{}
	if context != "" {
		configOverrides.CurrentContext = context
	}

	kubeConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		loadingRules,
		configOverrides,
	)

	config, err := kubeConfig.ClientConfig()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidConfig, err)
	}

	return config, nil
}

// applyConfigOverrides applies ClientConfig settings to rest.Config.
func applyConfigOverrides(restConfig *rest.Config, cfg ClientConfig) {
	restConfig.QPS = cfg.QPS
	restConfig.Burst = cfg.Burst
	restConfig.Timeout = cfg.Timeout

	if cfg.APIServer != "" {
		restConfig.Host = cfg.APIServer
	}

	if cfg.BearerToken != "" {
		restConfig.BearerToken = cfg.BearerToken
	}

	if cfg.TLSConfig != nil {
		if cfg.TLSConfig.CAFile != "" {
			restConfig.CAFile = cfg.TLSConfig.CAFile
		}
		if cfg.TLSConfig.CertFile != "" {
			restConfig.CertFile = cfg.TLSConfig.CertFile
		}
		if cfg.TLSConfig.KeyFile != "" {
			restConfig.KeyFile = cfg.TLSConfig.KeyFile
		}
		restConfig.Insecure = cfg.TLSConfig.Insecure
	}
}
