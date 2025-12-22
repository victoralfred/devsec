package kubernetes

import (
	"context"
	"time"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// Client provides Kubernetes operations for deployment integration.
type Client interface {
	// Deployments returns a DeploymentClient for deployment operations.
	Deployments(namespace string) DeploymentClient

	// Health returns a HealthClient for health probe operations.
	Health() HealthClient

	// Close releases any resources held by the client.
	Close() error
}

// DeploymentClient provides deployment-specific operations.
type DeploymentClient interface {
	// Get retrieves a deployment by name.
	Get(ctx context.Context, name string) (*DeploymentStatus, error)

	// List retrieves all deployments matching the selector.
	List(ctx context.Context, selector string) ([]DeploymentStatus, error)

	// WaitForReady waits until the deployment reaches ready state or timeout.
	WaitForReady(ctx context.Context, name string, timeout time.Duration) error

	// GetRolloutStatus returns the current rollout status.
	GetRolloutStatus(ctx context.Context, name string) (*RolloutStatus, error)
}

// HealthClient provides health probe operations.
type HealthClient interface {
	// CheckPodHealth checks the health of pods for a deployment.
	CheckPodHealth(ctx context.Context, namespace, deployment string) (*HealthReport, error)

	// GetReadiness checks readiness probe status for pods.
	GetReadiness(ctx context.Context, namespace, selector string) ([]PodReadiness, error)

	// GetLiveness checks liveness probe status for pods.
	GetLiveness(ctx context.Context, namespace, selector string) ([]PodLiveness, error)

	// WaitForHealthy waits until all pods are healthy or timeout.
	WaitForHealthy(ctx context.Context, namespace, deployment string, timeout time.Duration) error
}

// DefaultClient implements the Client interface.
// Fields are ordered for optimal memory alignment.
type DefaultClient struct {
	clientset kubernetes.Interface
	config    *rest.Config
	cfg       ClientConfig
}

// NewClient creates a new Kubernetes client.
func NewClient(opts ...ClientOption) (*DefaultClient, error) {
	cfg := DefaultClientConfig()
	for _, opt := range opts {
		opt(&cfg)
	}

	// Build rest.Config from options.
	restConfig, err := buildRestConfig(cfg)
	if err != nil {
		return nil, NewClientError("new client", "", "", err)
	}

	// Apply configuration overrides.
	applyConfigOverrides(restConfig, cfg)

	// Create clientset.
	clientset, err := kubernetes.NewForConfig(restConfig)
	if err != nil {
		return nil, NewClientError("create clientset", "", "", err)
	}

	return &DefaultClient{
		clientset: clientset,
		config:    restConfig,
		cfg:       cfg,
	}, nil
}

// NewClientWithClientset creates a DefaultClient with an injected clientset.
// This is primarily useful for testing with fake clients.
func NewClientWithClientset(clientset kubernetes.Interface, cfg ClientConfig) *DefaultClient {
	return &DefaultClient{
		clientset: clientset,
		cfg:       cfg,
	}
}

// Deployments returns a DeploymentClient for the namespace.
func (c *DefaultClient) Deployments(namespace string) DeploymentClient {
	if namespace == "" {
		namespace = c.cfg.Namespace
	}
	return &defaultDeploymentClient{
		client:    c.clientset,
		namespace: namespace,
	}
}

// Health returns a HealthClient.
func (c *DefaultClient) Health() HealthClient {
	return &defaultHealthClient{
		client:    c.clientset,
		namespace: c.cfg.Namespace,
	}
}

// Close releases resources held by the client.
func (c *DefaultClient) Close() error {
	// client-go clientset doesn't require explicit closing.
	return nil
}

// Clientset returns the underlying Kubernetes clientset.
// This is useful for advanced operations not covered by the Client interface.
func (c *DefaultClient) Clientset() kubernetes.Interface {
	return c.clientset
}

// Config returns the client configuration.
func (c *DefaultClient) Config() ClientConfig {
	return c.cfg
}
