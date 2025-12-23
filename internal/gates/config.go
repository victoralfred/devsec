package gates

import (
	"context"
	"time"

	"github.com/victoralfred/devsec/internal/model"
)

// Default configuration values.
const (
	DefaultNamespace        = "default"
	DefaultTimeout          = 5 * time.Minute
	DefaultHealthThreshold  = 0.8 // 80% healthy pods
	DefaultMinReadySeconds  = 10
	DefaultPostCheckTimeout = 2 * time.Minute
)

// DeployStatus represents deployment outcome.
type DeployStatus string

// Deployment status constants.
const (
	DeployStatusSuccess         DeployStatus = "success"
	DeployStatusFailed          DeployStatus = "failed"
	DeployStatusRolledBack      DeployStatus = "rolled_back"
	DeployStatusPreCheckFailed  DeployStatus = "pre_check_failed"
	DeployStatusPostCheckFailed DeployStatus = "post_check_failed"
)

// IsValid returns true if the status is valid.
func (s DeployStatus) IsValid() bool {
	switch s {
	case DeployStatusSuccess, DeployStatusFailed, DeployStatusRolledBack,
		DeployStatusPreCheckFailed, DeployStatusPostCheckFailed:
		return true
	}
	return false
}

// IsSuccess returns true if the deployment was successful.
func (s DeployStatus) IsSuccess() bool {
	return s == DeployStatusSuccess
}

// IsFailure returns true if the deployment failed.
func (s DeployStatus) IsFailure() bool {
	return s == DeployStatusFailed || s == DeployStatusPreCheckFailed ||
		s == DeployStatusPostCheckFailed
}

// KubeClient defines the Kubernetes client interface for gates.
// This allows for dependency injection and testing.
type KubeClient interface {
	// CheckPodHealth checks the health of pods for a deployment.
	CheckPodHealth(ctx context.Context, namespace, deployment string) (*HealthReport, error)

	// WaitForReady waits until the deployment reaches ready state.
	WaitForReady(ctx context.Context, namespace, deployment string, timeout time.Duration) error
}

// HelmClient defines the Helm client interface for gates.
// This allows for dependency injection and testing.
type HelmClient interface {
	// Install installs a Helm chart.
	Install(ctx context.Context, namespace, name, chart string, values map[string]interface{}) (*ReleaseInfo, error)

	// Upgrade upgrades an existing release.
	Upgrade(ctx context.Context, namespace, name, chart string, values map[string]interface{}) (*ReleaseInfo, error)

	// Rollback rolls back to a previous revision.
	Rollback(ctx context.Context, namespace, name string, revision int) error

	// GetCurrentRevision gets the current revision number.
	GetCurrentRevision(ctx context.Context, namespace, name string) (int, error)
}

// PolicyEvaluator defines the policy engine interface for gates.
// This allows for dependency injection and testing.
type PolicyEvaluator interface {
	// Evaluate evaluates policies against findings.
	Evaluate(ctx context.Context, findings []model.Finding) (PolicyResult, error)
}

// HealthReport contains pod health information.
// Fields are ordered for optimal memory alignment.
type HealthReport struct {
	Namespace        string   `json:"namespace"`
	Deployment       string   `json:"deployment"`
	UnhealthyPods    []string `json:"unhealthy_pods,omitempty"`
	TotalPods        int      `json:"total_pods"`
	HealthyPods      int      `json:"healthy_pods"`
	HealthPercentage float64  `json:"health_percentage"`
	Healthy          bool     `json:"healthy"`
}

// ReleaseInfo contains Helm release information.
// Fields are ordered for optimal memory alignment.
type ReleaseInfo struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
	Chart     string `json:"chart"`
	Version   string `json:"version"`
	Status    string `json:"status"`
	Revision  int    `json:"revision"`
}

// PolicyResult contains policy evaluation results.
// Fields are ordered for optimal memory alignment.
type PolicyResult struct {
	Violations []string `json:"violations,omitempty"`
	Warnings   []string `json:"warnings,omitempty"`
	Allow      bool     `json:"allow"`
	Deny       bool     `json:"deny"`
}

// GateInput provides context for gate evaluation.
// Fields are ordered for optimal memory alignment.
type GateInput struct {
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
	Namespace string                 `json:"namespace"`
	Resource  string                 `json:"resource"`
}

// GateDecision represents a gate evaluation result.
// Fields are ordered for optimal memory alignment.
type GateDecision struct {
	Timestamp  time.Time              `json:"timestamp"`
	Details    map[string]interface{} `json:"details,omitempty"`
	GateName   string                 `json:"gate_name"`
	Message    string                 `json:"message"`
	EvalTimeMs int64                  `json:"eval_time_ms"`
	Passed     bool                   `json:"passed"`
}

// GateResult aggregates multiple gate decisions.
// Fields are ordered for optimal memory alignment.
type GateResult struct {
	Timestamp   time.Time      `json:"timestamp"`
	Summary     string         `json:"summary"`
	Decisions   []GateDecision `json:"decisions"`
	TotalGates  int            `json:"total_gates"`
	PassedGates int            `json:"passed_gates"`
	FailedGates int            `json:"failed_gates"`
	Passed      bool           `json:"passed"`
}

// DeploymentResult contains full deployment outcome.
// Fields are ordered for optimal memory alignment.
type DeploymentResult struct {
	StartTime        time.Time    `json:"start_time"`
	EndTime          time.Time    `json:"end_time"`
	PreCheckResult   *GateResult  `json:"pre_check_result,omitempty"`
	PostCheckResult  *GateResult  `json:"post_check_result,omitempty"`
	Namespace        string       `json:"namespace"`
	ReleaseName      string       `json:"release_name"`
	ChartRef         string       `json:"chart_ref"`
	Status           DeployStatus `json:"status"`
	Revision         int          `json:"revision"`
	PreviousRevision int          `json:"previous_revision,omitempty"`
	RolledBack       bool         `json:"rolled_back"`
}

// Config holds deployment gates configuration.
// Fields are ordered for optimal memory alignment.
type Config struct {
	KubeClient   KubeClient
	HelmClient   HelmClient
	PolicyEngine PolicyEvaluator
	Namespace    string
	Timeout      time.Duration
	DryRun       bool
}

// DefaultConfig returns the default gates configuration.
func DefaultConfig() Config {
	return Config{
		Namespace: DefaultNamespace,
		Timeout:   DefaultTimeout,
	}
}

// Option configures a Config.
type Option func(*Config)

// WithKubeClient sets the Kubernetes client.
func WithKubeClient(client KubeClient) Option {
	return func(c *Config) {
		c.KubeClient = client
	}
}

// WithHelmClient sets the Helm client.
func WithHelmClient(client HelmClient) Option {
	return func(c *Config) {
		c.HelmClient = client
	}
}

// WithPolicyEngine sets the policy engine.
func WithPolicyEngine(engine PolicyEvaluator) Option {
	return func(c *Config) {
		c.PolicyEngine = engine
	}
}

// WithNamespace sets the default namespace.
func WithNamespace(ns string) Option {
	return func(c *Config) {
		c.Namespace = ns
	}
}

// WithTimeout sets the default timeout.
func WithTimeout(timeout time.Duration) Option {
	return func(c *Config) {
		c.Timeout = timeout
	}
}

// WithDryRun enables dry-run mode.
func WithDryRun(dryRun bool) Option {
	return func(c *Config) {
		c.DryRun = dryRun
	}
}

// PreCheckOptions for pre-deployment checks.
// Fields are ordered for optimal memory alignment.
type PreCheckOptions struct {
	Metadata   map[string]interface{} `json:"metadata,omitempty"`
	PolicyPath string                 `json:"policy_path,omitempty"`
	Findings   []model.Finding        `json:"findings,omitempty"`
	StrictMode bool                   `json:"strict_mode"`
}

// PostCheckOptions for post-deployment verification.
// Fields are ordered for optimal memory alignment.
type PostCheckOptions struct {
	Namespace       string        `json:"namespace"`
	ReleaseName     string        `json:"release_name"`
	DeploymentName  string        `json:"deployment_name,omitempty"`
	Timeout         time.Duration `json:"timeout"`
	MinReadySeconds int           `json:"min_ready_seconds"`
	HealthThreshold float64       `json:"health_threshold"`
}

// DefaultPostCheckOptions returns default post-check options.
func DefaultPostCheckOptions() PostCheckOptions {
	return PostCheckOptions{
		Timeout:         DefaultPostCheckTimeout,
		MinReadySeconds: DefaultMinReadySeconds,
		HealthThreshold: DefaultHealthThreshold,
	}
}

// DeployOptions for full deployment with gates.
// Fields are ordered for optimal memory alignment.
type DeployOptions struct {
	Values       map[string]interface{} `json:"values,omitempty"`
	PreCheck     *PreCheckOptions       `json:"pre_check,omitempty"`
	PostCheck    *PostCheckOptions      `json:"post_check,omitempty"`
	ReleaseName  string                 `json:"release_name"`
	ChartRef     string                 `json:"chart_ref"`
	Timeout      time.Duration          `json:"timeout"`
	AutoRollback bool                   `json:"auto_rollback"`
}

// RollbackOptions for rollback operation.
// Fields are ordered for optimal memory alignment.
type RollbackOptions struct {
	ReleaseName string        `json:"release_name"`
	Namespace   string        `json:"namespace"`
	Timeout     time.Duration `json:"timeout"`
	Revision    int           `json:"revision"`
	Force       bool          `json:"force"`
}

// Validate validates the deploy options.
func (o *DeployOptions) Validate() error {
	if o.ReleaseName == "" {
		return ErrEmptyReleaseName
	}
	if o.ChartRef == "" {
		return ErrEmptyChartRef
	}
	return nil
}

// Validate validates the rollback options.
func (o *RollbackOptions) Validate() error {
	if o.ReleaseName == "" {
		return ErrEmptyReleaseName
	}
	return nil
}

// Validate validates the pre-check options.
func (o *PreCheckOptions) Validate() error {
	if len(o.Findings) == 0 {
		return ErrNoFindings
	}
	return nil
}

// Validate validates the post-check options.
func (o *PostCheckOptions) Validate() error {
	if o.Namespace == "" {
		return ErrEmptyNamespace
	}
	if o.ReleaseName == "" {
		return ErrEmptyReleaseName
	}
	return nil
}
