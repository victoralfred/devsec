// Package metrics provides Prometheus metrics for the devsec pipeline.
package metrics

import (
	"sync"

	"github.com/prometheus/client_golang/prometheus"
)

// Namespace for all devsec metrics.
const Namespace = "devsec"

// Metrics holds all Prometheus metrics for the pipeline.
type Metrics struct {
	// Scan metrics.
	ScanDuration   *prometheus.HistogramVec
	ScanTotal      *prometheus.CounterVec
	ScanErrors     *prometheus.CounterVec
	ScanInProgress *prometheus.GaugeVec

	// Finding metrics.
	FindingsTotal      *prometheus.CounterVec
	FindingsBySeverity *prometheus.GaugeVec

	// Policy metrics.
	PolicyEvaluations *prometheus.CounterVec
	PolicyViolations  *prometheus.CounterVec

	// Pipeline metrics.
	PipelineRuns     *prometheus.CounterVec
	PipelineDuration *prometheus.HistogramVec
	StagesDuration   *prometheus.HistogramVec

	// Deployment metrics.
	DeploymentsTotal   *prometheus.CounterVec
	RollbacksTotal     *prometheus.CounterVec
	GateChecksDuration *prometheus.HistogramVec

	registry *prometheus.Registry
	mu       sync.RWMutex
}

// Option configures Metrics.
type Option func(*Metrics)

// WithRegistry sets a custom Prometheus registry.
func WithRegistry(reg *prometheus.Registry) Option {
	return func(m *Metrics) {
		m.registry = reg
	}
}

// New creates a new Metrics instance with all collectors registered.
func New(opts ...Option) *Metrics {
	m := &Metrics{
		registry: prometheus.NewRegistry(),
	}

	for _, opt := range opts {
		opt(m)
	}

	m.initMetrics()
	m.registerMetrics()

	return m
}

// initMetrics initializes all metric collectors.
func (m *Metrics) initMetrics() {
	// Scan duration histogram with buckets from 100ms to 10 minutes.
	m.ScanDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: Namespace,
			Subsystem: "scan",
			Name:      "duration_seconds",
			Help:      "Duration of scan operations in seconds.",
			Buckets:   []float64{0.1, 0.5, 1, 2, 5, 10, 30, 60, 120, 300, 600},
		},
		[]string{"scanner", "status"},
	)

	m.ScanTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: Namespace,
			Subsystem: "scan",
			Name:      "total",
			Help:      "Total number of scans performed.",
		},
		[]string{"scanner"},
	)

	m.ScanErrors = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: Namespace,
			Subsystem: "scan",
			Name:      "errors_total",
			Help:      "Total number of scan errors.",
		},
		[]string{"scanner", "error_type"},
	)

	m.ScanInProgress = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: Namespace,
			Subsystem: "scan",
			Name:      "in_progress",
			Help:      "Number of scans currently in progress.",
		},
		[]string{"scanner"},
	)

	// Finding metrics.
	m.FindingsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: Namespace,
			Subsystem: "findings",
			Name:      "total",
			Help:      "Total number of findings discovered.",
		},
		[]string{"scanner", "severity"},
	)

	m.FindingsBySeverity = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: Namespace,
			Subsystem: "findings",
			Name:      "by_severity",
			Help:      "Current number of findings by severity.",
		},
		[]string{"severity"},
	)

	// Policy metrics.
	m.PolicyEvaluations = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: Namespace,
			Subsystem: "policy",
			Name:      "evaluations_total",
			Help:      "Total number of policy evaluations.",
		},
		[]string{"policy", "result"},
	)

	m.PolicyViolations = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: Namespace,
			Subsystem: "policy",
			Name:      "violations_total",
			Help:      "Total number of policy violations.",
		},
		[]string{"policy", "severity"},
	)

	// Pipeline metrics.
	m.PipelineRuns = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: Namespace,
			Subsystem: "pipeline",
			Name:      "runs_total",
			Help:      "Total number of pipeline runs.",
		},
		[]string{"pipeline", "status"},
	)

	m.PipelineDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: Namespace,
			Subsystem: "pipeline",
			Name:      "duration_seconds",
			Help:      "Duration of pipeline runs in seconds.",
			Buckets:   []float64{1, 5, 10, 30, 60, 120, 300, 600, 1200, 1800},
		},
		[]string{"pipeline", "status"},
	)

	m.StagesDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: Namespace,
			Subsystem: "pipeline",
			Name:      "stage_duration_seconds",
			Help:      "Duration of pipeline stages in seconds.",
			Buckets:   []float64{0.5, 1, 2, 5, 10, 30, 60, 120, 300},
		},
		[]string{"pipeline", "stage", "status"},
	)

	// Deployment metrics.
	m.DeploymentsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: Namespace,
			Subsystem: "deployment",
			Name:      "total",
			Help:      "Total number of deployments.",
		},
		[]string{"namespace", "release", "status"},
	)

	m.RollbacksTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: Namespace,
			Subsystem: "deployment",
			Name:      "rollbacks_total",
			Help:      "Total number of rollbacks performed.",
		},
		[]string{"namespace", "release", "reason"},
	)

	m.GateChecksDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: Namespace,
			Subsystem: "deployment",
			Name:      "gate_check_duration_seconds",
			Help:      "Duration of deployment gate checks in seconds.",
			Buckets:   []float64{0.1, 0.5, 1, 2, 5, 10, 30, 60},
		},
		[]string{"gate", "status"},
	)
}

// registerMetrics registers all collectors with the registry.
func (m *Metrics) registerMetrics() {
	m.registry.MustRegister(
		m.ScanDuration,
		m.ScanTotal,
		m.ScanErrors,
		m.ScanInProgress,
		m.FindingsTotal,
		m.FindingsBySeverity,
		m.PolicyEvaluations,
		m.PolicyViolations,
		m.PipelineRuns,
		m.PipelineDuration,
		m.StagesDuration,
		m.DeploymentsTotal,
		m.RollbacksTotal,
		m.GateChecksDuration,
	)
}

// Registry returns the Prometheus registry.
func (m *Metrics) Registry() *prometheus.Registry {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.registry
}

// Reset resets all metrics to zero (useful for testing).
func (m *Metrics) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.ScanDuration.Reset()
	m.ScanTotal.Reset()
	m.ScanErrors.Reset()
	m.ScanInProgress.Reset()
	m.FindingsTotal.Reset()
	m.FindingsBySeverity.Reset()
	m.PolicyEvaluations.Reset()
	m.PolicyViolations.Reset()
	m.PipelineRuns.Reset()
	m.PipelineDuration.Reset()
	m.StagesDuration.Reset()
	m.DeploymentsTotal.Reset()
	m.RollbacksTotal.Reset()
	m.GateChecksDuration.Reset()
}

// Default is the default metrics instance.
var (
	defaultMetrics *Metrics
	defaultOnce    sync.Once
)

// Default returns the default metrics instance.
func Default() *Metrics {
	defaultOnce.Do(func() {
		defaultMetrics = New()
	})
	return defaultMetrics
}

// Exporter returns a Exporter that exports to Prometheus.
func (m *Metrics) Exporter() Exporter {
	return NewPrometheusExporter(m)
}

// DefaultExporter returns an exporter using the default metrics instance.
func DefaultExporter() Exporter {
	return Default().Exporter()
}
