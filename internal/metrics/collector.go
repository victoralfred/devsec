package metrics

import (
	"time"

	"github.com/victoralfred/devsec/internal/model"
)

// ScanRecorder records metrics for scan operations.
type ScanRecorder struct {
	startTime time.Time
	metrics   *Metrics
	scanner   string
}

// NewScanRecorder creates a new scan recorder.
func NewScanRecorder(m *Metrics, scanner string) *ScanRecorder {
	return &ScanRecorder{
		metrics: m,
		scanner: scanner,
	}
}

// Start marks the start of a scan operation.
func (r *ScanRecorder) Start() {
	r.startTime = time.Now()
	r.metrics.ScanInProgress.WithLabelValues(r.scanner).Inc()
	r.metrics.ScanTotal.WithLabelValues(r.scanner).Inc()
}

// End marks the end of a successful scan operation.
func (r *ScanRecorder) End(findings []model.Finding) {
	r.metrics.ScanInProgress.WithLabelValues(r.scanner).Dec()

	duration := time.Since(r.startTime).Seconds()
	r.metrics.ScanDuration.WithLabelValues(r.scanner, "success").Observe(duration)

	// Record findings by severity.
	severityCounts := make(map[string]int)
	for i := range findings {
		sev := normalizeSeverity(string(findings[i].Severity))
		severityCounts[sev]++
		r.metrics.FindingsTotal.WithLabelValues(r.scanner, sev).Inc()
	}

	// Update severity gauge.
	for sev, count := range severityCounts {
		r.metrics.FindingsBySeverity.WithLabelValues(sev).Add(float64(count))
	}
}

// Error marks a scan operation that ended in error.
func (r *ScanRecorder) Error(errorType string) {
	r.metrics.ScanInProgress.WithLabelValues(r.scanner).Dec()

	duration := time.Since(r.startTime).Seconds()
	r.metrics.ScanDuration.WithLabelValues(r.scanner, "error").Observe(duration)
	r.metrics.ScanErrors.WithLabelValues(r.scanner, errorType).Inc()
}

// PolicyRecorder records metrics for policy evaluations.
type PolicyRecorder struct {
	metrics *Metrics
	policy  string
}

// NewPolicyRecorder creates a new policy recorder.
func NewPolicyRecorder(m *Metrics, policy string) *PolicyRecorder {
	return &PolicyRecorder{
		metrics: m,
		policy:  policy,
	}
}

// RecordEvaluation records a policy evaluation result.
func (r *PolicyRecorder) RecordEvaluation(passed bool) {
	result := "pass"
	if !passed {
		result = "fail"
	}
	r.metrics.PolicyEvaluations.WithLabelValues(r.policy, result).Inc()
}

// RecordViolation records a policy violation.
func (r *PolicyRecorder) RecordViolation(severity string) {
	r.metrics.PolicyViolations.WithLabelValues(r.policy, normalizeSeverity(severity)).Inc()
}

// PipelineRecorder records metrics for pipeline runs.
type PipelineRecorder struct {
	startTime time.Time
	metrics   *Metrics
	pipeline  string
}

// NewPipelineRecorder creates a new pipeline recorder.
func NewPipelineRecorder(m *Metrics, pipeline string) *PipelineRecorder {
	return &PipelineRecorder{
		metrics:  m,
		pipeline: pipeline,
	}
}

// Start marks the start of a pipeline run.
func (r *PipelineRecorder) Start() {
	r.startTime = time.Now()
}

// End marks the end of a pipeline run.
func (r *PipelineRecorder) End(success bool) {
	status := "success"
	if !success {
		status = "failure"
	}

	duration := time.Since(r.startTime).Seconds()
	r.metrics.PipelineRuns.WithLabelValues(r.pipeline, status).Inc()
	r.metrics.PipelineDuration.WithLabelValues(r.pipeline, status).Observe(duration)
}

// RecordStage records a stage execution.
func (r *PipelineRecorder) RecordStage(stage string, duration time.Duration, success bool) {
	status := "success"
	if !success {
		status = "failure"
	}
	r.metrics.StagesDuration.WithLabelValues(r.pipeline, stage, status).Observe(duration.Seconds())
}

// DeploymentRecorder records metrics for deployment operations.
type DeploymentRecorder struct {
	metrics   *Metrics
	namespace string
	release   string
}

// NewDeploymentRecorder creates a new deployment recorder.
func NewDeploymentRecorder(m *Metrics, namespace, release string) *DeploymentRecorder {
	return &DeploymentRecorder{
		metrics:   m,
		namespace: namespace,
		release:   release,
	}
}

// RecordDeployment records a deployment operation.
func (r *DeploymentRecorder) RecordDeployment(status string) {
	r.metrics.DeploymentsTotal.WithLabelValues(r.namespace, r.release, status).Inc()
}

// RecordRollback records a rollback operation.
func (r *DeploymentRecorder) RecordRollback(reason string) {
	r.metrics.RollbacksTotal.WithLabelValues(r.namespace, r.release, reason).Inc()
}

// RecordGateCheck records a gate check duration.
func (r *DeploymentRecorder) RecordGateCheck(gate string, duration time.Duration, passed bool) {
	status := "pass"
	if !passed {
		status = "fail"
	}
	r.metrics.GateChecksDuration.WithLabelValues(gate, status).Observe(duration.Seconds())
}

// normalizeSeverity normalizes severity strings to standard values.
func normalizeSeverity(severity string) string {
	switch severity {
	case "CRITICAL", "critical":
		return "critical"
	case "HIGH", "high":
		return "high"
	case "MEDIUM", "medium", "MODERATE", "moderate":
		return "medium"
	case "LOW", "low":
		return "low"
	case "INFO", "info", "INFORMATIONAL", "informational":
		return "info"
	default:
		return "unknown"
	}
}

// RecordFindings records findings directly to metrics.
func RecordFindings(m *Metrics, scanner string, findings []model.Finding) {
	for i := range findings {
		sev := normalizeSeverity(string(findings[i].Severity))
		m.FindingsTotal.WithLabelValues(scanner, sev).Inc()
	}
}

// RecordFindingSummary updates the severity gauge with current counts.
func RecordFindingSummary(m *Metrics, counts map[string]int) {
	// Reset gauge before updating.
	m.FindingsBySeverity.Reset()

	for severity, count := range counts {
		m.FindingsBySeverity.WithLabelValues(normalizeSeverity(severity)).Set(float64(count))
	}
}
