// Package metrics provides metrics collection for the devsec pipeline.
package metrics

import (
	"time"

	"github.com/victoralfred/devsec/internal/model"
)

// MetricsExporter defines the interface for exporting metrics to various backends.
// Implementations can export to Prometheus, CloudWatch, DataDog, StatsD, etc.
type MetricsExporter interface {
	// Scan metrics.
	RecordScanStart(scanner string)
	RecordScanEnd(scanner string, status string, duration time.Duration)
	RecordScanError(scanner, errorType string)
	RecordScanInProgress(scanner string, delta int)

	// Finding metrics.
	RecordFinding(scanner, severity string)
	RecordFindingsBySeverity(severity string, count int)

	// Policy metrics.
	RecordPolicyEvaluation(policy, result string)
	RecordPolicyViolation(policy, severity string)

	// Pipeline metrics.
	RecordPipelineRun(pipeline, status string, duration time.Duration)
	RecordStageExecution(pipeline, stage, status string, duration time.Duration)

	// Deployment metrics.
	RecordDeployment(namespace, release, status string)
	RecordRollback(namespace, release, reason string)
	RecordGateCheck(gate, status string, duration time.Duration)
}

// PrometheusExporter exports metrics to Prometheus using the Metrics struct.
// This is the default exporter implementation.
type PrometheusExporter struct {
	metrics *Metrics
}

// NewPrometheusExporter creates a new Prometheus exporter.
func NewPrometheusExporter(m *Metrics) *PrometheusExporter {
	return &PrometheusExporter{metrics: m}
}

// RecordScanStart records the start of a scan.
func (e *PrometheusExporter) RecordScanStart(scanner string) {
	e.metrics.ScanInProgress.WithLabelValues(scanner).Inc()
	e.metrics.ScanTotal.WithLabelValues(scanner).Inc()
}

// RecordScanEnd records the end of a scan.
func (e *PrometheusExporter) RecordScanEnd(scanner string, status string, duration time.Duration) {
	e.metrics.ScanInProgress.WithLabelValues(scanner).Dec()
	e.metrics.ScanDuration.WithLabelValues(scanner, status).Observe(duration.Seconds())
}

// RecordScanError records a scan error.
func (e *PrometheusExporter) RecordScanError(scanner, errorType string) {
	e.metrics.ScanErrors.WithLabelValues(scanner, errorType).Inc()
}

// RecordScanInProgress adjusts the in-progress scan count.
func (e *PrometheusExporter) RecordScanInProgress(scanner string, delta int) {
	if delta > 0 {
		e.metrics.ScanInProgress.WithLabelValues(scanner).Add(float64(delta))
	} else {
		e.metrics.ScanInProgress.WithLabelValues(scanner).Sub(float64(-delta))
	}
}

// RecordFinding records a finding.
func (e *PrometheusExporter) RecordFinding(scanner, severity string) {
	e.metrics.FindingsTotal.WithLabelValues(scanner, normalizeSeverity(severity)).Inc()
}

// RecordFindingsBySeverity updates the severity gauge.
func (e *PrometheusExporter) RecordFindingsBySeverity(severity string, count int) {
	e.metrics.FindingsBySeverity.WithLabelValues(normalizeSeverity(severity)).Set(float64(count))
}

// RecordPolicyEvaluation records a policy evaluation.
func (e *PrometheusExporter) RecordPolicyEvaluation(policy, result string) {
	e.metrics.PolicyEvaluations.WithLabelValues(policy, result).Inc()
}

// RecordPolicyViolation records a policy violation.
func (e *PrometheusExporter) RecordPolicyViolation(policy, severity string) {
	e.metrics.PolicyViolations.WithLabelValues(policy, normalizeSeverity(severity)).Inc()
}

// RecordPipelineRun records a pipeline run.
func (e *PrometheusExporter) RecordPipelineRun(pipeline, status string, duration time.Duration) {
	e.metrics.PipelineRuns.WithLabelValues(pipeline, status).Inc()
	e.metrics.PipelineDuration.WithLabelValues(pipeline, status).Observe(duration.Seconds())
}

// RecordStageExecution records a stage execution.
func (e *PrometheusExporter) RecordStageExecution(pipeline, stage, status string, duration time.Duration) {
	e.metrics.StagesDuration.WithLabelValues(pipeline, stage, status).Observe(duration.Seconds())
}

// RecordDeployment records a deployment.
func (e *PrometheusExporter) RecordDeployment(namespace, release, status string) {
	e.metrics.DeploymentsTotal.WithLabelValues(namespace, release, status).Inc()
}

// RecordRollback records a rollback.
func (e *PrometheusExporter) RecordRollback(namespace, release, reason string) {
	e.metrics.RollbacksTotal.WithLabelValues(namespace, release, reason).Inc()
}

// RecordGateCheck records a gate check.
func (e *PrometheusExporter) RecordGateCheck(gate, status string, duration time.Duration) {
	e.metrics.GateChecksDuration.WithLabelValues(gate, status).Observe(duration.Seconds())
}

// NoOpExporter is a no-op exporter for testing or disabled metrics.
type NoOpExporter struct{}

// NewNoOpExporter creates a no-op exporter.
func NewNoOpExporter() *NoOpExporter {
	return &NoOpExporter{}
}

// RecordScanStart is a no-op.
func (e *NoOpExporter) RecordScanStart(scanner string) {}

// RecordScanEnd is a no-op.
func (e *NoOpExporter) RecordScanEnd(scanner string, status string, duration time.Duration) {}

// RecordScanError is a no-op.
func (e *NoOpExporter) RecordScanError(scanner, errorType string) {}

// RecordScanInProgress is a no-op.
func (e *NoOpExporter) RecordScanInProgress(scanner string, delta int) {}

// RecordFinding is a no-op.
func (e *NoOpExporter) RecordFinding(scanner, severity string) {}

// RecordFindingsBySeverity is a no-op.
func (e *NoOpExporter) RecordFindingsBySeverity(severity string, count int) {}

// RecordPolicyEvaluation is a no-op.
func (e *NoOpExporter) RecordPolicyEvaluation(policy, result string) {}

// RecordPolicyViolation is a no-op.
func (e *NoOpExporter) RecordPolicyViolation(policy, severity string) {}

// RecordPipelineRun is a no-op.
func (e *NoOpExporter) RecordPipelineRun(pipeline, status string, duration time.Duration) {}

// RecordStageExecution is a no-op.
func (e *NoOpExporter) RecordStageExecution(pipeline, stage, status string, duration time.Duration) {
}

// RecordDeployment is a no-op.
func (e *NoOpExporter) RecordDeployment(namespace, release, status string) {}

// RecordRollback is a no-op.
func (e *NoOpExporter) RecordRollback(namespace, release, reason string) {}

// RecordGateCheck is a no-op.
func (e *NoOpExporter) RecordGateCheck(gate, status string, duration time.Duration) {}

// ExporterRecorder provides a simplified recording interface using an exporter.
// This wraps the exporter to provide timing helpers.
type ExporterRecorder struct {
	exporter MetricsExporter
}

// NewExporterRecorder creates a new recorder using the given exporter.
func NewExporterRecorder(exporter MetricsExporter) *ExporterRecorder {
	return &ExporterRecorder{exporter: exporter}
}

// StartScan returns a function that records scan completion.
func (r *ExporterRecorder) StartScan(scanner string) func(findings []model.Finding, err error) {
	startTime := time.Now()
	r.exporter.RecordScanStart(scanner)

	return func(findings []model.Finding, err error) {
		duration := time.Since(startTime)
		if err != nil {
			r.exporter.RecordScanEnd(scanner, "error", duration)
			r.exporter.RecordScanError(scanner, "scan_failed")
		} else {
			r.exporter.RecordScanEnd(scanner, "success", duration)
			for i := range findings {
				r.exporter.RecordFinding(scanner, string(findings[i].Severity))
			}
		}
	}
}

// StartPipeline returns a function that records pipeline completion.
func (r *ExporterRecorder) StartPipeline(pipeline string) func(success bool) {
	startTime := time.Now()

	return func(success bool) {
		duration := time.Since(startTime)
		status := "success"
		if !success {
			status = "failure"
		}
		r.exporter.RecordPipelineRun(pipeline, status, duration)
	}
}
