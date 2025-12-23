// Package alerting provides notification capabilities for the devsec pipeline.
package alerting

import (
	"context"
	"time"

	"github.com/victoralfred/devsec/internal/model"
)

// Severity levels for alerts.
type Severity string

const (
	// SeverityCritical indicates a critical alert requiring immediate attention.
	SeverityCritical Severity = "critical"
	// SeverityHigh indicates a high priority alert.
	SeverityHigh Severity = "high"
	// SeverityMedium indicates a medium priority alert.
	SeverityMedium Severity = "medium"
	// SeverityLow indicates a low priority alert.
	SeverityLow Severity = "low"
	// SeverityInfo indicates an informational alert.
	SeverityInfo Severity = "info"
)

// AlertType categorizes the type of alert.
type AlertType string

const (
	// AlertTypeScanComplete indicates a scan has completed.
	AlertTypeScanComplete AlertType = "scan_complete"
	// AlertTypeScanFailed indicates a scan has failed.
	AlertTypeScanFailed AlertType = "scan_failed"
	// AlertTypePolicyViolation indicates a policy violation was detected.
	AlertTypePolicyViolation AlertType = "policy_violation"
	// AlertTypeDeploymentFailed indicates a deployment has failed.
	AlertTypeDeploymentFailed AlertType = "deployment_failed"
	// AlertTypeRollback indicates a rollback was performed.
	AlertTypeRollback AlertType = "rollback"
	// AlertTypeFindingsDetected indicates security findings were detected.
	AlertTypeFindingsDetected AlertType = "findings_detected"
	// AlertTypeCustom indicates a custom alert type.
	AlertTypeCustom AlertType = "custom"
)

// Alert represents a notification to be sent.
type Alert struct {
	Timestamp time.Time         `json:"timestamp"`
	Metadata  map[string]string `json:"metadata,omitempty"`
	ID        string            `json:"id"`
	Title     string            `json:"title"`
	Message   string            `json:"message"`
	Source    string            `json:"source"`
	Type      AlertType         `json:"type"`
	Severity  Severity          `json:"severity"`
	Findings  []model.Finding   `json:"findings,omitempty"`
}

// Notifier is the interface for sending notifications.
type Notifier interface {
	// Name returns the notifier name.
	Name() string

	// Send sends an alert notification.
	Send(ctx context.Context, alert Alert) error

	// SendBatch sends multiple alerts.
	SendBatch(ctx context.Context, alerts []Alert) error

	// IsEnabled returns whether the notifier is enabled.
	IsEnabled() bool
}

// NotifyResult contains the result of a notification attempt.
type NotifyResult struct {
	// Timestamp when the notification was sent.
	Timestamp time.Time `json:"timestamp"`

	// Error message if the notification failed.
	Error string `json:"error,omitempty"`

	// AlertID is the ID of the alert that was sent.
	AlertID string `json:"alert_id"`

	// Notifier is the name of the notifier used.
	Notifier string `json:"notifier"`

	// Success indicates whether the notification was successful.
	Success bool `json:"success"`
}

// AlertBuilder provides a fluent interface for creating alerts.
type AlertBuilder struct {
	alert Alert
}

// NewAlert creates a new AlertBuilder.
func NewAlert() *AlertBuilder {
	return &AlertBuilder{
		alert: Alert{
			Timestamp: time.Now().UTC(),
			Metadata:  make(map[string]string),
		},
	}
}

// WithID sets the alert ID.
func (b *AlertBuilder) WithID(id string) *AlertBuilder {
	b.alert.ID = id
	return b
}

// WithTitle sets the alert title.
func (b *AlertBuilder) WithTitle(title string) *AlertBuilder {
	b.alert.Title = title
	return b
}

// WithMessage sets the alert message.
func (b *AlertBuilder) WithMessage(msg string) *AlertBuilder {
	b.alert.Message = msg
	return b
}

// WithType sets the alert type.
func (b *AlertBuilder) WithType(t AlertType) *AlertBuilder {
	b.alert.Type = t
	return b
}

// WithSeverity sets the alert severity.
func (b *AlertBuilder) WithSeverity(s Severity) *AlertBuilder {
	b.alert.Severity = s
	return b
}

// WithSource sets the alert source.
func (b *AlertBuilder) WithSource(source string) *AlertBuilder {
	b.alert.Source = source
	return b
}

// WithMetadata adds metadata to the alert.
func (b *AlertBuilder) WithMetadata(key, value string) *AlertBuilder {
	b.alert.Metadata[key] = value
	return b
}

// WithFindings adds findings to the alert.
func (b *AlertBuilder) WithFindings(findings []model.Finding) *AlertBuilder {
	b.alert.Findings = findings
	return b
}

// Build returns the constructed alert.
func (b *AlertBuilder) Build() Alert {
	return b.alert
}

// SeverityFromModel converts a model.Severity to alerting.Severity.
func SeverityFromModel(s model.Severity) Severity {
	switch s {
	case model.SeverityCritical:
		return SeverityCritical
	case model.SeverityHigh:
		return SeverityHigh
	case model.SeverityMedium:
		return SeverityMedium
	case model.SeverityLow:
		return SeverityLow
	case model.SeverityInfo:
		return SeverityInfo
	default:
		return SeverityInfo
	}
}

// SeverityColor returns a color code for the severity (useful for Slack).
func SeverityColor(s Severity) string {
	switch s {
	case SeverityCritical:
		return "#dc3545" // Red
	case SeverityHigh:
		return "#fd7e14" // Orange
	case SeverityMedium:
		return "#ffc107" // Yellow
	case SeverityLow:
		return "#17a2b8" // Cyan
	case SeverityInfo:
		return "#6c757d" // Gray
	default:
		return "#6c757d"
	}
}

// SeverityEmoji returns an emoji for the severity.
func SeverityEmoji(s Severity) string {
	switch s {
	case SeverityCritical:
		return ":rotating_light:"
	case SeverityHigh:
		return ":warning:"
	case SeverityMedium:
		return ":large_orange_diamond:"
	case SeverityLow:
		return ":large_blue_diamond:"
	case SeverityInfo:
		return ":information_source:"
	default:
		return ":grey_question:"
	}
}
