// Package cicd provides CI/CD integration for the pipeline orchestrator.
package cicd

import (
	"context"
	"time"
)

// ProviderType represents the CI/CD provider type.
type ProviderType string

// Provider types.
const (
	ProviderGitHub  ProviderType = "github"
	ProviderGitLab  ProviderType = "gitlab"
	ProviderWebhook ProviderType = "webhook"
)

// IsValid checks if the provider type is valid.
func (p ProviderType) IsValid() bool {
	switch p {
	case ProviderGitHub, ProviderGitLab, ProviderWebhook:
		return true
	default:
		return false
	}
}

// EventType represents the CI/CD event type.
type EventType string

// Event types.
const (
	EventPush        EventType = "push"
	EventPullRequest EventType = "pull_request"
	EventTag         EventType = "tag"
	EventSchedule    EventType = "schedule"
	EventManual      EventType = "manual"
)

// IsValid checks if the event type is valid.
func (e EventType) IsValid() bool {
	switch e {
	case EventPush, EventPullRequest, EventTag, EventSchedule, EventManual:
		return true
	default:
		return false
	}
}

// StatusType represents the pipeline run status.
type StatusType string

// Status types.
const (
	StatusPending    StatusType = "pending"
	StatusRunning    StatusType = "running"
	StatusSuccess    StatusType = "success"
	StatusFailure    StatusType = "failure"
	StatusCanceled   StatusType = "canceled"
	StatusError      StatusType = "error"
	StatusNeutral    StatusType = "neutral"
	StatusInProgress StatusType = "in_progress"
)

// IsTerminal returns true if the status is a terminal state.
func (s StatusType) IsTerminal() bool {
	switch s {
	case StatusSuccess, StatusFailure, StatusCanceled, StatusError, StatusNeutral:
		return true
	default:
		return false
	}
}

// Event represents a CI/CD event.
// Fields are ordered for optimal memory alignment.
type Event struct {
	Timestamp time.Time         `json:"timestamp"`
	Metadata  map[string]string `json:"metadata,omitempty"`
	Provider  ProviderType      `json:"provider"`
	Type      EventType         `json:"type"`
	Ref       string            `json:"ref"`
	SHA       string            `json:"sha"`
	Repo      string            `json:"repo"`
	Branch    string            `json:"branch,omitempty"`
	Author    string            `json:"author,omitempty"`
	Message   string            `json:"message,omitempty"`
}

// RunStatus represents the status of a pipeline run.
// Fields are ordered for optimal memory alignment.
type RunStatus struct {
	StartTime   time.Time         `json:"start_time"`
	EndTime     time.Time         `json:"end_time,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
	RunID       string            `json:"run_id"`
	PipelineRef string            `json:"pipeline_ref"`
	Description string            `json:"description,omitempty"`
	URL         string            `json:"url,omitempty"`
	Status      StatusType        `json:"status"`
	Stages      []StageStatus     `json:"stages,omitempty"`
	Duration    time.Duration     `json:"duration"`
}

// StageStatus represents the status of a pipeline stage.
type StageStatus struct {
	StartTime   time.Time     `json:"start_time"`
	EndTime     time.Time     `json:"end_time,omitempty"`
	Name        string        `json:"name"`
	Description string        `json:"description,omitempty"`
	Status      StatusType    `json:"status"`
	Duration    time.Duration `json:"duration"`
}

// Provider interface for CI/CD providers.
type Provider interface {
	// Type returns the provider type.
	Type() ProviderType

	// ParseEvent parses an event from the request body and headers.
	ParseEvent(ctx context.Context, body []byte, headers map[string]string) (*Event, error)

	// UpdateStatus updates the status of a pipeline run.
	UpdateStatus(ctx context.Context, status RunStatus) error

	// CreateCheck creates a check run or status.
	CreateCheck(ctx context.Context, event Event, name string) (string, error)

	// UpdateCheck updates an existing check run or status.
	UpdateCheck(ctx context.Context, checkID string, status RunStatus) error
}

// Notifier interface for sending notifications.
type Notifier interface {
	// Notify sends a notification about pipeline status.
	Notify(ctx context.Context, status RunStatus) error
}

// ProviderConfig holds common provider configuration.
// Fields are ordered for optimal memory alignment.
type ProviderConfig struct {
	Headers       map[string]string `json:"headers,omitempty"`
	BaseURL       string            `json:"base_url,omitempty"`
	Token         string            `json:"token,omitempty"`
	Secret        string            `json:"secret,omitempty"`
	WebhookURL    string            `json:"webhook_url,omitempty"`
	SkipTLSVerify bool              `json:"skip_tls_verify,omitempty"`
}

// Validate validates the provider configuration.
func (c *ProviderConfig) Validate() error {
	// Base URL and token are optional but if provided should be non-empty strings.
	// No specific validation needed for basic config.
	return nil
}

// DetectProvider attempts to detect the CI/CD provider from environment.
func DetectProvider() ProviderType {
	// Detection logic would check for CI/CD-specific environment variables.
	// This is a placeholder - actual implementation would check env vars.
	return ProviderWebhook
}

// DefaultProviderConfig returns default configuration.
func DefaultProviderConfig() ProviderConfig {
	return ProviderConfig{}
}
