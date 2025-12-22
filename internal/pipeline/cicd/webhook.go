package cicd

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Webhook-specific errors.
var (
	ErrInvalidWebhookSignature = errors.New("invalid webhook signature")
	ErrMissingWebhookSignature = errors.New("missing webhook signature")
	ErrInvalidWebhookPayload   = errors.New("invalid webhook payload format")
)

// WebhookProvider implements the Provider interface for generic webhooks.
type WebhookProvider struct {
	config ProviderConfig
}

// WebhookOption configures a WebhookProvider.
type WebhookOption func(*WebhookProvider)

// WithWebhookSecret sets the webhook secret for signature verification.
func WithWebhookSecret(secret string) WebhookOption {
	return func(w *WebhookProvider) {
		w.config.Secret = secret
	}
}

// WithWebhookURL sets the callback URL for status updates.
func WithWebhookURL(url string) WebhookOption {
	return func(w *WebhookProvider) {
		w.config.WebhookURL = url
	}
}

// WithWebhookHeaders sets custom headers for webhook requests.
func WithWebhookHeaders(headers map[string]string) WebhookOption {
	return func(w *WebhookProvider) {
		w.config.Headers = headers
	}
}

// WithWebhookSkipTLSVerify sets whether to skip TLS verification.
func WithWebhookSkipTLSVerify(skip bool) WebhookOption {
	return func(w *WebhookProvider) {
		w.config.SkipTLSVerify = skip
	}
}

// NewWebhookProvider creates a new webhook provider.
func NewWebhookProvider(opts ...WebhookOption) *WebhookProvider {
	w := &WebhookProvider{
		config: ProviderConfig{},
	}

	for _, opt := range opts {
		opt(w)
	}

	return w
}

// Type returns the provider type.
func (w *WebhookProvider) Type() ProviderType {
	return ProviderWebhook
}

// ParseEvent parses a generic webhook event.
func (w *WebhookProvider) ParseEvent(ctx context.Context, body []byte, headers map[string]string) (*Event, error) {
	if ctx == nil {
		return nil, errors.New("context cannot be nil")
	}

	// Check context cancellation.
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	// Verify signature if secret is configured.
	if w.config.Secret != "" {
		if err := w.verifySignature(body, headers); err != nil {
			return nil, err
		}
	}

	// Parse the generic webhook payload.
	return w.parsePayload(body)
}

// verifySignature verifies the webhook signature.
func (w *WebhookProvider) verifySignature(body []byte, headers map[string]string) error {
	// Try common signature header names.
	signature := headers["X-Signature"]
	if signature == "" {
		signature = headers["x-signature"]
	}
	if signature == "" {
		signature = headers["X-Hub-Signature-256"]
	}
	if signature == "" {
		signature = headers["x-hub-signature-256"]
	}
	if signature == "" {
		signature = headers["X-Webhook-Signature"]
	}
	if signature == "" {
		signature = headers["x-webhook-signature"]
	}

	if signature == "" {
		return ErrMissingWebhookSignature
	}

	// Handle "sha256=" prefix if present.
	signatureValue := signature
	if strings.HasPrefix(signature, "sha256=") {
		signatureValue = signature[7:]
	}

	expectedMAC, err := hex.DecodeString(signatureValue)
	if err != nil {
		return ErrInvalidWebhookSignature
	}

	mac := hmac.New(sha256.New, []byte(w.config.Secret))
	mac.Write(body)
	actualMAC := mac.Sum(nil)

	if !hmac.Equal(expectedMAC, actualMAC) {
		return ErrInvalidWebhookSignature
	}

	return nil
}

// webhookPayload represents a generic webhook payload.
type webhookPayload struct {
	Metadata   map[string]string `json:"metadata"`
	Event      string            `json:"event"`
	Type       string            `json:"type"`
	Ref        string            `json:"ref"`
	SHA        string            `json:"sha"`
	Commit     string            `json:"commit"`
	Repository string            `json:"repository"`
	Repo       string            `json:"repo"`
	Branch     string            `json:"branch"`
	Author     string            `json:"author"`
	Sender     string            `json:"sender"`
	Message    string            `json:"message"`
}

// parsePayload parses the webhook payload.
func (w *WebhookProvider) parsePayload(body []byte) (*Event, error) {
	var payload webhookPayload
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidWebhookPayload, err)
	}

	// Determine event type.
	eventType := w.determineEventType(payload)

	// Get repository name.
	repo := payload.Repository
	if repo == "" {
		repo = payload.Repo
	}

	// Get SHA.
	sha := payload.SHA
	if sha == "" {
		sha = payload.Commit
	}

	// Get author.
	author := payload.Author
	if author == "" {
		author = payload.Sender
	}

	return &Event{
		Provider:  ProviderWebhook,
		Type:      eventType,
		Ref:       payload.Ref,
		SHA:       sha,
		Repo:      repo,
		Branch:    payload.Branch,
		Author:    author,
		Message:   payload.Message,
		Timestamp: time.Now(),
		Metadata:  payload.Metadata,
	}, nil
}

// determineEventType determines the event type from the payload.
func (w *WebhookProvider) determineEventType(payload webhookPayload) EventType {
	// Check event field first.
	eventStr := payload.Event
	if eventStr == "" {
		eventStr = payload.Type
	}

	switch strings.ToLower(eventStr) {
	case "push":
		return EventPush
	case "pull_request", "merge_request", "pr", "mr":
		return EventPullRequest
	case "tag", "tag_push":
		return EventTag
	case "schedule", "scheduled":
		return EventSchedule
	case "manual", "workflow_dispatch":
		return EventManual
	default:
		// Default to push if we can't determine.
		return EventPush
	}
}

// UpdateStatus updates the pipeline status via webhook callback.
func (w *WebhookProvider) UpdateStatus(ctx context.Context, status RunStatus) error {
	if ctx == nil {
		return errors.New("context cannot be nil")
	}

	// Check context cancellation.
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	// This is a placeholder - actual implementation would POST to webhook URL.
	// Would use http.Client to send status updates to w.config.WebhookURL.
	return nil
}

// CreateCheck creates a check status (for webhook, this is often a no-op).
func (w *WebhookProvider) CreateCheck(ctx context.Context, event Event, name string) (string, error) {
	if ctx == nil {
		return "", errors.New("context cannot be nil")
	}

	// Check context cancellation.
	select {
	case <-ctx.Done():
		return "", ctx.Err()
	default:
	}

	// For webhooks, we generate a unique ID and optionally notify via callback.
	checkID := fmt.Sprintf("webhook_%s_%d", name, time.Now().UnixNano())
	return checkID, nil
}

// UpdateCheck updates an existing check status.
func (w *WebhookProvider) UpdateCheck(ctx context.Context, checkID string, status RunStatus) error {
	if ctx == nil {
		return errors.New("context cannot be nil")
	}

	// Check context cancellation.
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	// This is a placeholder - actual implementation would POST to webhook URL.
	return nil
}

// MapStatusToWebhook converts internal status to webhook status string.
func MapStatusToWebhook(status StatusType) string {
	switch status {
	case StatusPending:
		return "pending"
	case StatusRunning, StatusInProgress:
		return "running"
	case StatusSuccess:
		return "success"
	case StatusFailure:
		return "failure"
	case StatusError:
		return "error"
	case StatusCanceled:
		return "canceled"
	case StatusNeutral:
		return "neutral"
	default:
		return "pending"
	}
}
