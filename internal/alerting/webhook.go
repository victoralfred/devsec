package alerting

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// WebhookConfig holds configuration for the webhook notifier.
type WebhookConfig struct {
	// Headers to include in requests.
	Headers map[string]string

	// URL is the webhook endpoint URL.
	URL string

	// Secret for HMAC signature (optional).
	Secret string

	// Method is the HTTP method (default: POST).
	Method string

	// ContentType is the content type header (default: application/json).
	ContentType string

	// SignatureHeader is the header name for the signature (default: X-Signature-256).
	SignatureHeader string

	// Timeout for HTTP requests.
	Timeout time.Duration

	// Enabled indicates whether the notifier is enabled.
	Enabled bool

	// IncludeTimestamp adds timestamp header.
	IncludeTimestamp bool
}

// WebhookOption configures WebhookConfig.
type WebhookOption func(*WebhookConfig)

// WithWebhookSecret sets the HMAC secret.
func WithWebhookSecret(secret string) WebhookOption {
	return func(c *WebhookConfig) {
		c.Secret = secret
	}
}

// WithWebhookMethod sets the HTTP method.
func WithWebhookMethod(method string) WebhookOption {
	return func(c *WebhookConfig) {
		c.Method = method
	}
}

// WithWebhookHeaders sets custom headers.
func WithWebhookHeaders(headers map[string]string) WebhookOption {
	return func(c *WebhookConfig) {
		c.Headers = headers
	}
}

// WithWebhookTimeout sets the HTTP timeout.
func WithWebhookTimeout(d time.Duration) WebhookOption {
	return func(c *WebhookConfig) {
		c.Timeout = d
	}
}

// WithWebhookEnabled sets whether the notifier is enabled.
func WithWebhookEnabled(enabled bool) WebhookOption {
	return func(c *WebhookConfig) {
		c.Enabled = enabled
	}
}

// WithWebhookSignatureHeader sets the signature header name.
func WithWebhookSignatureHeader(header string) WebhookOption {
	return func(c *WebhookConfig) {
		c.SignatureHeader = header
	}
}

// WithWebhookTimestamp enables timestamp header.
func WithWebhookTimestamp(enabled bool) WebhookOption {
	return func(c *WebhookConfig) {
		c.IncludeTimestamp = enabled
	}
}

// WebhookNotifier sends notifications to a generic webhook.
type WebhookNotifier struct {
	client *http.Client
	config WebhookConfig
}

// WebhookPayload is the payload sent to webhooks.
type WebhookPayload struct {
	Timestamp time.Time `json:"timestamp"`
	Version   string    `json:"version"`
	Source    string    `json:"source"`
	Alert     Alert     `json:"alert"`
}

// NewWebhookNotifier creates a new webhook notifier.
func NewWebhookNotifier(webhookURL string, opts ...WebhookOption) (*WebhookNotifier, error) {
	if webhookURL == "" {
		return nil, ErrInvalidWebhookURL
	}

	// Validate URL.
	if _, err := url.Parse(webhookURL); err != nil {
		return nil, ErrInvalidWebhookURL
	}

	config := WebhookConfig{
		URL:              webhookURL,
		Method:           http.MethodPost,
		ContentType:      "application/json",
		SignatureHeader:  "X-Signature-256",
		Timeout:          10 * time.Second,
		Enabled:          true,
		Headers:          make(map[string]string),
		IncludeTimestamp: true,
	}

	for _, opt := range opts {
		opt(&config)
	}

	return &WebhookNotifier{
		config: config,
		client: &http.Client{
			Timeout: config.Timeout,
		},
	}, nil
}

// Name returns the notifier name.
func (n *WebhookNotifier) Name() string {
	return "webhook"
}

// IsEnabled returns whether the notifier is enabled.
func (n *WebhookNotifier) IsEnabled() bool {
	return n.config.Enabled
}

// Send sends an alert to the webhook.
func (n *WebhookNotifier) Send(ctx context.Context, alert Alert) error {
	if ctx == nil {
		return ErrNilContext
	}

	if !n.config.Enabled {
		return ErrNotifierDisabled
	}

	payload := WebhookPayload{
		Version:   "1.0",
		Source:    "devsec",
		Timestamp: time.Now().UTC(),
		Alert:     alert,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return NewNotifyError("marshal", n.Name(), alert.ID, err)
	}

	req, err := http.NewRequestWithContext(ctx, n.config.Method, n.config.URL, bytes.NewReader(body))
	if err != nil {
		return NewNotifyError("create request", n.Name(), alert.ID, err)
	}

	// Set headers.
	req.Header.Set("Content-Type", n.config.ContentType)
	req.Header.Set("User-Agent", "DevSec/1.0")

	for k, v := range n.config.Headers {
		req.Header.Set(k, v)
	}

	// Add timestamp header if enabled.
	if n.config.IncludeTimestamp {
		req.Header.Set("X-Timestamp", fmt.Sprintf("%d", payload.Timestamp.Unix()))
	}

	// Add HMAC signature if secret is configured.
	if n.config.Secret != "" {
		signature := n.computeSignature(body)
		req.Header.Set(n.config.SignatureHeader, "sha256="+signature)
	}

	resp, err := n.client.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return NewNotifyError("send", n.Name(), alert.ID, ErrTimeout)
		}
		return NewNotifyError("send", n.Name(), alert.ID, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusTooManyRequests {
		return NewNotifyError("send", n.Name(), alert.ID, ErrRateLimited)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(resp.Body)
		return NewNotifyError("send", n.Name(), alert.ID,
			fmt.Errorf("%w: status %d: %s", ErrSendFailed, resp.StatusCode, string(respBody)))
	}

	return nil
}

// SendBatch sends multiple alerts to the webhook.
func (n *WebhookNotifier) SendBatch(ctx context.Context, alerts []Alert) error {
	if ctx == nil {
		return ErrNilContext
	}

	if !n.config.Enabled {
		return ErrNotifierDisabled
	}

	var lastErr error
	for i := range alerts {
		if err := n.Send(ctx, alerts[i]); err != nil {
			lastErr = err
		}
	}

	return lastErr
}

// computeSignature computes HMAC-SHA256 signature.
func (n *WebhookNotifier) computeSignature(payload []byte) string {
	h := hmac.New(sha256.New, []byte(n.config.Secret))
	h.Write(payload)
	return hex.EncodeToString(h.Sum(nil))
}

// VerifySignature verifies an HMAC-SHA256 signature.
func VerifySignature(payload []byte, signature, secret string) bool {
	if secret == "" || signature == "" {
		return false
	}

	// Remove "sha256=" prefix if present.
	if len(signature) > 7 && signature[:7] == "sha256=" {
		signature = signature[7:]
	}

	h := hmac.New(sha256.New, []byte(secret))
	h.Write(payload)
	expected := hex.EncodeToString(h.Sum(nil))

	return hmac.Equal([]byte(expected), []byte(signature))
}
