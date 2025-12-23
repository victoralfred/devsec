package alerting

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// SlackConfig holds configuration for the Slack notifier.
type SlackConfig struct {
	// WebhookURL is the Slack incoming webhook URL.
	WebhookURL string

	// Channel is the target channel (optional, uses webhook default).
	Channel string

	// Username is the bot username (optional).
	Username string

	// IconEmoji is the bot icon emoji (optional).
	IconEmoji string

	// Timeout for HTTP requests.
	Timeout time.Duration

	// Enabled indicates whether the notifier is enabled.
	Enabled bool
}

// SlackOption configures SlackConfig.
type SlackOption func(*SlackConfig)

// WithSlackChannel sets the channel.
func WithSlackChannel(channel string) SlackOption {
	return func(c *SlackConfig) {
		c.Channel = channel
	}
}

// WithSlackUsername sets the username.
func WithSlackUsername(username string) SlackOption {
	return func(c *SlackConfig) {
		c.Username = username
	}
}

// WithSlackIcon sets the icon emoji.
func WithSlackIcon(emoji string) SlackOption {
	return func(c *SlackConfig) {
		c.IconEmoji = emoji
	}
}

// WithSlackTimeout sets the HTTP timeout.
func WithSlackTimeout(d time.Duration) SlackOption {
	return func(c *SlackConfig) {
		c.Timeout = d
	}
}

// WithSlackEnabled sets whether the notifier is enabled.
func WithSlackEnabled(enabled bool) SlackOption {
	return func(c *SlackConfig) {
		c.Enabled = enabled
	}
}

// SlackNotifier sends notifications to Slack.
type SlackNotifier struct {
	client *http.Client
	config SlackConfig
}

// slackMessage represents a Slack message payload.
type slackMessage struct {
	Text        string            `json:"text,omitempty"`
	Channel     string            `json:"channel,omitempty"`
	Username    string            `json:"username,omitempty"`
	IconEmoji   string            `json:"icon_emoji,omitempty"`
	Attachments []slackAttachment `json:"attachments,omitempty"`
}

// slackAttachment represents a Slack message attachment.
type slackAttachment struct {
	Fallback  string       `json:"fallback"`
	Color     string       `json:"color,omitempty"`
	Title     string       `json:"title,omitempty"`
	Text      string       `json:"text,omitempty"`
	Footer    string       `json:"footer,omitempty"`
	Fields    []slackField `json:"fields,omitempty"`
	Timestamp int64        `json:"ts,omitempty"`
}

// slackField represents a field in a Slack attachment.
type slackField struct {
	Title string `json:"title"`
	Value string `json:"value"`
	Short bool   `json:"short"`
}

// NewSlackNotifier creates a new Slack notifier.
func NewSlackNotifier(webhookURL string, opts ...SlackOption) (*SlackNotifier, error) {
	if webhookURL == "" {
		return nil, ErrInvalidWebhookURL
	}

	if !strings.HasPrefix(webhookURL, "https://hooks.slack.com/") {
		return nil, ErrInvalidWebhookURL
	}

	config := SlackConfig{
		WebhookURL: webhookURL,
		Timeout:    10 * time.Second,
		Enabled:    true,
		Username:   "DevSec Bot",
		IconEmoji:  ":shield:",
	}

	for _, opt := range opts {
		opt(&config)
	}

	return &SlackNotifier{
		config: config,
		client: &http.Client{
			Timeout: config.Timeout,
		},
	}, nil
}

// Name returns the notifier name.
func (n *SlackNotifier) Name() string {
	return "slack"
}

// IsEnabled returns whether the notifier is enabled.
func (n *SlackNotifier) IsEnabled() bool {
	return n.config.Enabled
}

// Send sends an alert to Slack.
func (n *SlackNotifier) Send(ctx context.Context, alert Alert) error {
	if ctx == nil {
		return ErrNilContext
	}

	if !n.config.Enabled {
		return ErrNotifierDisabled
	}

	msg := n.buildMessage(alert)

	payload, err := json.Marshal(msg)
	if err != nil {
		return NewNotifyError("marshal", n.Name(), alert.ID, err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, n.config.WebhookURL, bytes.NewReader(payload))
	if err != nil {
		return NewNotifyError("create request", n.Name(), alert.ID, err)
	}

	req.Header.Set("Content-Type", "application/json")

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

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return NewNotifyError("send", n.Name(), alert.ID,
			fmt.Errorf("%w: status %d: %s", ErrSendFailed, resp.StatusCode, string(body)))
	}

	return nil
}

// SendBatch sends multiple alerts to Slack.
func (n *SlackNotifier) SendBatch(ctx context.Context, alerts []Alert) error {
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

// buildMessage builds a Slack message from an alert.
func (n *SlackNotifier) buildMessage(alert Alert) slackMessage {
	msg := slackMessage{
		Username:  n.config.Username,
		IconEmoji: n.config.IconEmoji,
	}

	if n.config.Channel != "" {
		msg.Channel = n.config.Channel
	}

	// Build attachment.
	attachment := slackAttachment{
		Fallback:  fmt.Sprintf("[%s] %s: %s", alert.Severity, alert.Title, alert.Message),
		Color:     SeverityColor(alert.Severity),
		Title:     fmt.Sprintf("%s %s", SeverityEmoji(alert.Severity), alert.Title),
		Text:      alert.Message,
		Footer:    fmt.Sprintf("DevSec | %s", alert.Source),
		Timestamp: alert.Timestamp.Unix(),
	}

	// Add fields.
	fields := []slackField{
		{Title: "Severity", Value: string(alert.Severity), Short: true},
		{Title: "Type", Value: string(alert.Type), Short: true},
	}

	// Add findings summary if present.
	if len(alert.Findings) > 0 {
		fields = append(fields, slackField{
			Title: "Findings",
			Value: fmt.Sprintf("%d findings detected", len(alert.Findings)),
			Short: true,
		})

		// Count by severity.
		counts := make(map[string]int)
		for i := range alert.Findings {
			counts[string(alert.Findings[i].Severity)]++
		}

		summary := formatFindingsSummary(counts)
		if summary != "" {
			fields = append(fields, slackField{
				Title: "Summary",
				Value: summary,
				Short: false,
			})
		}
	}

	// Add metadata fields.
	for k, v := range alert.Metadata {
		fields = append(fields, slackField{
			Title: k,
			Value: v,
			Short: true,
		})
	}

	attachment.Fields = fields
	msg.Attachments = []slackAttachment{attachment}

	return msg
}

// formatFindingsSummary formats finding counts as a string.
func formatFindingsSummary(counts map[string]int) string {
	var parts []string

	if c, ok := counts["critical"]; ok && c > 0 {
		parts = append(parts, fmt.Sprintf(":rotating_light: Critical: %d", c))
	}
	if c, ok := counts["high"]; ok && c > 0 {
		parts = append(parts, fmt.Sprintf(":warning: High: %d", c))
	}
	if c, ok := counts["medium"]; ok && c > 0 {
		parts = append(parts, fmt.Sprintf(":large_orange_diamond: Medium: %d", c))
	}
	if c, ok := counts["low"]; ok && c > 0 {
		parts = append(parts, fmt.Sprintf(":large_blue_diamond: Low: %d", c))
	}
	if c, ok := counts["info"]; ok && c > 0 {
		parts = append(parts, fmt.Sprintf(":information_source: Info: %d", c))
	}

	return strings.Join(parts, " | ")
}
