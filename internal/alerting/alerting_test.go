package alerting

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/victoralfred/devsec/internal/model"
)

func TestAlertBuilder(t *testing.T) {
	t.Parallel()

	alert := NewAlert().
		WithID("test-123").
		WithTitle("Test Alert").
		WithMessage("This is a test").
		WithType(AlertTypeScanComplete).
		WithSeverity(SeverityHigh).
		WithSource("test").
		WithMetadata("key", "value").
		Build()

	if alert.ID != "test-123" {
		t.Errorf("expected ID=test-123, got %s", alert.ID)
	}

	if alert.Title != "Test Alert" {
		t.Errorf("expected Title=Test Alert, got %s", alert.Title)
	}

	if alert.Severity != SeverityHigh {
		t.Errorf("expected Severity=high, got %s", alert.Severity)
	}

	if alert.Metadata["key"] != "value" {
		t.Errorf("expected metadata key=value, got %s", alert.Metadata["key"])
	}

	if alert.Timestamp.IsZero() {
		t.Error("expected non-zero timestamp")
	}
}

func TestAlertBuilder_WithFindings(t *testing.T) {
	t.Parallel()

	findings := []model.Finding{
		{ID: "1", Severity: model.SeverityHigh},
		{ID: "2", Severity: model.SeverityCritical},
	}

	alert := NewAlert().
		WithFindings(findings).
		Build()

	if len(alert.Findings) != 2 {
		t.Errorf("expected 2 findings, got %d", len(alert.Findings))
	}
}

func TestSeverityFromModel(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input    model.Severity
		expected Severity
	}{
		{model.SeverityCritical, SeverityCritical},
		{model.SeverityHigh, SeverityHigh},
		{model.SeverityMedium, SeverityMedium},
		{model.SeverityLow, SeverityLow},
		{model.SeverityInfo, SeverityInfo},
		{model.Severity("unknown"), SeverityInfo},
	}

	for _, tt := range tests {
		t.Run(string(tt.input), func(t *testing.T) {
			t.Parallel()
			got := SeverityFromModel(tt.input)
			if got != tt.expected {
				t.Errorf("SeverityFromModel(%s) = %s, want %s", tt.input, got, tt.expected)
			}
		})
	}
}

func TestSeverityColor(t *testing.T) {
	t.Parallel()

	tests := []struct {
		severity Severity
		expected string
	}{
		{SeverityCritical, "#dc3545"},
		{SeverityHigh, "#fd7e14"},
		{SeverityMedium, "#ffc107"},
		{SeverityLow, "#17a2b8"},
		{SeverityInfo, "#6c757d"},
		{Severity("unknown"), "#6c757d"},
	}

	for _, tt := range tests {
		t.Run(string(tt.severity), func(t *testing.T) {
			t.Parallel()
			got := SeverityColor(tt.severity)
			if got != tt.expected {
				t.Errorf("SeverityColor(%s) = %s, want %s", tt.severity, got, tt.expected)
			}
		})
	}
}

func TestSeverityEmoji(t *testing.T) {
	t.Parallel()

	// Just test that each severity returns non-empty.
	severities := []Severity{SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityInfo}

	for _, s := range severities {
		emoji := SeverityEmoji(s)
		if emoji == "" {
			t.Errorf("SeverityEmoji(%s) returned empty", s)
		}
	}
}

func TestSlackNotifier_InvalidURL(t *testing.T) {
	t.Parallel()

	_, err := NewSlackNotifier("")
	if err != ErrInvalidWebhookURL {
		t.Errorf("expected ErrInvalidWebhookURL, got %v", err)
	}

	_, err = NewSlackNotifier("http://example.com/webhook")
	if err != ErrInvalidWebhookURL {
		t.Errorf("expected ErrInvalidWebhookURL for non-Slack URL, got %v", err)
	}
}

func TestSlackNotifier_Send(t *testing.T) {
	t.Parallel()

	var receivedPayload []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedPayload, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Create notifier with test server URL (we need to bypass URL validation for testing).
	notifier := &SlackNotifier{
		config: SlackConfig{
			WebhookURL: server.URL,
			Enabled:    true,
			Username:   "TestBot",
			IconEmoji:  ":robot:",
			Timeout:    5 * time.Second,
		},
		client: &http.Client{Timeout: 5 * time.Second},
	}

	alert := NewAlert().
		WithID("test-1").
		WithTitle("Test Alert").
		WithMessage("Test message").
		WithSeverity(SeverityHigh).
		WithType(AlertTypeScanComplete).
		WithSource("test").
		Build()

	ctx := context.Background()
	err := notifier.Send(ctx, alert)

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if len(receivedPayload) == 0 {
		t.Error("expected payload to be sent")
	}

	// Verify JSON structure.
	var msg slackMessage
	if err := json.Unmarshal(receivedPayload, &msg); err != nil {
		t.Errorf("failed to parse payload: %v", err)
	}

	if msg.Username != "TestBot" {
		t.Errorf("expected username=TestBot, got %s", msg.Username)
	}
}

func TestSlackNotifier_Disabled(t *testing.T) {
	t.Parallel()

	notifier := &SlackNotifier{
		config: SlackConfig{
			WebhookURL: "https://hooks.slack.com/test",
			Enabled:    false,
		},
	}

	alert := NewAlert().WithID("test").Build()

	err := notifier.Send(context.Background(), alert)
	if err != ErrNotifierDisabled {
		t.Errorf("expected ErrNotifierDisabled, got %v", err)
	}
}

func TestSlackNotifier_NilContext(t *testing.T) {
	t.Parallel()

	notifier := &SlackNotifier{
		config: SlackConfig{
			WebhookURL: "https://hooks.slack.com/test",
			Enabled:    true,
		},
		client: &http.Client{Timeout: 5 * time.Second},
	}

	alert := NewAlert().WithID("test").Build()

	err := notifier.Send(nil, alert) //nolint:staticcheck // intentionally passing nil context for testing
	if err != ErrNilContext {
		t.Errorf("expected ErrNilContext, got %v", err)
	}
}

func TestWebhookNotifier_InvalidURL(t *testing.T) {
	t.Parallel()

	_, err := NewWebhookNotifier("")
	if err != ErrInvalidWebhookURL {
		t.Errorf("expected ErrInvalidWebhookURL, got %v", err)
	}
}

func TestWebhookNotifier_Send(t *testing.T) {
	t.Parallel()

	var receivedPayload []byte
	var receivedHeaders http.Header

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedPayload, _ = io.ReadAll(r.Body)
		receivedHeaders = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	notifier, err := NewWebhookNotifier(server.URL,
		WithWebhookSecret("test-secret"),
		WithWebhookHeaders(map[string]string{"X-Custom": "header"}),
	)
	if err != nil {
		t.Fatalf("failed to create notifier: %v", err)
	}

	alert := NewAlert().
		WithID("test-1").
		WithTitle("Test Alert").
		WithSeverity(SeverityCritical).
		Build()

	ctx := context.Background()
	err = notifier.Send(ctx, alert)

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	// Verify payload.
	var payload WebhookPayload
	if err := json.Unmarshal(receivedPayload, &payload); err != nil {
		t.Errorf("failed to parse payload: %v", err)
	}

	if payload.Alert.ID != "test-1" {
		t.Errorf("expected alert ID=test-1, got %s", payload.Alert.ID)
	}

	if payload.Version != "1.0" {
		t.Errorf("expected version=1.0, got %s", payload.Version)
	}

	// Verify headers.
	if receivedHeaders.Get("X-Custom") != "header" {
		t.Error("expected custom header")
	}

	if receivedHeaders.Get("X-Signature-256") == "" {
		t.Error("expected signature header")
	}

	if receivedHeaders.Get("X-Timestamp") == "" {
		t.Error("expected timestamp header")
	}
}

func TestWebhookNotifier_RateLimited(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer server.Close()

	notifier, _ := NewWebhookNotifier(server.URL)
	alert := NewAlert().WithID("test").Build()

	err := notifier.Send(context.Background(), alert)

	if !IsRateLimited(err) {
		t.Errorf("expected rate limited error, got %v", err)
	}
}

func TestWebhookNotifier_Disabled(t *testing.T) {
	t.Parallel()

	notifier, _ := NewWebhookNotifier("http://example.com",
		WithWebhookEnabled(false),
	)

	alert := NewAlert().WithID("test").Build()

	err := notifier.Send(context.Background(), alert)
	if err != ErrNotifierDisabled {
		t.Errorf("expected ErrNotifierDisabled, got %v", err)
	}
}

func TestVerifySignature(t *testing.T) {
	t.Parallel()

	payload := []byte(`{"test": "data"}`)
	secret := "my-secret"

	// Create notifier to compute signature.
	notifier := &WebhookNotifier{
		config: WebhookConfig{Secret: secret},
	}
	signature := notifier.computeSignature(payload)

	// Verify with prefix.
	if !VerifySignature(payload, "sha256="+signature, secret) {
		t.Error("signature verification failed with prefix")
	}

	// Verify without prefix.
	if !VerifySignature(payload, signature, secret) {
		t.Error("signature verification failed without prefix")
	}

	// Invalid signature.
	if VerifySignature(payload, "invalid", secret) {
		t.Error("expected verification to fail for invalid signature")
	}

	// Empty secret.
	if VerifySignature(payload, signature, "") {
		t.Error("expected verification to fail with empty secret")
	}
}

func TestManager_AddRemoveNotifier(t *testing.T) {
	t.Parallel()

	manager := NewManager()

	// Add mock notifier.
	mock := &mockNotifier{name: "test", enabled: true}
	manager.AddNotifier(mock)

	if len(manager.Notifiers()) != 1 {
		t.Errorf("expected 1 notifier, got %d", len(manager.Notifiers()))
	}

	if manager.GetNotifier("test") == nil {
		t.Error("expected to find notifier 'test'")
	}

	if manager.GetNotifier("nonexistent") != nil {
		t.Error("expected nil for nonexistent notifier")
	}

	// Remove notifier.
	manager.RemoveNotifier("test")

	if len(manager.Notifiers()) != 0 {
		t.Errorf("expected 0 notifiers after removal, got %d", len(manager.Notifiers()))
	}
}

func TestManager_Send(t *testing.T) {
	t.Parallel()

	manager := NewManager()

	var sent int32
	mock1 := &mockNotifier{name: "mock1", enabled: true, onSend: func() { atomic.AddInt32(&sent, 1) }}
	mock2 := &mockNotifier{name: "mock2", enabled: true, onSend: func() { atomic.AddInt32(&sent, 1) }}
	mock3 := &mockNotifier{name: "mock3", enabled: false} // Disabled.

	manager.AddNotifier(mock1)
	manager.AddNotifier(mock2)
	manager.AddNotifier(mock3)

	alert := NewAlert().WithID("test").WithSeverity(SeverityHigh).Build()
	results := manager.Send(context.Background(), alert)

	// Should have 2 results (only enabled notifiers).
	if len(results) != 2 {
		t.Errorf("expected 2 results, got %d", len(results))
	}

	if atomic.LoadInt32(&sent) != 2 {
		t.Errorf("expected 2 sends, got %d", sent)
	}

	for _, r := range results {
		if !r.Success {
			t.Errorf("expected success for %s", r.Notifier)
		}
	}
}

func TestManager_SendAsync(t *testing.T) {
	t.Parallel()

	manager := NewManager()

	var sent int32
	mock := &mockNotifier{name: "async", enabled: true, onSend: func() { atomic.AddInt32(&sent, 1) }}
	manager.AddNotifier(mock)

	alert := NewAlert().WithID("async-test").WithSeverity(SeverityCritical).Build()
	resultCh := manager.SendAsync(context.Background(), alert)

	results := make([]NotifyResult, 0, 1)
	for r := range resultCh {
		results = append(results, r)
	}

	if len(results) != 1 {
		t.Errorf("expected 1 result, got %d", len(results))
	}

	if atomic.LoadInt32(&sent) != 1 {
		t.Errorf("expected 1 send, got %d", sent)
	}
}

func TestManager_NoNotifiers(t *testing.T) {
	t.Parallel()

	manager := NewManager()
	alert := NewAlert().WithID("test").Build()

	results := manager.Send(context.Background(), alert)

	if len(results) != 1 {
		t.Errorf("expected 1 result, got %d", len(results))
	}

	if results[0].Success {
		t.Error("expected failure when no notifiers")
	}

	if results[0].Error != ErrNoNotifiers.Error() {
		t.Errorf("expected ErrNoNotifiers, got %s", results[0].Error)
	}
}

func TestManager_MinSeverity(t *testing.T) {
	t.Parallel()

	manager := NewManager(WithMinSeverity(SeverityHigh))

	var sent int32
	mock := &mockNotifier{name: "test", enabled: true, onSend: func() { atomic.AddInt32(&sent, 1) }}
	manager.AddNotifier(mock)

	// Low severity should be filtered.
	alert := NewAlert().WithID("low").WithSeverity(SeverityLow).Build()
	results := manager.Send(context.Background(), alert)

	if len(results) != 0 {
		t.Errorf("expected 0 results for low severity, got %d", len(results))
	}

	if atomic.LoadInt32(&sent) != 0 {
		t.Errorf("expected 0 sends, got %d", sent)
	}

	// High severity should pass.
	alert = NewAlert().WithID("high").WithSeverity(SeverityHigh).Build()
	results = manager.Send(context.Background(), alert)

	if len(results) != 1 {
		t.Errorf("expected 1 result for high severity, got %d", len(results))
	}
}

func TestManager_EnabledCount(t *testing.T) {
	t.Parallel()

	manager := NewManager()

	manager.AddNotifier(&mockNotifier{name: "m1", enabled: true})
	manager.AddNotifier(&mockNotifier{name: "m2", enabled: false})
	manager.AddNotifier(&mockNotifier{name: "m3", enabled: true})

	if manager.EnabledCount() != 2 {
		t.Errorf("expected 2 enabled, got %d", manager.EnabledCount())
	}
}

func TestManager_Close(t *testing.T) {
	t.Parallel()

	manager := NewManager()

	var closed bool
	mock := &mockNotifierWithClose{
		mockNotifier: mockNotifier{name: "closable", enabled: true},
		onClose:      func() { closed = true },
	}
	manager.AddNotifier(mock)

	if err := manager.Close(); err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if !closed {
		t.Error("expected Close to be called")
	}

	if len(manager.Notifiers()) != 0 {
		t.Error("expected notifiers to be cleared after Close")
	}
}

func TestNotifyError(t *testing.T) {
	t.Parallel()

	err := NewNotifyError("send", "slack", "alert-123", ErrSendFailed)

	if err.Error() != "send: failed to send notification [notifier=slack, alert=alert-123]" {
		t.Errorf("unexpected error message: %s", err.Error())
	}

	if err.Unwrap() != ErrSendFailed {
		t.Error("expected unwrap to return ErrSendFailed")
	}

	// Without alert ID.
	err2 := NewNotifyError("send", "webhook", "", ErrTimeout)
	if err2.Error() != "send: notification timed out [notifier=webhook]" {
		t.Errorf("unexpected error message: %s", err2.Error())
	}
}

func TestErrorChecks(t *testing.T) {
	t.Parallel()

	timeoutErr := NewNotifyError("send", "test", "", ErrTimeout)
	rateLimitErr := NewNotifyError("send", "test", "", ErrRateLimited)
	sendErr := NewNotifyError("send", "test", "", ErrSendFailed)

	if !IsTimeout(timeoutErr) {
		t.Error("expected IsTimeout to return true")
	}

	if !IsRateLimited(rateLimitErr) {
		t.Error("expected IsRateLimited to return true")
	}

	if !IsSendFailed(sendErr) {
		t.Error("expected IsSendFailed to return true")
	}
}

// mockNotifier is a simple mock for testing.
type mockNotifier struct {
	onSend  func()
	name    string
	enabled bool
}

func (m *mockNotifier) Name() string {
	return m.name
}

func (m *mockNotifier) IsEnabled() bool {
	return m.enabled
}

func (m *mockNotifier) Send(_ context.Context, _ Alert) error {
	if m.onSend != nil {
		m.onSend()
	}
	return nil
}

func (m *mockNotifier) SendBatch(ctx context.Context, alerts []Alert) error {
	for i := range alerts {
		if err := m.Send(ctx, alerts[i]); err != nil {
			return err
		}
	}
	return nil
}

// mockNotifierWithClose adds Close support.
type mockNotifierWithClose struct {
	onClose func()
	mockNotifier
}

func (m *mockNotifierWithClose) Close() error {
	if m.onClose != nil {
		m.onClose()
	}
	return nil
}
