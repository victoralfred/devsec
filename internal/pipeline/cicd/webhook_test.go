package cicd

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"
)

func TestNewWebhookProvider(t *testing.T) {
	tests := []struct {
		name          string
		wantSecret    string
		wantURL       string
		opts          []WebhookOption
		wantHeaderLen int
		wantSkipTLS   bool
	}{
		{
			name:          "Default configuration",
			opts:          nil,
			wantSecret:    "",
			wantURL:       "",
			wantSkipTLS:   false,
			wantHeaderLen: 0,
		},
		{
			name: "With secret",
			opts: []WebhookOption{
				WithWebhookSecret("test-secret"),
			},
			wantSecret:    "test-secret",
			wantURL:       "",
			wantSkipTLS:   false,
			wantHeaderLen: 0,
		},
		{
			name: "With webhook URL",
			opts: []WebhookOption{
				WithWebhookURL("https://example.com/webhook"),
			},
			wantSecret:    "",
			wantURL:       "https://example.com/webhook",
			wantSkipTLS:   false,
			wantHeaderLen: 0,
		},
		{
			name: "With skip TLS verify",
			opts: []WebhookOption{
				WithWebhookSkipTLSVerify(true),
			},
			wantSecret:    "",
			wantURL:       "",
			wantSkipTLS:   true,
			wantHeaderLen: 0,
		},
		{
			name: "With headers",
			opts: []WebhookOption{
				WithWebhookHeaders(map[string]string{
					"X-Custom": "value",
				}),
			},
			wantSecret:    "",
			wantURL:       "",
			wantSkipTLS:   false,
			wantHeaderLen: 1,
		},
		{
			name: "With all options",
			opts: []WebhookOption{
				WithWebhookSecret("secret"),
				WithWebhookURL("https://callback.example.com"),
				WithWebhookSkipTLSVerify(true),
				WithWebhookHeaders(map[string]string{
					"Authorization": "Bearer token",
				}),
			},
			wantSecret:    "secret",
			wantURL:       "https://callback.example.com",
			wantSkipTLS:   true,
			wantHeaderLen: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := NewWebhookProvider(tt.opts...)

			if w.config.Secret != tt.wantSecret {
				t.Errorf("Secret = %v, want %v", w.config.Secret, tt.wantSecret)
			}
			if w.config.WebhookURL != tt.wantURL {
				t.Errorf("WebhookURL = %v, want %v", w.config.WebhookURL, tt.wantURL)
			}
			if w.config.SkipTLSVerify != tt.wantSkipTLS {
				t.Errorf("SkipTLSVerify = %v, want %v", w.config.SkipTLSVerify, tt.wantSkipTLS)
			}
			if len(w.config.Headers) != tt.wantHeaderLen {
				t.Errorf("len(Headers) = %v, want %v", len(w.config.Headers), tt.wantHeaderLen)
			}
		})
	}
}

func TestWebhookProvider_Type(t *testing.T) {
	w := NewWebhookProvider()
	if w.Type() != ProviderWebhook {
		t.Errorf("Type() = %v, want %v", w.Type(), ProviderWebhook)
	}
}

//nolint:unparam // Test helper with consistent test values
func computeWebhookSignature(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

func TestWebhookProvider_ParseEvent_Push(t *testing.T) {
	payload := webhookPayload{
		Event:      "push",
		Ref:        "refs/heads/main",
		SHA:        "abc123def456",
		Repository: "owner/repo",
		Branch:     "main",
		Author:     "testuser",
		Message:    "test commit message",
		Metadata: map[string]string{
			"custom": "value",
		},
	}

	body, _ := json.Marshal(payload)
	secret := "test-secret"
	signature := computeWebhookSignature(secret, body)

	w := NewWebhookProvider(WithWebhookSecret(secret))

	ctx := context.Background()
	headers := map[string]string{
		"X-Signature": signature,
	}

	event, err := w.ParseEvent(ctx, body, headers)
	if err != nil {
		t.Fatalf("ParseEvent() error = %v", err)
	}

	if event.Provider != ProviderWebhook {
		t.Errorf("Provider = %v, want %v", event.Provider, ProviderWebhook)
	}
	if event.Type != EventPush {
		t.Errorf("Type = %v, want %v", event.Type, EventPush)
	}
	if event.Ref != "refs/heads/main" {
		t.Errorf("Ref = %v, want refs/heads/main", event.Ref)
	}
	if event.SHA != "abc123def456" {
		t.Errorf("SHA = %v, want abc123def456", event.SHA)
	}
	if event.Repo != "owner/repo" {
		t.Errorf("Repo = %v, want owner/repo", event.Repo)
	}
	if event.Branch != "main" {
		t.Errorf("Branch = %v, want main", event.Branch)
	}
	if event.Author != "testuser" {
		t.Errorf("Author = %v, want testuser", event.Author)
	}
	if event.Metadata["custom"] != "value" {
		t.Errorf("Metadata[custom] = %v, want value", event.Metadata["custom"])
	}
}

func TestWebhookProvider_ParseEvent_PullRequest(t *testing.T) {
	payload := webhookPayload{
		Event:      "pull_request",
		Ref:        "refs/pull/42/head",
		SHA:        "pr123",
		Repository: "owner/repo",
		Branch:     "feature-branch",
		Author:     "prauthor",
		Message:    "Add feature",
	}

	body, _ := json.Marshal(payload)

	w := NewWebhookProvider()

	ctx := context.Background()
	headers := map[string]string{}

	event, err := w.ParseEvent(ctx, body, headers)
	if err != nil {
		t.Fatalf("ParseEvent() error = %v", err)
	}

	if event.Type != EventPullRequest {
		t.Errorf("Type = %v, want %v", event.Type, EventPullRequest)
	}
}

func TestWebhookProvider_ParseEvent_Tag(t *testing.T) {
	payload := webhookPayload{
		Event:      "tag",
		Ref:        "refs/tags/v1.0.0",
		Repository: "owner/repo",
	}

	body, _ := json.Marshal(payload)

	w := NewWebhookProvider()

	ctx := context.Background()
	headers := map[string]string{}

	event, err := w.ParseEvent(ctx, body, headers)
	if err != nil {
		t.Fatalf("ParseEvent() error = %v", err)
	}

	if event.Type != EventTag {
		t.Errorf("Type = %v, want %v", event.Type, EventTag)
	}
}

func TestWebhookProvider_ParseEvent_Schedule(t *testing.T) {
	payload := webhookPayload{
		Event:      "schedule",
		Repository: "owner/repo",
	}

	body, _ := json.Marshal(payload)

	w := NewWebhookProvider()

	ctx := context.Background()
	headers := map[string]string{}

	event, err := w.ParseEvent(ctx, body, headers)
	if err != nil {
		t.Fatalf("ParseEvent() error = %v", err)
	}

	if event.Type != EventSchedule {
		t.Errorf("Type = %v, want %v", event.Type, EventSchedule)
	}
}

func TestWebhookProvider_ParseEvent_Manual(t *testing.T) {
	payload := webhookPayload{
		Event:      "manual",
		Repository: "owner/repo",
	}

	body, _ := json.Marshal(payload)

	w := NewWebhookProvider()

	ctx := context.Background()
	headers := map[string]string{}

	event, err := w.ParseEvent(ctx, body, headers)
	if err != nil {
		t.Fatalf("ParseEvent() error = %v", err)
	}

	if event.Type != EventManual {
		t.Errorf("Type = %v, want %v", event.Type, EventManual)
	}
}

func TestWebhookProvider_ParseEvent_AlternateFields(t *testing.T) {
	// Test with alternate field names.
	payload := webhookPayload{
		Type:   "push", // Using 'type' instead of 'event'
		Repo:   "owner/repo",
		Commit: "commit123", // Using 'commit' instead of 'sha'
		Sender: "sender",    // Using 'sender' instead of 'author'
	}

	body, _ := json.Marshal(payload)

	w := NewWebhookProvider()

	ctx := context.Background()
	headers := map[string]string{}

	event, err := w.ParseEvent(ctx, body, headers)
	if err != nil {
		t.Fatalf("ParseEvent() error = %v", err)
	}

	if event.Type != EventPush {
		t.Errorf("Type = %v, want %v", event.Type, EventPush)
	}
	if event.Repo != "owner/repo" {
		t.Errorf("Repo = %v, want owner/repo", event.Repo)
	}
	if event.SHA != "commit123" {
		t.Errorf("SHA = %v, want commit123", event.SHA)
	}
	if event.Author != "sender" {
		t.Errorf("Author = %v, want sender", event.Author)
	}
}

func TestWebhookProvider_ParseEvent_SignatureWithPrefix(t *testing.T) {
	payload := webhookPayload{
		Event:      "push",
		Repository: "owner/repo",
	}

	body, _ := json.Marshal(payload)
	secret := "test-secret"
	signature := "sha256=" + computeWebhookSignature(secret, body)

	w := NewWebhookProvider(WithWebhookSecret(secret))

	ctx := context.Background()
	headers := map[string]string{
		"X-Hub-Signature-256": signature,
	}

	event, err := w.ParseEvent(ctx, body, headers)
	if err != nil {
		t.Fatalf("ParseEvent() error = %v", err)
	}

	if event.Type != EventPush {
		t.Errorf("Type = %v, want %v", event.Type, EventPush)
	}
}

func TestWebhookProvider_ParseEvent_MissingSignature(t *testing.T) {
	w := NewWebhookProvider(WithWebhookSecret("secret"))

	ctx := context.Background()
	headers := map[string]string{}

	_, err := w.ParseEvent(ctx, []byte(`{}`), headers)
	if err != ErrMissingWebhookSignature {
		t.Errorf("ParseEvent() error = %v, want %v", err, ErrMissingWebhookSignature)
	}
}

func TestWebhookProvider_ParseEvent_InvalidSignature(t *testing.T) {
	w := NewWebhookProvider(WithWebhookSecret("correct-secret"))

	ctx := context.Background()
	headers := map[string]string{
		"X-Signature": "invalid",
	}

	_, err := w.ParseEvent(ctx, []byte(`{"event":"push"}`), headers)
	if err != ErrInvalidWebhookSignature {
		t.Errorf("ParseEvent() error = %v, want %v", err, ErrInvalidWebhookSignature)
	}
}

func TestWebhookProvider_ParseEvent_InvalidPayload(t *testing.T) {
	w := NewWebhookProvider()

	ctx := context.Background()
	headers := map[string]string{}

	_, err := w.ParseEvent(ctx, []byte(`{invalid json`), headers)
	if err == nil {
		t.Error("ParseEvent() expected error for invalid payload")
	}
}

func TestWebhookProvider_ParseEvent_NilContext(t *testing.T) {
	w := NewWebhookProvider()

	//lint:ignore SA1012 Testing nil context handling
	_, err := w.ParseEvent(context.TODO(), []byte(`{}`), map[string]string{})
	if err == nil {
		t.Error("ParseEvent() expected error for nil context")
	}
}

func TestWebhookProvider_ParseEvent_CanceledContext(t *testing.T) {
	w := NewWebhookProvider()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := w.ParseEvent(ctx, []byte(`{}`), map[string]string{})
	if err != context.Canceled {
		t.Errorf("ParseEvent() error = %v, want %v", err, context.Canceled)
	}
}

func TestWebhookProvider_ParseEvent_LowercaseHeaders(t *testing.T) {
	payload := webhookPayload{
		Event:      "push",
		Repository: "owner/repo",
	}

	body, _ := json.Marshal(payload)
	secret := "test-secret"
	signature := computeWebhookSignature(secret, body)

	w := NewWebhookProvider(WithWebhookSecret(secret))

	ctx := context.Background()
	headers := map[string]string{
		"x-signature": signature,
	}

	event, err := w.ParseEvent(ctx, body, headers)
	if err != nil {
		t.Fatalf("ParseEvent() error = %v", err)
	}

	if event.Type != EventPush {
		t.Errorf("Type = %v, want %v", event.Type, EventPush)
	}
}

func TestWebhookProvider_ParseEvent_WebhookSignatureHeader(t *testing.T) {
	payload := webhookPayload{
		Event:      "push",
		Repository: "owner/repo",
	}

	body, _ := json.Marshal(payload)
	secret := "test-secret"
	signature := computeWebhookSignature(secret, body)

	w := NewWebhookProvider(WithWebhookSecret(secret))

	ctx := context.Background()
	headers := map[string]string{
		"X-Webhook-Signature": signature,
	}

	event, err := w.ParseEvent(ctx, body, headers)
	if err != nil {
		t.Fatalf("ParseEvent() error = %v", err)
	}

	if event.Type != EventPush {
		t.Errorf("Type = %v, want %v", event.Type, EventPush)
	}
}

func TestWebhookProvider_UpdateStatus(t *testing.T) {
	w := NewWebhookProvider()

	ctx := context.Background()
	status := RunStatus{
		RunID:  "run123",
		Status: StatusSuccess,
	}

	err := w.UpdateStatus(ctx, status)
	if err != nil {
		t.Errorf("UpdateStatus() error = %v", err)
	}
}

func TestWebhookProvider_UpdateStatus_NilContext(t *testing.T) {
	w := NewWebhookProvider()

	//lint:ignore SA1012 Testing nil context handling
	err := w.UpdateStatus(context.TODO(), RunStatus{})
	if err == nil {
		t.Error("UpdateStatus() expected error for nil context")
	}
}

func TestWebhookProvider_CreateCheck(t *testing.T) {
	w := NewWebhookProvider()

	ctx := context.Background()
	event := Event{
		Repo: "owner/repo",
		SHA:  "abc123",
	}

	checkID, err := w.CreateCheck(ctx, event, "security-scan")
	if err != nil {
		t.Errorf("CreateCheck() error = %v", err)
	}
	if checkID == "" {
		t.Error("CreateCheck() returned empty check ID")
	}
}

func TestWebhookProvider_CreateCheck_NilContext(t *testing.T) {
	w := NewWebhookProvider()

	//lint:ignore SA1012 Testing nil context handling
	_, err := w.CreateCheck(context.TODO(), Event{}, "test")
	if err == nil {
		t.Error("CreateCheck() expected error for nil context")
	}
}

func TestWebhookProvider_UpdateCheck(t *testing.T) {
	w := NewWebhookProvider()

	ctx := context.Background()
	status := RunStatus{
		Status: StatusSuccess,
	}

	err := w.UpdateCheck(ctx, "webhook123", status)
	if err != nil {
		t.Errorf("UpdateCheck() error = %v", err)
	}
}

func TestWebhookProvider_UpdateCheck_NilContext(t *testing.T) {
	w := NewWebhookProvider()

	//lint:ignore SA1012 Testing nil context handling
	err := w.UpdateCheck(nil, "check123", RunStatus{})
	if err == nil {
		t.Error("UpdateCheck() expected error for nil context")
	}
}

func TestMapStatusToWebhook(t *testing.T) {
	tests := []struct {
		status StatusType
		want   string
	}{
		{StatusPending, "pending"},
		{StatusRunning, "running"},
		{StatusInProgress, "running"},
		{StatusSuccess, "success"},
		{StatusFailure, "failure"},
		{StatusError, "error"},
		{StatusCanceled, "canceled"},
		{StatusNeutral, "neutral"},
		{"unknown", "pending"},
	}

	for _, tt := range tests {
		t.Run(string(tt.status), func(t *testing.T) {
			if got := MapStatusToWebhook(tt.status); got != tt.want {
				t.Errorf("MapStatusToWebhook(%v) = %v, want %v", tt.status, got, tt.want)
			}
		})
	}
}

func TestWebhookProvider_DetermineEventType(t *testing.T) {
	w := NewWebhookProvider()

	tests := []struct {
		name    string
		payload webhookPayload
		want    EventType
	}{
		{
			name:    "push event",
			payload: webhookPayload{Event: "push"},
			want:    EventPush,
		},
		{
			name:    "pull_request event",
			payload: webhookPayload{Event: "pull_request"},
			want:    EventPullRequest,
		},
		{
			name:    "merge_request event",
			payload: webhookPayload{Event: "merge_request"},
			want:    EventPullRequest,
		},
		{
			name:    "pr event",
			payload: webhookPayload{Event: "pr"},
			want:    EventPullRequest,
		},
		{
			name:    "mr event",
			payload: webhookPayload{Event: "mr"},
			want:    EventPullRequest,
		},
		{
			name:    "tag event",
			payload: webhookPayload{Event: "tag"},
			want:    EventTag,
		},
		{
			name:    "tag_push event",
			payload: webhookPayload{Event: "tag_push"},
			want:    EventTag,
		},
		{
			name:    "schedule event",
			payload: webhookPayload{Event: "schedule"},
			want:    EventSchedule,
		},
		{
			name:    "scheduled event",
			payload: webhookPayload{Event: "scheduled"},
			want:    EventSchedule,
		},
		{
			name:    "manual event",
			payload: webhookPayload{Event: "manual"},
			want:    EventManual,
		},
		{
			name:    "workflow_dispatch event",
			payload: webhookPayload{Event: "workflow_dispatch"},
			want:    EventManual,
		},
		{
			name:    "PUSH uppercase",
			payload: webhookPayload{Event: "PUSH"},
			want:    EventPush,
		},
		{
			name:    "unknown defaults to push",
			payload: webhookPayload{Event: "unknown"},
			want:    EventPush,
		},
		{
			name:    "empty defaults to push",
			payload: webhookPayload{},
			want:    EventPush,
		},
		{
			name:    "type field fallback",
			payload: webhookPayload{Type: "pull_request"},
			want:    EventPullRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := w.determineEventType(tt.payload)
			if got != tt.want {
				t.Errorf("determineEventType() = %v, want %v", got, tt.want)
			}
		})
	}
}
