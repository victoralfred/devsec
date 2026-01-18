package cicd

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNewGitHubProvider(t *testing.T) {
	tests := []struct {
		name        string
		wantBaseURL string
		wantToken   string
		wantSecret  string
		opts        []GitHubOption
	}{
		{
			name:        "Default configuration",
			opts:        nil,
			wantBaseURL: "https://api.github.com",
			wantToken:   "",
			wantSecret:  "",
		},
		{
			name: "With token",
			opts: []GitHubOption{
				WithGitHubToken("test-token"),
			},
			wantBaseURL: "https://api.github.com",
			wantToken:   "test-token",
			wantSecret:  "",
		},
		{
			name: "With secret",
			opts: []GitHubOption{
				WithGitHubSecret("test-secret"),
			},
			wantBaseURL: "https://api.github.com",
			wantToken:   "",
			wantSecret:  "test-secret",
		},
		{
			name: "With custom base URL",
			opts: []GitHubOption{
				WithGitHubBaseURL("https://github.example.com/api/v3"),
			},
			wantBaseURL: "https://github.example.com/api/v3",
			wantToken:   "",
			wantSecret:  "",
		},
		{
			name: "With all options",
			opts: []GitHubOption{
				WithGitHubToken("token"),
				WithGitHubSecret("secret"),
				WithGitHubBaseURL("https://custom.github.com"),
			},
			wantBaseURL: "https://custom.github.com",
			wantToken:   "token",
			wantSecret:  "secret",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewGitHubProvider(tt.opts...)

			if g.config.BaseURL != tt.wantBaseURL {
				t.Errorf("BaseURL = %v, want %v", g.config.BaseURL, tt.wantBaseURL)
			}
			if g.config.Token != tt.wantToken {
				t.Errorf("Token = %v, want %v", g.config.Token, tt.wantToken)
			}
			if g.config.Secret != tt.wantSecret {
				t.Errorf("Secret = %v, want %v", g.config.Secret, tt.wantSecret)
			}
		})
	}
}

func TestGitHubProvider_Type(t *testing.T) {
	g := NewGitHubProvider()
	if g.Type() != ProviderGitHub {
		t.Errorf("Type() = %v, want %v", g.Type(), ProviderGitHub)
	}
}

func computeGitHubSignature(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

func TestGitHubProvider_ParseEvent_Push(t *testing.T) {
	payload := githubPushEvent{
		Ref:   "refs/heads/main",
		After: "abc123def456",
	}
	payload.Repository.FullName = "owner/repo"
	payload.Pusher.Name = "testuser"
	payload.HeadCommit.Message = "test commit message"

	body, _ := json.Marshal(payload)
	secret := "test-secret"
	signature := computeGitHubSignature(secret, body)

	g := NewGitHubProvider(WithGitHubSecret(secret))

	ctx := context.Background()
	headers := map[string]string{
		"X-GitHub-Event":      "push",
		"X-Hub-Signature-256": signature,
	}

	event, err := g.ParseEvent(ctx, body, headers)
	if err != nil {
		t.Fatalf("ParseEvent() error = %v", err)
	}

	if event.Provider != ProviderGitHub {
		t.Errorf("Provider = %v, want %v", event.Provider, ProviderGitHub)
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
}

func TestGitHubProvider_ParseEvent_PullRequest(t *testing.T) {
	payload := githubPullRequestEvent{
		Action: "opened",
		Number: 42,
	}
	payload.PullRequest.Head.SHA = "pr123"
	payload.PullRequest.Head.Ref = "feature-branch"
	payload.PullRequest.Title = "Add feature"
	payload.PullRequest.User.Login = "prauthor"
	payload.Repository.FullName = "owner/repo"

	body, _ := json.Marshal(payload)

	g := NewGitHubProvider()

	ctx := context.Background()
	headers := map[string]string{
		"X-GitHub-Event": "pull_request",
	}

	event, err := g.ParseEvent(ctx, body, headers)
	if err != nil {
		t.Fatalf("ParseEvent() error = %v", err)
	}

	if event.Type != EventPullRequest {
		t.Errorf("Type = %v, want %v", event.Type, EventPullRequest)
	}
	if event.SHA != "pr123" {
		t.Errorf("SHA = %v, want pr123", event.SHA)
	}
	if event.Branch != "feature-branch" {
		t.Errorf("Branch = %v, want feature-branch", event.Branch)
	}
	if event.Metadata["pr_number"] != "42" {
		t.Errorf("Metadata[pr_number] = %v, want 42", event.Metadata["pr_number"])
	}
}

func TestGitHubProvider_ParseEvent_Create(t *testing.T) {
	payload := githubCreateEvent{
		Ref:     "v1.0.0",
		RefType: "tag",
	}
	payload.Repository.FullName = "owner/repo"
	payload.Sender.Login = "releaser"

	body, _ := json.Marshal(payload)

	g := NewGitHubProvider()

	ctx := context.Background()
	headers := map[string]string{
		"X-GitHub-Event": "create",
	}

	event, err := g.ParseEvent(ctx, body, headers)
	if err != nil {
		t.Fatalf("ParseEvent() error = %v", err)
	}

	if event.Type != EventTag {
		t.Errorf("Type = %v, want %v", event.Type, EventTag)
	}
	if event.Ref != "v1.0.0" {
		t.Errorf("Ref = %v, want v1.0.0", event.Ref)
	}
	if event.Metadata["ref_type"] != "tag" {
		t.Errorf("Metadata[ref_type] = %v, want tag", event.Metadata["ref_type"])
	}
}

func TestGitHubProvider_ParseEvent_MissingEventHeader(t *testing.T) {
	g := NewGitHubProvider()

	ctx := context.Background()
	headers := map[string]string{}

	_, err := g.ParseEvent(ctx, []byte(`{}`), headers)
	if err != ErrMissingEventHeader {
		t.Errorf("ParseEvent() error = %v, want %v", err, ErrMissingEventHeader)
	}
}

func TestGitHubProvider_ParseEvent_UnsupportedEvent(t *testing.T) {
	g := NewGitHubProvider()

	ctx := context.Background()
	headers := map[string]string{
		"X-GitHub-Event": "issues",
	}

	_, err := g.ParseEvent(ctx, []byte(`{}`), headers)
	if err == nil {
		t.Error("ParseEvent() expected error for unsupported event")
	}
}

func TestGitHubProvider_ParseEvent_InvalidSignature(t *testing.T) {
	g := NewGitHubProvider(WithGitHubSecret("correct-secret"))

	ctx := context.Background()
	headers := map[string]string{
		"X-GitHub-Event":      "push",
		"X-Hub-Signature-256": "sha256=invalid",
	}

	_, err := g.ParseEvent(ctx, []byte(`{"ref":"refs/heads/main"}`), headers)
	if err != ErrInvalidSignature {
		t.Errorf("ParseEvent() error = %v, want %v", err, ErrInvalidSignature)
	}
}

func TestGitHubProvider_ParseEvent_MissingSignature(t *testing.T) {
	g := NewGitHubProvider(WithGitHubSecret("secret"))

	ctx := context.Background()
	headers := map[string]string{
		"X-GitHub-Event": "push",
	}

	_, err := g.ParseEvent(ctx, []byte(`{}`), headers)
	if err != ErrMissingSignature {
		t.Errorf("ParseEvent() error = %v, want %v", err, ErrMissingSignature)
	}
}

func TestGitHubProvider_ParseEvent_NilContext(t *testing.T) {
	g := NewGitHubProvider()

	//lint:ignore SA1012 Testing nil context handling
	_, err := g.ParseEvent(nil, []byte(`{}`), map[string]string{})
	if err == nil {
		t.Error("ParseEvent() expected error for nil context")
	}
}

func TestGitHubProvider_ParseEvent_CanceledContext(t *testing.T) {
	g := NewGitHubProvider()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := g.ParseEvent(ctx, []byte(`{}`), map[string]string{})
	if err != context.Canceled {
		t.Errorf("ParseEvent() error = %v, want %v", err, context.Canceled)
	}
}

func TestGitHubProvider_UpdateStatus(t *testing.T) {
	// Create a mock server.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if !strings.Contains(r.URL.Path, "/statuses/") {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"state": "success"}`))
	}))
	defer server.Close()

	g := NewGitHubProvider(
		WithGitHubToken("test-token"),
		WithGitHubBaseURL(server.URL),
	)

	ctx := context.Background()
	status := RunStatus{
		RunID:  "run123",
		Status: StatusSuccess,
		Metadata: map[string]string{
			"repo": "owner/repo",
			"sha":  "abc123",
		},
	}

	err := g.UpdateStatus(ctx, status)
	if err != nil {
		t.Errorf("UpdateStatus() error = %v", err)
	}
}

func TestGitHubProvider_UpdateStatus_MissingToken(t *testing.T) {
	g := NewGitHubProvider()

	ctx := context.Background()
	status := RunStatus{
		RunID:  "run123",
		Status: StatusSuccess,
	}

	err := g.UpdateStatus(ctx, status)
	if err != ErrMissingToken {
		t.Errorf("UpdateStatus() error = %v, want %v", err, ErrMissingToken)
	}
}

func TestGitHubProvider_UpdateStatus_MissingMetadata(t *testing.T) {
	g := NewGitHubProvider(WithGitHubToken("test-token"))

	ctx := context.Background()
	status := RunStatus{
		RunID:  "run123",
		Status: StatusSuccess,
	}

	err := g.UpdateStatus(ctx, status)
	if err == nil {
		t.Error("UpdateStatus() expected error for missing metadata")
	}
}

func TestGitHubProvider_UpdateStatus_NilContext(t *testing.T) {
	g := NewGitHubProvider()

	//lint:ignore SA1012 Testing nil context handling
	err := g.UpdateStatus(nil, RunStatus{})
	if err == nil {
		t.Error("UpdateStatus() expected error for nil context")
	}
}

func TestGitHubProvider_CreateCheck(t *testing.T) {
	// Create a mock server.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if !strings.Contains(r.URL.Path, "/check-runs") {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id": 12345}`))
	}))
	defer server.Close()

	g := NewGitHubProvider(
		WithGitHubToken("test-token"),
		WithGitHubBaseURL(server.URL),
	)

	ctx := context.Background()
	event := Event{
		Repo: "owner/repo",
		SHA:  "abc123",
	}

	checkID, err := g.CreateCheck(ctx, event, "security-scan")
	if err != nil {
		t.Errorf("CreateCheck() error = %v", err)
	}
	if checkID != "12345" {
		t.Errorf("CreateCheck() returned %s, want 12345", checkID)
	}
}

func TestGitHubProvider_CreateCheck_MissingToken(t *testing.T) {
	g := NewGitHubProvider()

	ctx := context.Background()
	event := Event{}

	_, err := g.CreateCheck(ctx, event, "test")
	if err != ErrMissingToken {
		t.Errorf("CreateCheck() error = %v, want %v", err, ErrMissingToken)
	}
}

func TestGitHubProvider_UpdateCheck(t *testing.T) {
	// Create a mock server.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPatch {
			t.Errorf("expected PATCH, got %s", r.Method)
		}
		if !strings.Contains(r.URL.Path, "/check-runs/") {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id": 12345}`))
	}))
	defer server.Close()

	g := NewGitHubProvider(
		WithGitHubToken("test-token"),
		WithGitHubBaseURL(server.URL),
	)

	ctx := context.Background()
	status := RunStatus{
		Status: StatusSuccess,
		Metadata: map[string]string{
			"repo": "owner/repo",
		},
	}

	err := g.UpdateCheck(ctx, "12345", status)
	if err != nil {
		t.Errorf("UpdateCheck() error = %v", err)
	}
}

func TestGitHubProvider_UpdateCheck_MissingRepo(t *testing.T) {
	g := NewGitHubProvider(WithGitHubToken("test-token"))

	ctx := context.Background()
	status := RunStatus{
		Status: StatusSuccess,
	}

	err := g.UpdateCheck(ctx, "check123", status)
	if err == nil {
		t.Error("UpdateCheck() expected error for missing repo")
	}
}

func TestGitHubProvider_UpdateCheck_MissingCheckID(t *testing.T) {
	g := NewGitHubProvider(WithGitHubToken("token"))

	ctx := context.Background()
	status := RunStatus{}

	err := g.UpdateCheck(ctx, "", status)
	if err != ErrMissingCheckDetails {
		t.Errorf("UpdateCheck() error = %v, want %v", err, ErrMissingCheckDetails)
	}
}

func TestMapStatusToGitHub(t *testing.T) {
	tests := []struct {
		status StatusType
		want   string
	}{
		{StatusPending, "queued"},
		{StatusRunning, "in_progress"},
		{StatusInProgress, "in_progress"},
		{StatusSuccess, "completed"},
		{StatusFailure, "completed"},
		{StatusError, "completed"},
		{StatusCanceled, "completed"},
		{StatusNeutral, "completed"},
		{"unknown", "queued"},
	}

	for _, tt := range tests {
		t.Run(string(tt.status), func(t *testing.T) {
			if got := MapStatusToGitHub(tt.status); got != tt.want {
				t.Errorf("MapStatusToGitHub(%v) = %v, want %v", tt.status, got, tt.want)
			}
		})
	}
}

func TestMapConclusionToGitHub(t *testing.T) {
	tests := []struct {
		status StatusType
		want   string
	}{
		{StatusSuccess, "success"},
		{StatusFailure, "failure"},
		{StatusError, "failure"},
		{StatusCanceled, "cancelled"}, //nolint:misspell // GitHub API uses British spelling
		{StatusNeutral, "neutral"},
		{StatusPending, ""},
		{StatusRunning, ""},
	}

	for _, tt := range tests {
		t.Run(string(tt.status), func(t *testing.T) {
			if got := MapConclusionToGitHub(tt.status); got != tt.want {
				t.Errorf("MapConclusionToGitHub(%v) = %v, want %v", tt.status, got, tt.want)
			}
		})
	}
}
