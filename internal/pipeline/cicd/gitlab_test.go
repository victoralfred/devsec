package cicd

import (
	"context"
	"encoding/json"
	"testing"
)

func TestNewGitLabProvider(t *testing.T) {
	tests := []struct {
		name        string
		wantBaseURL string
		wantToken   string
		wantSecret  string
		opts        []GitLabOption
	}{
		{
			name:        "Default configuration",
			opts:        nil,
			wantBaseURL: "https://gitlab.com/api/v4",
			wantToken:   "",
			wantSecret:  "",
		},
		{
			name: "With token",
			opts: []GitLabOption{
				WithGitLabToken("test-token"),
			},
			wantBaseURL: "https://gitlab.com/api/v4",
			wantToken:   "test-token",
			wantSecret:  "",
		},
		{
			name: "With secret",
			opts: []GitLabOption{
				WithGitLabSecret("test-secret"),
			},
			wantBaseURL: "https://gitlab.com/api/v4",
			wantToken:   "",
			wantSecret:  "test-secret",
		},
		{
			name: "With custom base URL",
			opts: []GitLabOption{
				WithGitLabBaseURL("https://gitlab.example.com/api/v4"),
			},
			wantBaseURL: "https://gitlab.example.com/api/v4",
			wantToken:   "",
			wantSecret:  "",
		},
		{
			name: "With all options",
			opts: []GitLabOption{
				WithGitLabToken("token"),
				WithGitLabSecret("secret"),
				WithGitLabBaseURL("https://custom.gitlab.com"),
			},
			wantBaseURL: "https://custom.gitlab.com",
			wantToken:   "token",
			wantSecret:  "secret",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewGitLabProvider(tt.opts...)

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

func TestGitLabProvider_Type(t *testing.T) {
	g := NewGitLabProvider()
	if g.Type() != ProviderGitLab {
		t.Errorf("Type() = %v, want %v", g.Type(), ProviderGitLab)
	}
}

func TestGitLabProvider_ParseEvent_Push(t *testing.T) {
	payload := gitlabPushEvent{
		Ref:         "refs/heads/main",
		CheckoutSHA: "abc123def456",
		UserName:    "testuser",
	}
	payload.Project.PathWithNamespace = "group/project"
	payload.Commits = []struct {
		Message string `json:"message"`
	}{
		{Message: "test commit message"},
	}

	body, _ := json.Marshal(payload)

	g := NewGitLabProvider(WithGitLabSecret("test-token"))

	ctx := context.Background()
	headers := map[string]string{
		"X-Gitlab-Event": "Push Hook",
		"X-Gitlab-Token": "test-token",
	}

	event, err := g.ParseEvent(ctx, body, headers)
	if err != nil {
		t.Fatalf("ParseEvent() error = %v", err)
	}

	if event.Provider != ProviderGitLab {
		t.Errorf("Provider = %v, want %v", event.Provider, ProviderGitLab)
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
	if event.Repo != "group/project" {
		t.Errorf("Repo = %v, want group/project", event.Repo)
	}
	if event.Author != "testuser" {
		t.Errorf("Author = %v, want testuser", event.Author)
	}
	if event.Message != "test commit message" {
		t.Errorf("Message = %v, want test commit message", event.Message)
	}
}

func TestGitLabProvider_ParseEvent_MergeRequest(t *testing.T) {
	payload := gitlabMergeRequestEvent{
		ObjectKind: "merge_request",
	}
	payload.ObjectAttributes.IID = 42
	payload.ObjectAttributes.SourceBranch = "feature-branch"
	payload.ObjectAttributes.TargetBranch = "main"
	payload.ObjectAttributes.Title = "Add feature"
	payload.ObjectAttributes.LastCommit.ID = "mr123"
	payload.ObjectAttributes.State = "opened"
	payload.ObjectAttributes.Action = "open"
	payload.Project.PathWithNamespace = "group/project"
	payload.User.Name = "mrauthor"

	body, _ := json.Marshal(payload)

	g := NewGitLabProvider()

	ctx := context.Background()
	headers := map[string]string{
		"X-Gitlab-Event": "Merge Request Hook",
	}

	event, err := g.ParseEvent(ctx, body, headers)
	if err != nil {
		t.Fatalf("ParseEvent() error = %v", err)
	}

	if event.Type != EventPullRequest {
		t.Errorf("Type = %v, want %v", event.Type, EventPullRequest)
	}
	if event.SHA != "mr123" {
		t.Errorf("SHA = %v, want mr123", event.SHA)
	}
	if event.Branch != "feature-branch" {
		t.Errorf("Branch = %v, want feature-branch", event.Branch)
	}
	if event.Metadata["mr_iid"] != "42" {
		t.Errorf("Metadata[mr_iid] = %v, want 42", event.Metadata["mr_iid"])
	}
	if event.Metadata["target_branch"] != "main" {
		t.Errorf("Metadata[target_branch] = %v, want main", event.Metadata["target_branch"])
	}
}

func TestGitLabProvider_ParseEvent_Tag(t *testing.T) {
	payload := gitlabTagEvent{
		Ref:         "refs/tags/v1.0.0",
		CheckoutSHA: "tag123",
		UserName:    "releaser",
	}
	payload.Project.PathWithNamespace = "group/project"

	body, _ := json.Marshal(payload)

	g := NewGitLabProvider()

	ctx := context.Background()
	headers := map[string]string{
		"X-Gitlab-Event": "Tag Push Hook",
	}

	event, err := g.ParseEvent(ctx, body, headers)
	if err != nil {
		t.Fatalf("ParseEvent() error = %v", err)
	}

	if event.Type != EventTag {
		t.Errorf("Type = %v, want %v", event.Type, EventTag)
	}
	if event.Ref != "refs/tags/v1.0.0" {
		t.Errorf("Ref = %v, want refs/tags/v1.0.0", event.Ref)
	}
}

func TestGitLabProvider_ParseEvent_Pipeline(t *testing.T) {
	payload := gitlabPipelineEvent{
		ObjectKind: "pipeline",
	}
	payload.ObjectAttributes.ID = 123
	payload.ObjectAttributes.Ref = "main"
	payload.ObjectAttributes.SHA = "pipeline123"
	payload.ObjectAttributes.Status = "running"
	payload.Project.PathWithNamespace = "group/project"
	payload.User.Name = "pipelineuser"

	body, _ := json.Marshal(payload)

	g := NewGitLabProvider()

	ctx := context.Background()
	headers := map[string]string{
		"X-Gitlab-Event": "Pipeline Hook",
	}

	event, err := g.ParseEvent(ctx, body, headers)
	if err != nil {
		t.Fatalf("ParseEvent() error = %v", err)
	}

	if event.Type != EventPush {
		t.Errorf("Type = %v, want %v", event.Type, EventPush)
	}
	if event.Metadata["pipeline_id"] != "123" {
		t.Errorf("Metadata[pipeline_id] = %v, want 123", event.Metadata["pipeline_id"])
	}
	if event.Metadata["pipeline_status"] != "running" {
		t.Errorf("Metadata[pipeline_status] = %v, want running", event.Metadata["pipeline_status"])
	}
}

func TestGitLabProvider_ParseEvent_MissingEventHeader(t *testing.T) {
	g := NewGitLabProvider()

	ctx := context.Background()
	headers := map[string]string{}

	_, err := g.ParseEvent(ctx, []byte(`{}`), headers)
	if err != ErrMissingGitLabEvent {
		t.Errorf("ParseEvent() error = %v, want %v", err, ErrMissingGitLabEvent)
	}
}

func TestGitLabProvider_ParseEvent_UnsupportedEvent(t *testing.T) {
	g := NewGitLabProvider()

	ctx := context.Background()
	headers := map[string]string{
		"X-Gitlab-Event": "Issue Hook",
	}

	_, err := g.ParseEvent(ctx, []byte(`{}`), headers)
	if err == nil {
		t.Error("ParseEvent() expected error for unsupported event")
	}
}

func TestGitLabProvider_ParseEvent_InvalidToken(t *testing.T) {
	g := NewGitLabProvider(WithGitLabSecret("correct-token"))

	ctx := context.Background()
	headers := map[string]string{
		"X-Gitlab-Event": "Push Hook",
		"X-Gitlab-Token": "wrong-token",
	}

	_, err := g.ParseEvent(ctx, []byte(`{"ref":"refs/heads/main"}`), headers)
	if err != ErrInvalidGitLabToken {
		t.Errorf("ParseEvent() error = %v, want %v", err, ErrInvalidGitLabToken)
	}
}

func TestGitLabProvider_ParseEvent_MissingToken(t *testing.T) {
	g := NewGitLabProvider(WithGitLabSecret("secret"))

	ctx := context.Background()
	headers := map[string]string{
		"X-Gitlab-Event": "Push Hook",
	}

	_, err := g.ParseEvent(ctx, []byte(`{}`), headers)
	if err != ErrMissingGitLabToken {
		t.Errorf("ParseEvent() error = %v, want %v", err, ErrMissingGitLabToken)
	}
}

func TestGitLabProvider_ParseEvent_NilContext(t *testing.T) {
	g := NewGitLabProvider()

	//nolint:staticcheck // SA1012: Testing nil context handling
	_, err := g.ParseEvent(nil, []byte(`{}`), map[string]string{})
	if err == nil {
		t.Error("ParseEvent() expected error for nil context")
	}
}

func TestGitLabProvider_ParseEvent_CanceledContext(t *testing.T) {
	g := NewGitLabProvider()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := g.ParseEvent(ctx, []byte(`{}`), map[string]string{})
	if err != context.Canceled {
		t.Errorf("ParseEvent() error = %v, want %v", err, context.Canceled)
	}
}

func TestGitLabProvider_ParseEvent_LowercaseHeaders(t *testing.T) {
	payload := gitlabPushEvent{
		Ref: "refs/heads/main",
	}
	payload.Project.PathWithNamespace = "group/project"

	body, _ := json.Marshal(payload)

	g := NewGitLabProvider(WithGitLabSecret("test-token"))

	ctx := context.Background()
	headers := map[string]string{
		"x-gitlab-event": "Push Hook",
		"x-gitlab-token": "test-token",
	}

	event, err := g.ParseEvent(ctx, body, headers)
	if err != nil {
		t.Fatalf("ParseEvent() error = %v", err)
	}

	if event.Type != EventPush {
		t.Errorf("Type = %v, want %v", event.Type, EventPush)
	}
}

func TestGitLabProvider_UpdateStatus(t *testing.T) {
	g := NewGitLabProvider()

	ctx := context.Background()
	status := RunStatus{
		RunID:  "run123",
		Status: StatusSuccess,
	}

	err := g.UpdateStatus(ctx, status)
	if err != nil {
		t.Errorf("UpdateStatus() error = %v", err)
	}
}

func TestGitLabProvider_UpdateStatus_NilContext(t *testing.T) {
	g := NewGitLabProvider()

	//nolint:staticcheck // SA1012: Testing nil context handling
	err := g.UpdateStatus(nil, RunStatus{})
	if err == nil {
		t.Error("UpdateStatus() expected error for nil context")
	}
}

func TestGitLabProvider_CreateCheck(t *testing.T) {
	g := NewGitLabProvider(WithGitLabToken("token"))

	ctx := context.Background()
	event := Event{
		Repo: "group/project",
		SHA:  "abc123",
	}

	checkID, err := g.CreateCheck(ctx, event, "security-scan")
	if err != nil {
		t.Errorf("CreateCheck() error = %v", err)
	}
	if checkID == "" {
		t.Error("CreateCheck() returned empty check ID")
	}
}

func TestGitLabProvider_CreateCheck_MissingToken(t *testing.T) {
	g := NewGitLabProvider()

	ctx := context.Background()
	event := Event{}

	_, err := g.CreateCheck(ctx, event, "test")
	if err != ErrMissingToken {
		t.Errorf("CreateCheck() error = %v, want %v", err, ErrMissingToken)
	}
}

func TestGitLabProvider_UpdateCheck(t *testing.T) {
	g := NewGitLabProvider(WithGitLabToken("token"))

	ctx := context.Background()
	status := RunStatus{
		Status: StatusSuccess,
	}

	err := g.UpdateCheck(ctx, "status123", status)
	if err != nil {
		t.Errorf("UpdateCheck() error = %v", err)
	}
}

func TestGitLabProvider_UpdateCheck_MissingToken(t *testing.T) {
	g := NewGitLabProvider()

	ctx := context.Background()
	status := RunStatus{}

	err := g.UpdateCheck(ctx, "status123", status)
	if err != ErrMissingToken {
		t.Errorf("UpdateCheck() error = %v, want %v", err, ErrMissingToken)
	}
}

func TestMapStatusToGitLab(t *testing.T) {
	tests := []struct {
		status StatusType
		want   string
	}{
		{StatusPending, "pending"},
		{StatusRunning, "running"},
		{StatusInProgress, "running"},
		{StatusSuccess, "success"},
		{StatusFailure, "failed"},
		{StatusError, "failed"},
		{StatusCanceled, "canceled"},
		{"unknown", "pending"},
	}

	for _, tt := range tests {
		t.Run(string(tt.status), func(t *testing.T) {
			if got := MapStatusToGitLab(tt.status); got != tt.want {
				t.Errorf("MapStatusToGitLab(%v) = %v, want %v", tt.status, got, tt.want)
			}
		})
	}
}
