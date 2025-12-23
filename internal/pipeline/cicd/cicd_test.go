package cicd

import (
	"os"
	"testing"
	"time"
)

func TestProviderType_IsValid(t *testing.T) {
	tests := []struct {
		name     string
		provider ProviderType
		want     bool
	}{
		{
			name:     "GitHub is valid",
			provider: ProviderGitHub,
			want:     true,
		},
		{
			name:     "GitLab is valid",
			provider: ProviderGitLab,
			want:     true,
		},
		{
			name:     "Webhook is valid",
			provider: ProviderWebhook,
			want:     true,
		},
		{
			name:     "Empty is invalid",
			provider: "",
			want:     false,
		},
		{
			name:     "Unknown is invalid",
			provider: "unknown",
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.provider.IsValid(); got != tt.want {
				t.Errorf("ProviderType.IsValid() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestEventType_IsValid(t *testing.T) {
	tests := []struct {
		name      string
		eventType EventType
		want      bool
	}{
		{
			name:      "Push is valid",
			eventType: EventPush,
			want:      true,
		},
		{
			name:      "PullRequest is valid",
			eventType: EventPullRequest,
			want:      true,
		},
		{
			name:      "Tag is valid",
			eventType: EventTag,
			want:      true,
		},
		{
			name:      "Schedule is valid",
			eventType: EventSchedule,
			want:      true,
		},
		{
			name:      "Manual is valid",
			eventType: EventManual,
			want:      true,
		},
		{
			name:      "Empty is invalid",
			eventType: "",
			want:      false,
		},
		{
			name:      "Unknown is invalid",
			eventType: "unknown",
			want:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.eventType.IsValid(); got != tt.want {
				t.Errorf("EventType.IsValid() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestStatusType_IsTerminal(t *testing.T) {
	tests := []struct {
		name   string
		status StatusType
		want   bool
	}{
		{
			name:   "Pending is not terminal",
			status: StatusPending,
			want:   false,
		},
		{
			name:   "Running is not terminal",
			status: StatusRunning,
			want:   false,
		},
		{
			name:   "InProgress is not terminal",
			status: StatusInProgress,
			want:   false,
		},
		{
			name:   "Success is terminal",
			status: StatusSuccess,
			want:   true,
		},
		{
			name:   "Failure is terminal",
			status: StatusFailure,
			want:   true,
		},
		{
			name:   "Canceled is terminal",
			status: StatusCanceled,
			want:   true,
		},
		{
			name:   "Error is terminal",
			status: StatusError,
			want:   true,
		},
		{
			name:   "Neutral is terminal",
			status: StatusNeutral,
			want:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.status.IsTerminal(); got != tt.want {
				t.Errorf("StatusType.IsTerminal() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestProviderConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		config  ProviderConfig
		wantErr bool
	}{
		{
			name:    "Empty config is valid",
			config:  ProviderConfig{},
			wantErr: false,
		},
		{
			name: "Full config is valid",
			config: ProviderConfig{
				BaseURL:       "https://api.github.com",
				Token:         "token123",
				Secret:        "secret123",
				WebhookURL:    "https://example.com/webhook",
				SkipTLSVerify: false,
				Headers: map[string]string{
					"X-Custom": "value",
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.config.Validate(); (err != nil) != tt.wantErr {
				t.Errorf("ProviderConfig.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestDefaultProviderConfig(t *testing.T) {
	config := DefaultProviderConfig()

	if config.BaseURL != "" {
		t.Errorf("DefaultProviderConfig().BaseURL = %v, want empty", config.BaseURL)
	}
	if config.Token != "" {
		t.Errorf("DefaultProviderConfig().Token = %v, want empty", config.Token)
	}
}

func TestDetectProvider(t *testing.T) {
	// Save and clear CI environment variables.
	envVars := []string{"GITHUB_ACTIONS", "GITLAB_CI", "GITHUB_RUN_ID", "CI_PROJECT_ID"}
	saved := make(map[string]string)
	for _, env := range envVars {
		saved[env] = os.Getenv(env)
		os.Unsetenv(env)
	}
	defer func() {
		for env, val := range saved {
			if val != "" {
				os.Setenv(env, val)
			}
		}
	}()

	// Default detection returns webhook.
	provider := DetectProvider()
	if provider != ProviderWebhook {
		t.Errorf("DetectProvider() = %v, want %v", provider, ProviderWebhook)
	}
}

func TestEvent_Fields(t *testing.T) {
	now := time.Now()
	event := Event{
		Provider:  ProviderGitHub,
		Type:      EventPush,
		Ref:       "refs/heads/main",
		SHA:       "abc123",
		Repo:      "owner/repo",
		Branch:    "main",
		Author:    "user",
		Message:   "test commit",
		Timestamp: now,
		Metadata: map[string]string{
			"key": "value",
		},
	}

	if event.Provider != ProviderGitHub {
		t.Errorf("Event.Provider = %v, want %v", event.Provider, ProviderGitHub)
	}
	if event.Type != EventPush {
		t.Errorf("Event.Type = %v, want %v", event.Type, EventPush)
	}
	if event.Ref != "refs/heads/main" {
		t.Errorf("Event.Ref = %v, want refs/heads/main", event.Ref)
	}
	if event.SHA != "abc123" {
		t.Errorf("Event.SHA = %v, want abc123", event.SHA)
	}
	if event.Repo != "owner/repo" {
		t.Errorf("Event.Repo = %v, want owner/repo", event.Repo)
	}
	if event.Branch != "main" {
		t.Errorf("Event.Branch = %v, want main", event.Branch)
	}
	if event.Author != "user" {
		t.Errorf("Event.Author = %v, want user", event.Author)
	}
	if event.Message != "test commit" {
		t.Errorf("Event.Message = %v, want test commit", event.Message)
	}
	if event.Timestamp != now {
		t.Errorf("Event.Timestamp = %v, want %v", event.Timestamp, now)
	}
	if event.Metadata["key"] != "value" {
		t.Errorf("Event.Metadata[key] = %v, want value", event.Metadata["key"])
	}
}

func TestRunStatus_Fields(t *testing.T) {
	now := time.Now()
	status := RunStatus{
		RunID:       "run123",
		PipelineRef: "pipeline-ref",
		Status:      StatusRunning,
		Description: "Running tests",
		URL:         "https://example.com/run/123",
		StartTime:   now,
		EndTime:     now.Add(time.Minute),
		Duration:    time.Minute,
		Stages: []StageStatus{
			{
				Name:   "test",
				Status: StatusSuccess,
			},
		},
		Metadata: map[string]string{
			"key": "value",
		},
	}

	if status.RunID != "run123" {
		t.Errorf("RunStatus.RunID = %v, want run123", status.RunID)
	}
	if status.PipelineRef != "pipeline-ref" {
		t.Errorf("RunStatus.PipelineRef = %v, want pipeline-ref", status.PipelineRef)
	}
	if status.Status != StatusRunning {
		t.Errorf("RunStatus.Status = %v, want %v", status.Status, StatusRunning)
	}
	if status.Description != "Running tests" {
		t.Errorf("RunStatus.Description = %v, want Running tests", status.Description)
	}
	if status.URL != "https://example.com/run/123" {
		t.Errorf("RunStatus.URL = %v, want https://example.com/run/123", status.URL)
	}
	if status.StartTime != now {
		t.Errorf("RunStatus.StartTime = %v, want %v", status.StartTime, now)
	}
	if status.Duration != time.Minute {
		t.Errorf("RunStatus.Duration = %v, want 1m", status.Duration)
	}
	if status.EndTime != now.Add(time.Minute) {
		t.Errorf("RunStatus.EndTime mismatch")
	}
	if len(status.Stages) != 1 {
		t.Errorf("len(RunStatus.Stages) = %v, want 1", len(status.Stages))
	}
	if status.Metadata["key"] != "value" {
		t.Errorf("RunStatus.Metadata[key] = %v, want value", status.Metadata["key"])
	}
}

func TestStageStatus_Fields(t *testing.T) {
	now := time.Now()
	stage := StageStatus{
		Name:        "build",
		Description: "Building project",
		Status:      StatusSuccess,
		StartTime:   now,
		EndTime:     now.Add(30 * time.Second),
		Duration:    30 * time.Second,
	}

	if stage.Name != "build" {
		t.Errorf("StageStatus.Name = %v, want build", stage.Name)
	}
	if stage.Description != "Building project" {
		t.Errorf("StageStatus.Description = %v, want Building project", stage.Description)
	}
	if stage.Status != StatusSuccess {
		t.Errorf("StageStatus.Status = %v, want %v", stage.Status, StatusSuccess)
	}
	if stage.StartTime != now {
		t.Errorf("StageStatus.StartTime = %v, want %v", stage.StartTime, now)
	}
	if stage.EndTime != now.Add(30*time.Second) {
		t.Errorf("StageStatus.EndTime mismatch")
	}
	if stage.Duration != 30*time.Second {
		t.Errorf("StageStatus.Duration = %v, want 30s", stage.Duration)
	}
}
