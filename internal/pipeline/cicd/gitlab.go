package cicd

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// GitLab-specific errors.
var (
	ErrInvalidGitLabToken = errors.New("invalid GitLab webhook token")
	ErrMissingGitLabToken = errors.New("missing GitLab webhook token")
	ErrMissingGitLabEvent = errors.New("missing X-Gitlab-Event header")
)

// GitLabProvider implements the Provider interface for GitLab CI.
// Fields are ordered for optimal memory alignment.
type GitLabProvider struct {
	client *http.Client
	config ProviderConfig
}

// GitLabOption configures a GitLabProvider.
type GitLabOption func(*GitLabProvider)

// WithGitLabToken sets the GitLab API token.
func WithGitLabToken(token string) GitLabOption {
	return func(g *GitLabProvider) {
		g.config.Token = token
	}
}

// WithGitLabSecret sets the webhook secret token for verification.
func WithGitLabSecret(secret string) GitLabOption {
	return func(g *GitLabProvider) {
		g.config.Secret = secret
	}
}

// WithGitLabBaseURL sets the GitLab API base URL (for self-hosted GitLab).
func WithGitLabBaseURL(baseURL string) GitLabOption {
	return func(g *GitLabProvider) {
		g.config.BaseURL = baseURL
	}
}

// WithGitLabHTTPClient sets a custom HTTP client.
func WithGitLabHTTPClient(client *http.Client) GitLabOption {
	return func(g *GitLabProvider) {
		g.client = client
	}
}

// NewGitLabProvider creates a new GitLab provider.
func NewGitLabProvider(opts ...GitLabOption) *GitLabProvider {
	g := &GitLabProvider{
		config: ProviderConfig{
			BaseURL: "https://gitlab.com/api/v4",
		},
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}

	for _, opt := range opts {
		opt(g)
	}

	return g
}

// Type returns the provider type.
func (g *GitLabProvider) Type() ProviderType {
	return ProviderGitLab
}

// ParseEvent parses a GitLab webhook event.
func (g *GitLabProvider) ParseEvent(ctx context.Context, body []byte, headers map[string]string) (*Event, error) {
	if ctx == nil {
		return nil, errors.New("context cannot be nil")
	}

	// Check context cancellation.
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	// Verify token if secret is configured.
	if g.config.Secret != "" {
		token := headers["X-Gitlab-Token"]
		if token == "" {
			token = headers["x-gitlab-token"]
		}
		if token == "" {
			return nil, ErrMissingGitLabToken
		}

		if subtle.ConstantTimeCompare([]byte(token), []byte(g.config.Secret)) != 1 {
			return nil, ErrInvalidGitLabToken
		}
	}

	// Get event type from header.
	eventType := headers["X-Gitlab-Event"]
	if eventType == "" {
		eventType = headers["x-gitlab-event"]
	}
	if eventType == "" {
		return nil, ErrMissingGitLabEvent
	}

	// Parse based on event type.
	switch eventType {
	case "Push Hook":
		return g.parsePushEvent(body)
	case "Merge Request Hook":
		return g.parseMergeRequestEvent(body)
	case "Tag Push Hook":
		return g.parseTagEvent(body)
	case "Pipeline Hook":
		return g.parsePipelineEvent(body)
	default:
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedEvent, eventType)
	}
}

// gitlabPushEvent represents a GitLab push event payload.
type gitlabPushEvent struct {
	Ref         string `json:"ref"`
	CheckoutSHA string `json:"checkout_sha"`
	Project     struct {
		PathWithNamespace string `json:"path_with_namespace"`
	} `json:"project"`
	UserName string `json:"user_name"`
	Commits  []struct {
		Message string `json:"message"`
	} `json:"commits"`
}

// parsePushEvent parses a push event.
func (g *GitLabProvider) parsePushEvent(body []byte) (*Event, error) {
	var payload gitlabPushEvent
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidPayload, err)
	}

	message := ""
	if len(payload.Commits) > 0 {
		message = payload.Commits[0].Message
	}

	return &Event{
		Provider:  ProviderGitLab,
		Type:      EventPush,
		Ref:       payload.Ref,
		SHA:       payload.CheckoutSHA,
		Repo:      payload.Project.PathWithNamespace,
		Author:    payload.UserName,
		Message:   message,
		Timestamp: time.Now(),
		Metadata: map[string]string{
			"event_type": "push",
		},
	}, nil
}

// gitlabMergeRequestEvent represents a GitLab merge request event payload.
type gitlabMergeRequestEvent struct {
	ObjectKind string `json:"object_kind"`
	Project    struct {
		PathWithNamespace string `json:"path_with_namespace"`
	} `json:"project"`
	User struct {
		Name string `json:"name"`
	} `json:"user"`
	ObjectAttributes struct {
		SourceBranch string `json:"source_branch"`
		TargetBranch string `json:"target_branch"`
		Title        string `json:"title"`
		LastCommit   struct {
			ID string `json:"id"`
		} `json:"last_commit"`
		State  string `json:"state"`
		Action string `json:"action"`
		IID    int    `json:"iid"`
	} `json:"object_attributes"`
}

// parseMergeRequestEvent parses a merge request event.
func (g *GitLabProvider) parseMergeRequestEvent(body []byte) (*Event, error) {
	var payload gitlabMergeRequestEvent
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidPayload, err)
	}

	return &Event{
		Provider:  ProviderGitLab,
		Type:      EventPullRequest,
		Ref:       fmt.Sprintf("refs/merge-requests/%d/head", payload.ObjectAttributes.IID),
		SHA:       payload.ObjectAttributes.LastCommit.ID,
		Repo:      payload.Project.PathWithNamespace,
		Branch:    payload.ObjectAttributes.SourceBranch,
		Author:    payload.User.Name,
		Message:   payload.ObjectAttributes.Title,
		Timestamp: time.Now(),
		Metadata: map[string]string{
			"event_type":    "merge_request",
			"action":        payload.ObjectAttributes.Action,
			"mr_iid":        fmt.Sprintf("%d", payload.ObjectAttributes.IID),
			"target_branch": payload.ObjectAttributes.TargetBranch,
		},
	}, nil
}

// gitlabTagEvent represents a GitLab tag event payload.
type gitlabTagEvent struct {
	Ref         string `json:"ref"`
	CheckoutSHA string `json:"checkout_sha"`
	Project     struct {
		PathWithNamespace string `json:"path_with_namespace"`
	} `json:"project"`
	UserName string `json:"user_name"`
}

// parseTagEvent parses a tag event.
func (g *GitLabProvider) parseTagEvent(body []byte) (*Event, error) {
	var payload gitlabTagEvent
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidPayload, err)
	}

	return &Event{
		Provider:  ProviderGitLab,
		Type:      EventTag,
		Ref:       payload.Ref,
		SHA:       payload.CheckoutSHA,
		Repo:      payload.Project.PathWithNamespace,
		Author:    payload.UserName,
		Timestamp: time.Now(),
		Metadata: map[string]string{
			"event_type": "tag",
		},
	}, nil
}

// gitlabPipelineEvent represents a GitLab pipeline event payload.
type gitlabPipelineEvent struct {
	ObjectKind string `json:"object_kind"`
	Project    struct {
		PathWithNamespace string `json:"path_with_namespace"`
	} `json:"project"`
	User struct {
		Name string `json:"name"`
	} `json:"user"`
	ObjectAttributes struct {
		Ref    string `json:"ref"`
		SHA    string `json:"sha"`
		Status string `json:"status"`
		ID     int    `json:"id"`
	} `json:"object_attributes"`
}

// parsePipelineEvent parses a pipeline event.
func (g *GitLabProvider) parsePipelineEvent(body []byte) (*Event, error) {
	var payload gitlabPipelineEvent
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidPayload, err)
	}

	return &Event{
		Provider:  ProviderGitLab,
		Type:      EventPush,
		Ref:       payload.ObjectAttributes.Ref,
		SHA:       payload.ObjectAttributes.SHA,
		Repo:      payload.Project.PathWithNamespace,
		Author:    payload.User.Name,
		Timestamp: time.Now(),
		Metadata: map[string]string{
			"event_type":      "pipeline",
			"pipeline_id":     fmt.Sprintf("%d", payload.ObjectAttributes.ID),
			"pipeline_status": payload.ObjectAttributes.Status,
		},
	}, nil
}

// gitlabCommitStatusRequest represents a GitLab commit status API request.
type gitlabCommitStatusRequest struct {
	State       string `json:"state"`
	Ref         string `json:"ref,omitempty"`
	Name        string `json:"name,omitempty"`
	TargetURL   string `json:"target_url,omitempty"`
	Description string `json:"description,omitempty"`
	Coverage    string `json:"coverage,omitempty"`
	PipelineID  int    `json:"pipeline_id,omitempty"`
}

// UpdateStatus updates the pipeline status via GitLab API.
func (g *GitLabProvider) UpdateStatus(ctx context.Context, status RunStatus) error {
	if ctx == nil {
		return errors.New("context cannot be nil")
	}

	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	if g.config.Token == "" {
		return ErrMissingToken
	}

	// Extract project and SHA from metadata.
	project := status.Metadata["project"]
	sha := status.Metadata["sha"]
	if project == "" || sha == "" {
		return errors.New("missing project or sha in status metadata")
	}

	// URL-encode the project path.
	encodedProject := url.PathEscape(project)

	req := gitlabCommitStatusRequest{
		State:       MapStatusToGitLab(status.Status),
		Name:        status.PipelineRef,
		Description: truncateGitLabDescription(status.Description),
		TargetURL:   status.URL,
	}
	if req.Name == "" {
		req.Name = "devsec/pipeline"
	}

	body, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("failed to marshal status request: %w", err)
	}

	apiURL := fmt.Sprintf("%s/projects/%s/statuses/%s", g.config.BaseURL, encodedProject, sha)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, apiURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	httpReq.Header.Set("PRIVATE-TOKEN", g.config.Token)
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := g.client.Do(httpReq)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("GitLab API error (status %d): %s", resp.StatusCode, string(respBody))
	}

	return nil
}

// truncateGitLabDescription truncates description for GitLab (max 255 chars).
func truncateGitLabDescription(s string) string {
	if len(s) <= 255 {
		return s
	}
	return s[:252] + "..."
}

// CreateCheck creates a GitLab commit status.
func (g *GitLabProvider) CreateCheck(ctx context.Context, event Event, name string) (string, error) {
	if ctx == nil {
		return "", errors.New("context cannot be nil")
	}

	if g.config.Token == "" {
		return "", ErrMissingToken
	}

	select {
	case <-ctx.Done():
		return "", ctx.Err()
	default:
	}

	if event.Repo == "" || event.SHA == "" {
		return "", errors.New("missing repo or sha in event")
	}

	// URL-encode the project path.
	encodedProject := url.PathEscape(event.Repo)

	req := gitlabCommitStatusRequest{
		State:       "pending",
		Name:        name,
		Description: "Pipeline started",
	}

	body, err := json.Marshal(req)
	if err != nil {
		return "", fmt.Errorf("failed to marshal status request: %w", err)
	}

	apiURL := fmt.Sprintf("%s/projects/%s/statuses/%s", g.config.BaseURL, encodedProject, event.SHA)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, apiURL, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	httpReq.Header.Set("PRIVATE-TOKEN", g.config.Token)
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := g.client.Do(httpReq)
	if err != nil {
		return "", fmt.Errorf("failed to send request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("GitLab API error (status %d): %s", resp.StatusCode, string(respBody))
	}

	// GitLab commit status doesn't return an ID, use name as identifier.
	return name, nil
}

// UpdateCheck updates an existing GitLab commit status.
func (g *GitLabProvider) UpdateCheck(ctx context.Context, checkID string, status RunStatus) error {
	if ctx == nil {
		return errors.New("context cannot be nil")
	}

	if g.config.Token == "" {
		return ErrMissingToken
	}

	if checkID == "" {
		return errors.New("missing check ID (status name)")
	}

	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	project := status.Metadata["project"]
	sha := status.Metadata["sha"]
	if project == "" || sha == "" {
		return errors.New("missing project or sha in status metadata")
	}

	// URL-encode the project path.
	encodedProject := url.PathEscape(project)

	req := gitlabCommitStatusRequest{
		State:       MapStatusToGitLab(status.Status),
		Name:        checkID,
		Description: truncateGitLabDescription(status.Description),
		TargetURL:   status.URL,
	}

	body, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("failed to marshal status request: %w", err)
	}

	apiURL := fmt.Sprintf("%s/projects/%s/statuses/%s", g.config.BaseURL, encodedProject, sha)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, apiURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	httpReq.Header.Set("PRIVATE-TOKEN", g.config.Token)
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := g.client.Do(httpReq)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("GitLab API error (status %d): %s", resp.StatusCode, string(respBody))
	}

	return nil
}

// MapStatusToGitLab converts internal status to GitLab commit status.
func MapStatusToGitLab(status StatusType) string {
	switch status {
	case StatusPending:
		return "pending"
	case StatusRunning, StatusInProgress:
		return "running"
	case StatusSuccess:
		return "success"
	case StatusFailure, StatusError:
		return "failed"
	case StatusCanceled:
		return "canceled"
	default:
		return "pending"
	}
}
