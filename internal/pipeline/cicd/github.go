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

// GitHub-specific errors.
var (
	ErrInvalidSignature    = errors.New("invalid webhook signature")
	ErrMissingSignature    = errors.New("missing webhook signature")
	ErrUnsupportedEvent    = errors.New("unsupported GitHub event type")
	ErrMissingEventHeader  = errors.New("missing X-GitHub-Event header")
	ErrInvalidPayload      = errors.New("invalid payload format")
	ErrMissingToken        = errors.New("missing API token")
	ErrMissingCheckDetails = errors.New("missing check details")
)

// GitHubProvider implements the Provider interface for GitHub Actions.
type GitHubProvider struct {
	config ProviderConfig
}

// GitHubOption configures a GitHubProvider.
type GitHubOption func(*GitHubProvider)

// WithGitHubToken sets the GitHub API token.
func WithGitHubToken(token string) GitHubOption {
	return func(g *GitHubProvider) {
		g.config.Token = token
	}
}

// WithGitHubSecret sets the webhook secret for signature verification.
func WithGitHubSecret(secret string) GitHubOption {
	return func(g *GitHubProvider) {
		g.config.Secret = secret
	}
}

// WithGitHubBaseURL sets the GitHub API base URL (for GitHub Enterprise).
func WithGitHubBaseURL(url string) GitHubOption {
	return func(g *GitHubProvider) {
		g.config.BaseURL = url
	}
}

// NewGitHubProvider creates a new GitHub provider.
func NewGitHubProvider(opts ...GitHubOption) *GitHubProvider {
	g := &GitHubProvider{
		config: ProviderConfig{
			BaseURL: "https://api.github.com",
		},
	}

	for _, opt := range opts {
		opt(g)
	}

	return g
}

// Type returns the provider type.
func (g *GitHubProvider) Type() ProviderType {
	return ProviderGitHub
}

// ParseEvent parses a GitHub webhook event.
func (g *GitHubProvider) ParseEvent(ctx context.Context, body []byte, headers map[string]string) (*Event, error) {
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
	if g.config.Secret != "" {
		signature := headers["X-Hub-Signature-256"]
		if signature == "" {
			signature = headers["x-hub-signature-256"]
		}
		if signature == "" {
			return nil, ErrMissingSignature
		}

		if !g.verifySignature(body, signature) {
			return nil, ErrInvalidSignature
		}
	}

	// Get event type from header.
	eventType := headers["X-GitHub-Event"]
	if eventType == "" {
		eventType = headers["x-github-event"]
	}
	if eventType == "" {
		return nil, ErrMissingEventHeader
	}

	// Parse based on event type.
	switch eventType {
	case "push":
		return g.parsePushEvent(body)
	case "pull_request":
		return g.parsePullRequestEvent(body)
	case "create":
		return g.parseCreateEvent(body)
	default:
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedEvent, eventType)
	}
}

// verifySignature verifies the webhook signature.
func (g *GitHubProvider) verifySignature(body []byte, signature string) bool {
	// GitHub sends signature as "sha256=<hash>".
	const prefix = "sha256="
	if !strings.HasPrefix(signature, prefix) {
		return false
	}

	expectedMAC, err := hex.DecodeString(signature[len(prefix):])
	if err != nil {
		return false
	}

	mac := hmac.New(sha256.New, []byte(g.config.Secret))
	mac.Write(body)
	actualMAC := mac.Sum(nil)

	return hmac.Equal(expectedMAC, actualMAC)
}

// githubPushEvent represents a GitHub push event payload.
type githubPushEvent struct {
	Ref        string `json:"ref"`
	After      string `json:"after"`
	Repository struct {
		FullName string `json:"full_name"`
	} `json:"repository"`
	Pusher struct {
		Name string `json:"name"`
	} `json:"pusher"`
	HeadCommit struct {
		Message string `json:"message"`
	} `json:"head_commit"`
}

// parsePushEvent parses a push event.
func (g *GitHubProvider) parsePushEvent(body []byte) (*Event, error) {
	var payload githubPushEvent
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidPayload, err)
	}

	// Extract branch from ref.
	branch := strings.TrimPrefix(payload.Ref, "refs/heads/")

	return &Event{
		Provider:  ProviderGitHub,
		Type:      EventPush,
		Ref:       payload.Ref,
		SHA:       payload.After,
		Repo:      payload.Repository.FullName,
		Branch:    branch,
		Author:    payload.Pusher.Name,
		Message:   payload.HeadCommit.Message,
		Timestamp: time.Now(),
		Metadata: map[string]string{
			"event_type": "push",
		},
	}, nil
}

// githubPullRequestEvent represents a GitHub pull request event payload.
type githubPullRequestEvent struct {
	PullRequest struct {
		Head struct {
			SHA string `json:"sha"`
			Ref string `json:"ref"`
		} `json:"head"`
		Title string `json:"title"`
		User  struct {
			Login string `json:"login"`
		} `json:"user"`
	} `json:"pull_request"`
	Action     string `json:"action"`
	Repository struct {
		FullName string `json:"full_name"`
	} `json:"repository"`
	Number int `json:"number"`
}

// parsePullRequestEvent parses a pull request event.
func (g *GitHubProvider) parsePullRequestEvent(body []byte) (*Event, error) {
	var payload githubPullRequestEvent
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidPayload, err)
	}

	return &Event{
		Provider:  ProviderGitHub,
		Type:      EventPullRequest,
		Ref:       fmt.Sprintf("refs/pull/%d/head", payload.Number),
		SHA:       payload.PullRequest.Head.SHA,
		Repo:      payload.Repository.FullName,
		Branch:    payload.PullRequest.Head.Ref,
		Author:    payload.PullRequest.User.Login,
		Message:   payload.PullRequest.Title,
		Timestamp: time.Now(),
		Metadata: map[string]string{
			"event_type": "pull_request",
			"action":     payload.Action,
			"pr_number":  fmt.Sprintf("%d", payload.Number),
		},
	}, nil
}

// githubCreateEvent represents a GitHub create event payload.
type githubCreateEvent struct {
	Ref        string `json:"ref"`
	RefType    string `json:"ref_type"`
	Repository struct {
		FullName string `json:"full_name"`
	} `json:"repository"`
	Sender struct {
		Login string `json:"login"`
	} `json:"sender"`
}

// parseCreateEvent parses a create (tag/branch) event.
func (g *GitHubProvider) parseCreateEvent(body []byte) (*Event, error) {
	var payload githubCreateEvent
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidPayload, err)
	}

	eventType := EventPush
	if payload.RefType == "tag" {
		eventType = EventTag
	}

	return &Event{
		Provider:  ProviderGitHub,
		Type:      eventType,
		Ref:       payload.Ref,
		Repo:      payload.Repository.FullName,
		Author:    payload.Sender.Login,
		Timestamp: time.Now(),
		Metadata: map[string]string{
			"event_type": "create",
			"ref_type":   payload.RefType,
		},
	}, nil
}

// UpdateStatus updates the commit status.
func (g *GitHubProvider) UpdateStatus(ctx context.Context, status RunStatus) error {
	if ctx == nil {
		return errors.New("context cannot be nil")
	}

	// Check context cancellation.
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	// This is a placeholder - actual implementation would make API calls.
	// Using the GitHub REST or GraphQL API to update commit status.
	return nil
}

// CreateCheck creates a GitHub check run.
func (g *GitHubProvider) CreateCheck(ctx context.Context, event Event, name string) (string, error) {
	if ctx == nil {
		return "", errors.New("context cannot be nil")
	}

	if g.config.Token == "" {
		return "", ErrMissingToken
	}

	// Check context cancellation.
	select {
	case <-ctx.Done():
		return "", ctx.Err()
	default:
	}

	// This is a placeholder - actual implementation would create a check run via API.
	// Returns a mock check ID.
	checkID := fmt.Sprintf("check_%s_%d", name, time.Now().UnixNano())
	return checkID, nil
}

// UpdateCheck updates an existing GitHub check run.
func (g *GitHubProvider) UpdateCheck(ctx context.Context, checkID string, status RunStatus) error {
	if ctx == nil {
		return errors.New("context cannot be nil")
	}

	if g.config.Token == "" {
		return ErrMissingToken
	}

	if checkID == "" {
		return ErrMissingCheckDetails
	}

	// Check context cancellation.
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	// This is a placeholder - actual implementation would update check via API.
	return nil
}

// MapStatusToGitHub converts internal status to GitHub check status.
func MapStatusToGitHub(status StatusType) string {
	switch status {
	case StatusPending:
		return "queued"
	case StatusRunning, StatusInProgress:
		return "in_progress"
	case StatusSuccess:
		return "completed"
	case StatusFailure, StatusError:
		return "completed"
	case StatusCanceled:
		return "completed"
	case StatusNeutral:
		return "completed"
	default:
		return "queued"
	}
}

// MapConclusionToGitHub converts internal status to GitHub check conclusion.
func MapConclusionToGitHub(status StatusType) string {
	switch status {
	case StatusSuccess:
		return "success"
	case StatusFailure:
		return "failure"
	case StatusError:
		return "failure"
	case StatusCanceled:
		return "cancelled" //nolint:misspell // GitHub API uses British spelling
	case StatusNeutral:
		return "neutral"
	default:
		return ""
	}
}
