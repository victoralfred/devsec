package gates

import (
	"context"
	"errors"
	"testing"
)

// mockHelmClient is a mock implementation for testing.
type mockHelmClient struct {
	installErr       error
	upgradeErr       error
	rollbackErr      error
	revisionErr      error
	releaseInfo      *ReleaseInfo
	currentRevision  int
	rollbackRevision int
	rollbackCalled   bool
}

func (m *mockHelmClient) Install(_ context.Context, _, _, _ string, _ map[string]interface{}) (*ReleaseInfo, error) {
	if m.installErr != nil {
		return nil, m.installErr
	}
	return m.releaseInfo, nil
}

func (m *mockHelmClient) Upgrade(_ context.Context, _, _, _ string, _ map[string]interface{}) (*ReleaseInfo, error) {
	if m.upgradeErr != nil {
		return nil, m.upgradeErr
	}
	return m.releaseInfo, nil
}

func (m *mockHelmClient) Rollback(_ context.Context, _, _ string, revision int) error {
	m.rollbackCalled = true
	m.rollbackRevision = revision
	return m.rollbackErr
}

func (m *mockHelmClient) GetCurrentRevision(_ context.Context, _, _ string) (int, error) {
	if m.revisionErr != nil {
		return 0, m.revisionErr
	}
	return m.currentRevision, nil
}

func TestRollbackHandler_ShouldRollback(t *testing.T) {
	t.Parallel()

	handler := NewRollbackHandler(nil, nil)

	tests := []struct {
		result   *GateResult
		name     string
		expected bool
	}{
		{
			name:     "nil result",
			result:   nil,
			expected: false,
		},
		{
			name:     "passed result",
			result:   &GateResult{Passed: true},
			expected: false,
		},
		{
			name:     "failed result",
			result:   &GateResult{Passed: false},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := handler.ShouldRollback(tt.result); got != tt.expected {
				t.Errorf("ShouldRollback() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestRollbackHandler_Execute_NilContext(t *testing.T) {
	t.Parallel()

	handler := NewRollbackHandler(&mockHelmClient{currentRevision: 2}, nil)
	opts := RollbackOptions{ReleaseName: "app", Namespace: "default"}
	var ctx context.Context = nil
	err := handler.Execute(ctx, opts) //nolint:staticcheck // intentionally passing nil context for testing
	if err != ErrNilContext {
		t.Errorf("Execute(context.TODO()) error = %v, want ErrNilContext", err)
	}
}

func TestRollbackHandler_Execute_MissingClient(t *testing.T) {
	t.Parallel()

	handler := NewRollbackHandler(nil, nil)
	ctx := context.Background()
	opts := RollbackOptions{ReleaseName: "app", Namespace: "default"}

	err := handler.Execute(ctx, opts)
	if err != ErrMissingHelmClient {
		t.Errorf("Execute() error = %v, want ErrMissingHelmClient", err)
	}
}

func TestRollbackHandler_Execute_InvalidOptions(t *testing.T) {
	t.Parallel()

	handler := NewRollbackHandler(&mockHelmClient{}, nil)
	ctx := context.Background()
	opts := RollbackOptions{ReleaseName: ""} // Invalid: empty release name.

	err := handler.Execute(ctx, opts)
	if err != ErrEmptyReleaseName {
		t.Errorf("Execute() error = %v, want ErrEmptyReleaseName", err)
	}
}

func TestRollbackHandler_Execute_Success(t *testing.T) {
	t.Parallel()

	client := &mockHelmClient{currentRevision: 3}
	handler := NewRollbackHandler(client, nil)
	ctx := context.Background()
	opts := RollbackOptions{ReleaseName: "app", Namespace: "default"}

	err := handler.Execute(ctx, opts)
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if !client.rollbackCalled {
		t.Error("Rollback should be called")
	}
	if client.rollbackRevision != 2 {
		t.Errorf("rollbackRevision = %v, want 2", client.rollbackRevision)
	}
}

func TestRollbackHandler_Execute_WithSpecificRevision(t *testing.T) {
	t.Parallel()

	client := &mockHelmClient{currentRevision: 5}
	handler := NewRollbackHandler(client, nil)
	ctx := context.Background()
	opts := RollbackOptions{ReleaseName: "app", Namespace: "default", Revision: 2}

	err := handler.Execute(ctx, opts)
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if client.rollbackRevision != 2 {
		t.Errorf("rollbackRevision = %v, want 2", client.rollbackRevision)
	}
}

func TestRollbackHandler_Execute_RollbackError(t *testing.T) {
	t.Parallel()

	client := &mockHelmClient{
		currentRevision: 3,
		rollbackErr:     errors.New("rollback failed"),
	}
	handler := NewRollbackHandler(client, nil)
	ctx := context.Background()
	opts := RollbackOptions{ReleaseName: "app", Namespace: "default"}

	err := handler.Execute(ctx, opts)
	if err == nil {
		t.Error("Execute() should return error")
	}
	if !IsRollbackFailure(err) {
		t.Error("Execute() error should be rollback failure")
	}
}

func TestRollbackHandler_GetPreviousRevision_NilContext(t *testing.T) {
	t.Parallel()

	handler := NewRollbackHandler(&mockHelmClient{}, nil)
	var ctx context.Context = nil
	_, err := handler.GetPreviousRevision(ctx, "default", "app") //nolint:staticcheck // intentionally passing nil context for testing
	if err != ErrNilContext {
		t.Errorf("GetPreviousRevision(context.TODO()) error = %v, want ErrNilContext", err)
	}
}

func TestRollbackHandler_GetPreviousRevision_MissingClient(t *testing.T) {
	t.Parallel()

	handler := NewRollbackHandler(nil, nil)
	ctx := context.Background()
	_, err := handler.GetPreviousRevision(ctx, "default", "app")
	if err != ErrMissingHelmClient {
		t.Errorf("GetPreviousRevision() error = %v, want ErrMissingHelmClient", err)
	}
}

func TestRollbackHandler_GetPreviousRevision_EmptyNamespace(t *testing.T) {
	t.Parallel()

	handler := NewRollbackHandler(&mockHelmClient{}, nil)
	ctx := context.Background()
	_, err := handler.GetPreviousRevision(ctx, "", "app")
	if err != ErrEmptyNamespace {
		t.Errorf("GetPreviousRevision() error = %v, want ErrEmptyNamespace", err)
	}
}

func TestRollbackHandler_GetPreviousRevision_EmptyRelease(t *testing.T) {
	t.Parallel()

	handler := NewRollbackHandler(&mockHelmClient{}, nil)
	ctx := context.Background()
	_, err := handler.GetPreviousRevision(ctx, "default", "")
	if err != ErrEmptyReleaseName {
		t.Errorf("GetPreviousRevision() error = %v, want ErrEmptyReleaseName", err)
	}
}

func TestRollbackHandler_GetPreviousRevision_Success(t *testing.T) {
	t.Parallel()

	client := &mockHelmClient{currentRevision: 5}
	handler := NewRollbackHandler(client, nil)
	ctx := context.Background()

	revision, err := handler.GetPreviousRevision(ctx, "default", "app")
	if err != nil {
		t.Fatalf("GetPreviousRevision() error = %v", err)
	}
	if revision != 4 {
		t.Errorf("revision = %v, want 4", revision)
	}
}

func TestRollbackHandler_GetPreviousRevision_NoPrevious(t *testing.T) {
	t.Parallel()

	client := &mockHelmClient{currentRevision: 1}
	handler := NewRollbackHandler(client, nil)
	ctx := context.Background()

	_, err := handler.GetPreviousRevision(ctx, "default", "app")
	if err == nil {
		t.Error("GetPreviousRevision() should return error when at revision 1")
	}
}

func TestRollbackHandler_GetPreviousRevision_Error(t *testing.T) {
	t.Parallel()

	client := &mockHelmClient{
		revisionErr: errors.New("release not found"),
	}
	handler := NewRollbackHandler(client, nil)
	ctx := context.Background()

	_, err := handler.GetPreviousRevision(ctx, "default", "app")
	if err == nil {
		t.Error("GetPreviousRevision() should return error")
	}
}

func TestRollbackHandler_ExecuteWithResult_Success(t *testing.T) {
	t.Parallel()

	client := &mockHelmClient{currentRevision: 3}
	handler := NewRollbackHandler(client, nil)
	ctx := context.Background()
	opts := RollbackOptions{ReleaseName: "app", Namespace: "default"}

	result, err := handler.ExecuteWithResult(ctx, opts)
	if err != nil {
		t.Fatalf("ExecuteWithResult() error = %v", err)
	}
	if !result.Success {
		t.Error("result.Success should be true")
	}
	if result.FromRevision != 3 {
		t.Errorf("FromRevision = %v, want 3", result.FromRevision)
	}
	if result.ToRevision != 2 {
		t.Errorf("ToRevision = %v, want 2", result.ToRevision)
	}
}

func TestRollbackHandler_ExecuteWithResult_NilContext(t *testing.T) {
	t.Parallel()

	handler := NewRollbackHandler(&mockHelmClient{}, nil)
	opts := RollbackOptions{ReleaseName: "app", Namespace: "default"}
	var ctx context.Context = nil
	_, err := handler.ExecuteWithResult(ctx, opts) //nolint:staticcheck // intentionally passing nil context for testing
	if err != ErrNilContext {
		t.Errorf("ExecuteWithResult(context.TODO()) error = %v, want ErrNilContext", err)
	}
}

func TestRollbackHandler_ExecuteWithResult_Error(t *testing.T) {
	t.Parallel()

	client := &mockHelmClient{
		currentRevision: 3,
		rollbackErr:     errors.New("rollback failed"),
	}
	handler := NewRollbackHandler(client, nil)
	ctx := context.Background()
	opts := RollbackOptions{ReleaseName: "app", Namespace: "default"}

	result, err := handler.ExecuteWithResult(ctx, opts)
	if err == nil {
		t.Error("ExecuteWithResult() should return error")
	}
	if result.Success {
		t.Error("result.Success should be false")
	}
	if result.ErrorMessage == "" {
		t.Error("result.ErrorMessage should not be empty")
	}
}

func TestDefaultAutoRollbackConfig(t *testing.T) {
	t.Parallel()

	cfg := DefaultAutoRollbackConfig()

	if !cfg.Enabled {
		t.Error("Enabled should be true")
	}
	if cfg.OnPreCheck {
		t.Error("OnPreCheck should be false")
	}
	if !cfg.OnPostCheck {
		t.Error("OnPostCheck should be true")
	}
	if !cfg.OnDeployError {
		t.Error("OnDeployError should be true")
	}
	if cfg.MaxRetries != 1 {
		t.Errorf("MaxRetries = %v, want 1", cfg.MaxRetries)
	}
}

func TestAutoRollbackConfig_ShouldRollbackOn(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		failureType string
		cfg         AutoRollbackConfig
		expected    bool
	}{
		{
			name:        "disabled",
			cfg:         AutoRollbackConfig{Enabled: false},
			failureType: "post_check",
			expected:    false,
		},
		{
			name:        "pre_check enabled",
			cfg:         AutoRollbackConfig{Enabled: true, OnPreCheck: true},
			failureType: "pre_check",
			expected:    true,
		},
		{
			name:        "pre_check disabled",
			cfg:         AutoRollbackConfig{Enabled: true, OnPreCheck: false},
			failureType: "pre_check",
			expected:    false,
		},
		{
			name:        "post_check enabled",
			cfg:         AutoRollbackConfig{Enabled: true, OnPostCheck: true},
			failureType: "post_check",
			expected:    true,
		},
		{
			name:        "deploy_error enabled",
			cfg:         AutoRollbackConfig{Enabled: true, OnDeployError: true},
			failureType: "deploy_error",
			expected:    true,
		},
		{
			name:        "unknown failure type",
			cfg:         DefaultAutoRollbackConfig(),
			failureType: "unknown",
			expected:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.cfg.ShouldRollbackOn(tt.failureType); got != tt.expected {
				t.Errorf("ShouldRollbackOn(%v) = %v, want %v", tt.failureType, got, tt.expected)
			}
		})
	}
}

func TestRollbackResult(t *testing.T) {
	t.Parallel()

	result := RollbackResult{
		Namespace:    "default",
		ReleaseName:  "my-app",
		FromRevision: 3,
		ToRevision:   2,
		Success:      true,
	}

	if result.Namespace != "default" {
		t.Errorf("Namespace = %v, want default", result.Namespace)
	}
	if result.ReleaseName != "my-app" {
		t.Errorf("ReleaseName = %v, want my-app", result.ReleaseName)
	}
	if result.FromRevision != 3 {
		t.Errorf("FromRevision = %v, want 3", result.FromRevision)
	}
	if result.ToRevision != 2 {
		t.Errorf("ToRevision = %v, want 2", result.ToRevision)
	}
	if !result.Success {
		t.Error("Success should be true")
	}
}
