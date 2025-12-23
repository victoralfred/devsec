package helm

import (
	"testing"

	"helm.sh/helm/v3/pkg/action"
	"helm.sh/helm/v3/pkg/storage"
	"helm.sh/helm/v3/pkg/storage/driver"
)

func TestNewTestClient(t *testing.T) {
	t.Parallel()

	cfg := HelmConfig{
		Namespace: "test-namespace",
	}

	client := NewTestClient(cfg)

	if client == nil {
		t.Fatal("expected non-nil client")
	}
	if client.actionConfig == nil {
		t.Error("actionConfig not set")
	}
	if client.cfg.Namespace != "test-namespace" {
		t.Errorf("Namespace = %v, want test-namespace", client.cfg.Namespace)
	}
}

func TestDefaultClient_Release(t *testing.T) {
	t.Parallel()

	cfg := HelmConfig{
		Namespace: "default",
	}

	client := NewTestClient(cfg)

	// Test with empty namespace (should use default).
	releaseClient := client.Release("")
	if releaseClient == nil {
		t.Fatal("expected non-nil ReleaseClient")
	}

	// Test with explicit namespace.
	releaseClient = client.Release("custom-namespace")
	if releaseClient == nil {
		t.Fatal("expected non-nil ReleaseClient")
	}
}

func TestDefaultClient_Chart(t *testing.T) {
	t.Parallel()

	cfg := HelmConfig{
		Namespace: "default",
	}

	client := NewTestClient(cfg)

	chartClient := client.Chart()
	if chartClient == nil {
		t.Fatal("expected non-nil ChartClient")
	}
}

func TestDefaultClient_Values(t *testing.T) {
	t.Parallel()

	cfg := HelmConfig{
		Namespace: "default",
	}

	client := NewTestClient(cfg)

	valuesClient := client.Values()
	if valuesClient == nil {
		t.Fatal("expected non-nil ValuesClient")
	}
}

func TestDefaultClient_Close(t *testing.T) {
	t.Parallel()

	cfg := DefaultHelmConfig()
	client := NewTestClient(cfg)

	if err := client.Close(); err != nil {
		t.Errorf("Close() error = %v", err)
	}
}

func TestDefaultClient_Config(t *testing.T) {
	t.Parallel()

	cfg := HelmConfig{
		Namespace: "test",
		Debug:     true,
	}

	client := NewTestClient(cfg)

	gotCfg := client.Config()
	if gotCfg.Namespace != "test" {
		t.Errorf("Config().Namespace = %v, want test", gotCfg.Namespace)
	}
	if !gotCfg.Debug {
		t.Error("Config().Debug should be true")
	}
}

func TestDefaultClient_ActionConfig(t *testing.T) {
	t.Parallel()

	cfg := DefaultHelmConfig()
	client := NewTestClient(cfg)

	if client.ActionConfig() == nil {
		t.Error("ActionConfig() should return the underlying action.Configuration")
	}
}

func TestNewClientWithActionConfig(t *testing.T) {
	t.Parallel()

	actionCfg := newTestActionConfig()
	cfg := HelmConfig{
		Namespace: "test-namespace",
	}

	client := NewClientWithActionConfig(actionCfg, cfg)

	if client == nil {
		t.Fatal("expected non-nil client")
	}
	if client.actionConfig != actionCfg {
		t.Error("actionConfig not set correctly")
	}
	if client.cfg.Namespace != "test-namespace" {
		t.Errorf("Namespace = %v, want test-namespace", client.cfg.Namespace)
	}
}

func TestReleaseStatusType_IsValid(t *testing.T) {
	t.Parallel()

	tests := []struct {
		status   ReleaseStatusType
		expected bool
	}{
		{StatusDeployed, true},
		{StatusUninstalled, true},
		{StatusSuperseded, true},
		{StatusFailed, true},
		{StatusUninstalling, true},
		{StatusPendingInstall, true},
		{StatusPendingUpgrade, true},
		{StatusPendingRollback, true},
		{StatusUnknown, true},
		{ReleaseStatusType("invalid"), false},
	}

	for _, tt := range tests {
		t.Run(string(tt.status), func(t *testing.T) {
			t.Parallel()
			if got := tt.status.IsValid(); got != tt.expected {
				t.Errorf("IsValid() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestReleaseStatusType_IsTerminal(t *testing.T) {
	t.Parallel()

	tests := []struct {
		status   ReleaseStatusType
		expected bool
	}{
		{StatusDeployed, true},
		{StatusFailed, true},
		{StatusUninstalled, true},
		{StatusSuperseded, true},
		{StatusPendingInstall, false},
		{StatusPendingUpgrade, false},
		{StatusUninstalling, false},
	}

	for _, tt := range tests {
		t.Run(string(tt.status), func(t *testing.T) {
			t.Parallel()
			if got := tt.status.IsTerminal(); got != tt.expected {
				t.Errorf("IsTerminal() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestReleaseStatusType_IsSuccess(t *testing.T) {
	t.Parallel()

	tests := []struct {
		status   ReleaseStatusType
		expected bool
	}{
		{StatusDeployed, true},
		{StatusFailed, false},
		{StatusPendingInstall, false},
		{StatusUninstalled, false},
	}

	for _, tt := range tests {
		t.Run(string(tt.status), func(t *testing.T) {
			t.Parallel()
			if got := tt.status.IsSuccess(); got != tt.expected {
				t.Errorf("IsSuccess() = %v, want %v", got, tt.expected)
			}
		})
	}
}

// newTestActionConfig creates an action.Configuration with in-memory storage for testing.
func newTestActionConfig() *action.Configuration {
	cfg := new(action.Configuration)
	cfg.Releases = storage.Init(driver.NewMemory())
	cfg.Log = func(_ string, _ ...interface{}) {} // No-op logger.
	return cfg
}
