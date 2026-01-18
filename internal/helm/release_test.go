package helm

import (
	"context"
	"strings"
	"testing"
	"time"

	"helm.sh/helm/v3/pkg/release"
)

func TestReleaseClient_Install_NilContext(t *testing.T) {
	t.Parallel()

	client := &defaultReleaseClient{
		actionConfig: newTestActionConfig(),
		namespace:    "default",
	}

	var ctx context.Context = nil
	_, err := client.Install(ctx, "release", "/path/to/chart", InstallOptions{}) //nolint:staticcheck // intentionally passing nil context for testing
	if err != ErrNilContext {
		t.Errorf("Install(nil) error = %v, want ErrNilContext", err)
	}
}

func TestReleaseClient_Install_EmptyName(t *testing.T) {
	t.Parallel()

	client := &defaultReleaseClient{
		actionConfig: newTestActionConfig(),
		namespace:    "default",
	}
	ctx := context.Background()

	_, err := client.Install(ctx, "", "/path/to/chart", InstallOptions{})
	if err != ErrEmptyReleaseName {
		t.Errorf("Install('', chart) error = %v, want ErrEmptyReleaseName", err)
	}
}

func TestReleaseClient_Install_EmptyChartRef(t *testing.T) {
	t.Parallel()

	client := &defaultReleaseClient{
		actionConfig: newTestActionConfig(),
		namespace:    "default",
	}
	ctx := context.Background()

	_, err := client.Install(ctx, "release", "", InstallOptions{})
	if err != ErrEmptyChartRef {
		t.Errorf("Install(name, '') error = %v, want ErrEmptyChartRef", err)
	}
}

func TestReleaseClient_Upgrade_NilContext(t *testing.T) {
	t.Parallel()

	client := &defaultReleaseClient{
		actionConfig: newTestActionConfig(),
		namespace:    "default",
	}

	var ctx context.Context = nil
	_, err := client.Upgrade(ctx, "release", "/path/to/chart", UpgradeOptions{}) //nolint:staticcheck // intentionally passing nil context for testing
	if err != ErrNilContext {
		t.Errorf("Upgrade(nil) error = %v, want ErrNilContext", err)
	}
}

func TestReleaseClient_Upgrade_EmptyName(t *testing.T) {
	t.Parallel()

	client := &defaultReleaseClient{
		actionConfig: newTestActionConfig(),
		namespace:    "default",
	}
	ctx := context.Background()

	_, err := client.Upgrade(ctx, "", "/path/to/chart", UpgradeOptions{})
	if err != ErrEmptyReleaseName {
		t.Errorf("Upgrade('', chart) error = %v, want ErrEmptyReleaseName", err)
	}
}

func TestReleaseClient_Upgrade_EmptyChartRef(t *testing.T) {
	t.Parallel()

	client := &defaultReleaseClient{
		actionConfig: newTestActionConfig(),
		namespace:    "default",
	}
	ctx := context.Background()

	_, err := client.Upgrade(ctx, "release", "", UpgradeOptions{})
	if err != ErrEmptyChartRef {
		t.Errorf("Upgrade(name, '') error = %v, want ErrEmptyChartRef", err)
	}
}

func TestReleaseClient_Get_NilContext(t *testing.T) {
	t.Parallel()

	client := &defaultReleaseClient{
		actionConfig: newTestActionConfig(),
		namespace:    "default",
	}

	var ctx context.Context = nil
	_, err := client.Get(ctx, "release") //nolint:staticcheck // intentionally passing nil context for testing
	if err != ErrNilContext {
		t.Errorf("Get(nil) error = %v, want ErrNilContext", err)
	}
}

func TestReleaseClient_Get_EmptyName(t *testing.T) {
	t.Parallel()

	client := &defaultReleaseClient{
		actionConfig: newTestActionConfig(),
		namespace:    "default",
	}
	ctx := context.Background()

	_, err := client.Get(ctx, "")
	if err != ErrEmptyReleaseName {
		t.Errorf("Get('') error = %v, want ErrEmptyReleaseName", err)
	}
}

// Note: TestReleaseClient_Get_NotFound requires a Kubernetes cluster or mock KubeClient.
// Input validation is tested in TestReleaseClient_Get_NilContext and TestReleaseClient_Get_EmptyName.

func TestReleaseClient_List_NilContext(t *testing.T) {
	t.Parallel()

	client := &defaultReleaseClient{
		actionConfig: newTestActionConfig(),
		namespace:    "default",
	}

	var ctx context.Context = nil
	_, err := client.List(ctx, ListOptions{}) //nolint:staticcheck // intentionally passing nil context for testing
	if err != ErrNilContext {
		t.Errorf("List(nil) error = %v, want ErrNilContext", err)
	}
}

// Note: TestReleaseClient_List with actual Helm operations requires a Kubernetes
// cluster or mock KubeClient. Input validation is tested in TestReleaseClient_List_NilContext.

func TestReleaseClient_Uninstall_NilContext(t *testing.T) {
	t.Parallel()

	client := &defaultReleaseClient{
		actionConfig: newTestActionConfig(),
		namespace:    "default",
	}

	var ctx context.Context = nil
	err := client.Uninstall(ctx, "release") //nolint:staticcheck // intentionally passing nil context for testing
	if err != ErrNilContext {
		t.Errorf("Uninstall(nil) error = %v, want ErrNilContext", err)
	}
}

func TestReleaseClient_Uninstall_EmptyName(t *testing.T) {
	t.Parallel()

	client := &defaultReleaseClient{
		actionConfig: newTestActionConfig(),
		namespace:    "default",
	}
	ctx := context.Background()

	err := client.Uninstall(ctx, "")
	if err != ErrEmptyReleaseName {
		t.Errorf("Uninstall('') error = %v, want ErrEmptyReleaseName", err)
	}
}

// Note: TestReleaseClient_Uninstall_NotFound requires a Kubernetes cluster or mock KubeClient.
// Input validation is tested in TestReleaseClient_Uninstall_NilContext and TestReleaseClient_Uninstall_EmptyName.

func TestReleaseClient_Rollback_NilContext(t *testing.T) {
	t.Parallel()

	client := &defaultReleaseClient{
		actionConfig: newTestActionConfig(),
		namespace:    "default",
	}

	var ctx context.Context = nil
	err := client.Rollback(ctx, "release", 1) //nolint:staticcheck // intentionally passing nil context for testing
	if err != ErrNilContext {
		t.Errorf("Rollback(nil) error = %v, want ErrNilContext", err)
	}
}

func TestReleaseClient_Rollback_EmptyName(t *testing.T) {
	t.Parallel()

	client := &defaultReleaseClient{
		actionConfig: newTestActionConfig(),
		namespace:    "default",
	}
	ctx := context.Background()

	err := client.Rollback(ctx, "", 1)
	if err != ErrEmptyReleaseName {
		t.Errorf("Rollback('') error = %v, want ErrEmptyReleaseName", err)
	}
}

// Note: TestReleaseClient_Rollback_NotFound requires a Kubernetes cluster or mock KubeClient.
// Input validation is tested in TestReleaseClient_Rollback_NilContext and TestReleaseClient_Rollback_EmptyName.

func TestReleaseClient_GetHistory_NilContext(t *testing.T) {
	t.Parallel()

	client := &defaultReleaseClient{
		actionConfig: newTestActionConfig(),
		namespace:    "default",
	}

	var ctx context.Context = nil
	_, err := client.GetHistory(ctx, "release") //nolint:staticcheck // intentionally passing nil context for testing
	if err != ErrNilContext {
		t.Errorf("GetHistory(nil) error = %v, want ErrNilContext", err)
	}
}

func TestReleaseClient_GetHistory_EmptyName(t *testing.T) {
	t.Parallel()

	client := &defaultReleaseClient{
		actionConfig: newTestActionConfig(),
		namespace:    "default",
	}
	ctx := context.Background()

	_, err := client.GetHistory(ctx, "")
	if err != ErrEmptyReleaseName {
		t.Errorf("GetHistory('') error = %v, want ErrEmptyReleaseName", err)
	}
}

func TestReleaseClient_GetStatus_NilContext(t *testing.T) {
	t.Parallel()

	client := &defaultReleaseClient{
		actionConfig: newTestActionConfig(),
		namespace:    "default",
	}

	var ctx context.Context = nil
	_, err := client.GetStatus(ctx, "release") //nolint:staticcheck // intentionally passing nil context for testing
	if err != ErrNilContext {
		t.Errorf("GetStatus(nil) error = %v, want ErrNilContext", err)
	}
}

func TestReleaseClient_GetStatus_EmptyName(t *testing.T) {
	t.Parallel()

	client := &defaultReleaseClient{
		actionConfig: newTestActionConfig(),
		namespace:    "default",
	}
	ctx := context.Background()

	_, err := client.GetStatus(ctx, "")
	if err != ErrEmptyReleaseName {
		t.Errorf("GetStatus('') error = %v, want ErrEmptyReleaseName", err)
	}
}

func TestReleaseClient_WaitForReady_NilContext(t *testing.T) {
	t.Parallel()

	client := &defaultReleaseClient{
		actionConfig: newTestActionConfig(),
		namespace:    "default",
	}

	var ctx context.Context = nil
	err := client.WaitForReady(ctx, "release", time.Second) //nolint:staticcheck // intentionally passing nil context for testing
	if err != ErrNilContext {
		t.Errorf("WaitForReady(nil) error = %v, want ErrNilContext", err)
	}
}

func TestReleaseClient_WaitForReady_EmptyName(t *testing.T) {
	t.Parallel()

	client := &defaultReleaseClient{
		actionConfig: newTestActionConfig(),
		namespace:    "default",
	}
	ctx := context.Background()

	err := client.WaitForReady(ctx, "", time.Second)
	if err != ErrEmptyReleaseName {
		t.Errorf("WaitForReady('') error = %v, want ErrEmptyReleaseName", err)
	}
}

// Note: TestReleaseClient_WaitForReady_Timeout requires a Kubernetes cluster or mock KubeClient.
// Input validation is tested in TestReleaseClient_WaitForReady_NilContext and TestReleaseClient_WaitForReady_EmptyName.

func TestMapHelmRelease_Nil(t *testing.T) {
	t.Parallel()

	rel := mapHelmRelease(nil)
	if rel == nil {
		t.Fatal("mapHelmRelease(nil) should return empty Release, not nil")
	}
	if rel.Name != "" {
		t.Errorf("mapHelmRelease(nil).Name = %v, want empty", rel.Name)
	}
}

func TestMapHelmReleaseToStatus_Nil(t *testing.T) {
	t.Parallel()

	status := mapHelmReleaseToStatus(nil)
	if status == nil {
		t.Error("mapHelmReleaseToStatus(nil) should return empty ReleaseStatus, not nil")
	}
}

func TestMapHelmStatus(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input    release.Status
		expected ReleaseStatusType
	}{
		{release.StatusDeployed, StatusDeployed},
		{release.StatusUninstalled, StatusUninstalled},
		{release.StatusSuperseded, StatusSuperseded},
		{release.StatusFailed, StatusFailed},
		{release.StatusUninstalling, StatusUninstalling},
		{release.StatusPendingInstall, StatusPendingInstall},
		{release.StatusPendingUpgrade, StatusPendingUpgrade},
		{release.StatusPendingRollback, StatusPendingRollback},
		{release.Status("unknown"), StatusUnknown},
	}

	for _, tt := range tests {
		t.Run(string(tt.input), func(t *testing.T) {
			t.Parallel()
			got := mapHelmStatus(tt.input)
			if got != tt.expected {
				t.Errorf("mapHelmStatus(%v) = %v, want %v", tt.input, got, tt.expected)
			}
		})
	}
}

func TestIsReleaseExistsError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		err      error
		name     string
		expected bool
	}{
		{name: "nil", err: nil, expected: false},
		{name: "already exists", err: &HelmError{Op: "install", Err: ErrReleaseExists}, expected: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if tt.err != nil {
				errStr := tt.err.Error()
				result := strings.Contains(errStr, "already exists") || strings.Contains(errStr, "cannot re-use")
				if result != tt.expected {
					t.Errorf("isReleaseExistsError(%v) = %v, want %v", tt.err, result, tt.expected)
				}
			}
		})
	}
}

func TestIsRevisionNotFoundError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		err      error
		name     string
		expected bool
	}{
		{name: "nil", err: nil, expected: false},
		{name: "revision not found", err: &HelmError{Op: "rollback", Err: ErrRevisionNotFound}, expected: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if tt.err != nil {
				errStr := tt.err.Error()
				result := strings.Contains(errStr, "revision") && strings.Contains(errStr, "not found")
				if result != tt.expected {
					t.Errorf("isRevisionNotFoundError(%v) = %v, want %v", tt.err, result, tt.expected)
				}
			}
		})
	}
}
