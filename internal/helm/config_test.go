package helm

import (
	"testing"
	"time"
)

func TestDefaultHelmConfig(t *testing.T) {
	t.Parallel()

	cfg := DefaultHelmConfig()

	if cfg.Namespace != DefaultNamespace {
		t.Errorf("Namespace = %v, want %v", cfg.Namespace, DefaultNamespace)
	}
	if cfg.Timeout != DefaultTimeout {
		t.Errorf("Timeout = %v, want %v", cfg.Timeout, DefaultTimeout)
	}
}

func TestWithKubeconfig(t *testing.T) {
	t.Parallel()

	cfg := DefaultHelmConfig()
	WithKubeconfig("/path/to/kubeconfig")(&cfg)

	if cfg.Kubeconfig != "/path/to/kubeconfig" {
		t.Errorf("Kubeconfig = %v, want /path/to/kubeconfig", cfg.Kubeconfig)
	}
}

func TestWithContext(t *testing.T) {
	t.Parallel()

	cfg := DefaultHelmConfig()
	WithContext("my-context")(&cfg)

	if cfg.Context != "my-context" {
		t.Errorf("Context = %v, want my-context", cfg.Context)
	}
}

func TestWithNamespace(t *testing.T) {
	t.Parallel()

	cfg := DefaultHelmConfig()
	WithNamespace("kube-system")(&cfg)

	if cfg.Namespace != "kube-system" {
		t.Errorf("Namespace = %v, want kube-system", cfg.Namespace)
	}
}

func TestWithTimeout(t *testing.T) {
	t.Parallel()

	cfg := DefaultHelmConfig()
	WithTimeout(10 * time.Minute)(&cfg)

	if cfg.Timeout != 10*time.Minute {
		t.Errorf("Timeout = %v, want 10m", cfg.Timeout)
	}
}

func TestWithRegistryURL(t *testing.T) {
	t.Parallel()

	cfg := DefaultHelmConfig()
	WithRegistryURL("oci://registry.example.com")(&cfg)

	if cfg.RegistryURL != "oci://registry.example.com" {
		t.Errorf("RegistryURL = %v, want oci://registry.example.com", cfg.RegistryURL)
	}
}

func TestWithDebug(t *testing.T) {
	t.Parallel()

	cfg := DefaultHelmConfig()
	WithDebug(true)(&cfg)

	if !cfg.Debug {
		t.Error("Debug should be true")
	}
}

func TestInstallOptions(t *testing.T) {
	t.Parallel()

	opts := InstallOptions{
		Values:          map[string]interface{}{"replicas": 3},
		ChartVersion:    "1.0.0",
		Timeout:         5 * time.Minute,
		Wait:            true,
		Atomic:          true,
		CreateNamespace: true,
		DryRun:          false,
	}

	if opts.Values["replicas"] != 3 {
		t.Errorf("Values[replicas] = %v, want 3", opts.Values["replicas"])
	}
	if opts.ChartVersion != "1.0.0" {
		t.Errorf("ChartVersion = %v, want 1.0.0", opts.ChartVersion)
	}
	if opts.Timeout != 5*time.Minute {
		t.Errorf("Timeout = %v, want 5m", opts.Timeout)
	}
	if !opts.Wait {
		t.Error("Wait should be true")
	}
	if !opts.Atomic {
		t.Error("Atomic should be true")
	}
	if !opts.CreateNamespace {
		t.Error("CreateNamespace should be true")
	}
	if opts.DryRun {
		t.Error("DryRun should be false")
	}
}

func TestUpgradeOptions(t *testing.T) {
	t.Parallel()

	opts := UpgradeOptions{
		Values:       map[string]interface{}{"replicas": 5},
		ChartVersion: "2.0.0",
		Timeout:      10 * time.Minute,
		Wait:         true,
		Atomic:       true,
		Force:        false,
		DryRun:       false,
		ResetValues:  false,
		ReuseValues:  true,
	}

	if opts.Values["replicas"] != 5 {
		t.Errorf("Values[replicas] = %v, want 5", opts.Values["replicas"])
	}
	if opts.ChartVersion != "2.0.0" {
		t.Errorf("ChartVersion = %v, want 2.0.0", opts.ChartVersion)
	}
	if opts.Timeout != 10*time.Minute {
		t.Errorf("Timeout = %v, want 10m", opts.Timeout)
	}
	if !opts.Wait {
		t.Error("Wait should be true")
	}
	if !opts.Atomic {
		t.Error("Atomic should be true")
	}
	if opts.Force {
		t.Error("Force should be false")
	}
	if opts.DryRun {
		t.Error("DryRun should be false")
	}
	if opts.ResetValues {
		t.Error("ResetValues should be false")
	}
	if !opts.ReuseValues {
		t.Error("ReuseValues should be true")
	}
}

func TestListOptions(t *testing.T) {
	t.Parallel()

	opts := ListOptions{
		AllNamespaces: true,
		Deployed:      true,
		Failed:        false,
		Pending:       false,
		Uninstalled:   false,
		Limit:         10,
	}

	if !opts.AllNamespaces {
		t.Error("AllNamespaces should be true")
	}
	if !opts.Deployed {
		t.Error("Deployed should be true")
	}
	if opts.Failed {
		t.Error("Failed should be false")
	}
	if opts.Pending {
		t.Error("Pending should be false")
	}
	if opts.Uninstalled {
		t.Error("Uninstalled should be false")
	}
	if opts.Limit != 10 {
		t.Errorf("Limit = %v, want 10", opts.Limit)
	}
}

func TestRollbackOptions(t *testing.T) {
	t.Parallel()

	opts := RollbackOptions{
		Timeout:       5 * time.Minute,
		Wait:          true,
		Force:         false,
		CleanupOnFail: true,
		DisableHooks:  false,
		Recreate:      false,
		MaxHistory:    10,
	}

	if opts.Timeout != 5*time.Minute {
		t.Errorf("Timeout = %v, want 5m", opts.Timeout)
	}
	if !opts.Wait {
		t.Error("Wait should be true")
	}
	if opts.Force {
		t.Error("Force should be false")
	}
	if !opts.CleanupOnFail {
		t.Error("CleanupOnFail should be true")
	}
	if opts.DisableHooks {
		t.Error("DisableHooks should be false")
	}
	if opts.Recreate {
		t.Error("Recreate should be false")
	}
	if opts.MaxHistory != 10 {
		t.Errorf("MaxHistory = %v, want 10", opts.MaxHistory)
	}
}
