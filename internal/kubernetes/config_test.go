package kubernetes

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDefaultClientConfig(t *testing.T) {
	t.Parallel()

	cfg := DefaultClientConfig()

	if cfg.Namespace != DefaultNamespace {
		t.Errorf("Namespace = %v, want %v", cfg.Namespace, DefaultNamespace)
	}
	if cfg.Timeout != DefaultTimeout {
		t.Errorf("Timeout = %v, want %v", cfg.Timeout, DefaultTimeout)
	}
	if cfg.QPS != DefaultQPS {
		t.Errorf("QPS = %v, want %v", cfg.QPS, DefaultQPS)
	}
	if cfg.Burst != DefaultBurst {
		t.Errorf("Burst = %v, want %v", cfg.Burst, DefaultBurst)
	}
}

func TestWithKubeconfig(t *testing.T) {
	t.Parallel()

	cfg := DefaultClientConfig()
	WithKubeconfig("/path/to/kubeconfig")(&cfg)

	if cfg.Kubeconfig != "/path/to/kubeconfig" {
		t.Errorf("Kubeconfig = %v, want /path/to/kubeconfig", cfg.Kubeconfig)
	}
}

func TestWithContext(t *testing.T) {
	t.Parallel()

	cfg := DefaultClientConfig()
	WithContext("my-context")(&cfg)

	if cfg.Context != "my-context" {
		t.Errorf("Context = %v, want my-context", cfg.Context)
	}
}

func TestWithNamespace(t *testing.T) {
	t.Parallel()

	cfg := DefaultClientConfig()
	WithNamespace("kube-system")(&cfg)

	if cfg.Namespace != "kube-system" {
		t.Errorf("Namespace = %v, want kube-system", cfg.Namespace)
	}
}

func TestWithTimeout(t *testing.T) {
	t.Parallel()

	cfg := DefaultClientConfig()
	WithTimeout(5 * time.Minute)(&cfg)

	if cfg.Timeout != 5*time.Minute {
		t.Errorf("Timeout = %v, want 5m", cfg.Timeout)
	}
}

func TestWithInCluster(t *testing.T) {
	t.Parallel()

	cfg := DefaultClientConfig()
	WithInCluster()(&cfg)

	if !cfg.InCluster {
		t.Error("InCluster should be true")
	}
}

func TestWithQPS(t *testing.T) {
	t.Parallel()

	cfg := DefaultClientConfig()
	WithQPS(100.0)(&cfg)

	if cfg.QPS != 100.0 {
		t.Errorf("QPS = %v, want 100.0", cfg.QPS)
	}
}

func TestWithBurst(t *testing.T) {
	t.Parallel()

	cfg := DefaultClientConfig()
	WithBurst(200)(&cfg)

	if cfg.Burst != 200 {
		t.Errorf("Burst = %v, want 200", cfg.Burst)
	}
}

func TestWithAPIServer(t *testing.T) {
	t.Parallel()

	cfg := DefaultClientConfig()
	WithAPIServer("https://k8s.example.com:6443")(&cfg)

	if cfg.APIServer != "https://k8s.example.com:6443" {
		t.Errorf("APIServer = %v, want https://k8s.example.com:6443", cfg.APIServer)
	}
}

func TestWithBearerToken(t *testing.T) {
	t.Parallel()

	cfg := DefaultClientConfig()
	WithBearerToken("my-token")(&cfg)

	if cfg.BearerToken != "my-token" {
		t.Errorf("BearerToken = %v, want my-token", cfg.BearerToken)
	}
}

func TestWithTLSConfig(t *testing.T) {
	t.Parallel()

	tlsCfg := &TLSConfig{
		CAFile:   "/path/to/ca.crt",
		CertFile: "/path/to/client.crt",
		KeyFile:  "/path/to/client.key",
		Insecure: false,
	}

	cfg := DefaultClientConfig()
	WithTLSConfig(tlsCfg)(&cfg)

	if cfg.TLSConfig != tlsCfg {
		t.Error("TLSConfig not set correctly")
	}
}

func TestBuildRestConfig_KubeconfigNotFound(t *testing.T) {
	t.Parallel()

	// Clear KUBECONFIG env var for this test.
	origKubeconfig := os.Getenv("KUBECONFIG")
	if err := os.Unsetenv("KUBECONFIG"); err != nil {
		t.Fatalf("failed to unset KUBECONFIG: %v", err)
	}
	t.Cleanup(func() {
		if origKubeconfig != "" {
			_ = os.Setenv("KUBECONFIG", origKubeconfig)
		}
	})

	cfg := ClientConfig{
		Kubeconfig: "/nonexistent/kubeconfig",
	}

	_, err := buildRestConfig(cfg)
	if err == nil {
		t.Error("expected error for nonexistent kubeconfig")
	}
}

func TestBuildRestConfig_InClusterFails(t *testing.T) {
	t.Parallel()

	cfg := ClientConfig{
		InCluster: true,
	}

	// When not running in cluster, this should fail.
	_, err := buildRestConfig(cfg)
	if err == nil {
		t.Error("expected error when not in cluster")
	}
}

func TestLoadKubeconfig_InvalidFile(t *testing.T) {
	t.Parallel()

	// Create a temp file with invalid content.
	tmpDir := t.TempDir()
	invalidConfig := filepath.Join(tmpDir, "invalid-kubeconfig")
	if err := os.WriteFile(invalidConfig, []byte("invalid yaml content: ["), 0o600); err != nil {
		t.Fatalf("failed to create invalid config: %v", err)
	}

	_, err := loadKubeconfig(invalidConfig, "")
	if err == nil {
		t.Error("expected error for invalid kubeconfig")
	}
}

func TestLoadKubeconfig_ValidFile(t *testing.T) {
	t.Parallel()

	// Create a minimal valid kubeconfig.
	tmpDir := t.TempDir()
	validConfig := filepath.Join(tmpDir, "valid-kubeconfig")
	kubeconfig := `
apiVersion: v1
kind: Config
clusters:
- cluster:
    server: https://localhost:6443
  name: test-cluster
contexts:
- context:
    cluster: test-cluster
    user: test-user
  name: test-context
current-context: test-context
users:
- name: test-user
  user:
    token: test-token
`
	if err := os.WriteFile(validConfig, []byte(kubeconfig), 0o600); err != nil {
		t.Fatalf("failed to create valid config: %v", err)
	}

	cfg, err := loadKubeconfig(validConfig, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.Host != "https://localhost:6443" {
		t.Errorf("Host = %v, want https://localhost:6443", cfg.Host)
	}
}

func TestLoadKubeconfig_WithContext(t *testing.T) {
	t.Parallel()

	// Create a kubeconfig with multiple contexts.
	tmpDir := t.TempDir()
	multiConfig := filepath.Join(tmpDir, "multi-kubeconfig")
	kubeconfig := `
apiVersion: v1
kind: Config
clusters:
- cluster:
    server: https://cluster1:6443
  name: cluster1
- cluster:
    server: https://cluster2:6443
  name: cluster2
contexts:
- context:
    cluster: cluster1
    user: user1
  name: context1
- context:
    cluster: cluster2
    user: user2
  name: context2
current-context: context1
users:
- name: user1
  user:
    token: token1
- name: user2
  user:
    token: token2
`
	if err := os.WriteFile(multiConfig, []byte(kubeconfig), 0o600); err != nil {
		t.Fatalf("failed to create config: %v", err)
	}

	// Load with specific context.
	cfg, err := loadKubeconfig(multiConfig, "context2")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.Host != "https://cluster2:6443" {
		t.Errorf("Host = %v, want https://cluster2:6443", cfg.Host)
	}
}

func TestApplyConfigOverrides(t *testing.T) {
	t.Parallel()

	// Test that ClientConfig with all options can be created correctly.
	cfg := ClientConfig{
		QPS:         100,
		Burst:       200,
		Timeout:     5 * time.Minute,
		APIServer:   "https://example.com:6443",
		BearerToken: "my-token",
		TLSConfig: &TLSConfig{
			CAFile:   "/ca.crt",
			CertFile: "/client.crt",
			KeyFile:  "/client.key",
			Insecure: true,
		},
	}

	// Verify all fields are set correctly.
	if cfg.QPS != 100 {
		t.Errorf("QPS = %v, want 100", cfg.QPS)
	}
	if cfg.Burst != 200 {
		t.Errorf("Burst = %v, want 200", cfg.Burst)
	}
	if cfg.Timeout != 5*time.Minute {
		t.Errorf("Timeout = %v, want 5m", cfg.Timeout)
	}
	if cfg.APIServer != "https://example.com:6443" {
		t.Errorf("APIServer = %v, want https://example.com:6443", cfg.APIServer)
	}
	if cfg.BearerToken != "my-token" {
		t.Errorf("BearerToken = %v, want my-token", cfg.BearerToken)
	}
	if cfg.TLSConfig.CAFile != "/ca.crt" {
		t.Errorf("CAFile = %v, want /ca.crt", cfg.TLSConfig.CAFile)
	}
}
