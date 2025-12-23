package kubernetes

import (
	"testing"

	"k8s.io/client-go/kubernetes/fake"
)

func TestNewClientWithClientset(t *testing.T) {
	t.Parallel()

	fakeClient := fake.NewSimpleClientset()
	cfg := ClientConfig{
		Namespace: "test-namespace",
	}

	client := NewClientWithClientset(fakeClient, cfg)

	if client == nil {
		t.Fatal("expected non-nil client")
	}
	if client.clientset == nil {
		t.Error("clientset not set correctly")
	}
	if client.cfg.Namespace != "test-namespace" {
		t.Errorf("Namespace = %v, want test-namespace", client.cfg.Namespace)
	}
}

func TestDefaultClient_Deployments(t *testing.T) {
	t.Parallel()

	fakeClient := fake.NewSimpleClientset()
	cfg := ClientConfig{
		Namespace: "default",
	}

	client := NewClientWithClientset(fakeClient, cfg)

	// Test with empty namespace (should use default).
	deployClient := client.Deployments("")
	if deployClient == nil {
		t.Fatal("expected non-nil DeploymentClient")
	}

	// Test with explicit namespace.
	deployClient = client.Deployments("custom-namespace")
	if deployClient == nil {
		t.Fatal("expected non-nil DeploymentClient")
	}
}

func TestDefaultClient_Health(t *testing.T) {
	t.Parallel()

	fakeClient := fake.NewSimpleClientset()
	cfg := ClientConfig{
		Namespace: "default",
	}

	client := NewClientWithClientset(fakeClient, cfg)

	healthClient := client.Health()
	if healthClient == nil {
		t.Fatal("expected non-nil HealthClient")
	}
}

func TestDefaultClient_Close(t *testing.T) {
	t.Parallel()

	fakeClient := fake.NewSimpleClientset()
	cfg := DefaultClientConfig()

	client := NewClientWithClientset(fakeClient, cfg)

	if err := client.Close(); err != nil {
		t.Errorf("Close() error = %v", err)
	}
}

func TestDefaultClient_Clientset(t *testing.T) {
	t.Parallel()

	fakeClient := fake.NewSimpleClientset()
	cfg := DefaultClientConfig()

	client := NewClientWithClientset(fakeClient, cfg)

	if client.Clientset() == nil {
		t.Error("Clientset() should return the underlying clientset")
	}
}

func TestDefaultClient_Config(t *testing.T) {
	t.Parallel()

	fakeClient := fake.NewSimpleClientset()
	cfg := ClientConfig{
		Namespace: "test",
		Timeout:   DefaultTimeout,
	}

	client := NewClientWithClientset(fakeClient, cfg)

	gotCfg := client.Config()
	if gotCfg.Namespace != "test" {
		t.Errorf("Config().Namespace = %v, want test", gotCfg.Namespace)
	}
}
