package kubernetes

import (
	"context"
	"errors"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func createTestPodWithLabels(name, namespace string, ready, running bool, labels map[string]string) *corev1.Pod {
	phase := corev1.PodRunning
	if !running {
		phase = corev1.PodPending
	}

	conditions := []corev1.PodCondition{}
	if ready {
		conditions = append(conditions, corev1.PodCondition{
			Type:   corev1.PodReady,
			Status: corev1.ConditionTrue,
		})
	}

	containerState := corev1.ContainerState{}
	if running {
		containerState.Running = &corev1.ContainerStateRunning{
			StartedAt: metav1.Now(),
		}
	} else {
		containerState.Waiting = &corev1.ContainerStateWaiting{
			Reason:  "ContainerCreating",
			Message: "Container is being created",
		}
	}

	started := running

	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels:    labels,
		},
		Status: corev1.PodStatus{
			Phase:      phase,
			Conditions: conditions,
			ContainerStatuses: []corev1.ContainerStatus{
				{
					Name:    "main",
					Image:   "nginx:latest",
					Ready:   ready,
					Started: &started,
					State:   containerState,
				},
			},
		},
	}
}

//nolint:unparam // namespace is always "default" in tests but keeping parameter for flexibility
func createTestPod(name, namespace string, ready, running bool) *corev1.Pod {
	return createTestPodWithLabels(name, namespace, ready, running, map[string]string{"app": "test"})
}

func TestHealthClient_CheckPodHealth(t *testing.T) {
	t.Parallel()

	labels := map[string]string{"app": "test-app"}
	deploy := createTestDeployment("test-app", "default", 3, true)
	pod1 := createTestPodWithLabels("test-app-pod-1", "default", true, true, labels)
	pod2 := createTestPodWithLabels("test-app-pod-2", "default", true, true, labels)
	pod3 := createTestPodWithLabels("test-app-pod-3", "default", true, true, labels)

	fakeClient := fake.NewSimpleClientset(deploy, pod1, pod2, pod3)

	client := &defaultHealthClient{
		client:    fakeClient,
		namespace: "default",
	}

	report, err := client.CheckPodHealth(context.Background(), "default", "test-app")
	if err != nil {
		t.Fatalf("CheckPodHealth() error = %v", err)
	}

	if !report.Healthy {
		t.Error("expected healthy report")
	}
	if report.TotalPods != 3 {
		t.Errorf("TotalPods = %v, want 3", report.TotalPods)
	}
	if report.HealthyPods != 3 {
		t.Errorf("HealthyPods = %v, want 3", report.HealthyPods)
	}
	if report.UnhealthyPods != 0 {
		t.Errorf("UnhealthyPods = %v, want 0", report.UnhealthyPods)
	}
}

func TestHealthClient_CheckPodHealth_SomeUnhealthy(t *testing.T) {
	t.Parallel()

	labels := map[string]string{"app": "test-app"}
	deploy := createTestDeployment("test-app", "default", 3, true)
	pod1 := createTestPodWithLabels("test-app-pod-1", "default", true, true, labels)
	pod2 := createTestPodWithLabels("test-app-pod-2", "default", false, false, labels) // Unhealthy.
	pod3 := createTestPodWithLabels("test-app-pod-3", "default", true, true, labels)

	fakeClient := fake.NewSimpleClientset(deploy, pod1, pod2, pod3)

	client := &defaultHealthClient{
		client:    fakeClient,
		namespace: "default",
	}

	report, err := client.CheckPodHealth(context.Background(), "default", "test-app")
	if err != nil {
		t.Fatalf("CheckPodHealth() error = %v", err)
	}

	if report.Healthy {
		t.Error("expected unhealthy report")
	}
	if report.HealthyPods != 2 {
		t.Errorf("HealthyPods = %v, want 2", report.HealthyPods)
	}
	if report.UnhealthyPods != 1 {
		t.Errorf("UnhealthyPods = %v, want 1", report.UnhealthyPods)
	}
}

func TestHealthClient_CheckPodHealth_NilContext(t *testing.T) {
	t.Parallel()

	fakeClient := fake.NewSimpleClientset()
	client := &defaultHealthClient{
		client:    fakeClient,
		namespace: "default",
	}

	_, err := client.CheckPodHealth(nil, "default", "test") //nolint:staticcheck // intentionally passing nil context for testing
	if !errors.Is(err, ErrNilContext) {
		t.Errorf("CheckPodHealth(nil) error = %v, want ErrNilContext", err)
	}
}

func TestHealthClient_CheckPodHealth_EmptyName(t *testing.T) {
	t.Parallel()

	fakeClient := fake.NewSimpleClientset()
	client := &defaultHealthClient{
		client:    fakeClient,
		namespace: "default",
	}

	_, err := client.CheckPodHealth(context.Background(), "default", "")
	if !errors.Is(err, ErrEmptyName) {
		t.Errorf("CheckPodHealth('') error = %v, want ErrEmptyName", err)
	}
}

func TestHealthClient_CheckPodHealth_DeploymentNotFound(t *testing.T) {
	t.Parallel()

	fakeClient := fake.NewSimpleClientset()
	client := &defaultHealthClient{
		client:    fakeClient,
		namespace: "default",
	}

	_, err := client.CheckPodHealth(context.Background(), "default", "nonexistent")
	if !errors.Is(err, ErrDeploymentNotFound) {
		t.Errorf("CheckPodHealth() error = %v, want ErrDeploymentNotFound", err)
	}
}

func TestHealthClient_GetReadiness(t *testing.T) {
	t.Parallel()

	pod1 := createTestPod("pod-1", "default", true, true)
	pod2 := createTestPod("pod-2", "default", false, true)

	fakeClient := fake.NewSimpleClientset(pod1, pod2)

	client := &defaultHealthClient{
		client:    fakeClient,
		namespace: "default",
	}

	readiness, err := client.GetReadiness(context.Background(), "default", "")
	if err != nil {
		t.Fatalf("GetReadiness() error = %v", err)
	}

	if len(readiness) != 2 {
		t.Fatalf("GetReadiness() returned %d pods, want 2", len(readiness))
	}

	// Check that we have one ready and one not ready.
	readyCount := 0
	for _, r := range readiness {
		if r.Ready {
			readyCount++
		}
	}
	if readyCount != 1 {
		t.Errorf("Expected 1 ready pod, got %d", readyCount)
	}
}

func TestHealthClient_GetReadiness_NilContext(t *testing.T) {
	t.Parallel()

	fakeClient := fake.NewSimpleClientset()
	client := &defaultHealthClient{
		client:    fakeClient,
		namespace: "default",
	}

	_, err := client.GetReadiness(nil, "default", "") //nolint:staticcheck // intentionally passing nil context for testing
	if !errors.Is(err, ErrNilContext) {
		t.Errorf("GetReadiness(nil) error = %v, want ErrNilContext", err)
	}
}

func TestHealthClient_GetLiveness(t *testing.T) {
	t.Parallel()

	pod1 := createTestPod("pod-1", "default", true, true)
	pod2 := createTestPod("pod-2", "default", true, false) // Not running.

	fakeClient := fake.NewSimpleClientset(pod1, pod2)

	client := &defaultHealthClient{
		client:    fakeClient,
		namespace: "default",
	}

	liveness, err := client.GetLiveness(context.Background(), "default", "")
	if err != nil {
		t.Fatalf("GetLiveness() error = %v", err)
	}

	if len(liveness) != 2 {
		t.Fatalf("GetLiveness() returned %d pods, want 2", len(liveness))
	}

	// Check that we have one alive and one not alive.
	aliveCount := 0
	for _, l := range liveness {
		if l.Alive {
			aliveCount++
		}
	}
	if aliveCount != 1 {
		t.Errorf("Expected 1 alive pod, got %d", aliveCount)
	}
}

func TestHealthClient_GetLiveness_NilContext(t *testing.T) {
	t.Parallel()

	fakeClient := fake.NewSimpleClientset()
	client := &defaultHealthClient{
		client:    fakeClient,
		namespace: "default",
	}

	_, err := client.GetLiveness(nil, "default", "") //nolint:staticcheck // intentionally passing nil context for testing
	if !errors.Is(err, ErrNilContext) {
		t.Errorf("GetLiveness(nil) error = %v, want ErrNilContext", err)
	}
}

func TestHealthClient_WaitForHealthy_AlreadyHealthy(t *testing.T) {
	t.Parallel()

	labels := map[string]string{"app": "healthy-app"}
	deploy := createTestDeployment("healthy-app", "default", 2, true)
	pod1 := createTestPodWithLabels("healthy-app-pod-1", "default", true, true, labels)
	pod2 := createTestPodWithLabels("healthy-app-pod-2", "default", true, true, labels)

	fakeClient := fake.NewSimpleClientset(deploy, pod1, pod2)

	client := &defaultHealthClient{
		client:    fakeClient,
		namespace: "default",
	}

	err := client.WaitForHealthy(context.Background(), "default", "healthy-app", 5*time.Second)
	if err != nil {
		t.Errorf("WaitForHealthy() error = %v", err)
	}
}

func TestHealthClient_WaitForHealthy_NilContext(t *testing.T) {
	t.Parallel()

	fakeClient := fake.NewSimpleClientset()
	client := &defaultHealthClient{
		client:    fakeClient,
		namespace: "default",
	}

	err := client.WaitForHealthy(nil, "default", "test", time.Second) //nolint:staticcheck // intentionally passing nil context for testing
	if !errors.Is(err, ErrNilContext) {
		t.Errorf("WaitForHealthy(context.TODO()) error = %v, want ErrNilContext", err)
	}
}

func TestHealthClient_WaitForHealthy_EmptyName(t *testing.T) {
	t.Parallel()

	fakeClient := fake.NewSimpleClientset()
	client := &defaultHealthClient{
		client:    fakeClient,
		namespace: "default",
	}

	err := client.WaitForHealthy(context.Background(), "default", "", time.Second)
	if !errors.Is(err, ErrEmptyName) {
		t.Errorf("WaitForHealthy('') error = %v, want ErrEmptyName", err)
	}
}

func TestMapPodToHealth(t *testing.T) {
	t.Parallel()

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-pod",
			Namespace: "default",
		},
		Status: corev1.PodStatus{
			Phase: corev1.PodRunning,
			Conditions: []corev1.PodCondition{
				{
					Type:   corev1.PodReady,
					Status: corev1.ConditionTrue,
				},
			},
			ContainerStatuses: []corev1.ContainerStatus{
				{
					Name:  "main",
					Image: "nginx:latest",
					Ready: true,
					State: corev1.ContainerState{
						Running: &corev1.ContainerStateRunning{
							StartedAt: metav1.Now(),
						},
					},
				},
			},
		},
	}

	health := mapPodToHealth(pod)

	if health.Name != "test-pod" {
		t.Errorf("Name = %v, want test-pod", health.Name)
	}
	if !health.Ready {
		t.Error("Ready should be true")
	}
	if !health.Healthy {
		t.Error("Healthy should be true")
	}
	if len(health.Containers) != 1 {
		t.Errorf("Containers count = %v, want 1", len(health.Containers))
	}
	if !health.Containers[0].State.Running {
		t.Error("Container should be running")
	}
}

func TestMapPodToHealth_Unhealthy(t *testing.T) {
	t.Parallel()

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "unhealthy-pod",
			Namespace: "default",
		},
		Status: corev1.PodStatus{
			Phase: corev1.PodPending,
			Conditions: []corev1.PodCondition{
				{
					Type:   corev1.PodReady,
					Status: corev1.ConditionFalse,
				},
			},
			ContainerStatuses: []corev1.ContainerStatus{
				{
					Name: "main",
					State: corev1.ContainerState{
						Waiting: &corev1.ContainerStateWaiting{
							Reason:  "ImagePullBackOff",
							Message: "Failed to pull image",
						},
					},
				},
			},
		},
	}

	health := mapPodToHealth(pod)

	if health.Healthy {
		t.Error("Healthy should be false")
	}
	if health.Ready {
		t.Error("Ready should be false")
	}
	if health.Message == "" {
		t.Error("Message should be set for unhealthy pod")
	}
	if !health.Containers[0].State.Waiting {
		t.Error("Container should be in waiting state")
	}
}

func TestExtractUnhealthyPodNames(t *testing.T) {
	t.Parallel()

	report := &HealthReport{
		Pods: []PodHealth{
			{Name: "pod-1", Healthy: true},
			{Name: "pod-2", Healthy: false},
			{Name: "pod-3", Healthy: true},
			{Name: "pod-4", Healthy: false},
		},
		UnhealthyPods: 2,
	}

	names := extractUnhealthyPodNames(report)

	if len(names) != 2 {
		t.Errorf("Expected 2 unhealthy pod names, got %d", len(names))
	}

	expectedNames := map[string]bool{"pod-2": true, "pod-4": true}
	for _, name := range names {
		if !expectedNames[name] {
			t.Errorf("Unexpected unhealthy pod: %s", name)
		}
	}
}

func TestHealthClient_EmptyNamespace(t *testing.T) {
	t.Parallel()

	fakeClient := fake.NewSimpleClientset()
	client := &defaultHealthClient{
		client:    fakeClient,
		namespace: "", // Empty default namespace.
	}

	// Should return error for empty namespace.
	_, err := client.CheckPodHealth(context.Background(), "", "test")
	if !errors.Is(err, ErrEmptyNamespace) {
		t.Errorf("CheckPodHealth() error = %v, want ErrEmptyNamespace", err)
	}

	_, err = client.GetReadiness(context.Background(), "", "")
	if !errors.Is(err, ErrEmptyNamespace) {
		t.Errorf("GetReadiness() error = %v, want ErrEmptyNamespace", err)
	}

	_, err = client.GetLiveness(context.Background(), "", "")
	if !errors.Is(err, ErrEmptyNamespace) {
		t.Errorf("GetLiveness() error = %v, want ErrEmptyNamespace", err)
	}

	err = client.WaitForHealthy(context.Background(), "", "test", time.Second)
	if !errors.Is(err, ErrEmptyNamespace) {
		t.Errorf("WaitForHealthy() error = %v, want ErrEmptyNamespace", err)
	}
}
