package kubernetes

import (
	"context"
	"errors"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
)

func int32Ptr(i int32) *int32 {
	return &i
}

//nolint:unparam // namespace is always "default" in tests but keeping parameter for flexibility
func createTestDeployment(name, namespace string, replicas int32, available bool) *appsv1.Deployment {
	conditions := []appsv1.DeploymentCondition{}
	if available {
		conditions = append(conditions, appsv1.DeploymentCondition{
			Type:           appsv1.DeploymentAvailable,
			Status:         corev1.ConditionTrue,
			LastUpdateTime: metav1.Now(),
		})
	}

	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels:    map[string]string{"app": name},
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: int32Ptr(replicas),
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"app": name},
			},
			Template: corev1.PodTemplateSpec{
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  "main",
							Image: "nginx:latest",
						},
					},
				},
			},
		},
		Status: appsv1.DeploymentStatus{
			ReadyReplicas:     replicas,
			AvailableReplicas: replicas,
			UpdatedReplicas:   replicas,
			Conditions:        conditions,
		},
	}
}

func TestDeploymentClient_Get(t *testing.T) {
	t.Parallel()

	tests := []struct {
		wantErr      error
		deployment   *appsv1.Deployment
		name         string
		deployName   string
		wantReplicas int32
		wantAvail    bool
	}{
		{
			name:         "healthy deployment",
			deployName:   "test-deploy",
			deployment:   createTestDeployment("test-deploy", "default", 3, true),
			wantAvail:    true,
			wantReplicas: 3,
		},
		{
			name:       "deployment not found",
			deployName: "nonexistent",
			deployment: nil,
			wantErr:    ErrDeploymentNotFound,
		},
		{
			name:       "empty name",
			deployName: "",
			wantErr:    ErrEmptyName,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			objs := []runtime.Object{}
			if tt.deployment != nil {
				objs = append(objs, tt.deployment)
			}
			fakeClient := fake.NewSimpleClientset(objs...)

			client := &defaultDeploymentClient{
				client:    fakeClient,
				namespace: "default",
			}

			status, err := client.Get(context.Background(), tt.deployName)

			if tt.wantErr != nil {
				if err == nil || !errors.Is(err, tt.wantErr) {
					t.Errorf("Get() error = %v, wantErr %v", err, tt.wantErr)
				}
				return
			}

			if err != nil {
				t.Fatalf("Get() unexpected error: %v", err)
			}

			if status.Available != tt.wantAvail {
				t.Errorf("Available = %v, want %v", status.Available, tt.wantAvail)
			}
			if status.ReadyReplicas != tt.wantReplicas {
				t.Errorf("ReadyReplicas = %v, want %v", status.ReadyReplicas, tt.wantReplicas)
			}
		})
	}
}

func TestDeploymentClient_Get_NilContext(t *testing.T) {
	t.Parallel()

	fakeClient := fake.NewSimpleClientset()
	client := &defaultDeploymentClient{
		client:    fakeClient,
		namespace: "default",
	}

	_, err := client.Get(nil, "test") //nolint:staticcheck // intentionally passing nil context for testing
	if !errors.Is(err, ErrNilContext) {
		t.Errorf("Get(context.TODO()) error = %v, want ErrNilContext", err)
	}
}

func TestDeploymentClient_List(t *testing.T) {
	t.Parallel()

	deploy1 := createTestDeployment("app1", "default", 2, true)
	deploy2 := createTestDeployment("app2", "default", 3, true)

	fakeClient := fake.NewSimpleClientset(deploy1, deploy2)

	client := &defaultDeploymentClient{
		client:    fakeClient,
		namespace: "default",
	}

	// List all.
	statuses, err := client.List(context.Background(), "")
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}

	if len(statuses) != 2 {
		t.Errorf("List() returned %d deployments, want 2", len(statuses))
	}

	// List with selector.
	statuses, err = client.List(context.Background(), "app=app1")
	if err != nil {
		t.Fatalf("List() with selector error = %v", err)
	}

	if len(statuses) != 1 {
		t.Errorf("List() with selector returned %d deployments, want 1", len(statuses))
	}
}

func TestDeploymentClient_List_NilContext(t *testing.T) {
	t.Parallel()

	fakeClient := fake.NewSimpleClientset()
	client := &defaultDeploymentClient{
		client:    fakeClient,
		namespace: "default",
	}

	_, err := client.List(nil, "") //nolint:staticcheck // intentionally passing nil context for testing
	if !errors.Is(err, ErrNilContext) {
		t.Errorf("List(context.TODO()) error = %v, want ErrNilContext", err)
	}
}

func TestDeploymentClient_WaitForReady_AlreadyReady(t *testing.T) {
	t.Parallel()

	deploy := createTestDeployment("ready-app", "default", 3, true)
	fakeClient := fake.NewSimpleClientset(deploy)

	client := &defaultDeploymentClient{
		client:    fakeClient,
		namespace: "default",
	}

	err := client.WaitForReady(context.Background(), "ready-app", 5*time.Second)
	if err != nil {
		t.Errorf("WaitForReady() error = %v", err)
	}
}

func TestDeploymentClient_WaitForReady_NilContext(t *testing.T) {
	t.Parallel()

	fakeClient := fake.NewSimpleClientset()
	client := &defaultDeploymentClient{
		client:    fakeClient,
		namespace: "default",
	}

	err := client.WaitForReady(nil, "test", time.Second) //nolint:staticcheck // intentionally passing nil context for testing
	if !errors.Is(err, ErrNilContext) {
		t.Errorf("WaitForReady(nil) error = %v, want ErrNilContext", err)
	}
}

func TestDeploymentClient_WaitForReady_EmptyName(t *testing.T) {
	t.Parallel()

	fakeClient := fake.NewSimpleClientset()
	client := &defaultDeploymentClient{
		client:    fakeClient,
		namespace: "default",
	}

	err := client.WaitForReady(context.Background(), "", time.Second)
	if !errors.Is(err, ErrEmptyName) {
		t.Errorf("WaitForReady('') error = %v, want ErrEmptyName", err)
	}
}

func TestDeploymentClient_GetRolloutStatus(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		deployment *appsv1.Deployment
		wantPhase  RolloutPhase
	}{
		{
			name:       "complete rollout",
			deployment: createTestDeployment("complete", "default", 3, true),
			wantPhase:  RolloutPhaseComplete,
		},
		{
			name: "progressing rollout",
			deployment: &appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "progressing",
					Namespace: "default",
				},
				Spec: appsv1.DeploymentSpec{
					Replicas: int32Ptr(3),
				},
				Status: appsv1.DeploymentStatus{
					Conditions: []appsv1.DeploymentCondition{
						{
							Type:    appsv1.DeploymentProgressing,
							Status:  corev1.ConditionTrue,
							Reason:  "ReplicaSetUpdated",
							Message: "ReplicaSet is updating",
						},
					},
				},
			},
			wantPhase: RolloutPhaseProgressing,
		},
		{
			name: "paused rollout",
			deployment: &appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "paused",
					Namespace: "default",
				},
				Spec: appsv1.DeploymentSpec{
					Replicas: int32Ptr(3),
					Paused:   true,
				},
			},
			wantPhase: RolloutPhasePaused,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			fakeClient := fake.NewSimpleClientset(tt.deployment)
			client := &defaultDeploymentClient{
				client:    fakeClient,
				namespace: "default",
			}

			status, err := client.GetRolloutStatus(context.Background(), tt.deployment.Name)
			if err != nil {
				t.Fatalf("GetRolloutStatus() error = %v", err)
			}

			if status.Status != tt.wantPhase {
				t.Errorf("Status = %v, want %v", status.Status, tt.wantPhase)
			}
		})
	}
}

func TestDeploymentClient_GetRolloutStatus_NotFound(t *testing.T) {
	t.Parallel()

	fakeClient := fake.NewSimpleClientset()
	client := &defaultDeploymentClient{
		client:    fakeClient,
		namespace: "default",
	}

	_, err := client.GetRolloutStatus(context.Background(), "nonexistent")
	if !errors.Is(err, ErrDeploymentNotFound) {
		t.Errorf("GetRolloutStatus() error = %v, want ErrDeploymentNotFound", err)
	}
}

func TestMapDeploymentToStatus(t *testing.T) {
	t.Parallel()

	deploy := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test",
			Namespace: "default",
			Labels:    map[string]string{"app": "test"},
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: int32Ptr(3),
			Template: corev1.PodTemplateSpec{
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{Image: "nginx:1.19"},
					},
				},
			},
		},
		Status: appsv1.DeploymentStatus{
			ReadyReplicas:     3,
			AvailableReplicas: 3,
			Conditions: []appsv1.DeploymentCondition{
				{
					Type:   appsv1.DeploymentAvailable,
					Status: corev1.ConditionTrue,
				},
			},
		},
	}

	status := mapDeploymentToStatus(deploy)

	if status.Name != "test" {
		t.Errorf("Name = %v, want test", status.Name)
	}
	if status.Image != "nginx:1.19" {
		t.Errorf("Image = %v, want nginx:1.19", status.Image)
	}
	if !status.Available {
		t.Error("Available should be true")
	}
	if status.DesiredReplicas != 3 {
		t.Errorf("DesiredReplicas = %v, want 3", status.DesiredReplicas)
	}
}

func TestMapDeploymentToStatus_NilReplicas(t *testing.T) {
	t.Parallel()

	deploy := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test",
			Namespace: "default",
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: nil, // Default to 1.
		},
	}

	status := mapDeploymentToStatus(deploy)

	if status.DesiredReplicas != 1 {
		t.Errorf("DesiredReplicas = %v, want 1 (default)", status.DesiredReplicas)
	}
}
