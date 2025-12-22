package kubernetes

import (
	"context"
	"fmt"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// DefaultPollInterval is the default polling interval for wait operations.
const DefaultPollInterval = 2 * time.Second

// RolloutPhase represents the phase of a rollout.
type RolloutPhase string

// Rollout phases.
const (
	RolloutPhasePending     RolloutPhase = "pending"
	RolloutPhaseProgressing RolloutPhase = "progressing"
	RolloutPhaseComplete    RolloutPhase = "complete"
	RolloutPhaseFailed      RolloutPhase = "failed"
	RolloutPhasePaused      RolloutPhase = "paused"
)

// DeploymentCondition represents a condition of a deployment.
// Fields are ordered for optimal memory alignment.
type DeploymentCondition struct {
	LastTransitionTime time.Time `json:"last_transition_time"`
	LastUpdateTime     time.Time `json:"last_update_time"`
	Type               string    `json:"type"`
	Status             string    `json:"status"`
	Reason             string    `json:"reason,omitempty"`
	Message            string    `json:"message,omitempty"`
}

// DeploymentStatus represents the current state of a Kubernetes deployment.
// Fields are ordered for optimal memory alignment.
type DeploymentStatus struct {
	LastUpdated        time.Time             `json:"last_updated"`
	CreatedAt          time.Time             `json:"created_at"`
	Annotations        map[string]string     `json:"annotations,omitempty"`
	Labels             map[string]string     `json:"labels,omitempty"`
	Namespace          string                `json:"namespace"`
	Name               string                `json:"name"`
	Image              string                `json:"image,omitempty"`
	Conditions         []DeploymentCondition `json:"conditions,omitempty"`
	Generation         int64                 `json:"generation"`
	ObservedGeneration int64                 `json:"observed_generation"`
	DesiredReplicas    int32                 `json:"desired_replicas"`
	ReadyReplicas      int32                 `json:"ready_replicas"`
	AvailableReplicas  int32                 `json:"available_replicas"`
	UpdatedReplicas    int32                 `json:"updated_replicas"`
	Available          bool                  `json:"available"`
}

// RolloutStatus represents the status of a deployment rollout.
// Fields are ordered for optimal memory alignment.
type RolloutStatus struct {
	StartTime   time.Time     `json:"start_time,omitempty"`
	Message     string        `json:"message"`
	Status      RolloutPhase  `json:"status"`
	Duration    time.Duration `json:"duration,omitempty"`
	Revision    int64         `json:"revision"`
	Progressing bool          `json:"progressing"`
	Complete    bool          `json:"complete"`
}

// defaultDeploymentClient implements DeploymentClient.
type defaultDeploymentClient struct {
	client    kubernetes.Interface
	namespace string
}

// Get retrieves a deployment by name.
func (d *defaultDeploymentClient) Get(ctx context.Context, name string) (*DeploymentStatus, error) {
	if ctx == nil {
		return nil, ErrNilContext
	}
	if name == "" {
		return nil, ErrEmptyName
	}

	deployment, err := d.client.AppsV1().Deployments(d.namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		if k8serrors.IsNotFound(err) {
			return nil, NewClientError("get deployment", d.namespace, name, ErrDeploymentNotFound)
		}
		return nil, NewClientError("get deployment", d.namespace, name, err)
	}

	return mapDeploymentToStatus(deployment), nil
}

// List retrieves deployments matching selector.
func (d *defaultDeploymentClient) List(ctx context.Context, selector string) ([]DeploymentStatus, error) {
	if ctx == nil {
		return nil, ErrNilContext
	}

	listOptions := metav1.ListOptions{}
	if selector != "" {
		listOptions.LabelSelector = selector
	}

	deployments, err := d.client.AppsV1().Deployments(d.namespace).List(ctx, listOptions)
	if err != nil {
		return nil, NewClientError("list deployments", d.namespace, "", err)
	}

	result := make([]DeploymentStatus, 0, len(deployments.Items))
	for i := range deployments.Items {
		result = append(result, *mapDeploymentToStatus(&deployments.Items[i]))
	}

	return result, nil
}

// WaitForReady waits for deployment to be ready.
func (d *defaultDeploymentClient) WaitForReady(ctx context.Context, name string, timeout time.Duration) error {
	if ctx == nil {
		return ErrNilContext
	}
	if name == "" {
		return ErrEmptyName
	}

	// Create timeout context.
	timeoutCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Poll until ready.
	ticker := time.NewTicker(DefaultPollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-timeoutCtx.Done():
			if timeoutCtx.Err() == context.DeadlineExceeded {
				return NewClientError("wait for ready", d.namespace, name, ErrTimeout)
			}
			return NewClientError("wait for ready", d.namespace, name, ErrWaitInterrupted)
		case <-ticker.C:
			status, err := d.Get(ctx, name)
			if err != nil {
				// Continue trying on transient errors.
				continue
			}
			if status.Available && status.ReadyReplicas == status.DesiredReplicas {
				return nil
			}
		}
	}
}

// GetRolloutStatus returns rollout status.
func (d *defaultDeploymentClient) GetRolloutStatus(ctx context.Context, name string) (*RolloutStatus, error) {
	if ctx == nil {
		return nil, ErrNilContext
	}
	if name == "" {
		return nil, ErrEmptyName
	}

	deployment, err := d.client.AppsV1().Deployments(d.namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		if k8serrors.IsNotFound(err) {
			return nil, NewClientError("get rollout status", d.namespace, name, ErrDeploymentNotFound)
		}
		return nil, NewClientError("get rollout status", d.namespace, name, err)
	}

	return mapDeploymentToRolloutStatus(deployment), nil
}

// mapDeploymentToStatus converts K8s Deployment to DeploymentStatus.
func mapDeploymentToStatus(d *appsv1.Deployment) *DeploymentStatus {
	var desiredReplicas int32 = 1
	if d.Spec.Replicas != nil {
		desiredReplicas = *d.Spec.Replicas
	}

	status := &DeploymentStatus{
		Name:               d.Name,
		Namespace:          d.Namespace,
		Labels:             d.Labels,
		Annotations:        d.Annotations,
		DesiredReplicas:    desiredReplicas,
		ReadyReplicas:      d.Status.ReadyReplicas,
		AvailableReplicas:  d.Status.AvailableReplicas,
		UpdatedReplicas:    d.Status.UpdatedReplicas,
		Generation:         d.Generation,
		ObservedGeneration: d.Status.ObservedGeneration,
		CreatedAt:          d.CreationTimestamp.Time,
	}

	// Extract image from first container.
	if len(d.Spec.Template.Spec.Containers) > 0 {
		status.Image = d.Spec.Template.Spec.Containers[0].Image
	}

	// Map conditions.
	status.Conditions = make([]DeploymentCondition, 0, len(d.Status.Conditions))
	for _, c := range d.Status.Conditions {
		status.Conditions = append(status.Conditions, DeploymentCondition{
			Type:               string(c.Type),
			Status:             string(c.Status),
			Reason:             c.Reason,
			Message:            c.Message,
			LastTransitionTime: c.LastTransitionTime.Time,
			LastUpdateTime:     c.LastUpdateTime.Time,
		})

		if c.Type == appsv1.DeploymentAvailable && c.Status == corev1.ConditionTrue {
			status.Available = true
			status.LastUpdated = c.LastUpdateTime.Time
		}
	}

	return status
}

// mapDeploymentToRolloutStatus converts K8s Deployment to RolloutStatus.
func mapDeploymentToRolloutStatus(d *appsv1.Deployment) *RolloutStatus {
	status := &RolloutStatus{
		Revision: d.Generation,
	}

	// Determine rollout phase from conditions.
	for _, c := range d.Status.Conditions {
		switch c.Type {
		case appsv1.DeploymentProgressing:
			switch c.Status {
			case corev1.ConditionTrue:
				status.Progressing = true
				if c.Reason == "NewReplicaSetAvailable" {
					status.Status = RolloutPhaseComplete
					status.Complete = true
					status.Message = "Rollout complete"
				} else {
					status.Status = RolloutPhaseProgressing
					status.Message = fmt.Sprintf("Rollout in progress: %s", c.Message)
				}
			case corev1.ConditionFalse:
				status.Status = RolloutPhaseFailed
				status.Message = fmt.Sprintf("Rollout failed: %s", c.Message)
			}
		case appsv1.DeploymentAvailable:
			if c.Status == corev1.ConditionTrue && status.Status == "" {
				status.Status = RolloutPhaseComplete
				status.Complete = true
			}
		}
	}

	// Check if paused.
	if d.Spec.Paused {
		status.Status = RolloutPhasePaused
		status.Message = "Deployment is paused"
		status.Progressing = false
	}

	// Set default status if not determined.
	if status.Status == "" {
		status.Status = RolloutPhasePending
		status.Message = "Waiting for rollout to start"
	}

	// Calculate duration if we have a start time.
	if !d.CreationTimestamp.IsZero() {
		status.StartTime = d.CreationTimestamp.Time
		if status.Complete {
			// Use last condition update time as end time.
			for _, c := range d.Status.Conditions {
				if c.Type == appsv1.DeploymentProgressing && !c.LastUpdateTime.IsZero() {
					status.Duration = c.LastUpdateTime.Sub(status.StartTime)
					break
				}
			}
		}
	}

	return status
}
