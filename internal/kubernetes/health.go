package kubernetes

import (
	"context"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes"
)

// ContainerState represents the state of a container.
// Fields are ordered for optimal memory alignment.
type ContainerState struct {
	StartedAt  time.Time `json:"started_at,omitempty"`
	FinishedAt time.Time `json:"finished_at,omitempty"`
	Reason     string    `json:"reason,omitempty"`
	Message    string    `json:"message,omitempty"`
	Running    bool      `json:"running"`
	Waiting    bool      `json:"waiting"`
	Terminated bool      `json:"terminated"`
}

// ContainerHealth represents the health of a container.
// Fields are ordered for optimal memory alignment.
type ContainerHealth struct {
	Name         string         `json:"name"`
	Image        string         `json:"image"`
	State        ContainerState `json:"state"`
	RestartCount int32          `json:"restart_count"`
	Ready        bool           `json:"ready"`
	Started      bool           `json:"started"`
}

// PodCondition represents a condition of a pod.
// Fields are ordered for optimal memory alignment.
type PodCondition struct {
	LastTransitionTime time.Time `json:"last_transition_time"`
	Type               string    `json:"type"`
	Status             string    `json:"status"`
	Reason             string    `json:"reason,omitempty"`
	Message            string    `json:"message,omitempty"`
}

// PodHealth represents the health status of a single pod.
// Fields are ordered for optimal memory alignment.
type PodHealth struct {
	StartTime  time.Time         `json:"start_time,omitempty"`
	Name       string            `json:"name"`
	Namespace  string            `json:"namespace"`
	Phase      string            `json:"phase"`
	Message    string            `json:"message,omitempty"`
	Conditions []PodCondition    `json:"conditions,omitempty"`
	Containers []ContainerHealth `json:"containers,omitempty"`
	Ready      bool              `json:"ready"`
	Healthy    bool              `json:"healthy"`
}

// HealthReport represents the health status of a deployment's pods.
// Fields are ordered for optimal memory alignment.
type HealthReport struct {
	CheckedAt     time.Time   `json:"checked_at"`
	Namespace     string      `json:"namespace"`
	Deployment    string      `json:"deployment"`
	Message       string      `json:"message,omitempty"`
	Pods          []PodHealth `json:"pods"`
	TotalPods     int         `json:"total_pods"`
	HealthyPods   int         `json:"healthy_pods"`
	UnhealthyPods int         `json:"unhealthy_pods"`
	Healthy       bool        `json:"healthy"`
}

// PodReadiness represents readiness probe results.
// Fields are ordered for optimal memory alignment.
type PodReadiness struct {
	LastProbeTime time.Time `json:"last_probe_time,omitempty"`
	Name          string    `json:"name"`
	Namespace     string    `json:"namespace"`
	Message       string    `json:"message,omitempty"`
	Ready         bool      `json:"ready"`
}

// PodLiveness represents liveness probe results.
// Fields are ordered for optimal memory alignment.
type PodLiveness struct {
	LastProbeTime time.Time `json:"last_probe_time,omitempty"`
	Name          string    `json:"name"`
	Namespace     string    `json:"namespace"`
	Message       string    `json:"message,omitempty"`
	Alive         bool      `json:"alive"`
}

// defaultHealthClient implements HealthClient.
type defaultHealthClient struct {
	client    kubernetes.Interface
	namespace string
}

// CheckPodHealth checks health of deployment pods.
func (h *defaultHealthClient) CheckPodHealth(ctx context.Context, namespace, deployment string) (*HealthReport, error) {
	if ctx == nil {
		return nil, ErrNilContext
	}
	if namespace == "" {
		namespace = h.namespace
	}
	if namespace == "" {
		return nil, ErrEmptyNamespace
	}
	if deployment == "" {
		return nil, ErrEmptyName
	}

	// Get deployment to find pod selector.
	deploy, err := h.client.AppsV1().Deployments(namespace).Get(ctx, deployment, metav1.GetOptions{})
	if err != nil {
		if k8serrors.IsNotFound(err) {
			return nil, NewClientError("check pod health", namespace, deployment, ErrDeploymentNotFound)
		}
		return nil, NewClientError("check pod health", namespace, deployment, err)
	}

	// Build selector from deployment.
	selector := labels.SelectorFromSet(deploy.Spec.Selector.MatchLabels).String()

	// List pods.
	pods, err := h.client.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{
		LabelSelector: selector,
	})
	if err != nil {
		return nil, NewClientError("list pods", namespace, deployment, err)
	}

	report := &HealthReport{
		Namespace:  namespace,
		Deployment: deployment,
		CheckedAt:  time.Now(),
		TotalPods:  len(pods.Items),
		Pods:       make([]PodHealth, 0, len(pods.Items)),
	}

	for i := range pods.Items {
		podHealth := mapPodToHealth(&pods.Items[i])
		report.Pods = append(report.Pods, *podHealth)
		if podHealth.Healthy {
			report.HealthyPods++
		} else {
			report.UnhealthyPods++
		}
	}

	report.Healthy = report.UnhealthyPods == 0 && report.TotalPods > 0
	if !report.Healthy && report.UnhealthyPods > 0 {
		report.Message = fmt.Sprintf("%d of %d pods unhealthy", report.UnhealthyPods, report.TotalPods)
	}

	return report, nil
}

// GetReadiness checks readiness probe status.
func (h *defaultHealthClient) GetReadiness(ctx context.Context, namespace, selector string) ([]PodReadiness, error) {
	if ctx == nil {
		return nil, ErrNilContext
	}
	if namespace == "" {
		namespace = h.namespace
	}
	if namespace == "" {
		return nil, ErrEmptyNamespace
	}

	listOptions := metav1.ListOptions{}
	if selector != "" {
		listOptions.LabelSelector = selector
	}

	pods, err := h.client.CoreV1().Pods(namespace).List(ctx, listOptions)
	if err != nil {
		return nil, NewClientError("get readiness", namespace, "", err)
	}

	result := make([]PodReadiness, 0, len(pods.Items))
	for i := range pods.Items {
		pod := &pods.Items[i]
		readiness := PodReadiness{
			Name:      pod.Name,
			Namespace: pod.Namespace,
		}

		// Check pod conditions for readiness.
		for _, cond := range pod.Status.Conditions {
			if cond.Type == corev1.PodReady {
				readiness.Ready = cond.Status == corev1.ConditionTrue
				readiness.LastProbeTime = cond.LastTransitionTime.Time
				if !readiness.Ready {
					readiness.Message = cond.Message
				}
				break
			}
		}

		result = append(result, readiness)
	}

	return result, nil
}

// GetLiveness checks liveness probe status.
func (h *defaultHealthClient) GetLiveness(ctx context.Context, namespace, selector string) ([]PodLiveness, error) {
	if ctx == nil {
		return nil, ErrNilContext
	}
	if namespace == "" {
		namespace = h.namespace
	}
	if namespace == "" {
		return nil, ErrEmptyNamespace
	}

	listOptions := metav1.ListOptions{}
	if selector != "" {
		listOptions.LabelSelector = selector
	}

	pods, err := h.client.CoreV1().Pods(namespace).List(ctx, listOptions)
	if err != nil {
		return nil, NewClientError("get liveness", namespace, "", err)
	}

	result := make([]PodLiveness, 0, len(pods.Items))
	for i := range pods.Items {
		pod := &pods.Items[i]
		liveness := PodLiveness{
			Name:      pod.Name,
			Namespace: pod.Namespace,
			Alive:     pod.Status.Phase == corev1.PodRunning,
		}

		// Check container statuses for liveness.
		allContainersRunning := true
		for j := range pod.Status.ContainerStatuses {
			cs := &pod.Status.ContainerStatuses[j]
			if cs.State.Running == nil {
				allContainersRunning = false
				if cs.State.Waiting != nil {
					liveness.Message = fmt.Sprintf("container %s waiting: %s", cs.Name, cs.State.Waiting.Reason)
				} else if cs.State.Terminated != nil {
					liveness.Message = fmt.Sprintf("container %s terminated: %s", cs.Name, cs.State.Terminated.Reason)
				}
				break
			}
		}

		liveness.Alive = liveness.Alive && allContainersRunning
		if liveness.Alive {
			liveness.LastProbeTime = time.Now()
		}

		result = append(result, liveness)
	}

	return result, nil
}

// WaitForHealthy waits until all pods are healthy.
func (h *defaultHealthClient) WaitForHealthy(ctx context.Context, namespace, deployment string, timeout time.Duration) error {
	if ctx == nil {
		return ErrNilContext
	}
	if namespace == "" {
		namespace = h.namespace
	}
	if namespace == "" {
		return ErrEmptyNamespace
	}
	if deployment == "" {
		return ErrEmptyName
	}

	timeoutCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	ticker := time.NewTicker(DefaultPollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-timeoutCtx.Done():
			// Get final health report for error message.
			report, _ := h.CheckPodHealth(ctx, namespace, deployment)
			if report != nil {
				return &HealthError{
					TotalPods:     report.TotalPods,
					HealthyPods:   report.HealthyPods,
					UnhealthyPods: extractUnhealthyPodNames(report),
					Err:           ErrTimeout,
				}
			}
			return NewClientError("wait for healthy", namespace, deployment, ErrTimeout)
		case <-ticker.C:
			report, err := h.CheckPodHealth(ctx, namespace, deployment)
			if err != nil {
				continue // Keep trying.
			}
			if report.Healthy {
				return nil
			}
		}
	}
}

// mapPodToHealth converts K8s Pod to PodHealth.
func mapPodToHealth(pod *corev1.Pod) *PodHealth {
	health := &PodHealth{
		Name:      pod.Name,
		Namespace: pod.Namespace,
		Phase:     string(pod.Status.Phase),
	}

	if pod.Status.StartTime != nil {
		health.StartTime = pod.Status.StartTime.Time
	}

	// Map conditions.
	health.Conditions = make([]PodCondition, 0, len(pod.Status.Conditions))
	for _, c := range pod.Status.Conditions {
		health.Conditions = append(health.Conditions, PodCondition{
			Type:               string(c.Type),
			Status:             string(c.Status),
			Reason:             c.Reason,
			Message:            c.Message,
			LastTransitionTime: c.LastTransitionTime.Time,
		})

		if c.Type == corev1.PodReady && c.Status == corev1.ConditionTrue {
			health.Ready = true
		}
	}

	// Map container health.
	health.Containers = make([]ContainerHealth, 0, len(pod.Status.ContainerStatuses))
	for i := range pod.Status.ContainerStatuses {
		cs := &pod.Status.ContainerStatuses[i]
		containerHealth := ContainerHealth{
			Name:         cs.Name,
			Image:        cs.Image,
			Ready:        cs.Ready,
			RestartCount: cs.RestartCount,
		}

		if cs.Started != nil {
			containerHealth.Started = *cs.Started
		}

		switch {
		case cs.State.Running != nil:
			containerHealth.State = ContainerState{
				Running:   true,
				StartedAt: cs.State.Running.StartedAt.Time,
			}
		case cs.State.Waiting != nil:
			containerHealth.State = ContainerState{
				Waiting: true,
				Reason:  cs.State.Waiting.Reason,
				Message: cs.State.Waiting.Message,
			}
		case cs.State.Terminated != nil:
			containerHealth.State = ContainerState{
				Terminated: true,
				StartedAt:  cs.State.Terminated.StartedAt.Time,
				FinishedAt: cs.State.Terminated.FinishedAt.Time,
				Reason:     cs.State.Terminated.Reason,
				Message:    cs.State.Terminated.Message,
			}
		}

		health.Containers = append(health.Containers, containerHealth)
	}

	// Determine overall health.
	health.Healthy = health.Ready && pod.Status.Phase == corev1.PodRunning

	// Add message for unhealthy pods.
	if !health.Healthy {
		if pod.Status.Phase != corev1.PodRunning {
			health.Message = fmt.Sprintf("pod phase: %s", pod.Status.Phase)
		} else if !health.Ready {
			health.Message = "pod not ready"
		}
	}

	return health
}

// extractUnhealthyPodNames extracts names of unhealthy pods from a health report.
func extractUnhealthyPodNames(report *HealthReport) []string {
	names := make([]string, 0, report.UnhealthyPods)
	for i := range report.Pods {
		if !report.Pods[i].Healthy {
			names = append(names, report.Pods[i].Name)
		}
	}
	return names
}
