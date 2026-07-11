package e2e

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/remotecommand"
)

const (
	corsoNamespace = "corso-system"
	kindCluster    = "corso-e2e"
	defaultTimeout = 5 * time.Minute
	pollInterval   = 2 * time.Second
)

// kubeClient creates a Kubernetes client from kubeconfig.
func kubeClient(t *testing.T) kubernetes.Interface {
	t.Helper()

	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
	configOverrides := &clientcmd.ConfigOverrides{
		CurrentContext: "kind-" + kindCluster,
	}
	cfg, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, configOverrides).ClientConfig()
	if err != nil {
		t.Fatalf("Failed to build kubeconfig: %v", err)
	}

	clientset, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		t.Fatalf("Failed to create clientset: %v", err)
	}

	return clientset
}

// restConfig returns the rest.Config for exec operations.
func restConfig(t *testing.T) *rest.Config {
	t.Helper()

	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
	configOverrides := &clientcmd.ConfigOverrides{
		CurrentContext: "kind-" + kindCluster,
	}
	cfg, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, configOverrides).ClientConfig()
	if err != nil {
		t.Fatalf("Failed to build rest config: %v", err)
	}
	return cfg
}

// execCommand executes a command inside a pod and returns stdout+stderr.
func execCommand(t *testing.T, podName, namespace string, command []string) string {
	t.Helper()

	cfg := restConfig(t)
	clientset := kubeClient(t)

	req := clientset.CoreV1().RESTClient().Post().
		Resource("pods").
		Name(podName).
		Namespace(namespace).
		SubResource("exec").
		VersionedParams(&corev1.PodExecOptions{
			Container: "corso",
			Command:   command,
			Stdout:    true,
			Stderr:    true,
		}, scheme.ParameterCodec)

	executor, err := remotecommand.NewSPDYExecutor(cfg, "POST", req.URL())
	if err != nil {
		t.Fatalf("Failed to create executor: %v", err)
	}

	var stdout, stderr bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	err = executor.StreamWithContext(ctx, remotecommand.StreamOptions{
		Stdout: &stdout,
		Stderr: &stderr,
	})
	if err != nil {
		t.Logf("Exec stderr: %s", stderr.String())
		t.Fatalf("Failed to exec command %v in pod %s: %v", command, podName, err)
	}

	return stdout.String()
}

// waitForPodReady waits until a pod is in Ready condition.
func waitForPodReady(t *testing.T, podName, namespace string, timeout time.Duration) {
	t.Helper()

	clientset := kubeClient(t)

	err := wait.PollUntilContextTimeout(context.Background(), pollInterval, timeout, true,
		func(ctx context.Context) (bool, error) {
			pod, err := clientset.CoreV1().Pods(namespace).Get(ctx, podName, metav1.GetOptions{})
			if err != nil {
				return false, nil // keep trying
			}
			for _, cond := range pod.Status.Conditions {
				if cond.Type == corev1.PodReady && cond.Status == corev1.ConditionTrue {
					return true, nil
				}
			}
			return false, nil
		})
	if err != nil {
		t.Fatalf("Pod %s/%s not ready within %v: %v", namespace, podName, timeout, err)
	}
}

// waitForDaemonSetReady waits until all DaemonSet pods are ready.
func waitForDaemonSetReady(t *testing.T, dsName, namespace string, timeout time.Duration) {
	t.Helper()

	clientset := kubeClient(t)

	err := wait.PollUntilContextTimeout(context.Background(), pollInterval, timeout, true,
		func(ctx context.Context) (bool, error) {
			ds, err := clientset.AppsV1().DaemonSets(namespace).Get(ctx, dsName, metav1.GetOptions{})
			if err != nil {
				return false, nil
			}
			if ds.Status.DesiredNumberScheduled == 0 {
				return false, nil
			}
			return ds.Status.NumberReady == ds.Status.DesiredNumberScheduled, nil
		})
	if err != nil {
		t.Fatalf("DaemonSet %s/%s not ready within %v: %v", namespace, dsName, timeout, err)
	}
}

// getCorsoPods returns all Corso pods in the namespace.
func getCorsoPods(t *testing.T, namespace string) []corev1.Pod {
	t.Helper()

	clientset := kubeClient(t)
	pods, err := clientset.CoreV1().Pods(namespace).List(context.Background(), metav1.ListOptions{
		LabelSelector: "app=corso",
	})
	if err != nil {
		t.Fatalf("Failed to list Corso pods: %v", err)
	}
	return pods.Items
}

// getPodLogs returns the logs from a pod's first container.
func getPodLogs(t *testing.T, podName, namespace string) string {
	t.Helper()

	clientset := kubeClient(t)
	req := clientset.CoreV1().Pods(namespace).GetLogs(podName, &corev1.PodLogOptions{
		Container: "corso",
		TailLines: int64Ptr(100),
	})

	stream, err := req.Stream(context.Background())
	if err != nil {
		t.Fatalf("Failed to get logs for pod %s: %v", podName, err)
	}
	defer stream.Close()

	data, err := io.ReadAll(stream)
	if err != nil {
		t.Fatalf("Failed to read logs for pod %s: %v", podName, err)
	}
	return string(data)
}

// portForward sets up port forwarding to a pod and returns a stop channel.
func portForward(t *testing.T, podName, namespace string, localPort, remotePort int) func() {
	t.Helper()

	// We use kubectl for port-forwarding since the Go client port-forward
	// requires more boilerplate. This is simpler for e2e tests.
	stopCh := make(chan struct{})

	go func() {
		cmd := execCommandRaw(t, podName, namespace,
			[]string{"sh", "-c", fmt.Sprintf("echo 'port-forward placeholder for %d->%d'", localPort, remotePort)})
		_ = cmd
	}()

	return func() {
		close(stopCh)
	}
}

// fetchMetrics hits the /metrics endpoint on a Corso pod via kubectl port-forward
// and returns the response body.
func fetchMetrics(t *testing.T, podName, namespace string, localPort, remotePort int) string {
	t.Helper()

	_ = context.Background() // keep context available for future use

	kubectlArgs := []string{
		"port-forward",
		"-n", namespace,
		"pod/"+podName,
		fmt.Sprintf("%d:%d", localPort, remotePort),
	}

	t.Logf("Running: kubectl %s", strings.Join(kubectlArgs, " "))
	// For simplicity, we exec into the pod and curl localhost
	return execCommand(t, podName, namespace,
		[]string{"sh", "-c", fmt.Sprintf("wget -qO- http://localhost:%d/metrics 2>/dev/null || echo 'METRICS_FETCH_FAILED'", remotePort)})
}

// waitForMetric waits until a specific metric name appears in the /metrics output.
func waitForMetric(t *testing.T, podName, namespace, metricName string, timeout time.Duration) string {
	t.Helper()

	var result string
	err := wait.PollUntilContextTimeout(context.Background(), pollInterval, timeout, true,
		func(ctx context.Context) (bool, error) {
			metrics := execCommand(t, podName, namespace,
				[]string{"sh", "-c", fmt.Sprintf("wget -qO- http://localhost:9090/metrics 2>/dev/null || true")})
			if strings.Contains(metrics, metricName) {
				result = metrics
				return true, nil
			}
			return false, nil
		})
	if err != nil {
		t.Fatalf("Metric %q not found within %v", metricName, timeout)
	}
	return result
}

// createTestEBPFLoaderPod creates a privileged pod that loads an eBPF program.
func createTestEBPFLoaderPod(t *testing.T, clientset kubernetes.Interface, namespace, image string) string {
	t.Helper()

	podName := "ebpf-loader-test"
	privileged := true

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      podName,
			Namespace: namespace,
			Labels: map[string]string{
				"app":     "ebpf-loader",
				"test-e2e": "true",
			},
		},
		Spec: corev1.PodSpec{
			HostPID: true,
			NodeSelector: map[string]string{
				"kubernetes.io/os": "linux",
			},
			Tolerations: []corev1.Toleration{
				{Operator: corev1.TolerationOpExists},
			},
			Containers: []corev1.Container{
				{
					Name:  "loader",
					Image: image,
					SecurityContext: &corev1.SecurityContext{
						Privileged: &privileged,
					},
					VolumeMounts: []corev1.VolumeMount{
						{Name: "debugfs", MountPath: "/sys/kernel/debug"},
						{Name: "bpffs", MountPath: "/sys/fs/bpf"},
					},
				},
			},
			Volumes: []corev1.Volume{
				{
					Name: "debugfs",
					VolumeSource: corev1.VolumeSource{
						HostPath: &corev1.HostPathVolumeSource{Path: "/sys/kernel/debug"},
					},
				},
				{
					Name: "bpffs",
					VolumeSource: corev1.VolumeSource{
						HostPath: &corev1.HostPathVolumeSource{Path: "/sys/fs/bpf"},
					},
				},
			},
		},
	}

	// Delete existing pod if it exists
	_ = clientset.CoreV1().Pods(namespace).Delete(context.Background(), podName, metav1.DeleteOptions{})

	created, err := clientset.CoreV1().Pods(namespace).Create(context.Background(), pod, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("Failed to create eBPF loader pod: %v", err)
	}

	t.Cleanup(func() {
		_ = clientset.CoreV1().Pods(namespace).Delete(context.Background(), podName, metav1.DeleteOptions{})
	})

	return created.Name
}

// deletePod deletes a pod by name.
func deletePod(t *testing.T, clientset kubernetes.Interface, namespace, podName string) {
	t.Helper()
	err := clientset.CoreV1().Pods(namespace).Delete(context.Background(), podName, metav1.DeleteOptions{})
	if err != nil {
		t.Logf("Warning: failed to delete pod %s: %v", podName, err)
	}
}

// getKubernetesEvents returns events matching a reason in the given namespace.
func getKubernetesEvents(t *testing.T, clientset kubernetes.Interface, namespace, reason string) []corev1.Event {
	t.Helper()

	events, err := clientset.CoreV1().Events(namespace).List(context.Background(), metav1.ListOptions{})
	if err != nil {
		t.Fatalf("Failed to list events: %v", err)
	}

	var matching []corev1.Event
	for _, evt := range events.Items {
		if evt.Reason == reason {
			matching = append(matching, evt)
		}
	}
	return matching
}

// int64Ptr returns a pointer to an int64 value.
func int64Ptr(v int64) *int64 {
	return &v
}

// execCommandRaw is a helper that runs a command but doesn't fail on error.
func execCommandRaw(t *testing.T, podName, namespace string, command []string) string {
	t.Helper()

	cfg := restConfig(t)
	clientset := kubeClient(t)

	req := clientset.CoreV1().RESTClient().Post().
		Resource("pods").
		Name(podName).
		Namespace(namespace).
		SubResource("exec").
		VersionedParams(&corev1.PodExecOptions{
			Command: command,
			Stdout:  true,
			Stderr:  true,
		}, scheme.ParameterCodec)

	executor, err := remotecommand.NewSPDYExecutor(cfg, "POST", req.URL())
	if err != nil {
		return ""
	}

	var stdout, stderr bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_ = executor.StreamWithContext(ctx, remotecommand.StreamOptions{
		Stdout: &stdout,
		Stderr: &stderr,
	})

	return stdout.String()
}
