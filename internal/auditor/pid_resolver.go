package auditor

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/tools/cache"
)

// PodInfo represents the Kubernetes identity of a process
type PodInfo struct {
	PodName       string `json:"pod_name"`
	PodNamespace  string `json:"pod_namespace"`
	NodeName      string `json:"node_name"`
	ContainerID   string `json:"container_id"`
	ContainerName string `json:"container_name"`
	UID           string `json:"uid"`
}

// PIDResolver maps PIDs to Kubernetes pod identity
// Uses cgroup hierarchy to correlate kernel PIDs to K8s pods
// (similar to Bomfather's approach of correlating kernel events to build processes)
type PIDResolver struct {
	mu             sync.RWMutex
	podByUID       map[string]*corev1.Pod
	cgroupToPodUID map[string]string
	podInformer    cache.SharedIndexInformer
	nodeName       string
}

// NewPIDResolver creates a resolver scoped to this node
func NewPIDResolver(factory informers.SharedInformerFactory, nodeName string) *PIDResolver {
	r := &PIDResolver{
		podByUID:       make(map[string]*corev1.Pod),
		cgroupToPodUID: make(map[string]string),
		nodeName:       nodeName,
	}

	podInformer := factory.Core().V1().Pods().Informer()
	podInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    r.onPodAdd,
		UpdateFunc: r.onPodUpdate,
		DeleteFunc: r.onPodDelete,
	})
	r.podInformer = podInformer

	return r
}

func (r *PIDResolver) onPodAdd(obj interface{}) {
	pod, ok := obj.(*corev1.Pod)
	if !ok || pod.Spec.NodeName != r.nodeName {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.podByUID[string(pod.UID)] = pod
	r.indexPodCgroups(pod)
}

func (r *PIDResolver) onPodUpdate(oldObj, newObj interface{}) {
	r.onPodAdd(newObj)
}

func (r *PIDResolver) onPodDelete(obj interface{}) {
	pod, ok := obj.(*corev1.Pod)
	if !ok {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.podByUID, string(pod.UID))
	r.removePodCgroups(pod)
}

// indexPodCgroups maps cgroup paths to pod UID
// cgroup v2: /sys/fs/cgroup/kubepods.slice/kubepods-pod<uid>.slice/
// cgroup v1: /sys/fs/cgroup/cpu,cpuacct/kubepods/burstable/pod<uid>/
func (r *PIDResolver) indexPodCgroups(pod *corev1.Pod) {
	allStatuses := make([]corev1.ContainerStatus, 0, len(pod.Status.ContainerStatuses)+len(pod.Status.InitContainerStatuses))
	allStatuses = append(allStatuses, pod.Status.ContainerStatuses...)
	allStatuses = append(allStatuses, pod.Status.InitContainerStatuses...)
	for _, containerStatus := range allStatuses {
		cid := containerStatus.ContainerID
		if cid == "" {
			continue
		}
		parts := strings.SplitN(cid, "://", 2)
		if len(parts) != 2 {
			continue
		}
		containerID := parts[1]

		// Build multiple cgroup patterns for v1 and v2
		patterns := []string{
			// cgroup v2
			fmt.Sprintf("kubepods.slice/kubepods-pod%s.slice/docker-%s", string(pod.UID), containerID),
			fmt.Sprintf("kubepods.slice/kubepods-pod%s.slice/cri-containerd-%s", string(pod.UID), containerID),
			// cgroup v1
			fmt.Sprintf("kubepods/burstable/pod%s/%s", string(pod.UID), containerID),
			fmt.Sprintf("kubepods/besteffort/pod%s/%s", string(pod.UID), containerID),
			fmt.Sprintf("kubepods/pod%s/%s", string(pod.UID), containerID),
		}

		for _, pattern := range patterns {
			r.cgroupToPodUID[pattern] = string(pod.UID)
		}
	}
}

func (r *PIDResolver) removePodCgroups(pod *corev1.Pod) {
	for key, uid := range r.cgroupToPodUID {
		if uid == string(pod.UID) {
			delete(r.cgroupToPodUID, key)
		}
	}
}

// ResolvePID maps a PID to its Kubernetes pod identity
// Reads /proc/<pid>/cgroup and matches against known pod cgroup paths
func (r *PIDResolver) ResolvePID(pid int32) (PodInfo, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	cgroupPath, err := readCgroupForPID(pid)
	if err != nil {
		return PodInfo{}, fmt.Errorf("failed to read cgroup for pid %d: %w", pid, err)
	}

	// Match cgroup path to pod UID
	for pattern, podUID := range r.cgroupToPodUID {
		if strings.Contains(cgroupPath, pattern) {
			pod, ok := r.podByUID[podUID]
			if !ok {
				return PodInfo{}, fmt.Errorf("pod %s not found in cache", podUID)
			}
			return PodInfo{
				PodName:       pod.Name,
				PodNamespace:  pod.Namespace,
				NodeName:      pod.Spec.NodeName,
				ContainerID:   extractContainerID(cgroupPath),
				ContainerName: findContainerName(pod, extractContainerID(cgroupPath)),
				UID:           string(pod.UID),
			}, nil
		}
	}

	// Check if it's a host process (not in any pod)
	return PodInfo{}, fmt.Errorf("pid %d not mapped to any pod (host process)", pid)
}

// readCgroupForPID reads /proc/<pid>/cgroup
func readCgroupForPID(pid int32) (string, error) {
	path := fmt.Sprintf("/proc/%d/cgroup", pid)
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		parts := strings.SplitN(line, ":", 3)
		if len(parts) == 3 {
			return parts[2], nil // Return the path part
		}
	}
	return "", fmt.Errorf("no cgroup entry found for pid %d", pid)
}

func extractContainerID(cgroupPath string) string {
	// Extract from "docker-<id>" or "cri-containerd-<id>"
	if idx := strings.LastIndex(cgroupPath, "docker-"); idx >= 0 {
		return cgroupPath[idx+7:]
	}
	if idx := strings.LastIndex(cgroupPath, "cri-containerd-"); idx >= 0 {
		return cgroupPath[idx+15:]
	}
	return ""
}

func findContainerName(pod *corev1.Pod, containerID string) string {
	for _, cs := range pod.Status.ContainerStatuses {
		if strings.Contains(cs.ContainerID, containerID) {
			return cs.Name
		}
	}
	return ""
}

// Start begins the informer
func (r *PIDResolver) Start(stopCh <-chan struct{}) {
	go r.podInformer.Run(stopCh)
}

// WaitForCacheSync blocks until the pod cache is synced
func (r *PIDResolver) WaitForCacheSync(stopCh <-chan struct{}) bool {
	return cache.WaitForCacheSync(stopCh, r.podInformer.HasSynced)
}

// GetPodCount returns the number of cached pods on this node
func (r *PIDResolver) GetPodCount() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.podByUID)
}

// HostPID checks if a PID is a host process (not in any pod cgroup)
func HostPID(pid int32) bool {
	path := fmt.Sprintf("/proc/%d/cgroup", pid)
	data, err := os.ReadFile(path)
	if err != nil {
		return true // Can't read = assume host
	}

	content := string(data)
	// Host processes typically have "/" or "/init.scope" as their cgroup
	lines := strings.Split(content, "\n")
	for _, line := range lines {
		parts := strings.SplitN(line, ":", 3)
		if len(parts) == 3 {
			path := parts[2]
			if path == "/" || path == "/init.scope" {
				return true
			}
		}
	}
	return false
}

// ParsePIDFromString parses a PID from a string (useful for proc scanning)
func ParsePIDFromString(s string) (int32, error) {
	pid, err := strconv.ParseInt(s, 10, 32)
	if err != nil {
		return 0, err
	}
	return int32(pid), nil
}
