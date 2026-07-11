package auditor

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"
)

// AlertEmitter sends alerts via K8s Events
type AlertEmitter struct {
	clientset kubernetes.Interface
	namespace string
	nodeName  string
}

// NewAlertEmitter creates a new emitter
func NewAlertEmitter(clientset kubernetes.Interface, namespace, nodeName string) *AlertEmitter {
	return &AlertEmitter{
		clientset: clientset,
		namespace: namespace,
		nodeName:  nodeName,
	}
}

func randomSuffix() string {
	b := make([]byte, 4)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// EmitViolation emits a K8s Event for an unauthorized program
func (e *AlertEmitter) EmitViolation(state *ProgramState) {
	eventType := corev1.EventTypeWarning
	reason := "UnauthorizedBPFProgram"

	podRef := "host-process"
	if state.PodInfo != nil {
		podRef = fmt.Sprintf("%s/%s", state.PodInfo.PodNamespace, state.PodInfo.PodName)
	}

	message := fmt.Sprintf(
		"Unauthorized eBPF program detected on node %s: "+
			"program_id=%d name=%s type=%s owner=%s",
		e.nodeName,
		state.Program.ID,
		state.Program.Name,
		state.Program.Type,
		podRef,
	)

	if state.Context != nil {
		message += " " + FormatContextString(state.Context)
	}

	event := &corev1.Event{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("corso-%d-%d-%s", state.Program.ID, time.Now().Unix(), randomSuffix()),
			Namespace: e.namespace,
		},
		InvolvedObject: corev1.ObjectReference{
			Kind:      "Node",
			Name:      e.nodeName,
			Namespace: e.namespace,
		},
		Reason:         reason,
		Message:        message,
		FirstTimestamp: metav1.Now(),
		LastTimestamp:   metav1.Now(),
		Type:           eventType,
		Source: corev1.EventSource{
			Component: "corso",
			Host:      e.nodeName,
		},
	}

	_, err := e.clientset.CoreV1().Events(e.namespace).Create(
		context.TODO(), event, metav1.CreateOptions{},
	)
	if err != nil {
		klog.Errorf("Failed to emit K8s event: %v", err)
	}
}

// EmitInfo emits an informational K8s Event
func (e *AlertEmitter) EmitInfo(message string) {
	event := &corev1.Event{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("corso-info-%d-%s", time.Now().Unix(), randomSuffix()),
			Namespace: e.namespace,
		},
		InvolvedObject: corev1.ObjectReference{
			Kind:      "Node",
			Name:      e.nodeName,
			Namespace: e.namespace,
		},
		Reason:         "CorsoInfo",
		Message:        message,
		FirstTimestamp: metav1.Now(),
		LastTimestamp:   metav1.Now(),
		Type:           corev1.EventTypeNormal,
		Source: corev1.EventSource{
			Component: "corso",
			Host:      e.nodeName,
		},
	}

	_, err := e.clientset.CoreV1().Events(e.namespace).Create(
		context.TODO(), event, metav1.CreateOptions{},
	)
	if err != nil {
		klog.Errorf("Failed to emit info event: %v", err)
	}
}
