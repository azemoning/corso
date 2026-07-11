package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	v1alpha1 "github.com/azemoning/corso/api/v1alpha1"
	"github.com/azemoning/corso/internal/allowlist"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/dynamic/dynamicinformer"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"
)

var bpfAllowlistGVR = schema.GroupVersionResource{
	Group:    "corso.io",
	Version:  "v1alpha1",
	Resource: "bpfprogramallowlists",
}

// AllowlistUpdateFunc is called when the allowlist is updated from a CRD.
type AllowlistUpdateFunc func(programs []allowlist.AllowedProgram, defaultAction string, ignoreKnownDaemons bool)

// AllowlistResetFunc is called when the allowlist should revert to defaults.
type AllowlistResetFunc func()

// Controller watches BPFProgramAllowlist CRDs and updates the in-memory allowlist.
type Controller struct {
	client    dynamic.Interface
	namespace string

	informerFactory dynamicinformer.DynamicSharedInformerFactory
	informer        cache.SharedIndexInformer

	onUpdate AllowlistUpdateFunc
	onReset  AllowlistResetFunc

	ctx    context.Context
	cancel context.CancelFunc
}

// NewController creates a new CRD controller.
func NewController(
	client dynamic.Interface,
	namespace string,
	onUpdate AllowlistUpdateFunc,
	onReset AllowlistResetFunc,
) *Controller {
	ctx, cancel := context.WithCancel(context.Background())

	factory := dynamicinformer.NewDynamicSharedInformerFactory(
		client,
		30*time.Second,
	)

	informer := factory.ForResource(bpfAllowlistGVR).Informer()

	c := &Controller{
		client:          client,
		namespace:       namespace,
		informerFactory: factory,
		informer:        informer,
		onUpdate:        onUpdate,
		onReset:         onReset,
		ctx:             ctx,
		cancel:          cancel,
	}

	informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    c.handleAdd,
		UpdateFunc: c.handleUpdate,
		DeleteFunc: c.handleDelete,
	})

	return c
}

// Start runs the informer and blocks until Stop is called.
func (c *Controller) Start() {
	klog.Info("Starting BPFProgramAllowlist controller")
	c.informerFactory.Start(c.ctx.Done())

	if !cache.WaitForCacheSync(c.ctx.Done(), c.informer.HasSynced) {
		klog.Error("Failed to sync BPFProgramAllowlist informer cache")
		return
	}
	klog.Info("BPFProgramAllowlist informer cache synced")

	<-c.ctx.Done()
}

// Stop halts the controller.
func (c *Controller) Stop() {
	klog.Info("Stopping BPFProgramAllowlist controller")
	c.cancel()
}

func (c *Controller) handleAdd(obj interface{}) {
	u, ok := obj.(*unstructured.Unstructured)
	if !ok {
		klog.Warningf("Expected *unstructured.Unstructured, got %T", obj)
		return
	}
	klog.Infof("BPFProgramAllowlist added: %s/%s", u.GetNamespace(), u.GetName())
	c.applyAllowlist(u)
}

func (c *Controller) handleUpdate(oldObj, newObj interface{}) {
	u, ok := newObj.(*unstructured.Unstructured)
	if !ok {
		klog.Warningf("Expected *unstructured.Unstructured, got %T", newObj)
		return
	}
	klog.Infof("BPFProgramAllowlist updated: %s/%s", u.GetNamespace(), u.GetName())
	c.applyAllowlist(u)
}

func (c *Controller) handleDelete(obj interface{}) {
	u, ok := obj.(*unstructured.Unstructured)
	if !ok {
		tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			klog.Warningf("Expected *unstructured.Unstructured or tombstone, got %T", obj)
			return
		}
		u, ok = tombstone.Obj.(*unstructured.Unstructured)
		if !ok {
			klog.Warningf("Expected *unstructured.Unstructured in tombstone, got %T", tombstone.Obj)
			return
		}
	}
	klog.Infof("BPFProgramAllowlist deleted: %s/%s, reverting to defaults", u.GetNamespace(), u.GetName())
	if c.onReset != nil {
		c.onReset()
	}
}

// applyAllowlist parses the unstructured CR and calls the update callback.
func (c *Controller) applyAllowlist(u *unstructured.Unstructured) {
	// Convert unstructured to typed via JSON round-trip
	data, err := json.Marshal(u.Object)
	if err != nil {
		klog.Errorf("Failed to marshal CR %s/%s: %v", u.GetNamespace(), u.GetName(), err)
		return
	}

	var cr v1alpha1.BPFProgramAllowlist
	if err := json.Unmarshal(data, &cr); err != nil {
		klog.Errorf("Failed to unmarshal CR %s/%s: %v", u.GetNamespace(), u.GetName(), err)
		return
	}

	defaultAction := cr.Spec.DefaultAction
	if defaultAction == "" {
		defaultAction = "alert"
	}

	ignoreKnownDaemons := true
	if cr.Spec.IgnoreKnownDaemons != nil {
		ignoreKnownDaemons = *cr.Spec.IgnoreKnownDaemons
	}

	programs := make([]allowlist.AllowedProgram, 0, len(cr.Spec.Programs))
	for _, p := range cr.Spec.Programs {
		programs = append(programs, allowlist.AllowedProgram{
			Name:          p.Name,
			Type:          p.Type,
			Hash:          p.Hash,
			Namespace:     p.Namespace,
			ContainerName: p.ContainerName,
		})
	}

	klog.Infof("Applying allowlist from CR %s/%s: %d programs, defaultAction=%s, ignoreKnownDaemons=%v",
		u.GetNamespace(), u.GetName(), len(programs), defaultAction, ignoreKnownDaemons)

	if c.onUpdate != nil {
		c.onUpdate(programs, defaultAction, ignoreKnownDaemons)
	}

	// Update status
	c.updateStatus(u, len(programs))
}

// updateStatus patches the CR status with current state.
func (c *Controller) updateStatus(u *unstructured.Unstructured, totalPrograms int) {
	status := map[string]interface{}{
		"lastSyncTime":   metav1.Now().Format(time.RFC3339),
		"totalPrograms":  totalPrograms,
		"nodesEnforcing": 0,
	}

	obj := u.DeepCopy()
	if err := unstructured.SetNestedMap(obj.Object, status, "status"); err != nil {
		klog.Errorf("Failed to set status on CR %s/%s: %v", u.GetNamespace(), u.GetName(), err)
		return
	}

	gvr := bpfAllowlistGVR
	_, err := c.client.Resource(gvr).Namespace(u.GetNamespace()).UpdateStatus(
		context.Background(),
		obj,
		metav1.UpdateOptions{},
	)
	if err != nil {
		klog.V(2).Infof("Failed to update CR status %s/%s (non-fatal): %v",
			u.GetNamespace(), u.GetName(), err)
	}
}

// GetAllowlist returns the current allowlist from the cluster, or nil if none exists.
func GetAllowlist(client dynamic.Interface, namespace, name string) (*v1alpha1.BPFProgramAllowlist, error) {
	obj, err := client.Resource(bpfAllowlistGVR).Namespace(namespace).Get(
		context.Background(),
		name,
		metav1.GetOptions{},
	)
	if err != nil {
		return nil, fmt.Errorf("get BPFProgramAllowlist %s/%s: %w", namespace, name, err)
	}

	data, err := json.Marshal(obj.Object)
	if err != nil {
		return nil, fmt.Errorf("marshal BPFProgramAllowlist: %w", err)
	}

	var cr v1alpha1.BPFProgramAllowlist
	if err := json.Unmarshal(data, &cr); err != nil {
		return nil, fmt.Errorf("unmarshal BPFProgramAllowlist: %w", err)
	}

	return &cr, nil
}
