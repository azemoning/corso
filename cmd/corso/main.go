package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/azemoning/corso/internal/allowlist"
	"github.com/azemoning/corso/internal/auditor"
	"github.com/azemoning/corso/internal/config"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/klog/v2"
)

func main() {
	klog.InitFlags(nil)

	cfg := config.LoadConfig()
	klog.Infof("Corso agent starting on node %s", cfg.NodeName)

	// Kubernetes client
	restConfig, err := rest.InClusterConfig()
	if err != nil {
		klog.Fatalf("Failed to get in-cluster config: %v", err)
	}

	clientset, err := kubernetes.NewForConfig(restConfig)
	if err != nil {
		klog.Fatalf("Failed to create clientset: %v", err)
	}

	// Informer factory
	factory := informers.NewSharedInformerFactory(clientset, 0)

	// PID resolver
	resolver := auditor.NewPIDResolver(factory, cfg.NodeName)
	resolver.Start(context.Background().Done())
	if !resolver.WaitForCacheSync(context.Background().Done()) {
		klog.Fatal("Failed to sync pod cache")
	}

	// Allowlist
	al := allowlist.NewAllowlist()
	// TODO: Watch BPFProgramAllowlist CRD and call al.Update()

	// Auditor
	aud := auditor.NewAuditor(clientset, resolver, al, cfg.NodeName, cfg.Namespace, cfg.PollInterval)
	defer aud.Stop()

	// Start auditor
	go aud.Run()

	// Wait for signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
	fmt.Println("\nCorso shutting down...")
}
