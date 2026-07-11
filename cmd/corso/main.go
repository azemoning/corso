package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/azemoning/corso/internal/allowlist"
	"github.com/azemoning/corso/internal/auditor"
	"github.com/azemoning/corso/internal/config"
	"github.com/azemoning/corso/internal/controller"
	"github.com/azemoning/corso/internal/metrics"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/klog/v2"
)

func main() {
	klog.InitFlags(nil)

	controllerOnly := flag.Bool("controller-only", false, "Run only the CRD controller (no agent)")
	flag.Parse()

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

	dynamicClient, err := dynamic.NewForConfig(restConfig)
	if err != nil {
		klog.Fatalf("Failed to create dynamic client: %v", err)
	}

	// Register Prometheus metrics
	metrics.Register()

	// Start metrics HTTP server on :9090
	metricsAddr := fmt.Sprintf(":%d", 9090)
	go func() {
		mux := http.NewServeMux()
		mux.Handle("/metrics", promhttp.Handler())
		mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "ok")
		})
		klog.Infof("Metrics server listening on %s", metricsAddr)
		if err := http.ListenAndServe(metricsAddr, mux); err != nil && err != http.ErrServerClosed {
			klog.Errorf("Metrics server error: %v", err)
		}
	}()

	// Allowlist
	al := allowlist.NewAllowlist()

	// CRD Controller
	var ctrl *controller.Controller
	if cfg.ControllerEnabled {
		onUpdate := func(programs []allowlist.AllowedProgram, defaultAction string, ignoreKnownDaemons bool) {
			al.Update(programs, defaultAction, ignoreKnownDaemons)
		}
		onReset := func() {
			al.Update(nil, "alert", true)
			klog.Info("Allowlist reset to defaults")
		}
		ctrl = controller.NewController(dynamicClient, cfg.Namespace, onUpdate, onReset)
		defer ctrl.Stop()
		go ctrl.Start()
	}

	// If running as controller-only, skip the agent
	if *controllerOnly {
		klog.Info("Running in controller-only mode")
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh
		fmt.Println("\nCorso controller shutting down...")
		return
	}

	// Informer factory for pod cache
	factory := informers.NewSharedInformerFactory(clientset, 0)

	// PID resolver
	resolver := auditor.NewPIDResolver(factory, cfg.NodeName)
	resolver.Start(context.Background().Done())
	if !resolver.WaitForCacheSync(context.Background().Done()) {
		klog.Fatal("Failed to sync pod cache")
	}

	// Auditor
	aud := auditor.NewAuditor(clientset, resolver, al, cfg.NodeName, cfg.Namespace, cfg.PollInterval, cfg.EnforcementMode)
	defer aud.Stop()

	// Start auditor
	go aud.Run()

	// Wait for signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
	fmt.Println("\nCorso shutting down...")
}
