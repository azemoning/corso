.PHONY: e2e e2e-setup e2e-run e2e-cleanup e2e-build-image kind-create kind-delete deploy-corso deploy-crd

KIND_CLUSTER_NAME := corso-e2e
CORSO_IMAGE := corso:latest
LOADER_IMAGE := corso-e2e-loader:latest
ECHO_IMAGE := corso-e2e-echo:latest
CORSO_NAMESPACE := corso-system
TEST_TIMEOUT := 5m

# Root of the repo
REPO_ROOT := $(shell git rev-parse --show-toplevel 2>/dev/null || echo "..")

## Full e2e: setup, run tests, cleanup
e2e: e2e-setup e2e-run e2e-cleanup

## Setup: create cluster, build images, deploy Corso
e2e-setup: kind-create e2e-build-image deploy-crd deploy-corso

## Run the test suite
e2e-run:
	go test -v -timeout $(TEST_TIMEOUT) -count=1 ./...

## Cleanup: delete kind cluster
e2e-cleanup: kind-delete

## Create kind cluster with extra mounts for eBPF
kind-create:
	@echo "==> Creating kind cluster '$(KIND_CLUSTER_NAME)'..."
	kind create cluster --name $(KIND_CLUSTER_NAME) --config kind-config.yaml || true
	@echo "==> Waiting for nodes to be ready..."
	kubectl --context kind-$(KIND_CLUSTER_NAME) wait --for=condition=Ready nodes --all --timeout=120s

## Delete kind cluster
kind-delete:
	@echo "==> Deleting kind cluster '$(KIND_CLUSTER_NAME)'..."
	kind delete cluster --name $(KIND_CLUSTER_NAME) || true

## Build Docker images and load into kind
e2e-build-image:
	@echo "==> Building Corso image..."
	docker build -t $(CORSO_IMAGE) $(REPO_ROOT)
	@echo "==> Loading Corso image into kind..."
	kind load docker-image $(CORSO_IMAGE) --name $(KIND_CLUSTER_NAME)
	@echo "==> Building eBPF loader test image..."
	docker build -t $(LOADER_IMAGE) -f testdata/Dockerfile.e2e testdata/
	@echo "==> Loading loader image into kind..."
	kind load docker-image $(LOADER_IMAGE) --name $(KIND_CLUSTER_NAME)
	@echo "==> Building echo server test image..."
	docker build -t $(ECHO_IMAGE) -f testdata/Dockerfile.echo testdata/
	@echo "==> Loading echo server image into kind..."
	kind load docker-image $(ECHO_IMAGE) --name $(KIND_CLUSTER_NAME)

## Deploy Corso CRDs
deploy-crd:
	@echo "==> Deploying Corso CRDs..."
	kubectl --context kind-$(KIND_CLUSTER_NAME) apply -f $(REPO_ROOT)/deploy/crds/ || true

## Deploy Corso DaemonSet
deploy-corso:
	@echo "==> Creating namespace and RBAC..."
	kubectl --context kind-$(KIND_CLUSTER_NAME) apply -f $(REPO_ROOT)/deploy/rbac.yaml
	@echo "==> Deploying Corso DaemonSet..."
	kubectl --context kind-$(KIND_CLUSTER_NAME) apply -f $(REPO_ROOT)/deploy/daemonset.yaml
	@echo "==> Waiting for DaemonSet to be ready..."
	kubectl --context kind-$(KIND_CLUSTER_NAME) -n $(CORSO_NAMESPACE) rollout status daemonset/corso --timeout=180s
	@echo "==> Corso deployed successfully!"

## Verify cluster is healthy
e2e-verify:
	@echo "==> Verifying kind cluster..."
	kubectl --context kind-$(KIND_CLUSTER_NAME) get nodes
	kubectl --context kind-$(KIND_CLUSTER_NAME) -n $(CORSO_NAMESPACE) get pods -o wide

## Show help
help:
	@echo "Corso E2E Test Targets"
	@echo "====================="
	@echo ""
	@echo "  make e2e           - Full run: setup + tests + cleanup"
	@echo "  make e2e-setup     - Create cluster, build images, deploy"
	@echo "  make e2e-run       - Run the test suite only"
	@echo "  make e2e-cleanup   - Delete the kind cluster"
	@echo "  make e2e-verify    - Check cluster and pod health"
	@echo ""
	@echo "Variables:"
	@echo "  KIND_CLUSTER_NAME=$(KIND_CLUSTER_NAME)"
	@echo "  CORSO_IMAGE=$(CORSO_IMAGE)"
	@echo "  CORSO_NAMESPACE=$(CORSO_NAMESPACE)"
	@echo "  TEST_TIMEOUT=$(TEST_TIMEOUT)"
