.DEFAULT_GOAL := help

BPF_CLANG ?= clang
CC ?= gcc
ARCH ?= $(shell uname -m)

BPF_TARGET_ARCH := $(ARCH)
ifeq ($(ARCH),x86_64)
BPF_TARGET_ARCH := x86
else ifeq ($(ARCH),aarch64)
BPF_TARGET_ARCH := arm64
endif

BPF_SRC := src/x9.bpf.c
USER_SRC := src/x9.c
BIN_DIR := bin
BPF_OBJ := $(BIN_DIR)/x9.bpf.o
BIN := $(BIN_DIR)/x9

BPF_CFLAGS := -O2 -g -target bpf -D__TARGET_ARCH_$(BPF_TARGET_ARCH) -I/usr/include/$(ARCH)-linux-gnu
USER_CFLAGS := -O2 -g
USER_LDFLAGS := -lbpf -lelf -lz

OUTPUT_FILE ?= /tmp/x9-events.csv

IMAGE ?= x9:latest
KIND_CLUSTER ?= cluster-x9
KIND_CONFIG ?= kind/cluster-x9.yaml
K8S_MANIFEST ?= k8s/daemonset.yaml
K8S_NGINX_MANIFEST ?= k8s/nginx.yaml
K8S_NAMESPACE ?= kube-system
DAEMONSET_NAME ?= x9
TAIL ?= 100
EVENT_FILE ?= /var/log/x9/events.csv

.PHONY: help tools build build-bpf build-user run clean docker-build kind-up kind-down kind-reset kind-load k8s-apply k8s-restart k8s-status k8s-logs deploy-kind deploy status logs tail undeploy redeploy

help: ## Show this help message
	@printf "\n\033[1mX9 eBPF Connection Monitor\033[0m\n"
	@printf "\033[2mMain project commands\033[0m\n\n"
	@printf "Usage: make <target> [VAR=value]\n\n"
	@printf "\033[1mBuild and Local\033[0m\n"
	@printf "  \033[36m%-14s\033[0m %s\n" "tools" "Check required tools"
	@printf "  \033[36m%-14s\033[0m %s\n" "build" "Build eBPF and user-space binaries"
	@printf "  \033[36m%-14s\033[0m %s\n" "run" "Run locally (requires sudo)"
	@printf "  \033[36m%-14s\033[0m %s\n" "clean" "Remove local build artifacts"
	@printf "\n\033[1mContainer Image\033[0m\n"
	@printf "  \033[36m%-14s\033[0m %s\n" "docker-build" "Build Docker image (no cache)"
	@printf "\n\033[1mKind Cluster\033[0m\n"
	@printf "  \033[36m%-14s\033[0m %s\n" "kind-up" "Create a 3-node kind cluster"
	@printf "  \033[36m%-14s\033[0m %s\n" "kind-down" "Delete a kind cluster"
	@printf "  \033[36m%-14s\033[0m %s\n" "kind-reset" "Recreate a kind cluster"
	@printf "\n\033[1mKubernetes Ops\033[0m\n"
	@printf "  \033[36m%-14s\033[0m %s\n" "deploy" "Build image and deploy to kind"
	@printf "  \033[36m%-14s\033[0m %s\n" "status" "Show daemonset and pod status"
	@printf "  \033[36m%-14s\033[0m %s\n" "logs" "Follow DaemonSet logs"
	@printf "  \033[36m%-14s\033[0m %s\n" "tail" "Tail CSV event file in pod"
	@printf "  \033[36m%-14s\033[0m %s\n" "redeploy" "Reapply and restart DaemonSet"
	@printf "  \033[36m%-14s\033[0m %s\n" "undeploy" "Delete Kubernetes resources"
	@printf "\nExamples:\n"
	@printf "  make build\n"
	@printf "  make run OUTPUT_FILE=/tmp/events.csv\n"
	@printf "  make deploy KIND_CLUSTER=dev\n\n"

tools: ## Check required tools
	@missing=0; \
	for tool in "$(BPF_CLANG)" "$(CC)" docker kind kubectl; do \
		if command -v "$$tool" >/dev/null 2>&1; then \
			printf "[OK] %s\n" "$$tool"; \
		else \
			printf "[MISSING] %s\n" "$$tool"; \
			missing=1; \
		fi; \
	done; \
	if [ $$missing -ne 0 ]; then \
		echo "One or more required tools are missing."; \
		echo "Install them and run 'make tools' again."; \
		exit 1; \
	fi; \
	echo "All required tools are installed."

build: build-bpf build-user ## Build eBPF and user-space binaries

build-bpf: $(BPF_OBJ) ## Build the eBPF object

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

$(BPF_OBJ): $(BPF_SRC) | $(BIN_DIR)
	$(BPF_CLANG) $(BPF_CFLAGS) -c $< -o $@

build-user: $(BIN) ## Build the user-space binary

$(BIN): $(USER_SRC) | $(BIN_DIR)
	$(CC) $(USER_CFLAGS) $< -o $@ $(USER_LDFLAGS)

run: build ## Run locally (requires sudo)
	sudo ./$(BIN) $(OUTPUT_FILE) $(BPF_OBJ)

clean: ## Remove local build artifacts
	rm -rf $(BIN_DIR)

docker-build: ## Build Docker image (no cache)
	docker build --no-cache -t $(IMAGE) .

kind-up: ## Create a 3-node kind cluster
	kind create cluster --name $(KIND_CLUSTER) --config $(KIND_CONFIG)

kind-down: ## Delete a kind cluster
	kind delete cluster --name $(KIND_CLUSTER)

kind-reset: kind-down kind-up ## Recreate a kind cluster

kind-load:
	kind load docker-image $(IMAGE) --name $(KIND_CLUSTER)

k8s-apply:
	kubectl apply -f $(K8S_MANIFEST) -f $(K8S_NGINX_MANIFEST)

k8s-restart:
	kubectl -n $(K8S_NAMESPACE) rollout restart daemonset/$(DAEMONSET_NAME)

k8s-status:
	kubectl -n $(K8S_NAMESPACE) rollout status daemonset/$(DAEMONSET_NAME)

k8s-logs:
	kubectl -n $(K8S_NAMESPACE) logs -l app=$(DAEMONSET_NAME) -f --tail=$(TAIL)

deploy-kind: kind-load k8s-apply k8s-restart k8s-status

deploy: ## Build image and deploy to kind
	$(MAKE) deploy-kind

status: ## Show daemonset and pod status
	kubectl -n $(K8S_NAMESPACE) get daemonset $(DAEMONSET_NAME)
	kubectl -n $(K8S_NAMESPACE) get pods -l app=$(DAEMONSET_NAME) -o wide

logs: ## Follow DaemonSet logs
	$(MAKE) k8s-logs

tail: ## Tail CSV event file in pod
	@POD=$$(kubectl -n $(K8S_NAMESPACE) get pods -l app=$(DAEMONSET_NAME) -o jsonpath='{.items[0].metadata.name}'); \
	if [ -z "$$POD" ]; then \
		echo "No pod found for app=$(DAEMONSET_NAME) in namespace $(K8S_NAMESPACE)"; \
		exit 1; \
	fi; \
	kubectl -n $(K8S_NAMESPACE) exec -it "$$POD" -- tail -f $(EVENT_FILE)

undeploy: ## Delete Kubernetes resources
	kubectl delete -f $(K8S_MANIFEST) --ignore-not-found
	kubectl delete -f $(K8S_NGINX_MANIFEST) --ignore-not-found

redeploy: ## Reapply and restart DaemonSet
	$(MAKE) k8s-apply
	$(MAKE) k8s-restart
	$(MAKE) k8s-status
