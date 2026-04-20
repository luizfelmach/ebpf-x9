# X9 eBPF Lab

This lab captures Linux socket activity (`connect` and `accept4`) with eBPF and exports it as NDJSON for Kubernetes-focused observability.

The project includes:
- An eBPF program (`src/x9.bpf.c`) attached via kprobes/kretprobes
- A user-space loader (`src/x9.c`) using libbpf ring buffers
- A DaemonSet deployment for kind/Kubernetes (`k8s/daemonset.yaml`)
- A full Loki + Promtail + Grafana stack (`k8s/observability.yaml`)
- A demo traffic namespace to generate events (`k8s/traffic.yaml`)

## What It Monitors

X9 emits one JSON line per syscall event with metadata such as:
- timestamp (`ts_ns`, `unix_ns`, `iso_ts`)
- event type (`connect`, `accept`)
- process identity (`pid`, `tid`, `uid`, `comm`)
- socket information (`family`, `addr`, `port`, `ret`, `fd`)
- Kubernetes context (`pod_namespace`, `pod_name`)

Only Kubernetes cgroups are allowlisted into the BPF map at runtime, so events are scoped to pods instead of all host processes.

## Repository Layout

`src/`
- `x9.bpf.c`: kernel-space probes and ring buffer event submission
- `x9.c`: loader, cgroup/pod metadata sync, NDJSON writer
- `x9.h`: shared event structure

`k8s/`
- `daemonset.yaml`: privileged DaemonSet running X9 on each node
- `traffic.yaml`: synthetic traffic generators (`x9-demo` namespace)
- `observability.yaml`: Loki, Promtail, Grafana, and preloaded dashboard

`kind/`
- `cluster-x9.yaml`: local kind cluster definition

`Makefile`
- build, deploy, logs, tail, port-forward, and cleanup workflows

## Prerequisites

- Linux host with eBPF support
- `clang`, `gcc`, `libbpf`, `libelf`, `zlib` development headers
- `docker`, `kind`, `kubectl`
- root privileges for local run (`sudo`)

Check tooling quickly:

```bash
make tools
```

## Local Build and Run

Build binaries:

```bash
make build
```

Run locally (writes to `/tmp/x9-events.json` by default):

```bash
make run
```

Custom local output path:

```bash
make run OUTPUT_FILE=/tmp/events.json
```

Artifacts are generated in `bin/`.

## Kubernetes Lab (kind)

### 1) Create cluster

```bash
make kind-up
```

### 2) Build image

```bash
make docker-build IMAGE=x9:latest
```

### 3) Deploy everything

```bash
make deploy
```

`make deploy` loads the image into kind, applies all manifests, restarts workloads, and waits for the DaemonSet rollout.

### 4) Check status and logs

```bash
make status
make logs
```

### 5) Tail generated event file from a pod

```bash
make tail
```

### 6) Open Grafana

```bash
make port-forward
```

Then open `http://localhost:3000`.

## Event Example

```json
{"ts_ns":1243708352241,"unix_ns":1713565659124370835,"iso_ts":"2026-04-20T12:27:39.124370835Z","event_type":"connect","pid":1234,"tid":1234,"uid":0,"comm":"wget","fd":3,"ret":0,"flags":0,"family":2,"addr":"93.184.216.34","port":80,"addrlen":16,"pod_namespace":"x9-demo","pod_name":"traffic-a-6f5fcf9b9f-xxxxx"}
```

## Common Make Targets

- `make help`: show command reference
- `make build`: build eBPF + user binaries
- `make clean`: remove `bin/`
- `make docker-build`: build container image
- `make deploy`: deploy to kind
- `make redeploy`: reapply manifests + restart daemonset
- `make undeploy`: remove Kubernetes resources
- `make kind-down`: delete cluster

## Troubleshooting

- `connect probes could not be attached on this kernel`
  - Kernel symbols/syscall probe names may differ; use a compatible kernel version.
- `failed to load Kubernetes cgroup allowlist`
  - Ensure `/sys/fs/cgroup` is mounted into the container as `/host/sys/fs/cgroup`.
- No pod metadata in output (`pod_namespace` / `pod_name` are `-`)
  - Ensure `/var/log/pods` is mounted into the container as `/host/var/log/pods`.
- No events in Grafana
  - Verify `make logs` for X9 and Promtail, then check `make tail` to confirm NDJSON is being written.

## Cleanup

Remove deployed resources:

```bash
make undeploy
```

Remove kind cluster:

```bash
make kind-down
```
