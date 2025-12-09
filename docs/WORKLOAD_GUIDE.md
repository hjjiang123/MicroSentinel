# Workload Deployment Guide

This guide shows how each workload in the evaluation plan maps to concrete binaries, configs, and remote traffic patterns. It reflects the two-node topology (`ms-host` = 211.0.0.101, `client-host` = 211.0.0.102) and the truth-logging hooks baked into the Python reference implementations.

> **Terminology**
> - **ms-host** – Runs workload services and MicroSentinel instrumentation.
> - **client-host** – Generates traffic; automation reaches it via SSH (`control_user@211.0.0.102`).

## 1. Key Principles

1. **Single source of truth** – All workload knobs live under `experiments/configs/workloads/*.yaml`. Update those files (or suite overrides) instead of editing scripts inline.
2. **Remote-first clients** – Every client/traffic command declares a `remote` stanza so automation handles SSH and artifact retrieval automatically.
3. **Ground-truth logs** – KV, LB, and NFV workloads emit JSON truth logs capped with `truth_limit` to enable accuracy analysis downstream.

## 2. KV Store (memcached + Python client)

### 2.1 Server (ms-host)

Automation defaults to the Python reference server, but production runs typically pin `memcached` to NUMA node 0:

```bash
sudo systemctl stop memcached
sudo numactl --cpunodebind=0 --membind=0 \
  memcached -l 211.0.0.101 -p 7000 -t 32 -m 16384 -o hashpower=increase
```

Reflect the choice in `experiments/configs/workloads/kv.yaml`:

```yaml
server:
  implementation: memcached
  binary: memcached
  bind_address: "211.0.0.101"
  numa_policy: "numactl --cpunodebind=0 --membind=0"
```

### 2.2 Clients (client-host)

The reference client `experiments/workloads/kv/kv_client.py` already exposes `--metrics-file` and `--annotations-file`. The workload config sets:

```yaml
clients:
  generator: "python3 experiments/workloads/kv/kv_client.py"
  remote:
    host: "211.0.0.102"
    workdir: "~/MicroSentinel"
    metrics_dir: "~/MicroSentinel/artifacts/remote"
```

Metrics land under `<artifact_dir>/metrics/kv_client_<idx>.json`; optional annotations (per-connection traces) are stored in `<artifact_dir>/truth/kv_client_<idx>.json` when enabled.

### 2.3 Truth Logging

If `server.truth_file` is set, the Python KV server writes flattened request logs (operation, key, timestamps) to `truth/kv_server.json`. Keep `truth_limit` reasonable (e.g., 50k operations) to avoid giant files.

## 3. Software Load Balancer

### 3.1 Load balancer + backends

`experiments/configs/workloads/lb.yaml` binds the load balancer to `211.0.0.101`. Automation runs either the Python reference binary (`experiments/workloads/lb/l4_lb.py`) or an external `haproxy` command depending on `lb_node.implementation`.

Backends can be real services or the included `backend_echo.py`. Each backend entry defines host/port pairs; automation spawns the built-in echo server when `backend_stub` is configured.

### 3.2 Clients & Truth

`lb_client.py` supports remote execution, per-flow annotations, and metric summaries. The config includes:

```yaml
clients:
  generator: "python3 experiments/workloads/lb/lb_client.py"
  remote:
    host: "211.0.0.102"
    workdir: "~/MicroSentinel"
```

Set `clients.ground_truth_log: truth/lb_ground_truth.json` to capture VIP routing decisions and per-flow outcomes.

### 3.3 Metrics

`lb_client.py` writes throughput + latency percentiles to `metrics/lb_client.json`. Additional histograms (if `--latency` is enabled) are stored alongside the summary so `ResultRecorder` can ingest them.

## 4. NFV Service Chain

### 4.1 Chain configuration

`experiments/configs/workloads/nfv.yaml` declares the canonical four-stage chain (firewall -> NAT -> rate limiter -> logger). Important fields:

```yaml
chain:
  host: "211.0.0.101"
  stages:
    - name: firewall
      binary: "python3 experiments/workloads/nfv/firewall.py"
      policy_file: "experiments/workloads/nfv/policies/firewall.yaml"
      truth_log: "truth/firewall_decisions.json"
```

Because `chain.host` is set, every stage binds to `211.0.0.101` rather than loopback. Per-stage overrides (`listen_host`, `next_host`) are available when mixing local + remote components.

### 4.2 Traffic generator

`experiments/workloads/nfv/traffic_gen.py` runs on the remote node and now emits both truth logs and aggregate metrics:

```yaml
traffic_generator:
  binary: "python3 experiments/workloads/nfv/traffic_gen.py"
  target_host: "211.0.0.101"
  rate_values: [1_000_000, 2_000_000, 4_000_000]
  packet_size_bytes: [64, 256, 1500]
  tenants: ["tenant-a", "tenant-b", "tenant-c"]
  remote:
    host: "211.0.0.102"
    workdir: "~/MicroSentinel"
    metrics_dir: "~/MicroSentinel/artifacts/remote"
```

Automation automatically passes `--metrics-file` and `--truth-log` so the generator writes JSON telemetry that can be fetched via `scp` after each run.

### 4.3 Namespace setup (optional)

If you deploy the chain inside namespaces/veth pairs, run `scripts/nfv_setup.sh` on `ms-host` before launching the workload. That script should create `ms_ingress`, `ms_chain`, `ms_egress`, wire `veth_ing`↔`chain_ing`, and assign IPs. Update `chain.host`/`traffic_generator.target_host` if you use namespace IPs instead of the bare-metal address.

## 5. Remote Execution Reference

All workloads use the same pattern:

```yaml
remote:
  host: "211.0.0.102"
  workdir: "~/MicroSentinel"
  metrics_dir: "~/MicroSentinel/artifacts/remote"
```

- `host` – SSH endpoint automation connects to.
- `workdir` – directory used for `cd` before invoking the generator. Use `~/...` or an absolute path.
- `metrics_dir` – optional base path scanned after completion; any files the generator drops here (plus explicit truth-log paths) are copied back to the run artifact directory.

Keep the repository in sync on the remote host via `rsync` (see `docs/TWO_NODE_DEPLOYMENT.md`).

## 6. Telemetry Matrix

| Workload | Metrics JSON | Truth logs | Notes |
| --- | --- | --- | --- |
| KV | `metrics/kv_client_<i>.json` | `truth/kv_server.json`, `truth/kv_client_<i>.json` (optional) | Client annotations capture per-connection operations when enabled. |
| LB | `metrics/lb_client.json` | `truth/lb_ground_truth.json` | Add `--latency` to the client for percentile dumps. |
| NFV | `metrics/nfv_traffic.json`, per-stage metrics TBD | `truth/traffic_emit.json`, `truth/firewall_decisions.json`, `truth/nat_translations.json`, `truth/rate_limiter_events.json`, `truth/logger_snapshots.json` | Traffic generator summary now reports packet count + rate trace. |

Whenever you replace a reference component with an external binary (e.g., DPDK firewall), update the workload config accordingly and ensure the replacement still writes metrics/truth artifacts under the same filenames so downstream tooling keeps working.
