# MicroSentinel Operations Guide

This guide targets SRE and performance teams that operate MicroSentinel in production or lab clusters. It covers environment preparation, build steps, agent configuration, runtime controls, metrics, and troubleshooting so you can manage the system end to end.

---

## 1. Environment & Prerequisites

### 1.1 Hardware and Kernel

| Requirement | Notes |
| --- | --- |
| CPU | Intel Skylake or newer with PEBS, LBR, OFFCORE_RESPONSE, XSNP_HITM enabled |
| OS | Linux x86_64, kernel ≥ 5.10 with BTF (`/sys/kernel/btf/vmlinux`) |
| Kernel features | fentry/fexit, perf_event, XDP, BPF perf ring buffer |
| Clock stability | Per-CPU TSC must be calibratable (agent ships its own calibrator) |

### 1.2 Toolchain

| Component | Minimum | Purpose |
| --- | --- | --- |
| Clang/LLVM | 13 | Build CO-RE eBPF objects |
| bpftool | Matches kernel | Generate `vmlinux.h`, inspect programs/maps |
| GCC/G++ | 11 (C++20) | Build the user-space agent |
| CMake | 3.21 | Configure/build |
| libbpf (headers + shared lib) | 1.0+ | Load/manage eBPF assets |
| ClickHouse | 22.x+ | Store raw/rollup samples |
| Prometheus | 2.x+ | Scrape metrics |

### 1.3 Repository Layout

```
MicroSentinel/
├── bpf/                # CO-RE programs + Makefile
├── agent/              # C++20 agent, config loader, control plane
├── backend/            # ClickHouse schema, Prometheus descriptors
├── docs/               # Guides (this file, runbook, design notes)
└── build/              # CMake outputs (generated)
```

---

## 2. Build Workflow

### 2.1 Generate `vmlinux.h` and CO-RE Object

Run on each target kernel (once per version):

```bash
cd bpf
make vmlinux          # uses bpftool to dump BTF
make                   # produces micro_sentinel_kern.bpf.o
```

Verify with `file micro_sentinel_kern.bpf.o` or `bpftool btf dump file micro_sentinel_kern.bpf.o`.

### 2.2 Build the Agent

```bash
cmake -S . -B build
cmake --build build
```

Optional tests:

```bash
cd build
ctest --output-on-failure
```

Artifacts: `build/agent/micro_sentinel_agent`, `build/agent/ms_agent_tests`.

---

## 3. Configuration and Launch

### 3.1 Config File Template

Supply `key=value` pairs via `--config=/path/to/conf` (full list in `agent/src/config_loader.cpp`). Example:

```bash
cat > agent.conf <<'EOF'
sentinel_budget=6000
diagnostic_budget=20000
clickhouse_endpoint=http://127.0.0.1:8123
clickhouse_table=ms_flow_rollup
clickhouse_raw_table=ms_raw_samples
clickhouse_flush_ms=500
metrics_address=0.0.0.0
metrics_port=9105
control_address=127.0.0.1
control_port=9200
anomaly_enabled=true
anomaly_interfaces=eth0,eth1
anomaly_interval_ms=500
mode=false
perf_mock_mode=false
EOF
```

### 3.2 CLI Overrides

CLI flags override config-file values. Common ones:

- `--mode=sentinel|diagnostic`
- `--perf-mock` / `--no-perf-mock`
- `--mock-period-ms=25`
- `--sentinel-budget=8000`, `--diagnostic-budget=20000`

### 3.3 Launch Modes

**Mock/Test Run**

```bash
./build/agent/micro_sentinel_agent \
  --config=./agent/agent.conf \
  --perf-mock --mock-period-ms=25
```

**Live Deployment**

1. Ensure `micro_sentinel_kern.bpf.o` matches the host kernel.
2. Attach `ms_ctx_inject` (RX/TX fentry) and optional `ms_ctx_inject_xdp` to target interfaces.
3. Start with privileges (root or CAP_BPF + CAP_PERFMON + CAP_SYS_ADMIN):

```bash
sudo ./build/agent/micro_sentinel_agent \
  --config=/etc/micro_sentinel/agent.conf \
  --no-perf-mock
```

Logs list the active mode, map FDs, perf-event groups, and control-plane address.

---

## 4. Mode and Sampling Control

### 4.1 Sentinel vs Diagnostic

| Mode | Purpose | Typical Budget |
| --- | --- | --- |
| Sentinel | Low-overhead guard rails for steady-state monitoring | ~5k samples/sec/CPU |
| Diagnostic | High-resolution sampling triggered by anomalies | 20k+ samples/sec/CPU |

`ModeController` evaluates `ms_samples_per_sec / budget` plus `AnomalyMonitor` (throughput/latency) signals to toggle automatically.

### 4.2 Control-Plane APIs

All endpoints are HTTP POST on `control_address:control_port` (default `127.0.0.1:9200`).

| Endpoint | Example |
| --- | --- |
| `/api/v1/mode` | `curl -X POST localhost:9200/api/v1/mode -d '{"mode":"diagnostic"}'` |
| `/api/v1/token-bucket` | `curl -X POST ... -d '{"sentinel_samples_per_sec":8000,"diagnostic_samples_per_sec":20000,"hard_drop_ns":4000}'` |
| `/api/v1/pmu-config` | `curl -X POST ... -d '{"sentinel":{"groups":[...]}}'` |
| `/api/v1/symbols/jit` | Register JIT regions for symbolization |
| `/api/v1/symbols/data` | Register data objects/heap regions |
| `/api/v1/targets` | Configure flow/pid/cgroup filters (`[{"type":"flow","value":"10.1."}]`) |

Successful calls return `200 ok`; invalid payloads return `400 invalid request`.

### 4.3 Token Bucket & Safety

- `sentinel_budget`, `diagnostic_budget`, `hard_drop_ns` program the BPF token-bucket maps.
- When actual sampling exceeds budget, the agent switches `SafetyLevel` to `ShedHeavy`, limits enabled PMU events, and exports `ms_sampling_throttled=1`.
- Reset via the API or by writing `ms_tb_ctrl_map` (scripts in `docs/RUNBOOK.md`).

---

## 5. Metrics and Backends

### 5.1 Prometheus

Metrics exposed on `metrics_address:metrics_port` (OpenMetrics text):

- `ms_agent_mode` (0 Sentinel, 1 Diagnostic)
- `ms_samples_per_sec`
- `ms_flow_micromiss_rate{flow,function,event,...}` and other event-specific gauges
- `ms_false_sharing_score{line,mapping,pid}`
- `ms_remote_dram_hotspot{flow,numa,ifindex}`
- `ms_tsc_slope{cpu}`, `ms_tsc_offset_ns{cpu}`

See `backend/prometheus_metrics.yaml` for field descriptions.

### 5.2 ClickHouse

`backend/clickhouse_schema.sql` defines:

- `ms_raw_samples` – per-sample events (with LBR, flow, direction, GSO)
- `ms_flow_rollup` – aggregated windows keyed by flow/function/call stack/event
- `ms_stack_traces` – symbolized stack metadata
- `ms_data_objects` – registered data regions

The agent flushes via HTTP `INSERT ... FORMAT JSONEachRow`. Tune TTL and partitions to match retention goals.

### 5.3 Dashboards

`backend/dashboards.md` sketches Grafana dashboards (flame, heat, topology) that combine ClickHouse data with Prometheus metrics.

---

## 6. Operational Checklist

1. **BPF layer** – `bpftool prog show` lists `ms_ctx_inject` and `ms_pmu_handler`; `bpftool map dump id <ms_events>` confirms samples.
2. **perf subsystem** – `perf stat -e cycles -C <cpu>` succeeds; mount tracefs for fentry debugging.
3. **Agent health** – `curl localhost:9105/metrics`, trigger a mode change, inspect `journalctl -u micro_sentinel`.
4. **Backends** – ClickHouse query `SELECT count() FROM ms_raw_samples WHERE ts > now()-60`; watch `ms_samples_per_sec`, `ms_agent_mode`, `ms_pmu_scale` in Prometheus.

---

## 7. Troubleshooting

| Symptom | Likely Cause | Mitigation |
| --- | --- | --- |
| "Failed to open BPF object" | Missing BTF or incompatible libbpf | Regenerate `vmlinux.h`, upgrade libbpf/bpftool |
| Low `ms_samples_per_sec` despite high budget | Token bucket depleted or safety throttled | Increase budgets, inspect `ms_sampling_throttled` |
| Prometheus scrape errors | Wrong metrics address/port or firewall | `ss -ltnp | grep 9105`, adjust config/firewall |
| ClickHouse flush failures | Endpoint unreachable or bad credentials | Search logs for "Failed to flush ClickHouse", test with `curl` |
| Samples lack `flow_id` | Context injector missing or skid window too small | Attach `ms_ctx_inject` on RX/TX paths, tune `MS_FLOW_SKID_NS` and `SkewAdjuster` window |

Full cleanup:

```bash
sudo pkill micro_sentinel_agent
sudo bpftool prog detach name ms_ctx_inject
<!-- sudo bpftool prog detach name ms_ctx_inject_tx -->
sudo rm -f /sys/fs/bpf/*ms*
```

---

## 8. Quick Commands

| Task | Command |
| --- | --- |
| Check current mode | `curl -s localhost:9105/metrics | grep ms_agent_mode` |
| Force Diagnostic | `curl -X POST localhost:9200/api/v1/mode -d '{"mode":"diagnostic"}'` |
| Limit to flow prefix `10.1.` | `curl -X POST localhost:9200/api/v1/targets -d '{"targets":[{"type":"flow","value":"10.1."}]}'` |
| Inspect remote NUMA hotspots | Query `ms_remote_dram_hotspot` in Prometheus |
| Stress ClickHouse via mock mode | `./micro_sentinel_agent --perf-mock --mock-period-ms=5 --clickhouse-endpoint=http://127.0.0.1:8123` |

Pair this document with `docs/RUNBOOK.md` for day-to-day procedures and with `docs/TWO_NODE_DEPLOYMENT.md` when using the two-node experiment platform.
