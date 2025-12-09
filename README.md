# MicroSentinel

MicroSentinel is a cross-layer observability agent that correlates network flows, code locations, and microarchitectural signals without modifying the data plane. The project contains:

- **bpf/** — eBPF CO-RE programs for context injection, PMU sampling, and safety control.
- **agent/** — C++20 user-space daemon that consumes perf samples, aggregates metrics, detects anomalies, and exports data.
- **backend/** — ClickHouse schemas, Prometheus metric definitions, and dashboard notes.
- **docs/** — Implementation plan and operational runbooks (in progress).

## Prerequisites

- Linux x86_64 with BTF-enabled kernel (≥ 5.10 recommended).
- Clang/LLVM for eBPF compilation plus `bpftool` to emit `vmlinux.h`.
- CMake ≥ 3.21 and a C++20 compiler (GCC 11+/Clang 13+).

## Building

```bash
cmake -S . -B build
cmake --build build
```

### Running Tests

```bash
cd build
ctest --output-on-failure
```

## Compiling eBPF Objects

```bash
cd bpf
make vmlinux   # one-time BTF header generation
make            # produces micro_sentinel_kern.o
```

## Running the Agent

The agent ships with a mock perf consumer that synthesizes samples for end-to-end testing:

```bash
./build/micro_sentinel_agent --mock-period-ms=50
```

This starts the following components:

1. **PerfConsumer** (mock mode) generating samples.
2. **Aggregator** performing flow/function/event bucketing with GSO normalization.
3. **FalseSharingDetector** correlating XSNP_HITM events by cache line.
4. **ModeController** applying hysteresis thresholds between sentinel and diagnostic modes.
5. **MetricsExporter** serving Prometheus metrics on `0.0.0.0:9105`.
6. **ClickHouseSink** batching aggregated tuples (currently prints to stdout, ready for HTTP ingestion).
7. **MonitoringTargetManager** enforcing control-plane target selectors (flow prefix, PID, or cgroup).
8. **RemoteDramAnalyzer** turning OFFCORE_RESPONSE samples into per-flow NUMA hotspot signals.
9. **AnomalyMonitor** (optional) sampling `/proc/net/dev` throughput and optional latency probes to trigger diagnostic mode when QoS degrades.
10. **TscCalibrator** normalizing per-CPU timestamps so rollups and exports align on a shared timebase.

### Anomaly-driven Mode Switching

Set the following config keys (or CLI overrides) to enable hardware-mode transitions based on live QoS signals:

| Key | Description |
| --- | --- |
| `anomaly_enabled` | Toggle the monitor (default: `true`). |
| `anomaly_interfaces` | Comma-separated list of network interfaces to watch; empty = sum all. |
| `anomaly_interval_ms` | Polling cadence for `/proc/net/dev` counters. |
| `anomaly_throughput_ratio` | Trigger diagnostic mode when instantaneous throughput / EWMA baseline drops below this ratio (default `0.85`). |
| `anomaly_latency_path` | Optional path to a file containing the latest p99 latency (microseconds). |
| `anomaly_latency_ratio` | Trigger diagnostic mode when latency / EWMA baseline exceeds this ratio. |
| `anomaly_refractory_ms` | Minimum interval between anomaly-triggered transitions; also used as the quiet period before returning to sentinel mode. |

When enabled, the monitor exports gauges `ms_throughput_ratio`, `ms_throughput_bps`, `ms_latency_ratio`, and `ms_latency_us`, and informs the `ModeController`, which now respects both sampling load ratios and recent anomaly events before toggling back to sentinel mode.

### TSC Calibration

User-space aggregation now applies a per-CPU affine model so that timestamps from different cores align before bucketing or exporting to ClickHouse. Tweak the model via config keys:

| Key | Description |
| --- | --- |
| `tsc_calibration_enabled` | Turn calibration on/off (default `true`). |
| `tsc_slope_alpha` | EWMA factor for slope updates (`0.001`-`0.5`, default `0.05`). |
| `tsc_offset_alpha` | EWMA factor for offset updates (default `0.05`). |

Metrics `ms_tsc_slope{cpu}` and `ms_tsc_offset_ns{cpu}` expose the current model parameters for observability.

When real hardware integration is required, disable `mock_mode` via the configuration file or CLI (future work) and provide perf-event handles that feed the `ms_events` perf ring buffer populated by the eBPF program.

## Control Plane API

The agent exposes a lightweight HTTP control surface (default `127.0.0.1:9200`):

- `POST /api/v1/mode` with body `{"mode":"sentinel"|"diagnostic"}` toggles the sampling mode.
- `POST /api/v1/token-bucket` with body like `{"sentinel_samples_per_sec":8000,"diagnostic_samples_per_sec":20000,"hard_drop_ns":4000}` updates the per-mode token-bucket budgets and optional hard-drop window, then reprograms the eBPF maps.
- `POST /api/v1/targets` accepts a request such as `{"targets":[{"type":"flow","value":"10.1."},{"type":"pid","value":"1234"}]}` and applies the union of provided selectors to future samples. Supported selectors today: `flow` (prefix match), `pid`, and `cgroup_path`.

Use `control_address` / `control_port` in the config (or `--control-port=PORT`) to customize the listener.

Target filters apply on the hot path inside `AgentRuntime`, so ClickHouse and Prometheus exports only see whitelisted flows/threads. The configuration remains in-memory; re-issuing the API call overwrites the previous definition.

### Remote DRAM Hotspots

`RemoteDramAnalyzer` maintains a sliding window of OFFCORE_RESPONSE samples grouped by `(flow_id, numa_node, ingress_ifindex)` and emits the metric `ms_remote_dram_hotspot{flow,numa,ifindex}`. Each flush reflects the count of samples since the last observation, making it easy to alert when specific flows hammer remote sockets.

## Backend Artifacts

- `backend/clickhouse_schema.sql` — canonical tables for raw samples and rollups.
- `backend/prometheus_metrics.yaml` — metrics exposed by the agent along with labels.
- `backend/dashboards.md` — visualization guidelines for flame graphs, heat maps, and topology views.

## ClickHouse Configuration

Override ClickHouse settings via the config file or CLI aliases (e.g. `--clickhouse-raw-table=dev_raw`):

| Key | Default | Purpose |
| --- | --- | --- |
| `clickhouse_endpoint` | `http://localhost:8123` | HTTP endpoint for the native API. |
| `clickhouse_table` | `ms_flow_rollup` | Aggregated flow/function bucket table. |
| `clickhouse_stack_table` | `ms_stack_traces` | Storage for unique stack traces referenced by rollups. |
| `clickhouse_raw_table` | `ms_raw_samples` | Per-sample landing table populated by the runtime. |
| `clickhouse_flush_ms` | `500` | Flush cadence for all ClickHouse batches in milliseconds. |
| `clickhouse_batch_size` | `4096` | Maximum rows sent per HTTP batch for any table. |

