# MicroSentinel Implementation Plan

## Repository Layout

```
MicroSentinel/
├── bpf/                     # eBPF CO-RE object sources and shared headers
├── agent/                   # User-space agent (C++20, CMake build)
│   ├── include/
│   ├── src/
│   └── tests/
├── backend/                 # ClickHouse schema, Prometheus metrics descriptors
├── docs/                    # Design notes, runbooks, API description
└── README.md                # Top-level guide with quick start
```

## Deliverables per Layer

1. **Kernel Instrumentation (bpf/)**
   - Shared header `ms_common.h` with enums/structs/maps described in the spec.
   - Single CO-RE source `micro_sentinel_kern.bpf.c` compiling three programs:
     - `ms_ctx_inject` (fentry hook for `netif_receive_skb`)
     - `ms_pmu_handler` (perf-event program fed by user space)
     - `ms_tb_ctrl` helpers for token-bucket configuration updates.
   - Lightweight Makefile that compiles with `clang -target bpf` and produces `micro_sentinel_kern.o` plus `vmlinux.h` generation instructions.

2. **User-space Agent (agent/)**
   - Modern C++20 codebase built via CMake.
   - Modules:
     - `PerfConsumer`: wraps perf-event setup & ring buffer consumption with epoll fallback and exposes callback interface.
     - `Symbolizer`: DWARF/ELF aware interface with stubbed resolvers plus hooks for JIT/eBPF map updates.
     - `Aggregator`: flow/function/event keyed accumulator supporting per-packet normalization and cache-line views for false-sharing detection.
     - `FalseSharingDetector`, `ModeController`, `MetricsExporter` (Prometheus text exposition) and `ClickHouseSink` (batch writer stub).
     - `AgentRuntime` orchestrating threads, NUMA pinning, and sentinel/diagnostic state machine.
   - `tests/` folder with lightweight unit tests (using `Catch2` single-header vendored copy) covering aggregation math & token-bucket logic. Tests run via `ctest`.

3. **Backend Artifacts (backend/)**
   - `clickhouse_schema.sql`: canonical DDL for raw samples & rollups.
   - `prometheus_metrics.yaml`: YAML-like descriptions of exported metrics & labels.
   - `dashboards.md`: textual notes on flame/heat/topology visualization expectations.

4. **Documentation (docs/, README)**
   - `README.md` summarizing goals, build prerequisites, quick-start commands, and operational modes.
   - `docs/RUNBOOK.md` (if time) describing sentinel↔diagnostic transitions, control-plane APIs, and troubleshooting steps.

## Build & Test Strategy

- **BPF**: Provide Makefile targets `make vmlinux`, `make bpf` to generate CO-RE object; users can customize kernel headers via `BPF_CLANG` env. No automatic invocation inside CI to keep toolchain expectations explicit.
- **Agent**: CMake presets for release/debug. Dependencies limited to `pthread`, `libbpf` (optional at link via pkg-config), and `fmt` header-only shim (provided locally). Build command: `cmake -S agent -B build && cmake --build build`.
- **Tests**: `ctest --output-on-failure` executed after build; tests rely on deterministic synthetic samples.
- **Runtime**: `agent` binary accepts `--mode=sentinel|diagnostic`, `--pmu-config` path, and `--clickhouse-endpoint`. Exposes Prometheus metrics on configurable port using built-in HTTP server.

## Risk & Scope Guardrails

- eBPF programs lean on helpers only available on kernels ≥5.10; README will highlight requirement and provide fallback instructions.
- Symbolization and ClickHouse export layers are pluggable; current implementation prioritizes data plumbing and observability scaffolding over fully resolved DWARF parsing.
- Threading model keeps per-NUMA consumer count user-configurable, defaulting to one consumer per node.
- Sentinel↔diagnostic transition implemented with hysteresis thresholds to avoid flapping; metrics exported to observe agent overhead.

This plan keeps the initial drop focused on runnable scaffolding with clear extension seams for production hardening.
