# MicroSentinel 系统实现说明书

本文档详述 MicroSentinel 在源代码层面的实现方式，面向需要维护、扩展或审计该系统的工程师。内容按分层架构展开，覆盖关键模块、数据结构、控制路径和可扩展点，并附带源码位置以便交叉参考。

---

## 1. 总览

### 1.1 运行时拓扑

MicroSentinel 采用 Agent/Backend 架构：

1. **采集层（`bpf/`）**：多个 CO-RE eBPF 程序协同完成网络上下文注入、PMU 采样和安全控制。
2. **用户态 Agent（`agent/`）**：以 C++20 实现，包含 perf ring buffer 消费、符号化、噪声抑制、聚合、异常检测、导出以及控制面。
3. **后端（`backend/`）**：ClickHouse 与 Prometheus 的 DDL 与指标定义文件，Agent 通过 HTTP 直接写入/暴露。

数据流：网络栈 → eBPF Context Injector → per-CPU 历史窗口 → PMU perf_event → perf ring buffer → `PerfConsumer` → TSC/时序纠偏 → 目标过滤 → 聚合/检测 → ClickHouse + Prometheus。

### 1.2 核心语言与依赖

- eBPF 程序使用 Clang/LLVM 编译为 CO-RE 对象，依赖 `libbpf` 装载。
- 用户态使用 CMake + C++20（GCC/Clang），最小依赖为 `pthread`, `libbpf`, `libfmt`（内置）等。

---

## 2. eBPF 采集层实现

文件：`bpf/micro_sentinel_kern.bpf.c`, `bpf/ms_common.h`

### 2.1 Map 布局

`ms_common.h` 定义了所有结构体：

- `ms_flow_ctx`：per-CPU 当前包上下文。
- `ms_hist` + `ms_hist_head`：per-CPU 环形缓冲存储最近 `MS_HISTORY_LEN` 个 `<tsc, flow_id>`。
- `ms_tb` + `ms_tb_cfg_map` + `ms_tb_ctrl_map`：令牌桶状态与配置。
- `ms_event_cookie` / `ms_active_event`：perf attach cookie，用于映射硬件事件到逻辑枚举。
- `ms_events`：`BPF_MAP_TYPE_PERF_EVENT_ARRAY`，向用户态发送 `ms_sample`。

### 2.2 Context Injector

`ms_ctx_inject`（fentry/netif_receive_skb）与 `ms_ctx_inject_tx`（fentry/dev_queue_xmit）分别处理 RX/TX，`ms_ctx_inject_xdp` 则用于 XDP。关键函数：

- `calc_flow_hash` / `calc_flow_hash_xdp`：解析 VLAN、IPv4/v6、隧道头，生成 FNV64 哈希。
- `capture_flow_ctx`：记录 `tsc/gso/ifindex/proto/direction` 并写入历史缓冲。

### 2.3 PMU Perf Handler

`ms_pmu_handler`（`SEC("perf_event")`）：

1. 通过 `allow_sample()` 检查令牌桶与硬降级窗口。
2. 读取 `ctx->ip/addr/time`，合并 per-CPU `ms_flow_ctx` 与 `find_flow_in_history` 结果，补偿采样滑移。
3. 调用 `bpf_get_branch_snapshot` 采集 LBR，填充 `ms_sample.lbr`。
4. 将 `ms_sample` 推送到 `ms_events`。

### 2.4 令牌桶

`allow_sample` 内使用 `ms_tb_cfg_map` 提供的 `max_samples_per_sec/hard_drop_threshold` 对采样节流；`ms_update_tb` kprobe 支持用户态远程复位（`docs/RUNBOOK.md` 中提供调用方式）。

---

## 3. 用户态 Agent 实现

入口：`agent/src/main.cpp` → `AgentRuntime`（`agent/src/runtime.cpp`）。

### 3.1 进程结构

- `AgentRuntime` 负责装载 BPF（`BpfOrchestrator`）、启动 perf 消费线程（`PerfConsumer`）、配置控制面（`ControlPlane`）、按周期 flush（聚合、ClickHouse、Metrics、检测器）以及模式切换。
- 配置解析由 `config_loader.cpp` 完成，支持文件/CLI。

### 3.2 BPF 管理（`BpfOrchestrator`）

- `LoadBpfObject` 使用 libbpf 载入 `micro_sentinel_kern.bpf.o`，获取关键 map/prog 句柄。
- `AttachNetPrograms` 绑定 fentry/XDP；`AttachPerfGroupsLocked` 为每个 CPU 打开 `perf_event_open` 并 attach 到 `ms_pmu_handler`，支持 cookie 标注。
- `SwitchMode`/`RotateToGroup` 与 `PmuRotator` 协作实现事件轮转与 scale 因子调整。
- `ConfigureTokenBucket` 通过 `ms_tb_cfg_map`/`ms_tb_ctrl_map` 同步预算。

### 3.3 PerfConsumer（`agent/src/perf_consumer.cpp`）

- 根据 `PerfConsumerConfig` 为每个 CPU 打开 `PERF_COUNT_SW_BPF_OUTPUT`，`mmap` ring buffer。
- 利用 epoll + per-NUMA worker 消费 `PERF_RECORD_SAMPLE` 并反序列化为 `ms_sample`/`LbrStack`。
- 提供 mock 模式生成合成样本用于端到端测试。

### 3.4 噪声抑制模块

| 模块 | 文件 | 功能 |
| --- | --- | --- |
| `TscCalibrator` | `agent/src/tsc_calibrator.cpp` | 维护 per-CPU 线性模型，将原始 TSC 归一化。 |
| `SkewAdjuster` | `agent/src/skew_adjuster.cpp` | 在小窗口内重新关联缺失 `flow_id` 的样本。 |
| `MonitoringTargetManager` | `agent/src/monitoring_targets.cpp` | 在热路径过滤 PID/flow/cgroup。 |
| `RemoteDramAnalyzer` | `agent/src/remote_dram_analyzer.cpp` | 对 `MS_EVT_REMOTE_DRAM` 按 (flow, NUMA, ifindex) 聚合。 |
| `FalseSharingDetector` | `agent/src/fs_detector.cpp` | 监控 `MS_EVT_XSNP_HITM`，基于 cache line 判断伪共享。 |

### 3.5 聚合与导出

- `Aggregator`（`agent/src/aggregator.cpp`）将 `(flow,function,callstack,event,numa,direction,bucket)` 作为 key，用 `SampleScale` + `gso_segs` 进行归一。
- `ClickHouseSink` 将 rollup/raw/stack/data 四类批次通过 JSONEachRow 插入 `backend/clickhouse_schema.sql` 中定义的表。
- `MetricsExporter` 在 `metrics_address:metrics_port` 暴露所有指标串。

### 3.6 控制面与自动调度

- `ControlPlane` (HTTP server) 提供 `/api/v1/mode`, `/token-bucket`, `/pmu-config`, `/symbols/jit`, `/symbols/data`, `/targets` 等接口。
- `ModeController` 结合 `ms_samples_per_sec` 与 `AnomalyMonitor` 信号决定哨兵/诊断模式；`AnomalyMonitor` 周期性读取 `/proc/net/dev` 与可选延迟探测文件，触发 `AnomalySignal`。
- `PmuRotator` 基于当前模式的事件组轮转，并通过回调更新 `Aggregator::SampleScale` 以保持不同组间可比性。

### 3.7 线程与同步

- 主线程：初始化 + 阻塞 keepalive。
- `PerfConsumer` workers：按 CPU/NUMA 读取 perf ring buffer。
- `AgentRuntime::flush_thread_`：周期调用 `RunSingleFlushCycle`。
- 可选：`AnomalyMonitor`、`MetricsExporter`、`ControlPlane`、`ClickHouseSink` 各自内部线程。
- 关键数据结构（Agg table、ClickHouse batch、symbolizer caches）使用互斥锁；热路径 `target_manager_->Allow` 采用 `std::unordered_set` + `std::vector` 快速检查。

---

## 4. 后端接口实现

### 4.1 ClickHouse

`backend/clickhouse_schema.sql` 定义 4 张核心表。`ClickHouseSink` 通过 socket 直接向 `clickhouse_endpoint` POST。

关键字段：

- `ms_raw_samples`: `ts`, `host`, `cpu`, `pid`, `flow_id`, `pmu_event`, `ip`, `data_addr`, `lbr`, `norm_cost`。
- `ms_flow_rollup`: `window_start`, `flow_id`, `function_id`, `callstack_id`, `pmu_event`, `numa_node`, `direction`, `interference_class`, `data_object_id`, `samples`, `norm_cost`。

### 4.2 Prometheus

`backend/prometheus_metrics.yaml` 描述所有导出的 gauge，包括：

- 模式/采样相关：`ms_agent_mode`, `ms_samples_per_sec`, `ms_pmu_scale`。
- 事件归因：`ms_flow_micromiss_rate`, `ms_branch_mispred_rate`, …, `ms_flow_event_norm`。
- 诊断检测：`ms_false_sharing_score`, `ms_remote_dram_hotspot`, `ms_throughput_ratio`, `ms_latency_ratio` 等。

`MetricsExporter` 将指标名拼接 labels 后直接输出 OpenMetrics 兼容文本。

---

## 5. 算法与关键逻辑

### 5.1 时间与流关联

- **内核端**：`ms_hist_push` + `find_flow_in_history` 允许 `±MS_FLOW_SKID_NS` 时间窗口匹配。
- **用户态**：`SkewAdjuster` 在 per-CPU deque 内查找最近已知 flow 的邻居并回填。

### 5.2 令牌桶 + 安全控制

- 每 CPU `ms_token_bucket` 记录 `tokens`, `last_tsc`, `cfg_seq`, `last_emit_tsc`；
- `allow_sample` 在 `elapsed` 大于 0 时补充 token，token 上限 `MS_TOKEN_HEADROOM`；
- `hard_drop_ns` 约束连续采样最小间隔；
- 用户态 `MaybeAdjustSafety` 根据实际样本速率与预算比，动态限制 `max_events_per_group`。

### 5.3 伪共享检测

- 以 cache line 地址 (`data_addr & ~(64-1)`) 为 key；
- 记录 `total_hits`, per-CPU 命中向量、per-PID 计数；
- 超过阈值且活跃 CPU ≥ 2 且最大占比 < 0.9 时触发 `ReportFalseSharing`。

### 5.4 Remote DRAM 分析

- 针对 `MS_EVT_REMOTE_DRAM` 样本维持 `(flow_id, numa_node, ifindex)` → `count/last_tsc`；
- `Flush` 时输出窗口外的条目为 `RemoteDramFinding`。

### 5.5 PMU 轮转与归一

- `PmuRotator` 在固定窗口切换事件组，并以组数量作为 scale（或自定义比例），传递给 `Aggregator::SetSampleScale` 与 `MetricsExporter` (`ms_pmu_scale`)；确保不同事件组合下的数值可比。

---

## 6. 扩展与定制

### 6.1 新增 PMU 事件

1. 在 `ms_common.h` 中扩展 `enum ms_pmu_event_type`。
2. 更新 `interference.cpp` 的分类映射。
3. 在配置 (文件/CLI/API) 中为 sentinel/diagnostic 事件组添加新条目。
4. 若需特殊数据处理，在 `Aggregator::EventClass` 或新检测模块中加入逻辑。

### 6.2 自定义监控目标

- 通过 `/api/v1/targets` 设置 flow/pid/cgroup；
- 若需精细匹配，可扩展 `MonitoringTargetManager::Allow`，例如添加 ingress VLAN 或 L4 端口过滤。

### 6.3 额外分析模块

- 参照 `FalseSharingDetector`，实现 `Observe` + `Flush` 接口，在 `AgentRuntime::RunSingleFlushCycle` 中注册。
- 通过 `MetricsExporter` 或 `ClickHouseSink` 输出结果。

### 6.4 进程/堆对象符号化

- `Symbolizer` 支持 `RegisterJitRegion` / `RegisterDataObject` 控制面请求；
- 若需要自动化 uprobes，可在 Agent 内增加监听（尚未实现，README Next Steps 中列出）。

---

## 7. 构建与测试

- 完整构建：`cmake -S . -B build && cmake --build build`。
- eBPF 对象：`make -C bpf`（需先 `make vmlinux`）。
- 单元测试：`cd build && ctest --output-on-failure`，当前覆盖 `tests/test_*`（聚合、监控目标、Token bucket 等）。
- Mock 验证：`./build/agent/micro_sentinel_agent --perf-mock --mock-period-ms=25`，观察 ClickHouse/Prometheus 输出。

---

## 8. 参考与附录

| 模块 | 主要文件 |
| --- | --- |
| eBPF 程序 | `bpf/micro_sentinel_kern.bpf.c`, `bpf/ms_common.h` |
| Agent 核心 | `agent/src/runtime.cpp`, `agent/include/micro_sentinel/*.h` |
| Perf/BPF 管理 | `agent/src/perf_consumer.cpp`, `agent/src/bpf_orchestrator.cpp` |
| 导出 | `agent/src/clickhouse_sink.cpp`, `agent/src/metrics_exporter.cpp` |
| 控制面 | `agent/src/control_plane.cpp` |
| 后端定义 | `backend/clickhouse_schema.sql`, `backend/prometheus_metrics.yaml` |
| 运维文档 | `docs/OPERATIONS_GUIDE.md`, `docs/RUNBOOK.md` |

如需进一步细节，可结合上述文件与 `docs/IMPLEMENTATION_PLAN.md` 获取计划背景。
