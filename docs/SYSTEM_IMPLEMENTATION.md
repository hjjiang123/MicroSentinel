# MicroSentinel 系统实现说明书

本文档面向需要维护、扩展或审计 MicroSentinel 的工程师，汇总源代码层面的实现细节。内容按层次描述采集端、用户态 Agent、后端导出、核心算法以及构建/测试路径，并附源码文件以便交叉参考。

---

## 1. 总览

### 1.1 运行时拓扑

MicroSentinel 由三层组成：

1. **采集层（`bpf/`）**：CO-RE eBPF 程序负责注入网络上下文、执行 PMU perf_event handler，并通过 per-CPU map 实现滑动窗口、令牌桶与事件绑定。
2. **用户态 Agent（`agent/`）**：`AgentRuntime` 驱动 BPF 对象、消费 perf ring buffer、执行符号化/聚合/检测、暴露控制面与指标、并将数据推送到后端。
3. **后端（`backend/`）**：ClickHouse 与 Prometheus schema/指标定义，Agent 通过 HTTP POST 与 OpenMetrics 文本协议直接落地。

典型数据路径：`netif_receive_skb/dev_queue_xmit → ms_ctx_inject* → ms_hist → perf_event(ms_pmu_handler) → perf ring buffer → PerfConsumer → TSC/Skew 校正 → Target Filter → Aggregator/Detectors → ClickHouseSink + MetricsExporter`。

### 1.2 语言与依赖

- eBPF：Clang/LLVM 生成 CO-RE 对象，依赖 `libbpf` 装载以及内核 5.10+ 提供的 helper。
- Agent：C++20 + CMake，链接 `pthread`, `libbpf`, `libfmt`（vendored），其余依赖由标准库提供。
- 后端：HTTP/JSON（ClickHouse）与 OpenMetrics 文本（Prometheus）。

### 1.3 构建入口

- 根目录 `CMakeLists.txt` 统一生成 Agent、测试二进制。
- `bpf/Makefile` 提供 `make vmlinux` 与 `make`（生成 `micro_sentinel_kern.bpf.o`）。
- 构建产物位于 `build/agent/`（`micro_sentinel_agent`, `ms_agent_tests`）。

---

## 2. eBPF 采集层实现

关键文件：`bpf/micro_sentinel_kern.bpf.c`, `bpf/ms_common.h`。

### 2.1 Map 布局

| Map | 类型 | 作用 |
| --- | --- | --- |
| `ms_curr_ctx` | `BPF_MAP_TYPE_PERCPU_ARRAY` | 缓存当前包的 `ms_flow_ctx`（gso、ifindex、方向）。 |
| `ms_hist` / `ms_hist_head` | `PERCPU_ARRAY` | 每 CPU 的历史窗口（长度 `MS_HISTORY_LEN`），用于 `find_flow_in_history`。 |
| `ms_events` | `BPF_MAP_TYPE_PERF_EVENT_ARRAY` | 将 `ms_sample` 推送到用户态。 |
| `ms_tb`, `ms_tb_cfg_map`, `ms_tb_ctrl_map` | `PERCPU_ARRAY/ARRAY` | 令牌桶状态、配置与控制绕过。 |
| `ms_event_cookie` | `BPF_MAP_TYPE_HASH` | 将 `perf_event_open` 绑定 cookie 映射到逻辑 `ms_pmu_event_type`。 |
| `ms_active_event` | `BPF_MAP_TYPE_ARRAY` | 跟踪当前硬件事件槽（支持动态切换）。 |

`ms_common.h` 还定义了 `ms_sample`（包含 `tsc/ip/pid/tid/flow_id/pmu_event/lbr` 等字段）、`ms_hist_slot`、`ms_token_bucket` 等结构体，供内核与用户态共享。

### 2.2 上下文注入程序

- `SEC("fentry/netif_receive_skb") int ms_ctx_inject(struct sk_buff *skb)`（RX）
<!-- - `SEC("fentry/dev_queue_xmit") int ms_ctx_inject_tx(struct sk_buff *skb)`（TX） -->
- `SEC("xdp") int ms_ctx_inject_xdp(struct xdp_md *ctx)`（XDP fast path）

核心逻辑：

1. 通过 `calc_flow_hash*` 解析 VLAN/IPv4/IPv6/隧道头，生成 FNV64 flow_id；L4 端口解析在 `parse_ipv4_tuple`/`parse_ipv6_tuple` 中完成。
2. 从 `skb->gso_segs`, `ifindex`, `direction` 等字段填充 `ms_flow_ctx` 并写入 `ms_curr_ctx`。
3. 将 `<tsc, flow_id, direction>` 压入 `ms_hist`，供之后的 PMU 样本在 `±MS_FLOW_SKID_NS` 滑移窗口内关联。

### 2.3 PMU perf_event 处理程序

`SEC("perf_event") int ms_pmu_handler(struct bpf_perf_event_data *ctx)`：

1. `allow_sample(bpf_ktime_get_ns())` 依据 `ms_tb`/`ms_tb_cfg_map` 限速，并处理硬降级窗口 (`hard_drop_threshold`)。
2. 读取 `ctx->regs->ip/addr`、`load_perf_sample_time` 获取纳秒级时间戳。
3. 查找 `ms_curr_ctx` 与 `find_flow_in_history` 结果，若 TSC 偏移超出窗口则使用 `fallback_flow_id()`。
4. 可选 `bpf_get_branch_snapshot` 采集 LBR（硬件支持时），存入 `ms_sample.lbr`。
5. 通过 `bpf_perf_event_output` 将样本写入 `ms_events`，由用户态消费。

### 2.4 令牌桶与控制

- `allow_sample` 使用 `ms_token_bucket` 记录 `tokens/last_tsc/last_emit_tsc/cfg_seq`，并根据 `get_tb_limit()`（由 `ms_tb_cfg_map` 下发的 `max_samples_per_sec`）补充令牌。
- `ms_tb_ctrl_map` 存储来自用户态的 `cfg_seq`，允许即时清空 token 或改变 `hard_drop_threshold`。
- `ms_update_tb` kprobe（在 `micro_sentinel_kern.bpf.c` 内）允许用户态通过写 `ms_tb_ctrl_map` 触发重新配置。

---

## 3. 用户态 Agent

入口：`agent/src/main.cpp` 创建 `AgentRuntime`（`agent/src/runtime.cpp`）。

### 3.1 线程与对象图

- **主线程**：初始化配置、装载 BPF、启动后台线程并阻塞到 `Stop()`。
- **PerfConsumer workers**：`agent/src/perf_consumer.cpp` 每 CPU 建立 `perf_event_open`，`mmap` ring buffer，借助 epoll 轮询；mock 模式下生成合成样本。
- **flush 线程**：`AgentRuntime::FlushLoop` 周期调用 `RunSingleFlushCycle` 完成聚合/导出/检测。
- **ClickHouseSink**、**MetricsExporter**、**ControlPlane**、**AnomalyMonitor** 各自拥有独立线程，`Stop()` 时按顺序 join。

### 3.2 BpfOrchestrator（`agent/src/bpf_orchestrator.cpp`）

- `Init()`：加载 `micro_sentinel_kern.bpf.o`，解析 map/prog FD，配置 `perf_event_open`。
- `AttachNetPrograms()`：根据配置启用 fentry（RX/TX）与 XDP 程序。
- `AttachPerfGroupsLocked()`：为 sentinel/diagnostic 两组 PMU 事件创建 `perf_event_open`，并写入 `ms_event_cookie`。
- `SyncBudgetConfig()` / `UpdateSampleBudget()`：把 `sentinel/diagnostic/hard_drop_ns` 写入 `ms_tb_cfg_map`/`ms_tb_ctrl_map`。
- `SwitchMode()`：按当前 `AgentMode` 选择事件组，并配合 `PmuRotator` 在窗口内轮换。

### 3.3 样本消费与预处理

1. `PerfConsumer` 将 `ms_sample` 反序列化为 `Sample` + `LbrStack` 并回调给 `AgentRuntime::HandleSample`。
2. `TscCalibrator`（可选）用线性模型对 per-CPU TSC 归一化，提供 `ms_tsc_slope/ms_tsc_offset_ns` 指标。
3. `SkewAdjuster`（`agent/src/skew_adjuster.cpp`）维护 per-CPU 双端队列，在 `MS_FLOW_SKID_NS` 窗口内弥补流关联缺失。
4. `MonitoringTargetManager` 根据 `/api/v1/targets` 下发的 flow/pid/cgroup filter 做热路径过滤。
5. `RemoteDramAnalyzer`、`FalseSharingDetector` 在 `Observe` 阶段累积噪声抑制指标。

### 3.4 聚合、符号化与导出

- `Aggregator` 使用 `(flow_id,function_hash,callstack_id,data_object_id,pmu_event,numa_node,direction,interference_class,bucket)` 作为 key，value 包含 `samples` 与 `norm_cost`。`Bucketize(tsc)` 依据 `AggregatorConfig::time_window_ns` 生成时间桶。
- `Symbolizer`（`agent/src/symbolizer.cpp`）负责 `InternFunction/InternStack/InternDataObject`，并通过 `ConsumeStacks()/ConsumeDataObjects()` 将解析结果交给 `ClickHouseSink`。
- `ClickHouseSink`（`agent/src/clickhouse_sink.cpp`）维护四个批次：`rollup`（ms_flow_rollup）、`raw`（ms_raw_samples）、`stack`（ms_callstacks）、`data`（ms_data_objects）。批次通过 `SendPayload` 直接 POST `JSONEachRow` 至 `ClickHouseConfig::endpoint`。
- 同时，原始样本（含 LBR）按需写入 raw 表，并将 `norm_cost` 一并上传，方便后端重放。

### 3.5 模式控制、令牌桶与安全

- `ModeController`（`agent/src/mode_controller.cpp`）依据 `ms_samples_per_sec` 与 `AnomalyMonitor` 信号保持 hysteresis，并驱动 sentinel ↔ diagnostic 切换。
- `BucketUpdateRequest` 通过 `/api/v1/token-bucket` 更新 sentinel/diagnostic 预算与 `hard_drop_ns`，结果写回 `cfg_.perf` 并同步至 BPF。
- `MaybeAdjustSafety` 根据 `samples_per_sec / budget` 计算安全等级（`SafetyLevel::Normal`/`ShedHeavy`），在高水位时通过 `BpfOrchestrator::SetMaxEventsPerGroup` 限制每组事件数量，并为 Prometheus 置位 `ms_sampling_throttled`。

### 3.6 异常检测（`agent/src/anomaly_monitor.cpp`）

- 定期读取 `/proc/net/dev` 中的 RX bytes（可配置 `interfaces`）计算吞吐，使用 EWMA (`throughput_ewma_alpha`) 构建基线，小于 `throughput_ratio_trigger` 时发出 `AnomalySignal{ThroughputDrop}`。
- 可选从 `latency_probe_path` 读取延迟数据，同样以 EWMA 与 `latency_ratio_trigger` 检测尖刺。
- 每次触发都会写入 `ms_throughput_ratio/ms_throughput_bps` 或 `ms_latency_ratio/ms_latency_us` 指标，并让 `ModeController` 强制进入诊断模式直至 `refractory_period` 结束。

### 3.7 控制面 API（`agent/src/control_plane.cpp`）

HTTP 服务监听 `ControlPlaneConfig::listen_address:listen_port`，仅接受 `POST`：

| Endpoint | 请求体字段 | 作用 |
| --- | --- | --- |
| `/api/v1/mode` | `{ "mode": "sentinel|diagnostic" }` | 立即切换运行模式。 |
| `/api/v1/token-bucket` | `sentinel_samples_per_sec`, `diagnostic_samples_per_sec`, `hard_drop_ns` | 更新令牌桶预算，兼容 legacy `samples_per_sec`。 |
| `/api/v1/pmu-config` | `sentinel_groups`, `diagnostic_groups` | 调整每组 PMU 事件（支持逻辑枚举或原始 event 编号）。 |
| `/api/v1/symbols/jit` | `pid,start,end,path,build_id?` | 注册 JIT 区域，供符号化索引。 |
| `/api/v1/symbols/data` | `pid,address,name,type?,size?` | 注册数据对象/堆区。 |
| `/api/v1/targets` | `targets:[{flow_id|pid|cgroup}]` | 设置监控目标集合。 |

控制面解析逻辑由本地 `json.cpp` 提供的轻量 parser 实现，异常时返回 400。

### 3.8 指标导出（`agent/src/metrics_exporter.cpp`）

- 内部 HTTP 服务器暴露 OpenMetrics 文本，`MetricsExporter::SetGauge` 直接覆盖最新值。
- 样本相关指标：`ms_agent_mode`, `ms_samples_per_sec`, `ms_pmu_scale`, `ms_sampling_throttled`。
- 检测指标：`ms_false_sharing_score{line,...}`, `ms_remote_dram_hotspot{flow,...}`、`ms_throughput_ratio` 等，由对应模块在 `Flush` 时写入。

---

## 4. 后端数据通路

### 4.1 ClickHouse（`backend/clickhouse_schema.sql`）

- `ms_flow_rollup`：窗口化聚合结果，key 与 `AggregationKey` 对应，`norm_cost` = `samples * sample_scale / gso_segs`。
- `ms_raw_samples`：原始样本及 LBR，便于离线重放或符号重解析。
- `ms_callstacks`：`stack_id` → 帧序列，每帧包含 `binary/function/file/line`。
- `ms_data_objects`：追踪 `/api/v1/symbols/data` 下发的堆/映射。

`ClickHouseSink::FlushBatch` 将上述批次串成 `INSERT ... FORMAT JSONEachRow`，并复用 `SendPayload` 发送 HTTP POST；失败时仅打印 `stderr`（调用者可通过监控 `ms_clickhouse_flush_errors` gauge 追踪——TODO）。

### 4.2 Prometheus（`backend/prometheus_metrics.yaml`）

描述了全部 Gauge 及标签。关键分组：

1. **运行状态**：`ms_agent_mode`, `ms_pmu_scale`, `ms_sampling_throttled`。
2. **事件归因**：`ms_flow_micromiss_rate`, `ms_branch_mispred_rate`, `ms_flow_event_norm`（默认 fallback）。
3. **检测输出**：`ms_false_sharing_score`, `ms_remote_dram_hotspot`, `ms_throughput_ratio`, `ms_latency_ratio`。
4. **校准指标**：`ms_tsc_slope{cpu}`, `ms_tsc_offset_ns{cpu}`。

---

## 5. 算法与实现细节

### 5.1 时间/流关联

- **内核**：`ms_hist_push` 将 `<tsc,flow>` 入队，`find_flow_in_history` 允许在 `MS_HISTORY_LEN` * `MS_FLOW_SKID_NS` 范围内回溯，必要时返回 `fallback_flow_id()`。
- **用户态**：`SkewAdjuster` 用 per-CPU deque 保存待匹配样本；若窗口结束仍无匹配则按降级策略标记 `flow_id = 0`。

### 5.2 令牌桶 & 安全调度

- `ms_token_bucket` 的 `tokens` 以纳秒时间差折算补充，`MS_TOKEN_HEADROOM` 限定上限以避免长时间空闲后暴涨。
- 用户态 `ModeController` 保存 `hysteresis_high/low`，`MaybeAdjustSafety` 根据实际样本速率比值将 `SafetyLevel` 设置为 `ShedHeavy`（限制 PMU 事件数）或恢复 Normal，并写入 `ms_sampling_throttled`。

### 5.3 检测模块

- **FalseSharingDetector**：按 cache line 聚合 `MS_EVT_XSNP_HITM`，跟踪 per-CPU/per-PID 命中，阈值逻辑位于 `fs_detector.cpp::MaybeEmit`。
- **RemoteDramAnalyzer**：针对 `MS_EVT_REMOTE_DRAM`，维护 `(flow, numa, ifindex)` 计数及 `last_tsc`，窗口外条目经 `Flush` 输出。
- **AnomalyMonitor**：吞吐、延迟检测见 §3.6；触发后通过 `metrics_` 写入比值，并调用 `ModeController::Force`。

### 5.4 PMU 轮转与归一

- `PmuRotator`（`agent/src/pmu_rotator.cpp`）在 `cfg_.perf.rotation_window` 间隔内切换 sentinel/diagnostic 事件组，调用回调更新 `Aggregator::SetSampleScale` 与 `metrics_->SetGauge("ms_pmu_scale")`。
- `Aggregator::SampleScale` 也被 `ClickHouseSink::EnqueueRawSample` 使用，以确保 raw 表中的 `norm_cost` 与 rollup 一致。

---

## 6. 扩展与定制

### 6.1 新增 PMU 事件

1. 在 `bpf/ms_common.h` 的 `enum ms_pmu_event_type` 增加逻辑事件常量。
2. 更新 `agent/src/interference.cpp` 中的 `ClassifyEvent`，确保新的事件映射到正确的 `InterferenceClass`。
3. 在配置文件或控制面 `/api/v1/pmu-config` 中声明 sentinel/diagnostic 事件组。
4. 如需额外输出，可在 `Aggregator::EventClass` 或新增检测器中处理。

### 6.2 自定义监控目标

- 通过 `/api/v1/targets` 提交 JSON：`{"targets":[{"flow_id":123},{"pid":456}]}`。
- `MonitoringTargetManager::Allow` 支持 flow_id、pid、tid、cgroup、ingress ifindex 条件，必要时可在 `agent/src/monitoring_targets.cpp` 扩展字段。

### 6.3 扩展检测/导出

- 检测器需实现 `Observe(const Sample&)` 和 `Flush(now_ns, callback)`（参考 `FalseSharingDetector`）。
- 导出路径可通过新增 `MetricsExporter::SetGauge` 标签或扩展 `ClickHouseSink` schema（`backend/` 中同步修改）。

### 6.4 符号化增强

- `Symbolizer` 已支持 `RegisterJitRegion` 与 `RegisterDataObject`；若需要自动从 `/proc/<pid>/maps` 抓取，可在 `symbolizer.cpp` 中增加 watcher。
- 更复杂的 DWARF 解析可通过替换当前 stub（`Symbolizer::ResolveFrame`）来实现。

---

## 7. 构建与测试

### 7.1 构建

```bash
cmake -S . -B build
cmake --build build
make -C bpf                          # 需要 clang/bpftool && vmlinux.h
```

- `cmake` 生成的 Agent 二进制位于 `build/agent/micro_sentinel_agent`，测试位于 `build/agent/ms_agent_tests`。
- `bpf/Makefile` 需要 `BPF_CLANG`/`BPF_LLVM_STRIP` 等环境变量（可选）。

### 7.2 测试/验证

- 单元测试：`cd build && ctest --output-on-failure`，覆盖 `tests/test_json.cpp`, `tests/test_monitoring_targets.cpp`, `tests/test_skew_adjuster.cpp`, `tests/test_token_bucket.cpp`。
- Mock 运行：`./build/agent/micro_sentinel_agent --perf-mock --mock-period-ms=25 --metrics-port=9102` 验证导出链路。
- e2e：加载 BPF (`sudo ./build/agent/micro_sentinel_agent --config=...`)，观察 Prometheus 指标与 ClickHouse 表。

---

## 8. 文件索引

| 模块 | 主要文件 |
| --- | --- |
| eBPF 程序 | `bpf/micro_sentinel_kern.bpf.c`, `bpf/ms_common.h` |
| BPF 管理 | `agent/src/bpf_orchestrator.cpp`, `agent/include/micro_sentinel/bpf_orchestrator.h` |
| perf 消费 | `agent/src/perf_consumer.cpp`, `agent/include/micro_sentinel/perf_consumer.h` |
| 运行时与模式控制 | `agent/src/runtime.cpp`, `agent/src/mode_controller.cpp`, `agent/src/anomaly_monitor.cpp` |
| 聚合/导出 | `agent/src/aggregator.cpp`, `agent/src/clickhouse_sink.cpp`, `agent/src/metrics_exporter.cpp`, `agent/src/symbolizer.cpp` |
| 检测模块 | `agent/src/fs_detector.cpp`, `agent/src/remote_dram_analyzer.cpp`, `agent/src/interference.cpp` |
| 控制面 | `agent/src/control_plane.cpp`, `agent/src/json.cpp` |
| 配置与测试 | `agent/src/config_loader.cpp`, `tests/test_*.cpp` |

有关实现计划及背景，请参阅 `docs/IMPLEMENTATION_PLAN.md` 与 `docs/RUNBOOK.md`。
