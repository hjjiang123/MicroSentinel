# MicroSentinel 操作指南

本指南面向需要在生产或实验环境中部署 MicroSentinel 的运维与性能分析团队，提供从环境准备、编译、部署到运行期调优的完整步骤。阅读完本文档后，你应当能够：

1. 在具备 BTF 的 Linux x86_64 主机上构建 eBPF 程序与用户态 Agent；
2. 结合配置文件与 CLI 覆盖项启动 Agent，并在哨兵/诊断模式间切换；
3. 通过控制面 API 管理采样预算、PMU 事件组、监控目标以及符号化信息；
4. 使用 Prometheus 指标与 ClickHouse 表排查问题；
5. 在发生异常或资源压力时执行安全降级与故障恢复。

> **术语对应**：本文档中的 “Agent” 指 `agent/micro_sentinel_agent` 可执行文件；“BPF 对象” 指 `bpf/micro_sentinel_kern.bpf.o`。

---

## 1. 环境与依赖

### 1.1 硬件 / 内核要求

- CPU：Intel Skylake 及以上，开启 PEBS、LBR、OFFCORE_RESPONSE、XSNP_HITM 等 PMU 事件；
- 操作系统：Linux x86_64，建议内核 ≥ 5.10 且启用 BTF (`/sys/kernel/btf/vmlinux` 存在)；
- 内核特性：支持 fentry/fexit、perf_event、XDP、BPF perf ring buffer；
- 时钟能力：各 CPU TSC 可校准（Agent 内建 TSC 归一逻辑）。

### 1.2 依赖工具链

| 组件 | 最低版本 | 用途 |
| --- | --- | --- |
| Clang/LLVM | 13 | 编译 eBPF 程序 |
| bpftool | 与内核匹配 | 生成 `vmlinux.h`、调试 BPF 资源 |
| GCC / G++ | 11 (C++20) | 构建用户态 Agent |
| CMake | 3.21 | 构建系统 |
| libbpf + headers | 1.0+ | 运行时装载 / 管理 eBPF |
| ClickHouse (可选) | 22.x+ | 存储原始与聚合样本 |
| Prometheus (可选) | 2.x+ | 抓取 Agent 暴露的指标 |

### 1.3 目录速览

```
MicroSentinel/
├── bpf/                # eBPF 源码与 Makefile
├── agent/              # C++20 Agent、配置解析、控制面
├── backend/            # ClickHouse schema 与 Prometheus 指标描述
├── docs/               # 本指南、RUNBOOK、实现计划
└── build/              # CMake 产物（手动生成）
```

---

## 2. 构建流程

### 2.1 准备 BTF 与 eBPF 对象

首次在目标内核上部署时，需要生成匹配内核的 `vmlinux.h` 并编译 BPF 对象：

```bash
cd bpf
make vmlinux         # 使用 bpftool dump type format 生成 vmlinux.h
make                 # 产出 micro_sentinel_kern.bpf.o
```

构建完成后，可通过 `file micro_sentinel_kern.bpf.o` 或 `bpftool btf dump file micro_sentinel_kern.bpf.o` 进行检查。

### 2.2 编译用户态 Agent

在仓库根目录执行标准的 CMake 流程：

```bash
cmake -S . -B build
cmake --build build
```

若启用测试：

```bash
cd build
ctest --output-on-failure
```

编译完成后，主要可执行文件位于 `build/agent/micro_sentinel_agent`，单元测试位于 `build/agent/ms_agent_tests`。

---

## 3. 配置与启动

### 3.1 创建配置文件

Agent 默认使用内部配置，可通过 `--config=/path/to/conf` 载入键值对文件。示例：

```bash
cat > /etc/micro_sentinel/agent.conf <<'EOF'
# 采样预算（每 CPU 每秒）
sentinel_budget=6000
diagnostic_budget=20000
# ClickHouse 输出
clickhouse_endpoint=http://ch.example.com:8123
clickhouse_table=ms_flow_rollup
clickhouse_raw_table=ms_raw_samples
clickhouse_flush_ms=500
# Prometheus 指标
metrics_address=0.0.0.0
metrics_port=9105
# 控制面与异常监控
control_address=127.0.0.1
control_port=9200
anomaly_enabled=true
anomaly_interfaces=eth0,eth1
anomaly_interval_ms=500
# 运行模式
mode=sentinel
perf_mock_mode=false
EOF
```

> **格式说明**：每行 `key=value`，支持注释 `#`。常见键可在 `agent/src/config_loader.cpp` 中查阅。

### 3.2 常用 CLI 覆盖项

- `--mode=sentinel|diagnostic` 强制启动模式；
- `--mock-period-ms=50` 在 mock 模式下的样本间隔；
- `--sentinel-budget=8000` / `--diagnostic-budget=20000` 快速覆盖预算；
- `--perf-mock` / `--no-perf-mock` 切换是否连接真实 perf ring buffer。

CLI 覆盖项优先级高于配置文件。

### 3.3 启动 Agent

#### 3.3.1 模拟环境（无内核挂载）

```bash
./build/agent/micro_sentinel_agent --config=/etc/micro_sentinel/agent.conf --perf-mock --mock-period-ms=25
```

此模式会启用内置的样本生成器，便于验证 ClickHouse/Prometheus 管道。

#### 3.3.2 实机部署（连接 eBPF）

1. 确保 `libbpf` 可用且 `micro_sentinel_kern.bpf.o` 与目标内核匹配；
2. 为需要观测的网络路径加载 `ms_ctx_inject`（fentry RX/TX）以及可选 XDP 程序（`ms_ctx_inject_xdp`）；
3. 使用 root 或具备 `CAP_BPF`, `CAP_PERFMON`, `CAP_SYS_ADMIN` 权限的用户启动 Agent：

```bash
sudo ./build/agent/micro_sentinel_agent --config=/etc/micro_sentinel/agent.conf --no-perf-mock
```

成功后，Agent 日志会提示当前模式、BPF map FD、以及 perf-event 绑定情况。

---

## 4. 模式与采样控制

### 4.1 哨兵 / 诊断模式

- **哨兵模式**：低频采样（默认 5k samples/sec/CPU），用于常态监控；
- **诊断模式**：高频采样（默认 20k+ samples/sec/CPU），在吞吐下降/延迟升高时触发；
- `ModeController` 会根据负载比 (`ms_samples_per_sec / budget`) + `AnomalyMonitor` 信号进行模式切换。

### 4.2 控制面 API

所有 API 均为 HTTP `POST`，监听地址由 `control_address:control_port` 控制。

| 功能 | 请求 | 示例 |
| --- | --- | --- |
| 切换模式 | `/api/v1/mode` | `curl -X POST 127.0.0.1:9200/api/v1/mode -d '{"mode":"diagnostic"}'` |
| 更新采样预算 | `/api/v1/token-bucket` | `curl -X POST 127.0.0.1:9200/api/v1/token-bucket -d '{"sentinel_samples_per_sec":8000,"diagnostic_samples_per_sec":20000,"hard_drop_ns":4000}'` |
| 调整 PMU 事件组 | `/api/v1/pmu-config` | `curl -X POST 127.0.0.1:9200/api/v1/pmu-config -d '{"sentinel":{"groups":[...]}}'`（结构参考 `agent/include/micro_sentinel/config.h`） |
| 注册 JIT 代码段 | `/api/v1/symbols/jit` | `curl -X POST 127.0.0.1:9200/api/v1/symbols/jit -d '{"pid":1234,"start":140737488355328,"end":140737488441344,"path":"jit.so"}'` |
| 注册数据对象 | `/api/v1/symbols/data` | `curl -X POST 127.0.0.1:9200/api/v1/symbols/data -d '{"pid":1234,"address":0x7f00,"name":"rx_ring","type":"struct ring","size":4096}'` |
| 更新监控目标 | `/api/v1/targets` | `curl -X POST 127.0.0.1:9200/api/v1/targets -d '{"targets":[{"type":"flow","value":"10.1."},{"type":"pid","value":"1234"}]}'` |

接口调用成功后返回 `200 ok`，失败则返回 `400 invalid request`。

### 4.3 令牌桶与安全控制

- 令牌桶参数由 `sentinel_budget` / `diagnostic_budget` / `hard_drop_ns` 三元组控制，对应 BPF map `ms_tb_cfg_map`；
- Agent 会根据 `ms_samples_per_sec` 与预算比值自动触发 `SafetyLevel::ShedHeavy`，限制每组激活的 PMU 事件数量；
- 若需要手动复位，可调用 `POST /api/v1/token-bucket` 或使用 `bpftool prog run` 触发 `ms_update_tb` kprobe。

---

## 5. 指标与后端

### 5.1 Prometheus 指标

Agent 默认在 `metrics_address:metrics_port` 暴露 text 格式指标，常用项：

- `ms_agent_mode`：0=sentinel，1=diagnostic；
- `ms_samples_per_sec`：当前输出速率；
- `ms_flow_micromiss_rate{flow,function,event}` 等系列：按流/函数/事件聚合的归一化成本；
- `ms_false_sharing_score{line,mapping,pid}`：伪共享检测结果；
- `ms_remote_dram_hotspot{flow,numa,ifindex}`：跨 NUMA 热点；
- `ms_tsc_slope{cpu}` / `ms_tsc_offset_ns{cpu}`：TSC 校准参数。

可使用 `backend/prometheus_metrics.yaml` 作为抓取与告警参考。

### 5.2 ClickHouse 表

参考 `backend/clickhouse_schema.sql` 建表：

- `ms_raw_samples`：逐样本记录（含 LBR、GSO、flow_id 等）；
- `ms_flow_rollup`：时间窗聚合结果；
- `ms_stack_traces` 与 `ms_data_objects`：符号化辅助表。

Agent 通过 HTTP JSONEachRow 批量写入，可在 ClickHouse 端配置 TTL、分区策略与表引擎以控制存储成本。

### 5.3 Dashboards

`backend/dashboards.md` 描述了火焰图、热力图、拓扑图的构建思路，可结合 Grafana + ClickHouse + Prometheus 完成可视化闭环。

---

## 6. 运行期检查清单

1. **BPF 侧**：
   - `bpftool prog` 是否显示 `ms_ctx_inject`, `ms_pmu_handler` 已 attach；
   - `bpftool map dump id <ms_events>` 或 `bpftool perf show` 检查样本是否输出；
2. **perf 侧**：
   - `perf stat -e cycles -C <cpu>` 验证 PMU 子系统可用；
   - `sudo mount -t tracefs tracefs /sys/kernel/tracing` 以调试 fentry；
3. **Agent 侧**：
   - `curl 127.0.0.1:9105/metrics` 查看指标；
   - `curl -X POST 127.0.0.1:9200/api/v1/mode -d '{"mode":"diagnostic"}'` 验证控制面；
   - `journalctl -u micro_sentinel` 或 stdout 日志确认无错误；
4. **后端**：
   - ClickHouse：`SELECT count() FROM ms_raw_samples WHERE host='...' AND ts>now()-60;`；
   - Prometheus：关注 `ms_samples_per_sec`, `ms_agent_mode`, `ms_pmu_scale` 等曲线。

---

## 7. 故障排查与恢复

| 症状 | 可能原因 | 建议操作 |
| --- | --- | --- |
| Agent 启动失败，提示 "Failed to open BPF object" | 内核缺少 BTF 或 `libbpf` 版本不兼容 | 重新生成 `vmlinux.h`，确认 `bpftool` 可正常工作，升级 `libbpf` |
| `ms_samples_per_sec` 显著低于预算 | 令牌桶耗尽，或 SafetyLevel 触发限流 | 调整 `sentinel_budget/diagnostic_budget`，检查 `ms_sampling_throttled` 指标 |
| Prometheus 抓取失败 | `metrics_address`/`metrics_port` 配置错误或防火墙拦截 | 使用 `ss -ltnp | grep 9105` 检查监听，修正配置后重启 |
| ClickHouse 入库失败 | `clickhouse_endpoint` 不可达或凭据错误 | 在 Agent 日志中搜索 "Failed to flush ClickHouse"，使用 `curl` 手动测试 HTTP API |
| 样本缺少 flow_id | 流关联窗口不匹配或 GSO 造成滑移 | 确认 `ms_ctx_inject` 挂载在 RX/TX 热点，必要时调高 `MS_FLOW_SKID_NS` 或调整 `SkewAdjuster` 窗口 |

如需彻底清理：

```bash
sudo pkill micro_sentinel_agent
sudo bpftool prog detach name ms_ctx_inject
sudo bpftool prog detach name ms_ctx_inject_tx
sudo rm -f /sys/fs/bpf/*ms*
```

---

## 8. 常见操作速查

| 场景 | 命令 |
| --- | --- |
| 查看当前模式 | `curl -s 127.0.0.1:9105/metrics | grep ms_agent_mode` |
| 手工切换至诊断模式 | `curl -X POST 127.0.0.1:9200/api/v1/mode -d '{"mode":"diagnostic"}'` |
| 更新监控目标为 flow 前缀 `10.1.` | `curl -X POST 127.0.0.1:9200/api/v1/targets -d '{"targets":[{"type":"flow","value":"10.1."}]}'` |
| 观测远程 NUMA 热点 | 在 Prometheus 中查询 `ms_remote_dram_hotspot` 并结合告警阈值 |
| 使用 mock 模式压测 ClickHouse | `./micro_sentinel_agent --perf-mock --mock-period-ms=5 --clickhouse-endpoint=http://127.0.0.1:8123` |

---

通过上述流程即可在不同环境中完成 MicroSentinel 的部署、运行与维护。如需更细致的调参示例，可结合 `docs/RUNBOOK.md` 与 `backend/` 目录获取额外上下文。# MicroSentinel 操作指南

本指南面向需要在生产或实验环境中部署 MicroSentinel 的运维与性能分析团队，提供从环境准备、编译、部署到运行期调优的完整步骤。阅读完本文档后，你应当能够：

1. 在具备 BTF 的 Linux x86_64 主机上构建 eBPF 程序与用户态 Agent；
2. 结合配置文件与 CLI 覆盖项启动 Agent，并在哨兵/诊断模式间切换；
3. 通过控制面 API 管理采样预算、PMU 事件组、监控目标以及符号化信息；
4. 使用 Prometheus 指标与 ClickHouse 表排查问题；
5. 在发生异常或资源压力时执行安全降级与故障恢复。

> **术语对应**：本文档中的 “Agent” 指 `agent/micro_sentinel_agent` 可执行文件；“BPF 对象” 指 `bpf/micro_sentinel_kern.bpf.o`。

---

## 1. 环境与依赖

### 1.1 硬件 / 内核要求

- CPU：Intel Skylake 及以上，开启 PEBS、LBR、OFFCORE_RESPONSE、XSNP_HITM 等 PMU 事件；
- 操作系统：Linux x86_64，建议内核 ≥ 5.10 且启用 BTF (`/sys/kernel/btf/vmlinux` 存在)；
- 内核配置：支持 fentry/fexit、perf_event、XDP、BPF perf ring buffer；
- 时钟：各 CPU TSC 可校准（Agent 内建 TSC 归一逻辑）。

### 1.2 依赖工具链

| 组件 | 最低版本 | 用途 |
| --- | --- | --- |
| Clang/LLVM | 13 | 编译 eBPF 程序 |
| bpftool | 与内核匹配 | 生成 `vmlinux.h`、调试 BPF 资源 |
| GCC / G++ | 11 (C++20) | 构建用户态 Agent |
| CMake | 3.21 | 构建系统 |
| libbpf + headers | 1.0+ | 运行时装载 / 管理 eBPF |
| ClickHouse (可选) | 22.x+ | 存储原始与聚合样本 |
| Prometheus (可选) | 2.x+ | 抓取 Agent 暴露的指标 |

### 1.3 目录速览

```
MicroSentinel/
├── bpf/                # eBPF 源码与 Makefile
├── agent/              # C++20 Agent、配置解析、控制面
├── backend/            # ClickHouse schema 与 Prometheus 指标描述
├── docs/               # 本指南、RUNBOOK、实现计划
└── build/              # CMake 产物（手动生成）
```

---

## 2. 构建流程

### 2.1 准备 BTF 与 eBPF 对象

首次在目标内核上部署时，需要生成匹配内核的 `vmlinux.h` 并编译 BPF 对象：

```bash
cd bpf
make vmlinux         # 使用 bpftool dump type format 生成 vmlinux.h
make                 # 产出 micro_sentinel_kern.bpf.o
```

构建完成后，可通过 `file micro_sentinel_kern.bpf.o` 或 `bpftool btf dump file micro_sentinel_kern.bpf.o` 进行检查。

### 2.2 编译用户态 Agent

在仓库根目录执行标准的 CMake 流程：

```bash
cmake -S . -B build
cmake --build build
```

若启用测试：

```bash
cd build
ctest --output-on-failure
```

编译成功后，主要可执行文件位于 `build/agent/micro_sentinel_agent`，单元测试位于 `build/agent/ms_agent_tests`。

---

## 3. 配置与启动

### 3.1 创建配置文件

Agent 默认使用内部配置，可通过 `--config=/path/to/conf` 载入键值对文件。示例：

```bash
cat > /etc/micro_sentinel/agent.conf <<'EOF'
# 采样预算（每 CPU 每秒）
sentinel_budget=6000
diagnostic_budget=20000
# ClickHouse 输出
clickhouse_endpoint=http://ch.example.com:8123
clickhouse_table=ms_flow_rollup
clickhouse_raw_table=ms_raw_samples
clickhouse_flush_ms=500
# Prometheus 指标
metrics_address=0.0.0.0
metrics_port=9105
# 控制面与异常监控
control_address=127.0.0.1
control_port=9200
anomaly_enabled=true
anomaly_interfaces=eth0,eth1
anomaly_interval_ms=500
# 运行模式
mode=sentinel
perf_mock_mode=false
EOF
```

> **格式说明**：每行 `key=value`，支持注释 `#`。常见键可在 `agent/src/config_loader.cpp` 中查阅。

### 3.2 常用 CLI 覆盖项

- `--mode=sentinel|diagnostic` 强制启动模式；
- `--mock-period-ms=50` 在 mock 模式下的样本间隔；
- `--sentinel-budget=8000` / `--diagnostic-budget=20000` 快速覆盖预算；
- `--perf-mock` / `--no-perf-mock` 切换是否连接真实 perf ring buffer。

CLI 覆盖项优先级高于配置文件。

### 3.3 启动 Agent

#### 3.3.1 模拟环境（无内核挂载）

```bash
./build/agent/micro_sentinel_agent --config=/etc/micro_sentinel/agent.conf --perf-mock --mock-period-ms=25
```

此模式会启用内置的样本生成器，便于验证 ClickHouse/Prometheus 管道。

#### 3.3.2 实机部署（连接 eBPF）

1. 确保 `libbpf` 可用且 `micro_sentinel_kern.bpf.o` 与目标内核匹配；
2. 为需要观测的网络路径加载 `ms_ctx_inject`（fentry RX/TX）以及可选 XDP 程序（`ms_ctx_inject_xdp`）；
3. 使用 root 或具备 `CAP_BPF`, `CAP_PERFMON`, `CAP_SYS_ADMIN` 权限的用户启动 Agent：

```bash
sudo ./build/agent/micro_sentinel_agent --config=/etc/micro_sentinel/agent.conf --no-perf-mock
```

成功后，Agent 日志会提示当前模式、BPF map FD、以及 perf-event 绑定情况。

---

## 4. 模式与采样控制

### 4.1 哨兵 / 诊断模式

- **哨兵模式**：低频采样（默认 5k samples/sec/CPU），用于常态监控；
- **诊断模式**：高频采样（默认 20k+ samples/sec/CPU），在吞吐下降/延迟升高时触发；
- `ModeController` 会根据负载比 (`ms_samples_per_sec / budget`) + `AnomalyMonitor` 信号进行模式切换。

### 4.2 控制面 API

所有 API 均为 HTTP `POST`，监听地址由 `control_address:control_port` 控制。

| 功能 | 请求 | 示例 |
| --- | --- | --- |
| 切换模式 | `/api/v1/mode` | `curl -X POST 127.0.0.1:9200/api/v1/mode -d '{