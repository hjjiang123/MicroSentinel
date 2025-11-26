# Dashboard Notes

## Flame Graph
- Input: aggregated samples grouped by function_id and pmu_event via `ms_flow_micromiss_rate`, `ms_remote_dram_rate`, `ms_branch_mispred_rate`, `ms_icache_stall_rate`, `ms_avx_downclock_rate`, `ms_backend_stall_rate`, and `ms_flow_event_norm`.
- Render separate layers for network flow, function, and microarchitecture event type.
- Leverage the `direction` label to split RX/TX contributions when comparing flows.
- Provide drill-down links to ClickHouse queries for `ms_raw_samples` to inspect individual LBR traces.

## Heat Map
- Axes: NUMA node vs microarchitecture event rate.
- Color scale: normalized contribution (per-packet basis).
- Highlight cells exceeding configurable threshold with alerts.

## Topology View
- Nodes represent CPUs/NUMA domains; edges show cross-node memory traffic from OFFCORE_RESPONSE events.
- Annotate edges with remote DRAM percentage and responsible flows.

## Control Panel
- Toggle sentinel/diagnostic mode via `/api/v1/mode`.
- Display recent alerts (false sharing, cache pollution) with timestamps derived from `ms_false_sharing_score` spikes.
- Surface agent self-metrics (CPU, memory usage) alongside `ms_agent_mode`, `ms_samples_per_sec`, and `ms_pmu_scale` to avoid observer effects.
