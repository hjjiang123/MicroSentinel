# MicroSentinel Runbook

## Modes

- **Sentinel** — low overhead, coarse sampling. Enabled by default. Token bucket limits ~5k samples/sec per CPU.
- **Diagnostic** — activated when throughput ratio exceeds `thresholds.sentinel_to_diag`. Enables high-resolution sampling and richer PMU sets.

## Switching Modes Manually

```
curl -X POST localhost:9200/api/v1/mode -d '{"mode":"diagnostic"}'
```

The control plane listens on `control_address:control_port` (default `127.0.0.1:9200`). Modes take effect immediately and persist until another request arrives or the agent restarts.

To override token-bucket budgets on the fly:

```
curl -X POST localhost:9200/api/v1/token-bucket \
   -H 'Content-Type: application/json' \
   -d '{"sentinel_samples_per_sec":6000,"diagnostic_samples_per_sec":18000,"hard_drop_ns":4000}'
```

### Target Filters

Use the targets API to narrow monitoring to specific flows, PIDs, or cgroups:

```
curl -X POST localhost:9200/api/v1/targets \
   -H 'Content-Type: application/json' \
   -d '{"targets":[{"type":"flow","value":"10.1."},{"type":"pid","value":"4242"}]}'
```

Each call replaces the previous selector set. Leaving `targets` empty clears all filters and reverts to full capture.

## Handling Alerts

1. **False Sharing**
   - Check `backend/prometheus_metrics.yaml` metric `ms_false_sharing_score`.
   - Query ClickHouse for `data_addr` to resolve owning variable.
2. **Remote DRAM Hotspots**
   - Track the `ms_remote_dram_hotspot{flow,numa,ifindex}` gauge. Spikes indicate sustained remote-memory demand for a particular flow/NUMA pair.
   - If you need raw event rates, correlate with `ms_remote_dram_rate` by filtering the aggregated buckets on the same labels.
   - Re-pin offending threads or rebalance flows.
3. **Branch Storms / Control Path Issues**
   - Filter aggregated tuples where `pmu_event == MS_EVT_BRANCH_MISPRED` and review the `ms_flow_event_norm` metric for the top flows.

## Recovery

- To shed load, call `ms_update_tb` kprobe hook via `bpftool prog run` or restart agent.
- If metrics exporter stops responding, restart the agent; the HTTP server currently runs inside the process.
