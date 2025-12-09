# Experiment Automation & Results Pipeline

This guide explains how the suite runner, workload launcher, and result recorder cooperate to execute the evaluation plan repeatably on the two-node testbed (local server `211.0.0.101` + remote generator `211.0.0.102`). Pair it with `docs/EXPERIMENT_PLATFORM.md`, `docs/WORKLOAD_GUIDE.md`, and `docs/TWO_NODE_DEPLOYMENT.md` for hardware prep and synchronization details.

## 1. Moving Pieces

| Module | Path | Role |
| --- | --- | --- |
| Suite runner | `experiments/automation/run_suite.py` | Expands suite descriptors into concrete runs (modes × variants × repetitions) and applies optional Git patch “mutations”. |
| Workload launcher | `experiments/automation/workload_runner.py` | Starts workload services, remote clients, instrumentation, and host monitors; tracks truth logs + remote artifacts. |
| Instrumentation manager | `experiments/automation/instrumentation.py` | Encapsulates baseline / perf / MicroSentinel observer commands and logging. |
| Result recorder | `experiments/automation/results.py` | Serializes plan metadata, ingests metrics JSON, captures monitor logs, and writes `run_result.json`. |

## 2. Authoring Suite Files

Suites live under `experiments/configs/experiments/`. Each entry describes *what* to run and optionally how to sweep parameters:

```yaml
workloads:
  - name: kv
    config: experiments/configs/workloads/kv.yaml
    modes: [baseline, perf, microsentinel]
    repetitions: 5
    parameters:
      delta_values_us: [5, 10, 20]
      rate_scan:
        samples_per_core: [500, 1000, 2000]
    overrides:
      instrumentation:
        pmu_events: "cycles,LLC-load-misses"
      annotations:
        suite_case: "kv_baseline"
```

`run_suite.py --suite overhead --perf-freq 2000` walks every variant, merges overrides (suite + workload + variant), and invokes `workload_runner.execute_workload` for each repetition.

### Common Overrides

| Key | Location | Purpose |
| --- | --- | --- |
| `workload.server/clients/...` | Workload config *or* suite overrides | Change ports, NUMA policy, truth logs, remote spec, etc. |
| `instrumentation.*` | Suite overrides | Alter perf frequency, filters, PMU events, or MicroSentinel config path. |
| `annotations.*` | Suite overrides | Free-form tags stored in `plan.json`/`run_result.json` for later filtering. |

## 3. Instrumentation Modes

`instrumentation.py` exposes three modes:

1. **baseline** – no observer; only workload metrics and host monitors run.
2. **perf** – launches either `perf record` (default) or `perf stat` if `perf_mode: stat` is set. Frequency, event list, and interval come from CLI + overrides.
3. **microsentinel** – starts `micro_sentinel_agent` with `--config=<file>` and optional `--metrics-port=<port>`. Sampling knobs (token budgets, PMU groups, filters) stay in the config file so automation only passes supported CLI flags.

All instrumentation stdout/stderr is captured in `instrumentation_<mode>.log` inside the artifact folder.

## 4. Remote Execution Flow

Every workload config now includes a `remote` stanza for client/traffic commands. Example from the LB client block:

```yaml
clients:
  generator: "python3 experiments/workloads/lb/lb_client.py"
  remote:
    host: "211.0.0.102"
    workdir: "~/MicroSentinel"
    metrics_dir: "~/MicroSentinel/artifacts/remote"
```

During a run the launcher:

1. Builds the local command (log paths, metrics destinations, truth logs).
2. Wraps the argv with `ssh host "cd workdir && ..."`. `~/` prefixes are left unquoted so the remote shell expands them.
3. Tracks `metrics_dir` plus any explicit `extra_artifacts` (e.g., truth logs) for post-run copy-back.
4. After the command exits, pulls every declared artifact via `scp`, recording success/errors in `<artifact_dir>/remote_fetch.log`.

If a copy fails, inspect `remote_fetch.log` for the exact `scp` invocation and stderr. Missing directories on the remote side are the most common culprit—ensure `metrics_dir` exists and that the command writes files there (or use absolute paths in the command line itself).

## 5. Truth Logging & Metrics Destinations

The launcher provides helper functions so every workload consistently places artifacts under the run directory:

| Helper | Purpose |
| --- | --- |
| `_metric_path(artifact_dir, name)` | Reserve `<artifact_dir>/metrics/<name>.json` and pass it to generators via `--metrics-file`. |
| `_resolve_output_path(artifact_dir, relative_path)` | Expand truth-log paths (e.g., `truth/firewall.json`) into the run directory, creating parent folders. |
| `_resolve_metrics_destination(local_path, remote_spec)` | Decide whether to hand a local path or remote path based on `remote.metrics_dir`. |

Truth logs from KV, LB, and NFV stages therefore land under `<artifact_dir>/truth/` locally even when the producer ran remotely. Capture limits (e.g., `truth_limit`) prevent unbounded growth during long experiments.

## 6. Artifact Layout

Each run is stored under `experiments/artifacts/<timestamp>_<workload>/` and contains:

- `plan.json` – command plan, overrides, annotations, and serialized `CommandSpec`s.
- `run_result.json` – final summary (commands, monitors, errors, remote fetch status).
- `*_server.log`, `*_client.log`, `instrumentation_<mode>.log` – stdout/stderr for every command.
- `metrics/` – metrics JSON gathered from clients/traffic generators.
- `truth/` – ground-truth logs (KV annotations, NFV stage decisions, etc.).
- `mpstat.log`, `pidstat.log`, optionally `remote_fetch.log` – host monitoring and remote copy transcript.

`ResultRecorder` enriches `run_result.json` with per-command metrics (if JSON was produced) so notebooks can correlate instrumentation, workloads, and truth data without parsing logs again.

## 7. Recommended Run Workflow

1. **Pre-flight (once per boot)** – Follow `docs/EXPERIMENT_PLATFORM.md`: BIOS settings, kernel args, RSS/IRQ pinning, chrony/PTP, repo sync to the remote node.
2. **Dry run** – `python3 experiments/automation/run_suite.py --suite sanity --dry-run` to view planned commands without launching them.
3. **Execute** – e.g.

```bash
python3 experiments/automation/run_suite.py --suite overhead \
  --agent-bin build/agent/micro_sentinel_agent \
  --agent-config config/micro_sentinel.toml \
  --metrics-port 9105 \
  --summary experiments/artifacts/latest_summary.json
```

4. **Verify artifacts** – Inspect `remote_fetch.log` (if present), open `run_result.json`, and make sure truth files exist under `truth/`.
5. **Ingest** – Feed the artifacts into ClickHouse / notebooks as described in the implementation plan.

## 8. Troubleshooting Checklist

| Symptom | Likely Cause | Fix |
| --- | --- | --- |
| `unknown flag: --token-rate` in instrumentation log | Old CLI flags persisted | Ensure config holds sampling knobs; automation now passes only `--config`/`--metrics-port`. |
| `remote_fetch.log` missing or empty | No remote artifacts declared | Confirm `metrics_dir` is set and truth logs register via `extra_artifacts`. |
| SSH command fails with “No such file or directory” | Remote `workdir` does not exist | Sync repo via `rsync` as described in `docs/TWO_NODE_DEPLOYMENT.md`. |
| NFV traffic never arrives | Stage hosts still default to loopback | Verify `chain.host` or per-stage `listen_host` equals `211.0.0.101`. |

## 9. Outstanding Enhancements

- Publish a suite catalog (`overhead.yaml`, `accuracy.yaml`, `interference.yaml`, …) and CI-style smoke tests.
- Extend `ResultRecorder` to ingest perf-stats summaries and MicroSentinel Prometheus snapshots.
- Add first-class support for ClickHouse/Prometheus dumps so analysis notebooks can be regenerated from a single artifact ID.

Until then, follow the workflow above to keep runs reproducible and to ensure every piece of telemetry ends up beside the associated logs.
