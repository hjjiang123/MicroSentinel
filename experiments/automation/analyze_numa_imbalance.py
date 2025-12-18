#!/usr/bin/env python3
"""Offline analysis for the NUMA imbalance experiment (§5.5).

The suite (`experiments/configs/experiments/numa_imbalance.yaml`) typically uses
NUMA actions like:
  numactl --cpunodebind=0 --membind=1

This script:
- Scans artifacts under `artifacts/experiments/*`.
- Filters runs by `plan.overrides.annotations.suite == numa_imbalance`.
- Derives a ClickHouse query time window from `run_result.generated_at` and
  `plan.duration`.
- Queries `ms_flow_rollup` to aggregate `norm_cost` and `samples` by `numa_node`
  (and optionally by `pmu_event`).
- Computes a "remote ratio" as the share of `norm_cost` attributed to the
  `--membind` node (if present), both overall and for logical REMOTE_DRAM
  (event id 7) when present.
- Extracts KV client p99 latency from `run_result.json` if available.

Outputs:
- JSON report with per-run details and aggregated group summaries.
- CSV summaries:
  - `--out-csv`: one row per group with mean/stdev for ratios + latency
  - `--out-csv-nodes`: one row per (group, numa_node) with mean/stdev shares

Example:
  python3 -m experiments.automation.analyze_numa_imbalance \
    --artifact-root artifacts/experiments \
    --suite numa_imbalance \
    --out artifacts/experiments/numa_imbalance_summary.json \
    --out-csv artifacts/experiments/numa_imbalance_summary.csv \
    --out-csv-nodes artifacts/experiments/numa_imbalance_nodes.csv
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import statistics
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple


MS_EVT_REMOTE_DRAM = 7


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _get_nested(mapping: Any, path: List[str]) -> Any:
    cur = mapping
    for key in path:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(key)
    return cur


def _as_int(value: Any) -> Optional[int]:
    if value is None:
        return None
    try:
        return int(value)
    except Exception:
        return None


def _as_float(value: Any) -> Optional[float]:
    if value is None:
        return None
    try:
        return float(value)
    except Exception:
        return None


def _sql_str(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace("'", "\\'")
    return "'" + escaped + "'"


def _parse_agent_conf(path: Path) -> Dict[str, str]:
    if not path.exists():
        return {}
    values: Dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        values[k.strip()] = v.strip()
    return values


def _extract_suite(plan: Optional[Dict[str, Any]]) -> Optional[str]:
    if not isinstance(plan, dict):
        return None
    suite = (
        _get_nested(plan, ["overrides", "annotations", "suite"])
        or _get_nested(plan, ["annotations", "suite"])
        or plan.get("suite")
    )
    return str(suite) if suite else None


def _extract_annotations(plan: Dict[str, Any]) -> Dict[str, Any]:
    ann = _get_nested(plan, ["overrides", "annotations"]) or _get_nested(plan, ["annotations"]) or {}
    return ann if isinstance(ann, dict) else {}


def _extract_instr(plan: Dict[str, Any]) -> Dict[str, Any]:
    instr = _get_nested(plan, ["overrides", "instrumentation"])
    return instr if isinstance(instr, dict) else {}


def _norm_pmu_events(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return ",".join(part.strip() for part in value.split(",") if part.strip())
    if isinstance(value, (list, tuple)):
        return ",".join(str(part).strip() for part in value if str(part).strip())
    return str(value)


def _parse_generated_at(value: Any) -> Optional[datetime]:
    if not isinstance(value, str) or not value:
        return None
    s = value.strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(s)
    except Exception:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _dt_to_unix_ns(dt: datetime) -> int:
    return int(dt.timestamp() * 1_000_000_000)


_TS_RE = re.compile(r'"ts"\s*:\s*(\d+)')


def _extract_ts_range_from_instrumentation_log(artifact_dir: Path) -> Optional[Tuple[int, int]]:
    log_path = artifact_dir / "instrumentation_microsentinel.log"
    if not log_path.exists():
        return None

    t0: Optional[int] = None
    t1: Optional[int] = None
    try:
        with log_path.open("r", encoding="utf-8", errors="replace") as f:
            for line in f:
                if '"ts"' not in line:
                    continue
                m = _TS_RE.search(line)
                if not m:
                    continue
                try:
                    ts = int(m.group(1))
                except Exception:
                    continue
                if ts <= 0:
                    continue
                t0 = ts if t0 is None else min(t0, ts)
                t1 = ts if t1 is None else max(t1, ts)
    except Exception:
        return None

    if t0 is None or t1 is None or t1 <= t0:
        return None
    return t0, t1


def _mean(values: List[float]) -> Optional[float]:
    if not values:
        return None
    return float(statistics.mean(values))


def _stdev(values: List[float]) -> Optional[float]:
    if len(values) < 2:
        return None
    return float(statistics.stdev(values))


class ClickHouse:
    def __init__(self, endpoint: str):
        self.endpoint = endpoint.rstrip("/")

    def query_json(self, sql: str) -> Dict[str, Any]:
        q = urllib.parse.quote(sql + " FORMAT JSON")
        url = f"{self.endpoint}/?query={q}"
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=20.0) as resp:
            body = resp.read().decode("utf-8", errors="replace")
        return json.loads(body)


def _ch_rows(resp: Dict[str, Any]) -> List[Dict[str, Any]]:
    data = resp.get("data")
    return data if isinstance(data, list) else []


def _walk_artifacts(root: Path) -> Iterable[Path]:
    if not root.exists():
        return
    for child in root.iterdir():
        if child.is_dir() and ((child / "plan.json").exists() or (child / "run_result.json").exists()):
            yield child


def _guess_host(ch: ClickHouse, rollup_table: str, t0_ns: int, t1_ns: int) -> Optional[str]:
    sql = (
        f"SELECT host, count() AS c "
        f"FROM {rollup_table} "
        f"WHERE toUnixTimestamp64Nano(window_start) BETWEEN {t0_ns} AND {t1_ns} "
        f"GROUP BY host ORDER BY c DESC LIMIT 1"
    )
    rows = _ch_rows(ch.query_json(sql))
    if not rows:
        return None
    return rows[0].get("host")


_NUMACTL_CPU_RE = re.compile(r"--cpunodebind=(\d+)")
_NUMACTL_MEM_RE = re.compile(r"--membind=(\d+)")


def _parse_numactl_nodes(numa_policy: Any) -> Tuple[Optional[int], Optional[int]]:
    if not isinstance(numa_policy, str):
        return None, None
    cpu_m = _NUMACTL_CPU_RE.search(numa_policy)
    mem_m = _NUMACTL_MEM_RE.search(numa_policy)
    cpu = int(cpu_m.group(1)) if cpu_m else None
    mem = int(mem_m.group(1)) if mem_m else None
    return cpu, mem


def _extract_kv_p99_latency(run_result: Dict[str, Any]) -> Optional[float]:
    # `ResultRecorder` stores per-command metrics as JSON if present.
    p99s: List[float] = []
    for cmd in run_result.get("commands") or []:
        if not isinstance(cmd, dict):
            continue
        if cmd.get("role") != "client":
            continue
        metrics = cmd.get("metrics")
        if not isinstance(metrics, dict):
            continue
        lat = metrics.get("latency_us")
        if isinstance(lat, dict) and "p99" in lat:
            v = _as_float(lat.get("p99"))
            if v is not None:
                p99s.append(v)
    if not p99s:
        return None
    # Conservative aggregation across clients: take max p99.
    return float(max(p99s))


@dataclass(frozen=True)
class GroupKey:
    suite: str
    workload: str
    mode: str
    numa_action: str
    cpu_node: Optional[int]
    mem_node: Optional[int]
    delta_us: Optional[int]
    pmu_events: str
    token_rate: Optional[int]

    def as_dict(self) -> Dict[str, Any]:
        return {
            "suite": self.suite,
            "workload": self.workload,
            "mode": self.mode,
            "numa_action": self.numa_action,
            "cpu_node": self.cpu_node,
            "mem_node": self.mem_node,
            "delta_us": self.delta_us,
            "pmu_events": self.pmu_events,
            "token_rate": self.token_rate,
        }


def analyze_one(
    artifact_dir: Path,
    ch: ClickHouse,
    rollup_table: str,
    slack_s: int,
) -> Dict[str, Any]:
    out: Dict[str, Any] = {"artifact_dir": str(artifact_dir), "ok": False}

    rr_path = artifact_dir / "run_result.json"
    plan_path = artifact_dir / "plan.json"
    if not rr_path.exists() or not plan_path.exists():
        out["error"] = "plan/run_result not found"
        return out

    rr = _load_json(rr_path)
    plan = rr.get("plan") if isinstance(rr.get("plan"), dict) else _load_json(plan_path)
    if not isinstance(plan, dict):
        out["error"] = "invalid plan"
        return out

    generated_at = _parse_generated_at(rr.get("generated_at"))
    duration = _as_int(plan.get("duration")) or 0

    ts_range = _extract_ts_range_from_instrumentation_log(artifact_dir)
    if ts_range is not None:
        base_t0, base_t1 = ts_range
        t0 = base_t0 - slack_s * 1_000_000_000
        t1 = base_t1 + slack_s * 1_000_000_000
        window_src = "instrumentation_log"
    else:
        if not generated_at or duration <= 0:
            out["error"] = "cannot derive time window"
            return out

        t1 = _dt_to_unix_ns(generated_at) + slack_s * 1_000_000_000
        t0 = _dt_to_unix_ns(generated_at) - (duration + slack_s) * 1_000_000_000
        window_src = "generated_at"

    host = _guess_host(ch, rollup_table, t0, t1)
    if not host:
        out["error"] = "no ClickHouse samples found in time window"
        return out

    suite = _extract_suite(plan) or ""
    ann = _extract_annotations(plan)
    instr = _extract_instr(plan)

    # numactl prefix was applied to kv-server command; keep it in overrides.
    server_numa = _get_nested(plan, ["overrides", "workload", "server", "numa_policy"]) or _get_nested(plan, ["overrides", "server", "numa_policy"])
    cpu_node, mem_node = _parse_numactl_nodes(server_numa)

    out.update(
        {
            "ok": True,
            "suite": suite,
            "workload": str(plan.get("workload") or ""),
            "mode": str(plan.get("mode") or ""),
            "duration": duration,
            "window": {"t0_unix_ns": t0, "t1_unix_ns": t1, "source": window_src},
            "host": host,
            "numa_action": str(ann.get("numa_action") or ""),
            "cpu_node": cpu_node,
            "mem_node": mem_node,
            "delta_us": _as_int(instr.get("delta_us")),
            "pmu_events": _norm_pmu_events(instr.get("pmu_events")),
            "token_rate": _as_int(instr.get("token_rate")),
        }
    )

    # Aggregate cost/samples by node (all events).
    sql_nodes = (
        "SELECT numa_node, sum(samples) AS samples, sum(norm_cost) AS norm_cost "
        f"FROM {rollup_table} "
        f"WHERE host = {_sql_str(host)} "
        f"  AND toUnixTimestamp64Nano(window_start) BETWEEN {t0} AND {t1} "
        "GROUP BY numa_node ORDER BY norm_cost DESC"
    )
    nodes = _ch_rows(ch.query_json(sql_nodes))

    total_cost = sum(float(r.get("norm_cost") or 0.0) for r in nodes)
    for r in nodes:
        share = float((float(r.get("norm_cost") or 0.0) / total_cost)) if total_cost > 0 else 0.0
        r["share_norm_cost"] = share
    out["by_node"] = nodes
    out["total_norm_cost"] = total_cost

    # By (pmu_event, node) for deeper debugging.
    sql_event = (
        "SELECT pmu_event, numa_node, sum(samples) AS samples, sum(norm_cost) AS norm_cost "
        f"FROM {rollup_table} "
        f"WHERE host = {_sql_str(host)} "
        f"  AND toUnixTimestamp64Nano(window_start) BETWEEN {t0} AND {t1} "
        "GROUP BY pmu_event, numa_node ORDER BY pmu_event, norm_cost DESC"
    )
    rows = _ch_rows(ch.query_json(sql_event))
    out["by_event_node"] = rows

    # Derived ratios.
    def _ratio_for_mem_node(rows_in: List[Dict[str, Any]], node: Optional[int]) -> Optional[float]:
        if node is None:
            return None
        denom = sum(float(x.get("norm_cost") or 0.0) for x in rows_in)
        if denom <= 0:
            return None
        num = sum(float(x.get("norm_cost") or 0.0) for x in rows_in if int(x.get("numa_node") or -1) == int(node))
        return float(num / denom)

    out["remote_ratio_all"] = _ratio_for_mem_node(nodes, mem_node)

    remote_rows = [r for r in rows if int(r.get("pmu_event") or 0) == MS_EVT_REMOTE_DRAM]
    out["remote_ratio_remote_dram"] = _ratio_for_mem_node(remote_rows, mem_node) if remote_rows else None

    out["kv_latency_p99_us"] = _extract_kv_p99_latency(rr)

    return out


def analyze(
    artifact_root: Path,
    suite_filter: Optional[str],
    clickhouse_endpoint: str,
    rollup_table: str,
    slack_s: int,
) -> Dict[str, Any]:
    ch = ClickHouse(clickhouse_endpoint)

    per_run: List[Dict[str, Any]] = []
    runs_scanned = 0
    runs_used = 0

    # Summary buckets.
    summary_bucket: Dict[GroupKey, Dict[str, Any]] = {}
    node_bucket: Dict[Tuple[GroupKey, int], Dict[str, Any]] = {}

    for artifact_dir in _walk_artifacts(artifact_root):
        rr_path = artifact_dir / "run_result.json"
        plan_path = artifact_dir / "plan.json"
        if not rr_path.exists() or not plan_path.exists():
            continue

        runs_scanned += 1
        try:
            rr = _load_json(rr_path)
            plan = rr.get("plan") if isinstance(rr.get("plan"), dict) else _load_json(plan_path)
        except Exception:
            continue
        if not isinstance(plan, dict):
            continue

        suite = _extract_suite(plan) or ""
        if suite_filter and suite != suite_filter:
            continue

        report = analyze_one(artifact_dir, ch, rollup_table, slack_s)
        per_run.append(report)
        if not report.get("ok"):
            continue

        runs_used += 1
        ann = _extract_annotations(plan)
        instr = _extract_instr(plan)
        server_numa = _get_nested(plan, ["overrides", "workload", "server", "numa_policy"]) or _get_nested(plan, ["overrides", "server", "numa_policy"])
        cpu_node, mem_node = _parse_numactl_nodes(server_numa)

        key = GroupKey(
            suite=suite,
            workload=str(plan.get("workload") or ""),
            mode=str(plan.get("mode") or ""),
            numa_action=str(ann.get("numa_action") or ""),
            cpu_node=cpu_node,
            mem_node=mem_node,
            delta_us=_as_int(instr.get("delta_us")),
            pmu_events=_norm_pmu_events(instr.get("pmu_events")),
            token_rate=_as_int(instr.get("token_rate")),
        )

        sum_entry = summary_bucket.setdefault(
            key,
            {
                **key.as_dict(),
                "values_remote_ratio_all": [],
                "values_remote_ratio_remote_dram": [],
                "values_latency_p99_us": [],
            },
        )
        if report.get("remote_ratio_all") is not None:
            sum_entry["values_remote_ratio_all"].append(float(report["remote_ratio_all"]))
        if report.get("remote_ratio_remote_dram") is not None:
            sum_entry["values_remote_ratio_remote_dram"].append(float(report["remote_ratio_remote_dram"]))
        if report.get("kv_latency_p99_us") is not None:
            sum_entry["values_latency_p99_us"].append(float(report["kv_latency_p99_us"]))

        for row in report.get("by_node") or []:
            if not isinstance(row, dict):
                continue
            node = int(row.get("numa_node") or 0)
            share = float(row.get("share_norm_cost") or 0.0)
            cost = float(row.get("norm_cost") or 0.0)
            k2 = (key, node)
            nb = node_bucket.setdefault(
                k2,
                {
                    **key.as_dict(),
                    "numa_node": node,
                    "values_share": [],
                    "values_norm_cost": [],
                },
            )
            nb["values_share"].append(share)
            nb["values_norm_cost"].append(cost)

    summaries: List[Dict[str, Any]] = []
    for _k, agg in summary_bucket.items():
        r_all = [float(v) for v in agg.get("values_remote_ratio_all") or []]
        r_rd = [float(v) for v in agg.get("values_remote_ratio_remote_dram") or []]
        lat = [float(v) for v in agg.get("values_latency_p99_us") or []]
        summaries.append(
            {
                **{k: v for k, v in agg.items() if not k.startswith("values_")},
                "n_remote_ratio_all": len(r_all),
                "remote_ratio_all_mean": _mean(r_all),
                "remote_ratio_all_stdev": _stdev(r_all),
                "n_remote_ratio_remote_dram": len(r_rd),
                "remote_ratio_remote_dram_mean": _mean(r_rd),
                "remote_ratio_remote_dram_stdev": _stdev(r_rd),
                "n_latency_p99_us": len(lat),
                "latency_p99_us_mean": _mean(lat),
                "latency_p99_us_stdev": _stdev(lat),
            }
        )

    nodes_out: List[Dict[str, Any]] = []
    for _k, agg in node_bucket.items():
        sh = [float(v) for v in agg.get("values_share") or []]
        nc = [float(v) for v in agg.get("values_norm_cost") or []]
        nodes_out.append(
            {
                **{k: v for k, v in agg.items() if not k.startswith("values_")},
                "n": len(sh),
                "share_mean": _mean(sh),
                "share_stdev": _stdev(sh),
                "norm_cost_mean": _mean(nc),
                "norm_cost_stdev": _stdev(nc),
            }
        )

    summaries.sort(key=lambda r: (r.get("mode") or "", r.get("numa_action") or ""))
    nodes_out.sort(key=lambda r: (r.get("mode") or "", int(r.get("numa_node") or 0)))

    return {
        "ok": True,
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "artifact_root": str(artifact_root),
        "suite_filter": suite_filter,
        "clickhouse_endpoint": clickhouse_endpoint,
        "tables": {"rollup": rollup_table},
        "runs_scanned": runs_scanned,
        "runs_used": runs_used,
        "summary": summaries,
        "nodes": nodes_out,
        "per_run": per_run,
    }


def _write_csv_summary(path: Path, report: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fields = [
        "suite",
        "workload",
        "mode",
        "numa_action",
        "cpu_node",
        "mem_node",
        "delta_us",
        "pmu_events",
        "token_rate",
        "n_remote_ratio_all",
        "remote_ratio_all_mean",
        "remote_ratio_all_stdev",
        "n_remote_ratio_remote_dram",
        "remote_ratio_remote_dram_mean",
        "remote_ratio_remote_dram_stdev",
        "n_latency_p99_us",
        "latency_p99_us_mean",
        "latency_p99_us_stdev",
    ]
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for row in report.get("summary") or []:
            if not isinstance(row, dict):
                continue
            w.writerow({k: row.get(k) for k in fields})


def _write_csv_nodes(path: Path, report: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fields = [
        "suite",
        "workload",
        "mode",
        "numa_action",
        "cpu_node",
        "mem_node",
        "delta_us",
        "pmu_events",
        "token_rate",
        "numa_node",
        "n",
        "share_mean",
        "share_stdev",
        "norm_cost_mean",
        "norm_cost_stdev",
    ]
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for row in report.get("nodes") or []:
            if not isinstance(row, dict):
                continue
            w.writerow({k: row.get(k) for k in fields})


def main() -> int:
    ap = argparse.ArgumentParser(description="Analyze NUMA imbalance from artifacts + ClickHouse")
    ap.add_argument("--artifact-root", default="artifacts/experiments", help="Artifacts directory to scan")
    ap.add_argument("--suite", default="numa_imbalance", help="Filter by plan.overrides.annotations.suite (empty disables)")
    ap.add_argument("--agent-conf", default="agent/agent.conf", help="Path to agent.conf (for ClickHouse endpoint/table names)")
    ap.add_argument("--clickhouse-endpoint", default=None, help="Override ClickHouse HTTP endpoint")
    ap.add_argument("--rollup-table", default=None, help="Override rollup table (default from agent.conf)")
    ap.add_argument("--slack-s", type=int, default=10, help="Extra seconds around derived time window")
    ap.add_argument("--out", default=None, help="Write JSON report")
    ap.add_argument("--out-csv", default=None, help="Write summary CSV")
    ap.add_argument("--out-csv-nodes", default=None, help="Write per-node CSV")
    args = ap.parse_args()

    conf = _parse_agent_conf(Path(args.agent_conf))
    endpoint = args.clickhouse_endpoint or conf.get("clickhouse_endpoint") or "http://127.0.0.1:8123"
    rollup = args.rollup_table or conf.get("clickhouse_table") or "ms_flow_rollup"
    suite_filter = args.suite if args.suite else None

    report = analyze(
        artifact_root=Path(args.artifact_root),
        suite_filter=suite_filter,
        clickhouse_endpoint=endpoint,
        rollup_table=rollup,
        slack_s=max(0, int(args.slack_s)),
    )

    if args.out:
        out_path = Path(args.out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    else:
        print(json.dumps(report, indent=2))

    if args.out_csv:
        _write_csv_summary(Path(args.out_csv), report)
    if args.out_csv_nodes:
        _write_csv_nodes(Path(args.out_csv_nodes), report)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
