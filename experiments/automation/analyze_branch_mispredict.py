#!/usr/bin/env python3
"""Offline analysis for the branch mispredict experiment (§5.6).

Suite: `experiments/configs/experiments/branch_mispredict.yaml`.

What this script does:
- Scans artifacts under `artifacts/experiments/*`.
- Filters runs by `plan.overrides.annotations.suite == branch_mispredict`.
- Derives a ClickHouse query time window from `run_result.generated_at` and
  `plan.duration`.
- Queries `ms_flow_rollup` for the logical branch-mispredict event (default id=2)
  and ranks callstacks by `norm_cost`.
- Joins `ms_stack_traces` to extract a top frame function name for plotting.
- Extracts LB client throughput + latency (p99) from `run_result.json`.

Outputs:
- JSON: per-run details + aggregated summaries.
- CSV summary: one row per group.
- CSV hotspots: one row per (group, function) with mean/stdev cost.

Example:
  python3 -m experiments.automation.analyze_branch_mispredict \
    --artifact-root artifacts/experiments \
    --suite branch_mispredict \
    --out artifacts/experiments/branch_mispredict_summary.json \
    --out-csv artifacts/experiments/branch_mispredict_summary.csv \
    --out-csv-hotspots artifacts/experiments/branch_mispredict_hotspots.csv
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


MS_EVT_BRANCH_MISPRED = 2


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


def _extract_lb_metrics(run_result: Dict[str, Any]) -> Tuple[Optional[float], Optional[float]]:
    """Return (throughput_ops_per_s, latency_p99_us)."""
    for cmd in run_result.get("commands") or []:
        if not isinstance(cmd, dict):
            continue
        if cmd.get("name") != "lb-client":
            continue
        metrics = cmd.get("metrics")
        if not isinstance(metrics, dict):
            continue
        t = _as_float(metrics.get("throughput_ops_per_s"))
        p99 = None
        lat = metrics.get("latency_us")
        if isinstance(lat, dict):
            p99 = _as_float(lat.get("p99"))
        return t, p99
    return None, None


@dataclass(frozen=True)
class GroupKey:
    suite: str
    workload: str
    mode: str
    client_variant: str
    delta_us: Optional[int]
    pmu_events: str
    token_rate: Optional[int]

    def as_dict(self) -> Dict[str, Any]:
        return {
            "suite": self.suite,
            "workload": self.workload,
            "mode": self.mode,
            "client_variant": self.client_variant,
            "delta_us": self.delta_us,
            "pmu_events": self.pmu_events,
            "token_rate": self.token_rate,
        }


def analyze_one(
    artifact_dir: Path,
    ch: ClickHouse,
    rollup_table: str,
    stack_table: str,
    slack_s: int,
    event_id: int,
    topk: int,
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
        out["error"] = "no ClickHouse rollup rows found in time window"
        return out

    suite = _extract_suite(plan) or ""
    ann = _extract_annotations(plan)
    instr = _extract_instr(plan)

    client_variant = str(ann.get("client_variant") or "")

    lb_tput, lb_p99 = _extract_lb_metrics(rr)

    # Totals.
    sql_total = (
        f"SELECT sum(norm_cost) AS total_cost "
        f"FROM {rollup_table} "
        f"WHERE host = {_sql_str(host)} "
        f"  AND toUnixTimestamp64Nano(window_start) BETWEEN {t0} AND {t1}"
    )
    total_rows = _ch_rows(ch.query_json(sql_total))
    total_cost = float(total_rows[0].get("total_cost") or 0.0) if total_rows else 0.0

    sql_branch = (
        f"SELECT sum(norm_cost) AS branch_cost, sum(samples) AS branch_samples "
        f"FROM {rollup_table} "
        f"WHERE host = {_sql_str(host)} "
        f"  AND toUnixTimestamp64Nano(window_start) BETWEEN {t0} AND {t1} "
        f"  AND pmu_event = {int(event_id)}"
    )
    branch_rows = _ch_rows(ch.query_json(sql_branch))
    branch_cost = float(branch_rows[0].get("branch_cost") or 0.0) if branch_rows else 0.0
    branch_samples = int(branch_rows[0].get("branch_samples") or 0) if branch_rows else 0

    branch_share = float(branch_cost / total_cost) if total_cost > 0 else None

    # Hot callstacks: join stack traces, take the top frame function/bin.
    sql_hot = (
        "SELECT "
        "  r.callstack_id AS callstack_id, "
        "  any(tupleElement(arrayElement(s.frames, 1), 2)) AS top_function, "
        "  any(tupleElement(arrayElement(s.frames, 1), 1)) AS top_binary, "
        "  sum(r.samples) AS samples, "
        "  sum(r.norm_cost) AS norm_cost "
        f"FROM {rollup_table} AS r "
        f"LEFT JOIN {stack_table} AS s "
        "  ON s.host = r.host AND s.stack_id = r.callstack_id "
        f"WHERE r.host = {_sql_str(host)} "
        f"  AND toUnixTimestamp64Nano(r.window_start) BETWEEN {t0} AND {t1} "
        f"  AND r.pmu_event = {int(event_id)} "
        "  AND r.callstack_id != 0 "
        "GROUP BY callstack_id "
        "ORDER BY norm_cost DESC "
        f"LIMIT {int(topk)}"
    )
    hot = _ch_rows(ch.query_json(sql_hot))

    out.update(
        {
            "ok": True,
            "suite": suite,
            "workload": str(plan.get("workload") or ""),
            "mode": str(plan.get("mode") or ""),
            "duration": duration,
            "window": {"t0_unix_ns": t0, "t1_unix_ns": t1, "source": window_src},
            "host": host,
            "client_variant": client_variant,
            "delta_us": _as_int(instr.get("delta_us")),
            "pmu_events": _norm_pmu_events(instr.get("pmu_events")),
            "token_rate": _as_int(instr.get("token_rate")),
            "lb_throughput_ops_per_s": lb_tput,
            "lb_latency_p99_us": lb_p99,
            "total_norm_cost": total_cost,
            "branch_event_id": int(event_id),
            "branch_norm_cost": branch_cost,
            "branch_samples": branch_samples,
            "branch_share": branch_share,
            "hot_callstacks": hot,
        }
    )

    return out


def analyze(
    artifact_root: Path,
    suite_filter: Optional[str],
    clickhouse_endpoint: str,
    rollup_table: str,
    stack_table: str,
    slack_s: int,
    event_id: int,
    topk: int,
) -> Dict[str, Any]:
    ch = ClickHouse(clickhouse_endpoint)

    per_run: List[Dict[str, Any]] = []
    runs_scanned = 0
    runs_used = 0

    group_bucket: Dict[GroupKey, Dict[str, Any]] = {}
    hotspot_bucket: Dict[Tuple[GroupKey, str], Dict[str, Any]] = {}

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

        report = analyze_one(
            artifact_dir=artifact_dir,
            ch=ch,
            rollup_table=rollup_table,
            stack_table=stack_table,
            slack_s=slack_s,
            event_id=event_id,
            topk=topk,
        )
        per_run.append(report)
        if not report.get("ok"):
            continue

        runs_used += 1

        instr = _extract_instr(plan)
        ann = _extract_annotations(plan)
        key = GroupKey(
            suite=suite,
            workload=str(plan.get("workload") or ""),
            mode=str(plan.get("mode") or ""),
            client_variant=str(ann.get("client_variant") or ""),
            delta_us=_as_int(instr.get("delta_us")),
            pmu_events=_norm_pmu_events(instr.get("pmu_events")),
            token_rate=_as_int(instr.get("token_rate")),
        )

        g = group_bucket.setdefault(
            key,
            {
                **key.as_dict(),
                "branch_event_id": int(event_id),
                "values_branch_cost": [],
                "values_branch_share": [],
                "values_lb_tput": [],
                "values_lb_p99": [],
            },
        )
        g["values_branch_cost"].append(float(report.get("branch_norm_cost") or 0.0))
        if report.get("branch_share") is not None:
            g["values_branch_share"].append(float(report["branch_share"]))
        if report.get("lb_throughput_ops_per_s") is not None:
            g["values_lb_tput"].append(float(report["lb_throughput_ops_per_s"]))
        if report.get("lb_latency_p99_us") is not None:
            g["values_lb_p99"].append(float(report["lb_latency_p99_us"]))

        for row in report.get("hot_callstacks") or []:
            if not isinstance(row, dict):
                continue
            func = str(row.get("top_function") or "")
            if not func:
                func = f"callstack_{row.get('callstack_id') or 0}"
            norm_cost = float(row.get("norm_cost") or 0.0)
            samples = float(row.get("samples") or 0.0)
            hk = (key, func)
            hb = hotspot_bucket.setdefault(
                hk,
                {
                    **key.as_dict(),
                    "branch_event_id": int(event_id),
                    "function": func,
                    "values_norm_cost": [],
                    "values_samples": [],
                },
            )
            hb["values_norm_cost"].append(norm_cost)
            hb["values_samples"].append(samples)

    summary: List[Dict[str, Any]] = []
    for _k, agg in group_bucket.items():
        bc = [float(v) for v in agg.get("values_branch_cost") or []]
        bs = [float(v) for v in agg.get("values_branch_share") or []]
        tp = [float(v) for v in agg.get("values_lb_tput") or []]
        p9 = [float(v) for v in agg.get("values_lb_p99") or []]
        summary.append(
            {
                **{k: v for k, v in agg.items() if not k.startswith("values_")},
                "n": len(bc),
                "branch_cost_mean": _mean(bc),
                "branch_cost_stdev": _stdev(bc),
                "branch_share_mean": _mean(bs) if bs else None,
                "branch_share_stdev": _stdev(bs) if bs else None,
                "lb_throughput_mean": _mean(tp) if tp else None,
                "lb_throughput_stdev": _stdev(tp) if tp else None,
                "lb_latency_p99_us_mean": _mean(p9) if p9 else None,
                "lb_latency_p99_us_stdev": _stdev(p9) if p9 else None,
            }
        )

    hotspots: List[Dict[str, Any]] = []
    for _k, agg in hotspot_bucket.items():
        nc = [float(v) for v in agg.get("values_norm_cost") or []]
        sm = [float(v) for v in agg.get("values_samples") or []]
        hotspots.append(
            {
                **{k: v for k, v in agg.items() if not k.startswith("values_")},
                "n": len(nc),
                "norm_cost_mean": _mean(nc),
                "norm_cost_stdev": _stdev(nc),
                "samples_mean": _mean(sm),
                "samples_stdev": _stdev(sm),
            }
        )

    summary.sort(key=lambda r: (r.get("client_variant") or "", r.get("pmu_events") or ""))
    hotspots.sort(key=lambda r: float(r.get("norm_cost_mean") or 0.0) * -1.0)

    return {
        "ok": True,
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "artifact_root": str(artifact_root),
        "suite_filter": suite_filter,
        "clickhouse_endpoint": clickhouse_endpoint,
        "tables": {"rollup": rollup_table, "stack": stack_table},
        "branch_event_id": int(event_id),
        "topk": int(topk),
        "runs_scanned": runs_scanned,
        "runs_used": runs_used,
        "summary": summary,
        "hotspots": hotspots,
        "per_run": per_run,
    }


def _write_csv_summary(path: Path, report: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fields = [
        "suite",
        "workload",
        "mode",
        "client_variant",
        "delta_us",
        "pmu_events",
        "token_rate",
        "branch_event_id",
        "n",
        "branch_cost_mean",
        "branch_cost_stdev",
        "branch_share_mean",
        "branch_share_stdev",
        "lb_throughput_mean",
        "lb_throughput_stdev",
        "lb_latency_p99_us_mean",
        "lb_latency_p99_us_stdev",
    ]
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for row in report.get("summary") or []:
            if not isinstance(row, dict):
                continue
            w.writerow({k: row.get(k) for k in fields})


def _write_csv_hotspots(path: Path, report: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fields = [
        "suite",
        "workload",
        "mode",
        "client_variant",
        "delta_us",
        "pmu_events",
        "token_rate",
        "branch_event_id",
        "function",
        "n",
        "norm_cost_mean",
        "norm_cost_stdev",
        "samples_mean",
        "samples_stdev",
    ]
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for row in report.get("hotspots") or []:
            if not isinstance(row, dict):
                continue
            w.writerow({k: row.get(k) for k in fields})


def main() -> int:
    ap = argparse.ArgumentParser(description="Analyze branch mispredict experiment from artifacts + ClickHouse")
    ap.add_argument("--artifact-root", default="artifacts/experiments", help="Artifacts directory to scan")
    ap.add_argument("--suite", default="branch_mispredict", help="Filter by plan.overrides.annotations.suite (empty disables)")
    ap.add_argument("--agent-conf", default="agent/agent.conf", help="Path to agent.conf (for ClickHouse endpoint/table names)")
    ap.add_argument("--clickhouse-endpoint", default=None, help="Override ClickHouse HTTP endpoint")
    ap.add_argument("--rollup-table", default=None, help="Override rollup table (default from agent.conf)")
    ap.add_argument("--stack-table", default="ms_stack_traces", help="Override stack trace table")
    ap.add_argument("--event-id", type=int, default=MS_EVT_BRANCH_MISPRED, help="Logical event id to use (default: 2)")
    ap.add_argument("--topk", type=int, default=100, help="Top callstacks per run")
    ap.add_argument("--slack-s", type=int, default=10, help="Extra seconds around derived time window")
    ap.add_argument("--out", default=None, help="Write JSON report")
    ap.add_argument("--out-csv", default=None, help="Write summary CSV")
    ap.add_argument("--out-csv-hotspots", default=None, help="Write hotspots CSV")
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
        stack_table=args.stack_table,
        slack_s=max(0, int(args.slack_s)),
        event_id=int(args.event_id),
        topk=max(1, int(args.topk)),
    )

    if args.out:
        out_path = Path(args.out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    else:
        print(json.dumps(report, indent=2))

    if args.out_csv:
        _write_csv_summary(Path(args.out_csv), report)
    if args.out_csv_hotspots:
        _write_csv_hotspots(Path(args.out_csv_hotspots), report)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
