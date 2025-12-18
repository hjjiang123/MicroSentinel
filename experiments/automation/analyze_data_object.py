#!/usr/bin/env python3
"""Offline analysis for the data-object attribution experiment (§5.3).

This script reads per-run artifacts (plan/run_result) and queries ClickHouse to
summarize attribution by `data_object_id`.

Data sources:
- Artifacts: `<artifact_dir>/{plan.json,run_result.json}` for run metadata
  (mode, duration, overrides like delta_us / pmu_events / token_rate).
- ClickHouse:
  - `ms_flow_rollup` for aggregated samples + norm_cost and `data_object_id`
  - `ms_data_objects` for human-friendly mapping metadata

Time window:
- By default we approximate the run's sampling window as:
  [generated_at - duration - slack_s, generated_at + slack_s]
  where `generated_at` comes from `run_result.json`.

Outputs:
- JSON report with per-run and aggregated summaries
- CSV with one row per (group, pmu_event, data_object_id)

Example:
  python3 -m experiments.automation.analyze_data_object \
    --artifact-root artifacts/experiments \
    --suite data_object \
    --out artifacts/experiments/data_object_summary.json \
    --out-csv artifacts/experiments/data_object_summary.csv
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
    # run_result.json uses `datetime.utcnow().isoformat() + 'Z'`
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
    """Best-effort: parse ClickHouse JSONEachRow payload in instrumentation logs.

    Many runs write `instrumentation_microsentinel.log` containing lines like:
      {"ts":585914251222648,...}

    Those `ts` values match what's inserted into ClickHouse tables (`DateTime64(9)`),
    even if they are not wallclock UNIX time (e.g. monotonic ns interpreted as epoch).
    """

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


class ClickHouse:
    def __init__(self, endpoint: str):
        self.endpoint = endpoint.rstrip("/")

    def query_json(self, sql: str) -> Dict[str, Any]:
        q = urllib.parse.quote(sql + " FORMAT JSON")
        url = f"{self.endpoint}/?query={q}"
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=15.0) as resp:
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


_PMU_EVENT_NAMES = {
    1: "L3_MISS",
    2: "BRANCH_MISPRED",
    3: "ICACHE_STALL",
    4: "AVX_DOWNCLOCK",
    5: "STALL_BACKEND",
    6: "XSNP_HITM",
    7: "REMOTE_DRAM",
}


@dataclass(frozen=True)
class GroupKey:
    suite: str
    workload: str
    mode: str
    delta_us: Optional[int]
    pmu_events: str
    token_rate: Optional[int]
    object_map_preset: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "suite": self.suite,
            "workload": self.workload,
            "mode": self.mode,
            "delta_us": self.delta_us,
            "pmu_events": self.pmu_events,
            "token_rate": self.token_rate,
            "object_map_preset": self.object_map_preset,
        }


def analyze_one(
    artifact_dir: Path,
    ch: ClickHouse,
    rollup_table: str,
    data_objects_table: str,
    slack_s: int,
) -> Dict[str, Any]:
    out: Dict[str, Any] = {"artifact_dir": str(artifact_dir), "ok": False}

    rr_path = artifact_dir / "run_result.json"
    plan_path = artifact_dir / "plan.json"
    if rr_path.exists():
        rr = _load_json(rr_path)
        plan = rr.get("plan") if isinstance(rr.get("plan"), dict) else None
        generated_at = _parse_generated_at(rr.get("generated_at"))
    else:
        rr = None
        plan = _load_json(plan_path) if plan_path.exists() else None
        generated_at = None

    if not isinstance(plan, dict):
        out["error"] = "plan not found"
        return out

    suite = _extract_suite(plan) or ""
    out["suite"] = suite
    out["plan"] = plan

    duration = _as_int(plan.get("duration")) or 0
    mode = str(plan.get("mode") or "")
    workload = str(plan.get("workload") or "")
    instr = _extract_instr(plan)

    delta_us = _as_int(instr.get("delta_us"))
    pmu_events = _norm_pmu_events(instr.get("pmu_events"))
    token_rate = _as_int(instr.get("token_rate"))
    object_map_preset = str(instr.get("object_map_preset") or "")

    out.update(
        {
            "workload": workload,
            "mode": mode,
            "duration": duration,
            "delta_us": delta_us,
            "pmu_events": pmu_events,
            "token_rate": token_rate,
            "object_map_preset": object_map_preset,
        }
    )

    # Prefer deriving the ClickHouse query window from instrumentation logs.
    # This keeps analysis working even when the agent writes non-wallclock timestamps.
    ts_range = _extract_ts_range_from_instrumentation_log(artifact_dir)
    if ts_range is not None:
        base_t0, base_t1 = ts_range
        t0 = base_t0 - slack_s * 1_000_000_000
        t1 = base_t1 + slack_s * 1_000_000_000
        out["window"] = {"t0_unix_ns": t0, "t1_unix_ns": t1, "source": "instrumentation_log"}
    else:
        if not generated_at:
            # Best-effort fallback: use mtime of run_result.json if present.
            try:
                ts = rr_path.stat().st_mtime
                generated_at = datetime.fromtimestamp(ts, tz=timezone.utc)
            except Exception:
                generated_at = None

        if not generated_at or duration <= 0:
            out["error"] = "cannot derive time window (missing generated_at or duration)"
            return out

        t1 = _dt_to_unix_ns(generated_at) + slack_s * 1_000_000_000
        t0 = _dt_to_unix_ns(generated_at) - (duration + slack_s) * 1_000_000_000
        out["window"] = {"t0_unix_ns": t0, "t1_unix_ns": t1, "source": "generated_at"}

    host = _guess_host(ch, rollup_table, t0, t1)
    if not host:
        out["error"] = "no ClickHouse samples found in time window"
        return out
    out["host"] = host

    sql = (
        "SELECT "
        "  r.pmu_event AS pmu_event, "
        "  r.data_object_id AS data_object_id, "
        "  any(d.mapping) AS mapping, "
        "  any(d.base) AS base, "
        "  any(d.size) AS size, "
        "  sum(r.samples) AS samples, "
        "  sum(r.norm_cost) AS norm_cost "
        f"FROM {rollup_table} AS r "
        f"LEFT JOIN {data_objects_table} AS d "
        "  ON d.host = r.host AND d.object_id = r.data_object_id "
        f"WHERE r.host = {_sql_str(host)} "
        f"  AND toUnixTimestamp64Nano(r.window_start) BETWEEN {t0} AND {t1} "
        "  AND r.data_object_id != 0 "
        "GROUP BY pmu_event, data_object_id "
        "ORDER BY norm_cost DESC "
        "LIMIT 100000"
    )

    rows = _ch_rows(ch.query_json(sql))
    if not rows:
        out["error"] = "no data_object rows in ClickHouse for this run"
        return out

    # Compute per-pmu totals to produce shares.
    totals: Dict[int, float] = {}
    totals_samples: Dict[int, int] = {}
    for row in rows:
        pmu = _as_int(row.get("pmu_event")) or 0
        totals[pmu] = totals.get(pmu, 0.0) + float(row.get("norm_cost") or 0.0)
        totals_samples[pmu] = totals_samples.get(pmu, 0) + int(row.get("samples") or 0)

    entries: List[Dict[str, Any]] = []
    for row in rows:
        pmu = _as_int(row.get("pmu_event")) or 0
        obj = _as_int(row.get("data_object_id")) or 0
        norm_cost = float(row.get("norm_cost") or 0.0)
        samples = int(row.get("samples") or 0)
        denom = totals.get(pmu, 0.0)
        share = float(norm_cost / denom) if denom > 0 else 0.0
        mapping = row.get("mapping")
        entry = {
            "pmu_event": pmu,
            "pmu_event_name": _PMU_EVENT_NAMES.get(pmu, str(pmu)),
            "data_object_id": obj,
            "mapping": mapping if isinstance(mapping, str) else "",
            "base": int(row.get("base") or 0),
            "size": int(row.get("size") or 0),
            "samples": samples,
            "norm_cost": norm_cost,
            "share_norm_cost": share,
            "pmu_total_norm_cost": denom,
            "pmu_total_samples": totals_samples.get(pmu, 0),
        }
        entries.append(entry)

    out["ok"] = True
    out["entries"] = entries
    out["pmu_totals"] = {
        str(pmu): {"norm_cost": totals.get(pmu, 0.0), "samples": totals_samples.get(pmu, 0)}
        for pmu in sorted(totals.keys())
    }
    return out


def _mean(values: List[float]) -> Optional[float]:
    if not values:
        return None
    return float(statistics.mean(values))


def _stdev(values: List[float]) -> Optional[float]:
    if len(values) < 2:
        return None
    return float(statistics.stdev(values))


def analyze(
    artifact_root: Path,
    suite_filter: Optional[str],
    clickhouse_endpoint: str,
    rollup_table: str,
    data_objects_table: str,
    slack_s: int,
) -> Dict[str, Any]:
    ch = ClickHouse(clickhouse_endpoint)

    per_run: List[Dict[str, Any]] = []
    runs_scanned = 0
    runs_used = 0

    # Aggregation: key + (pmu_event, data_object_id)
    bucket: Dict[Tuple[GroupKey, int, int], Dict[str, Any]] = {}

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

        report = analyze_one(artifact_dir, ch, rollup_table, data_objects_table, slack_s)
        per_run.append(report)
        if not report.get("ok"):
            continue

        runs_used += 1

        instr = _extract_instr(plan)
        key = GroupKey(
            suite=suite,
            workload=str(plan.get("workload") or ""),
            mode=str(plan.get("mode") or ""),
            delta_us=_as_int(instr.get("delta_us")),
            pmu_events=_norm_pmu_events(instr.get("pmu_events")),
            token_rate=_as_int(instr.get("token_rate")),
            object_map_preset=str(instr.get("object_map_preset") or ""),
        )

        for entry in report.get("entries") or []:
            if not isinstance(entry, dict):
                continue
            pmu = _as_int(entry.get("pmu_event")) or 0
            obj = _as_int(entry.get("data_object_id")) or 0
            mapping = str(entry.get("mapping") or "")
            k = (key, pmu, obj)
            agg = bucket.setdefault(
                k,
                {
                    **key.as_dict(),
                    "pmu_event": pmu,
                    "pmu_event_name": entry.get("pmu_event_name"),
                    "data_object_id": obj,
                    "mapping": mapping,
                    "values_norm_cost": [],
                    "values_share": [],
                    "values_samples": [],
                },
            )
            agg["values_norm_cost"].append(float(entry.get("norm_cost") or 0.0))
            agg["values_share"].append(float(entry.get("share_norm_cost") or 0.0))
            agg["values_samples"].append(int(entry.get("samples") or 0))

    groups: List[Dict[str, Any]] = []
    for _k, agg in bucket.items():
        nc = [float(v) for v in agg.get("values_norm_cost") or []]
        sh = [float(v) for v in agg.get("values_share") or []]
        sm = [float(v) for v in agg.get("values_samples") or []]
        groups.append(
            {
                **{k: v for k, v in agg.items() if not k.startswith("values_")},
                "n": len(nc),
                "norm_cost_mean": _mean(nc),
                "norm_cost_stdev": _stdev(nc),
                "share_mean": _mean(sh),
                "share_stdev": _stdev(sh),
                "samples_mean": _mean(sm),
                "samples_stdev": _stdev(sm),
            }
        )

    groups.sort(
        key=lambda g: (
            g.get("workload") or "",
            g.get("mode") or "",
            int(g.get("pmu_event") or 0),
            float(g.get("share_mean") or 0.0) * -1.0,
            int(g.get("data_object_id") or 0),
        )
    )

    return {
        "ok": True,
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "artifact_root": str(artifact_root),
        "suite_filter": suite_filter,
        "clickhouse_endpoint": clickhouse_endpoint,
        "tables": {"rollup": rollup_table, "data_objects": data_objects_table},
        "runs_scanned": runs_scanned,
        "runs_used": runs_used,
        "groups": groups,
        "per_run": per_run,
    }


def _write_csv(path: Path, report: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fields = [
        "suite",
        "workload",
        "mode",
        "delta_us",
        "pmu_events",
        "token_rate",
        "object_map_preset",
        "pmu_event",
        "pmu_event_name",
        "data_object_id",
        "mapping",
        "n",
        "norm_cost_mean",
        "norm_cost_stdev",
        "share_mean",
        "share_stdev",
        "samples_mean",
        "samples_stdev",
    ]
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for row in report.get("groups") or []:
            if not isinstance(row, dict):
                continue
            w.writerow({k: row.get(k) for k in fields})


def main() -> int:
    ap = argparse.ArgumentParser(description="Analyze data-object attribution from artifacts + ClickHouse")
    ap.add_argument("--artifact-root", default="artifacts/experiments", help="Artifacts directory to scan")
    ap.add_argument("--suite", default="data_object", help="Filter by plan.overrides.annotations.suite (empty disables)")
    ap.add_argument("--agent-conf", default="agent/agent.conf", help="Path to agent.conf (for ClickHouse endpoint/table names)")
    ap.add_argument("--clickhouse-endpoint", default=None, help="Override ClickHouse HTTP endpoint")
    ap.add_argument("--rollup-table", default=None, help="Override rollup table (default from agent.conf)")
    ap.add_argument("--data-objects-table", default="ms_data_objects", help="Override data objects table")
    ap.add_argument("--slack-s", type=int, default=10, help="Extra seconds added around derived time window")
    ap.add_argument("--out", default=None, help="Write JSON report")
    ap.add_argument("--out-csv", default=None, help="Write CSV summary")
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
        data_objects_table=args.data_objects_table,
        slack_s=max(0, int(args.slack_s)),
    )

    if args.out:
        out_path = Path(args.out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    else:
        print(json.dumps(report, indent=2))

    if args.out_csv:
        _write_csv(Path(args.out_csv), report)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
