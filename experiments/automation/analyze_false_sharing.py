#!/usr/bin/env python3
"""Offline analysis for the false sharing experiment (§5.4).

The suite config (`experiments/configs/experiments/false_sharing.yaml`) sweeps
PMU events including `OFFCORE_RESPONSE.DEMAND_RFO.HITM`, which is a practical
proxy for cache-line bouncing / false sharing.

This script:
- Scans artifacts under `artifacts/experiments/*`.
- Filters runs by `plan.overrides.annotations.suite == false_sharing`.
- Derives a ClickHouse query time window from `run_result.generated_at` and
  `plan.duration`.
- Queries `ms_raw_samples` to rank cache lines by `norm_cost` and sample count.
- Optionally joins `ms_data_objects` to map addresses to object mappings.

Outputs:
- JSON report with per-run and aggregated summaries.
- CSV tables:
  - `--out-csv-lines`: top cache lines (grouped by mapping+cache_line)
  - `--out-csv-objects`: aggregated by object mapping

Example:
  python3 -m experiments.automation.analyze_false_sharing \
    --artifact-root artifacts/experiments \
    --suite false_sharing \
    --out artifacts/experiments/false_sharing_summary.json \
    --out-csv-lines artifacts/experiments/false_sharing_lines.csv \
    --out-csv-objects artifacts/experiments/false_sharing_objects.csv
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


# Logical event ids from `bpf/ms_common.h`.
MS_EVT_XSNP_HITM = 6


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


def _guess_host(ch: ClickHouse, raw_table: str, t0_ns: int, t1_ns: int) -> Optional[str]:
    sql = (
        f"SELECT host, count() AS c "
        f"FROM {raw_table} "
        f"WHERE toUnixTimestamp64Nano(ts) BETWEEN {t0_ns} AND {t1_ns} "
        f"GROUP BY host ORDER BY c DESC LIMIT 1"
    )
    rows = _ch_rows(ch.query_json(sql))
    if not rows:
        return None
    return rows[0].get("host")


@dataclass(frozen=True)
class GroupKey:
    suite: str
    workload: str
    mode: str
    delta_us: Optional[int]
    pmu_events: str
    token_rate: Optional[int]

    def as_dict(self) -> Dict[str, Any]:
        return {
            "suite": self.suite,
            "workload": self.workload,
            "mode": self.mode,
            "delta_us": self.delta_us,
            "pmu_events": self.pmu_events,
            "token_rate": self.token_rate,
        }


def analyze_one(
    artifact_dir: Path,
    ch: ClickHouse,
    raw_table: str,
    data_objects_table: str,
    slack_s: int,
    line_bytes: int,
    topk: int,
    event_id: int,
) -> Dict[str, Any]:
    out: Dict[str, Any] = {"artifact_dir": str(artifact_dir), "ok": False}

    rr_path = artifact_dir / "run_result.json"
    plan_path = artifact_dir / "plan.json"
    if not rr_path.exists() or not plan_path.exists():
        out["error"] = "plan/run_result not found"
        return out

    rr = _load_json(rr_path)
    plan = rr.get("plan") if isinstance(rr.get("plan"), dict) else _load_json(plan_path)
    generated_at = _parse_generated_at(rr.get("generated_at"))

    if not isinstance(plan, dict):
        out["error"] = "invalid plan"
        return out

    suite = _extract_suite(plan) or ""
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

    host = _guess_host(ch, raw_table, t0, t1)
    if not host:
        out["error"] = "no ClickHouse samples found in time window"
        return out

    out.update(
        {
            "ok": True,
            "suite": suite,
            "workload": str(plan.get("workload") or ""),
            "mode": str(plan.get("mode") or ""),
            "duration": duration,
            "window": {"t0_unix_ns": t0, "t1_unix_ns": t1, "source": window_src},
            "host": host,
        }
    )

    # Cache-line attribution with optional object mapping.
    # Note: join condition is intentionally a range predicate; this is OK because
    # `ms_data_objects` is expected to be small for object-map presets.
    sql_lines = (
        "SELECT "
        f"  intDiv(r.data_addr, {line_bytes}) * {line_bytes} AS cache_line, "
        "  any(d.mapping) AS mapping, "
        "  count() AS samples, "
        "  sum(r.norm_cost) AS norm_cost "
        f"FROM {raw_table} AS r "
        f"LEFT JOIN {data_objects_table} AS d "
        "  ON d.host = r.host AND r.data_addr >= d.base AND r.data_addr < (d.base + d.size) "
        f"WHERE r.host = {_sql_str(host)} "
        f"  AND toUnixTimestamp64Nano(r.ts) BETWEEN {t0} AND {t1} "
        f"  AND r.pmu_event = {int(event_id)} "
        "  AND r.data_addr != 0 "
        "GROUP BY cache_line "
        "ORDER BY norm_cost DESC "
        f"LIMIT {int(topk)}"
    )

    rows_lines = _ch_rows(ch.query_json(sql_lines))
    out["top_cache_lines"] = rows_lines

    # Object-level aggregation.
    sql_obj = (
        "SELECT "
        "  coalesce(any(d.mapping), '') AS mapping, "
        "  count() AS samples, "
        "  sum(r.norm_cost) AS norm_cost "
        f"FROM {raw_table} AS r "
        f"LEFT JOIN {data_objects_table} AS d "
        "  ON d.host = r.host AND r.data_addr >= d.base AND r.data_addr < (d.base + d.size) "
        f"WHERE r.host = {_sql_str(host)} "
        f"  AND toUnixTimestamp64Nano(r.ts) BETWEEN {t0} AND {t1} "
        f"  AND r.pmu_event = {int(event_id)} "
        "  AND r.data_addr != 0 "
        "GROUP BY mapping "
        "ORDER BY norm_cost DESC "
        "LIMIT 100000"
    )
    rows_obj = _ch_rows(ch.query_json(sql_obj))
    total_cost = sum(float(r.get("norm_cost") or 0.0) for r in rows_obj)
    for r in rows_obj:
        denom = total_cost
        share = float((float(r.get("norm_cost") or 0.0) / denom)) if denom > 0 else 0.0
        r["share_norm_cost"] = share
        r["event_id"] = int(event_id)
    out["objects"] = rows_obj
    out["total_norm_cost"] = total_cost

    # Copy key instrumentation hints (so CSV grouping is stable).
    instr = _extract_instr(plan)
    out["delta_us"] = _as_int(instr.get("delta_us"))
    out["pmu_events"] = _norm_pmu_events(instr.get("pmu_events"))
    out["token_rate"] = _as_int(instr.get("token_rate"))

    return out


def analyze(
    artifact_root: Path,
    suite_filter: Optional[str],
    clickhouse_endpoint: str,
    raw_table: str,
    data_objects_table: str,
    slack_s: int,
    line_bytes: int,
    topk: int,
    event_id: int,
) -> Dict[str, Any]:
    ch = ClickHouse(clickhouse_endpoint)

    per_run: List[Dict[str, Any]] = []
    runs_scanned = 0
    runs_used = 0

    # Aggregation buckets.
    line_bucket: Dict[Tuple[GroupKey, int, str], Dict[str, Any]] = {}
    obj_bucket: Dict[Tuple[GroupKey, str], Dict[str, Any]] = {}

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
            raw_table=raw_table,
            data_objects_table=data_objects_table,
            slack_s=slack_s,
            line_bytes=line_bytes,
            topk=topk,
            event_id=event_id,
        )
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
        )

        for row in report.get("top_cache_lines") or []:
            if not isinstance(row, dict):
                continue
            cache_line = int(row.get("cache_line") or 0)
            mapping = str(row.get("mapping") or "")
            samples = int(row.get("samples") or 0)
            norm_cost = float(row.get("norm_cost") or 0.0)

            k = (key, cache_line, mapping)
            agg = line_bucket.setdefault(
                k,
                {
                    **key.as_dict(),
                    "event_id": int(event_id),
                    "cache_line": cache_line,
                    "mapping": mapping,
                    "values_samples": [],
                    "values_norm_cost": [],
                },
            )
            agg["values_samples"].append(samples)
            agg["values_norm_cost"].append(norm_cost)

        for row in report.get("objects") or []:
            if not isinstance(row, dict):
                continue
            mapping = str(row.get("mapping") or "")
            samples = int(row.get("samples") or 0)
            norm_cost = float(row.get("norm_cost") or 0.0)
            share = float(row.get("share_norm_cost") or 0.0)

            k = (key, mapping)
            agg = obj_bucket.setdefault(
                k,
                {
                    **key.as_dict(),
                    "event_id": int(event_id),
                    "mapping": mapping,
                    "values_samples": [],
                    "values_norm_cost": [],
                    "values_share": [],
                },
            )
            agg["values_samples"].append(samples)
            agg["values_norm_cost"].append(norm_cost)
            agg["values_share"].append(share)

    lines_out: List[Dict[str, Any]] = []
    for _k, agg in line_bucket.items():
        ns = [float(v) for v in agg.get("values_norm_cost") or []]
        sm = [float(v) for v in agg.get("values_samples") or []]
        lines_out.append(
            {
                **{k: v for k, v in agg.items() if not k.startswith("values_")},
                "n": len(ns),
                "norm_cost_mean": _mean(ns),
                "norm_cost_stdev": _stdev(ns),
                "samples_mean": _mean(sm),
                "samples_stdev": _stdev(sm),
            }
        )

    objs_out: List[Dict[str, Any]] = []
    for _k, agg in obj_bucket.items():
        ns = [float(v) for v in agg.get("values_norm_cost") or []]
        sm = [float(v) for v in agg.get("values_samples") or []]
        sh = [float(v) for v in agg.get("values_share") or []]
        objs_out.append(
            {
                **{k: v for k, v in agg.items() if not k.startswith("values_")},
                "n": len(ns),
                "norm_cost_mean": _mean(ns),
                "norm_cost_stdev": _stdev(ns),
                "samples_mean": _mean(sm),
                "samples_stdev": _stdev(sm),
                "share_mean": _mean(sh),
                "share_stdev": _stdev(sh),
            }
        )

    lines_out.sort(key=lambda r: float(r.get("norm_cost_mean") or 0.0) * -1.0)
    objs_out.sort(key=lambda r: float(r.get("norm_cost_mean") or 0.0) * -1.0)

    return {
        "ok": True,
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "artifact_root": str(artifact_root),
        "suite_filter": suite_filter,
        "clickhouse_endpoint": clickhouse_endpoint,
        "tables": {"raw": raw_table, "data_objects": data_objects_table},
        "event_id": int(event_id),
        "line_bytes": int(line_bytes),
        "topk": int(topk),
        "runs_scanned": runs_scanned,
        "runs_used": runs_used,
        "lines": lines_out,
        "objects": objs_out,
        "per_run": per_run,
    }


def _write_csv_lines(path: Path, report: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fields = [
        "suite",
        "workload",
        "mode",
        "delta_us",
        "pmu_events",
        "token_rate",
        "event_id",
        "cache_line",
        "mapping",
        "n",
        "norm_cost_mean",
        "norm_cost_stdev",
        "samples_mean",
        "samples_stdev",
    ]
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for row in report.get("lines") or []:
            if not isinstance(row, dict):
                continue
            w.writerow({k: row.get(k) for k in fields})


def _write_csv_objects(path: Path, report: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fields = [
        "suite",
        "workload",
        "mode",
        "delta_us",
        "pmu_events",
        "token_rate",
        "event_id",
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
        for row in report.get("objects") or []:
            if not isinstance(row, dict):
                continue
            w.writerow({k: row.get(k) for k in fields})


def main() -> int:
    ap = argparse.ArgumentParser(description="Analyze false sharing (cache-line bouncing) from artifacts + ClickHouse")
    ap.add_argument("--artifact-root", default="artifacts/experiments", help="Artifacts directory to scan")
    ap.add_argument("--suite", default="false_sharing", help="Filter by plan.overrides.annotations.suite (empty disables)")
    ap.add_argument("--agent-conf", default="agent/agent.conf", help="Path to agent.conf (for ClickHouse endpoint/table names)")
    ap.add_argument("--clickhouse-endpoint", default=None, help="Override ClickHouse HTTP endpoint")
    ap.add_argument("--raw-table", default=None, help="Override raw samples table (default from agent.conf)")
    ap.add_argument("--data-objects-table", default="ms_data_objects", help="Override data objects table")
    ap.add_argument("--event-id", type=int, default=MS_EVT_XSNP_HITM, help="Logical event id to treat as false-sharing proxy (default: XSNP_HITM=6)")
    ap.add_argument("--line-bytes", type=int, default=64, help="Cache-line size in bytes")
    ap.add_argument("--topk", type=int, default=200, help="Top cache lines per run")
    ap.add_argument("--slack-s", type=int, default=10, help="Extra seconds around derived time window")
    ap.add_argument("--out", default=None, help="Write JSON report")
    ap.add_argument("--out-csv-lines", default=None, help="Write cache-line CSV")
    ap.add_argument("--out-csv-objects", default=None, help="Write object CSV")
    args = ap.parse_args()

    conf = _parse_agent_conf(Path(args.agent_conf))
    endpoint = args.clickhouse_endpoint or conf.get("clickhouse_endpoint") or "http://127.0.0.1:8123"
    raw = args.raw_table or conf.get("clickhouse_raw_table") or "ms_raw_samples"
    suite_filter = args.suite if args.suite else None

    report = analyze(
        artifact_root=Path(args.artifact_root),
        suite_filter=suite_filter,
        clickhouse_endpoint=endpoint,
        raw_table=raw,
        data_objects_table=args.data_objects_table,
        slack_s=max(0, int(args.slack_s)),
        line_bytes=max(1, int(args.line_bytes)),
        topk=max(1, int(args.topk)),
        event_id=int(args.event_id),
    )

    if args.out:
        out_path = Path(args.out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    else:
        print(json.dumps(report, indent=2))

    if args.out_csv_lines:
        _write_csv_lines(Path(args.out_csv_lines), report)
    if args.out_csv_objects:
        _write_csv_objects(Path(args.out_csv_objects), report)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
