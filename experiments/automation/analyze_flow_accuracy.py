#!/usr/bin/env python3
"""Offline analysis for the flow attribution accuracy experiment.

This script is meant to support the paper methodology (§5.2):
- Flow attribution accuracy (within ground-truth request windows)
- Attribution coverage (share of samples that get a non-zero flow_id)

Data sources:
- Ground truth: LB client `--ground-truth-log` JSON (per-flow request windows)
- Samples: ClickHouse tables populated by the MicroSentinel agent
  - Preferred for accuracy: `ms_flow_rollup` (aggregated by window_start)
  - Preferred for coverage: `ms_raw_samples` (counts of flow_id==0 vs non-zero)

It also supports a graceful fallback when ClickHouse is unavailable (it will
still emit a JSON report explaining what's missing).
"""

from __future__ import annotations

import argparse
import json
import re
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple, Any


@dataclass
class TruthFlow:
    flow_id: int
    intervals: List[Tuple[int, int]]  # [start_ns, end_ns]
    expected_function: Optional[str] = None


def _load_json(path: Path):
    # Guard: flow truth logs can become huge if something goes wrong (e.g.,
    # very long runs with per-request logging). Avoid hanging analysis/plotting.
    try:
        size = path.stat().st_size
    except OSError:
        size = 0
    max_bytes = int(512 * 1024 * 1024)  # 512 MiB default safety cap
    if size and size > max_bytes:
        raise RuntimeError(f"truth file too large ({size} bytes > {max_bytes}); refusing to load: {path}")
    return json.loads(path.read_text(encoding="utf-8"))


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


def _find_truth_file(artifact_dir: Path) -> Optional[Path]:
    # Common locations used by configs.
    candidates = [
        artifact_dir / "truth" / "lb_ground_truth.json",
        artifact_dir / "truth" / "flow_truth.json",
        artifact_dir / "metrics" / "flow_truth.json",
    ]
    for candidate in candidates:
        if candidate.exists():
            return candidate
    # Fallback: search.
    matches = list(artifact_dir.rglob("*flow*_truth*.json")) + list(artifact_dir.rglob("*ground_truth*.json"))
    for match in matches:
        if match.is_file():
            return match
    return None


def _get_nested(mapping: Any, path: List[str]) -> Any:
    cur = mapping
    for key in path:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(key)
    return cur


def _extract_delta_us(plan: Optional[Dict[str, object]]) -> Optional[int]:
    if not isinstance(plan, dict):
        return None
    # Preferred: overrides.instrumentation.delta_us (run_suite / workload_runner)
    candidates = [
        _get_nested(plan, ["overrides", "instrumentation", "delta_us"]),
        _get_nested(plan, ["annotations", "delta_us"]),
        plan.get("delta_us"),
    ]
    for value in candidates:
        if value is None:
            continue
        try:
            return int(value)
        except Exception:
            continue
    return None


def _extract_suite(plan: Optional[Dict[str, object]]) -> Optional[str]:
    if not isinstance(plan, dict):
        return None
    suite = _get_nested(plan, ["overrides", "annotations", "suite"]) or _get_nested(plan, ["annotations", "suite"]) or plan.get("suite")
    return str(suite) if suite else None


def _parse_truth(path: Path) -> Tuple[List[TruthFlow], str]:
    raw = _load_json(path)
    flows: List[TruthFlow] = []
    if not isinstance(raw, list):
        return flows, "unknown"

    # Prefer wall-clock Unix time if present; otherwise fall back to monotonic time.
    # Truth events can be either a dict (legacy) or a compact list:
    # - dict: {start_ns,end_ns,start_unix_ns,end_unix_ns}
    # - list: [start_ns,end_ns,start_unix_ns,end_unix_ns]
    time_domain = "monotonic_ns"
    for entry in raw:
        if not isinstance(entry, dict):
            continue
        events = entry.get("events")
        if not isinstance(events, list) or not events:
            continue
        ev0 = events[0]
        if isinstance(ev0, dict) and ("start_unix_ns" in ev0 or "end_unix_ns" in ev0):
            time_domain = "unix_ns"
            break
        if isinstance(ev0, (list, tuple)) and len(ev0) >= 4:
            time_domain = "unix_ns"
            break

    for entry in raw:
        if not isinstance(entry, dict):
            continue
        fid = entry.get("flow_id")
        if fid is None:
            continue
        try:
            flow_id = int(fid)
        except Exception:
            continue
        intervals: List[Tuple[int, int]] = []
        expected_function = entry.get("expected_function")
        if expected_function is not None:
            expected_function = str(expected_function)
        events = entry.get("events")
        if isinstance(events, list):
            for ev in events:
                if isinstance(ev, dict):
                    if time_domain == "unix_ns":
                        s = ev.get("start_unix_ns")
                        e = ev.get("end_unix_ns")
                    else:
                        s = ev.get("start_ns")
                        e = ev.get("end_ns")
                elif isinstance(ev, (list, tuple)):
                    if time_domain == "unix_ns":
                        # [start_monotonic_ns, end_monotonic_ns, start_unix_ns, end_unix_ns]
                        if len(ev) < 4:
                            continue
                        s = ev[2]
                        e = ev[3]
                    else:
                        if len(ev) < 2:
                            continue
                        s = ev[0]
                        e = ev[1]
                else:
                    continue
                try:
                    s_ns = int(s)
                    e_ns = int(e)
                except Exception:
                    continue
                if s_ns <= 0 or e_ns <= 0 or e_ns < s_ns:
                    continue
                intervals.append((s_ns, e_ns))
        if intervals:
            intervals.sort()
            flows.append(TruthFlow(flow_id=flow_id, intervals=_merge_intervals(intervals), expected_function=expected_function))
    return flows, time_domain


def _merge_intervals(intervals: List[Tuple[int, int]]) -> List[Tuple[int, int]]:
    if not intervals:
        return []
    merged: List[Tuple[int, int]] = []
    cur_s, cur_e = intervals[0]
    for s, e in intervals[1:]:
        if s <= cur_e:
            cur_e = max(cur_e, e)
        else:
            merged.append((cur_s, cur_e))
            cur_s, cur_e = s, e
    merged.append((cur_s, cur_e))
    return merged


def _truth_range_ns(truth: List[TruthFlow]) -> Tuple[int, int]:
    t0 = None
    t1 = None
    for flow in truth:
        for s, e in flow.intervals:
            t0 = s if t0 is None else min(t0, s)
            t1 = e if t1 is None else max(t1, e)
    return (t0 or 0, t1 or 0)


def _interval_overlaps(intervals: List[Tuple[int, int]], q_s: int, q_e: int) -> bool:
    # intervals are merged and sorted.
    # linear scan with early exit is fine because aggregator buckets are coarse (default 5ms)
    # and the number of merged intervals per flow is typically moderate.
    for s, e in intervals:
        if e < q_s:
            continue
        if s > q_e:
            return False
        return True
    return False


class ClickHouse:
    def __init__(self, endpoint: str):
        # Store a base endpoint (scheme://host:port[/path]). We'll use the
        # `/?query=` interface for maximum compatibility.
        self.endpoint = endpoint.rstrip("/")

    def query_json(self, sql: str) -> Dict:
        q = urllib.parse.quote(sql + " FORMAT JSON")
        url = f"{self.endpoint}/?query={q}"
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=10.0) as resp:
            body = resp.read().decode("utf-8", errors="replace")
        return json.loads(body)


def _ch_rows(resp: Dict) -> List[Dict]:
    data = resp.get("data")
    return data if isinstance(data, list) else []


def _sql_str(value: str) -> str:
    """Return a ClickHouse SQL single-quoted string literal."""
    escaped = value.replace("\\", "\\\\").replace("'", "\\'")
    return "'" + escaped + "'"


def _guess_clickhouse_host(ch: ClickHouse, raw_table: str, t0: int, t1: int) -> Optional[str]:
    sql = (
        f"SELECT host, count() AS c "
        f"FROM {raw_table} "
        f"WHERE toUnixTimestamp64Nano(ts) BETWEEN {t0} AND {t1} "
        f"GROUP BY host ORDER BY c DESC LIMIT 1"
    )
    rows = _ch_rows(ch.query_json(sql))
    print(f"Debug: ClickHouse host guess rows: {rows}")
    if not rows:
        return None
    return rows[0].get("host")


def analyze_single_artifact(
    artifact_dir: Path,
    clickhouse_endpoint: Optional[str],
    raw_table: str,
    rollup_table: str,
    window_ns: int,
    agent_conf: Path,
) -> Dict[str, object]:
    report: Dict[str, object] = {
        "artifact_dir": str(artifact_dir),
        "ok": False,
    }

    run_result = artifact_dir / "run_result.json"
    plan_json = artifact_dir / "plan.json"
    if run_result.exists():
        rr = _load_json(run_result)
        report["plan"] = rr.get("plan")
    elif plan_json.exists():
        report["plan"] = _load_json(plan_json)

    plan = report.get("plan") if isinstance(report.get("plan"), dict) else None
    report["delta_us"] = _extract_delta_us(plan)
    report["suite"] = _extract_suite(plan)
    if isinstance(plan, dict):
        report["mode"] = plan.get("mode")
        report["workload"] = plan.get("workload")

    truth_path = _find_truth_file(artifact_dir)
    if not truth_path:
        report["error"] = "ground truth file not found in artifact dir"
        return report

    truth, truth_time_domain = _parse_truth(truth_path)
    t0, t1 = _truth_range_ns(truth)
    if t0 <= 0 or t1 <= 0 or t1 <= t0:
        report["error"] = "invalid ground truth time range"
        report["truth_file"] = str(truth_path)
        return report

    report["truth_file"] = str(truth_path)
    report["truth_flows"] = len(truth)
    report["time_range_ns"] = {"start": t0, "end": t1}
    report["truth_time_domain"] = truth_time_domain
    report["window_ns"] = window_ns

    conf = _parse_agent_conf(agent_conf)
    endpoint = clickhouse_endpoint or conf.get("clickhouse_endpoint")
    if not endpoint:
        report["error"] = "clickhouse endpoint not provided and not found in agent config"
        return report

    ch = ClickHouse(endpoint)

    try:
        if truth_time_domain != "unix_ns":
            report.setdefault("warnings", [])
            if isinstance(report["warnings"], list):
                report["warnings"].append(
                    "truth uses monotonic_ns; ClickHouse queries assume Unix epoch ns. "
                    "Regenerate truth with start_unix_ns/end_unix_ns for accurate alignment."
                )

        host = _guess_clickhouse_host(ch, raw_table, t0, t1)
        report["clickhouse"] = {"endpoint": endpoint, "host": host, "raw_table": raw_table, "rollup_table": rollup_table}
        if not host:
            report["error"] = "no ClickHouse rows found in time range"
            return report

        host_sql = _sql_str(host)

        total_sql = (
            f"SELECT count() AS total, countIf(flow_id != 0) AS attributed "
            f"FROM {raw_table} "
            f"WHERE host = {host_sql} AND toUnixTimestamp64Nano(ingest_ts) BETWEEN {t0} AND {t1}"
        )
        total_row = _ch_rows(ch.query_json(total_sql))
        total = int(total_row[0].get("total", 0)) if total_row else 0
        attributed = int(total_row[0].get("attributed", 0)) if total_row else 0

        truth_map: Dict[int, List[Tuple[int, int]]] = {flow.flow_id: flow.intervals for flow in truth}

        rollup_sql = (
            "SELECT flow_id, toUnixTimestamp64Nano(window_start) AS ws_ns, sum(samples) AS samples "
            f"FROM {rollup_table} "
            f"WHERE host = {host_sql} AND toUnixTimestamp64Nano(window_start) BETWEEN {t0} AND {t1} "
            "GROUP BY flow_id, ws_ns"
        )
        rows = _ch_rows(ch.query_json(rollup_sql))

        in_truth = 0
        correct = 0
        per_flow: Dict[int, Dict[str, int]] = {}

        for row in rows:
            try:
                fid = int(row.get("flow_id"))
                ws_ns = int(row.get("ws_ns"))
                samples = int(row.get("samples"))
            except Exception:
                continue
            intervals = truth_map.get(fid)
            if not intervals:
                continue
            in_truth += samples
            bucket_s = ws_ns
            bucket_e = ws_ns + window_ns
            if _interval_overlaps(intervals, bucket_s, bucket_e):
                correct += samples
            pf = per_flow.setdefault(fid, {"attributed": 0, "correct": 0})
            pf["attributed"] += samples
            if _interval_overlaps(intervals, bucket_s, bucket_e):
                pf["correct"] += samples

        coverage_all = (attributed / total) if total else 0.0
        accuracy = (correct / in_truth) if in_truth else 0.0

        report["counts"] = {
            "total_raw_samples": total,
            "attributed_raw_samples": attributed,
            "attributed_samples_in_truth_flows": in_truth,
            "correct_samples_in_truth_flows": correct,
        }
        report["metrics"] = {
            "coverage_all": coverage_all,
            "flow_accuracy": accuracy,
        }
        report["per_flow"] = [
            {"flow_id": fid, "attributed": v["attributed"], "correct": v["correct"], "accuracy": (v["correct"] / v["attributed"]) if v["attributed"] else 0.0}
            for fid, v in sorted(per_flow.items(), key=lambda kv: kv[0])
        ]

        # Optional: function attribution accuracy, when truth provides expected_function.
        expected_map: Dict[int, str] = {
            tf.flow_id: tf.expected_function for tf in truth if isinstance(tf.expected_function, str) and tf.expected_function
        }
        if expected_map:
            func_sql = (
                "SELECT fr.flow_id AS flow_id, "
                "toUnixTimestamp64Nano(fr.window_start) AS ws_ns, "
                "sum(fr.samples) AS samples, "
                "if(length(st.frames) >= 1, st.frames[1].2, '') AS func "
                f"FROM {rollup_table} AS fr "
                "LEFT JOIN ms_stack_traces AS st ON (st.host = fr.host AND st.stack_id = fr.callstack_id) "
                f"WHERE fr.host = {host_sql} AND toUnixTimestamp64Nano(fr.window_start) BETWEEN {t0} AND {t1} "
                "GROUP BY flow_id, ws_ns, func"
            )
            func_rows = _ch_rows(ch.query_json(func_sql))
            func_total = 0
            func_correct = 0
            per_flow_func: Dict[int, Dict[str, int]] = {}
            for row in func_rows:
                try:
                    fid = int(row.get("flow_id"))
                    ws_ns = int(row.get("ws_ns"))
                    samples = int(row.get("samples"))
                    func = str(row.get("func") or "")
                except Exception:
                    continue
                intervals = truth_map.get(fid)
                if not intervals:
                    continue
                bucket_s = ws_ns
                bucket_e = ws_ns + window_ns
                if not _interval_overlaps(intervals, bucket_s, bucket_e):
                    continue
                exp = expected_map.get(fid)
                if not exp:
                    continue
                func_total += samples
                if exp in func:
                    func_correct += samples
                pf = per_flow_func.setdefault(fid, {"total": 0, "correct": 0})
                pf["total"] += samples
                if exp in func:
                    pf["correct"] += samples

            report.setdefault("metrics", {})
            if isinstance(report["metrics"], dict):
                report["metrics"]["function_accuracy"] = (func_correct / func_total) if func_total else 0.0
            report["function_counts"] = {"in_truth_samples": func_total, "correct_samples": func_correct}
            report["per_flow_function"] = [
                {
                    "flow_id": fid,
                    "total": v["total"],
                    "correct": v["correct"],
                    "accuracy": (v["correct"] / v["total"]) if v["total"] else 0.0,
                }
                for fid, v in sorted(per_flow_func.items(), key=lambda kv: kv[0])
            ]

        report["ok"] = True
        return report
    except Exception as exc:
        report["error"] = f"clickhouse query failed: {exc}"
        return report


def _expand_artifacts(arg: str) -> List[Path]:
    p = Path(arg)
    if p.is_dir():
        return [p]
    if p.is_file() and p.suffix.lower() == ".json":
        obj = _load_json(p)
        items = obj.get("artifacts") if isinstance(obj, dict) else None
        if isinstance(items, list):
            return [Path(x) for x in items if isinstance(x, str)]
    # allow comma-separated
    parts = [s.strip() for s in arg.split(",") if s.strip()]
    return [Path(x) for x in parts]


def main() -> None:
    ap = argparse.ArgumentParser(description="Analyze MicroSentinel flow attribution accuracy from artifacts")
    ap.add_argument("--artifacts", required=True, help="Artifact dir, or a JSON summary containing {artifacts:[...]} (comma-separated supported)")
    ap.add_argument("--clickhouse", default=None, help="ClickHouse HTTP endpoint, e.g. http://127.0.0.1:8123")
    ap.add_argument("--agent-conf", default="agent/agent.conf", help="Path to agent.conf for defaults")
    ap.add_argument("--raw-table", default="ms_raw_samples")
    ap.add_argument("--rollup-table", default="ms_flow_rollup")
    ap.add_argument("--window-ns", type=int, default=5_000_000, help="Aggregator window size in ns (default 5ms)")
    ap.add_argument("--out", default=None, help="Write JSON report to this path; default prints to stdout")
    ap.add_argument("--out-csv", default=None, help="Write per-delta CSV summary to this path")
    args = ap.parse_args()

    artifacts = _expand_artifacts(args.artifacts)
    reports: List[Dict[str, object]] = [
        analyze_single_artifact(
            artifact_dir=a,
            clickhouse_endpoint=args.clickhouse,
            raw_table=args.raw_table,
            rollup_table=args.rollup_table,
            window_ns=args.window_ns,
            agent_conf=Path(args.agent_conf),
        )
        for a in artifacts
    ]

    # Aggregate by delta_us for plotting Δ vs accuracy/coverage.
    by_delta: Dict[int, List[Dict[str, object]]] = {}
    for rep in reports:
        delta = rep.get("delta_us")
        if isinstance(delta, int):
            by_delta.setdefault(delta, []).append(rep)

    delta_summary: List[Dict[str, object]] = []
    for delta, reps in sorted(by_delta.items(), key=lambda kv: kv[0]):
        oks = [r for r in reps if r.get("ok") is True and isinstance(_get_nested(r, ["metrics", "coverage_all"]), (int, float))]
        covs = [float(_get_nested(r, ["metrics", "coverage_all"]) or 0.0) for r in oks]
        accs = [float(_get_nested(r, ["metrics", "flow_accuracy"]) or 0.0) for r in oks]
        def _stats(xs: List[float]) -> Dict[str, object]:
            if not xs:
                return {"n": 0}
            xs_sorted = sorted(xs)
            mean = sum(xs_sorted) / len(xs_sorted)
            var = sum((x - mean) ** 2 for x in xs_sorted) / len(xs_sorted)
            return {
                "n": len(xs_sorted),
                "mean": mean,
                "min": xs_sorted[0],
                "max": xs_sorted[-1],
                "std": var ** 0.5,
            }
        delta_summary.append(
            {
                "delta_us": delta,
                "runs": len(reps),
                "ok_runs": len(oks),
                "coverage_all": _stats(covs),
                "flow_accuracy": _stats(accs),
            }
        )

    output = {"reports": reports, "by_delta": delta_summary}

    if args.out_csv:
        out_csv = Path(args.out_csv)
        out_csv.parent.mkdir(parents=True, exist_ok=True)
        lines = ["delta_us,ok_runs,coverage_mean,coverage_std,accuracy_mean,accuracy_std"]
        for row in delta_summary:
            cov = row.get("coverage_all", {}) if isinstance(row.get("coverage_all"), dict) else {}
            acc = row.get("flow_accuracy", {}) if isinstance(row.get("flow_accuracy"), dict) else {}
            lines.append(
                f"{row.get('delta_us')},{row.get('ok_runs')},"
                f"{cov.get('mean','')},{cov.get('std','')},"
                f"{acc.get('mean','')},{acc.get('std','')}"
            )
        out_csv.write_text("\n".join(lines) + "\n", encoding="utf-8")
    payload = json.dumps(output, indent=2)
    if args.out:
        out = Path(args.out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(payload, encoding="utf-8")
    else:
        print(payload)


if __name__ == "__main__":
    main()
