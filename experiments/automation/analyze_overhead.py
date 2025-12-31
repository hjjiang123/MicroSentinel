#!/usr/bin/env python3
"""Offline analysis for the overhead experiment (§5.1).

This script scans experiment artifacts produced by `workload_runner` / `run_suite`
(e.g. `artifacts/experiments/*/run_result.json`) and extracts workload-level
performance metrics (throughput + optional latency) so you can compute overhead
of `perf` / `microsentinel` relative to `baseline`.

It is intentionally "paper glue": it emits JSON + CSV that can be directly
plotted.

Supported workloads (from `workload_runner.py`):
- kv: sums `throughput_ops_per_s` across clients (builtin generator) and also
  tries to parse memtier JSON if present.
- load_balancer: uses `lb-client` metrics (`throughput_ops_per_s`, latency_us).
- nfv_service_chain: uses `nfv-traffic` metrics (`avg_rate_pps`).

Typical usage:
  python3 -m experiments.automation.analyze_overhead \
    --artifact-root artifacts/experiments \
    --suite overhead \
    --out artifacts/experiments/overhead_summary.json \
    --out-csv artifacts/experiments/overhead_summary.csv
"""

from __future__ import annotations

import argparse
import json
import statistics
from dataclasses import dataclass
from datetime import datetime
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


def _extract_suite(plan: Optional[Dict[str, Any]]) -> Optional[str]:
    if not isinstance(plan, dict):
        return None
    suite = (
        _get_nested(plan, ["overrides", "annotations", "suite"])
        or _get_nested(plan, ["annotations", "suite"])
        or plan.get("suite")
    )
    return str(suite) if suite else None


def _norm_pmu_events(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return ",".join(part.strip() for part in value.split(",") if part.strip())
    if isinstance(value, (list, tuple)):
        return ",".join(str(part).strip() for part in value if str(part).strip())
    return str(value)


def _mean(values: List[float]) -> Optional[float]:
    if not values:
        return None
    return float(statistics.mean(values))


def _stdev(values: List[float]) -> Optional[float]:
    if len(values) < 2:
        return None
    return float(statistics.stdev(values))


@dataclass(frozen=True)
class GroupKey:
    suite: str
    workload: str
    delta_us: Optional[int]
    pmu_events: str
    token_rate: Optional[int]

    def as_dict(self) -> Dict[str, Any]:
        return {
            "suite": self.suite,
            "workload": self.workload,
            "delta_us": self.delta_us,
            "pmu_events": self.pmu_events,
            "token_rate": self.token_rate,
        }


def _walk_artifacts(root: Path) -> Iterable[Path]:
    if not root.exists():
        return
    for child in root.iterdir():
        if not child.is_dir():
            continue
        if (child / "plan.json").exists() or (child / "run_result.json").exists():
            yield child


def _extract_memtier_ops(metrics: Dict[str, Any]) -> Optional[float]:
    """Best-effort extraction for memtier_benchmark --json-out-file."""
    candidates: List[float] = []

    # Common format: {"ALL STATS": [{"Ops/sec": "12345.67", ...}, ...]}
    for key in ("ALL STATS", "ALL_STATS", "all_stats", "stats"):
        rows = metrics.get(key)
        if isinstance(rows, list):
            for row in rows:
                if not isinstance(row, dict):
                    continue
                for k in ("Ops/sec", "Ops/sec\n", "Ops/sec ", "Ops/sec (avg)"):
                    if k in row:
                        v = _as_float(row.get(k))
                        if v is not None:
                            candidates.append(v)
                if "Ops/sec" in row:
                    v = _as_float(row.get("Ops/sec"))
                    if v is not None:
                        candidates.append(v)

    # Fallback: search shallow keys that look like ops/sec
    for k, v in metrics.items():
        if not isinstance(k, str):
            continue
        lk = k.lower()
        if "ops" in lk and "sec" in lk:
            fv = _as_float(v)
            if fv is not None:
                candidates.append(fv)

    if not candidates:
        return None

    # Memtier may include multiple rows; the max is usually the aggregate.
    return float(max(candidates))


def _extract_client_metrics(run_result: Dict[str, Any]) -> List[Tuple[str, Dict[str, Any]]]:
    """Return [(command_name, metrics_dict)] for client commands."""
    out: List[Tuple[str, Dict[str, Any]]] = []
    for cmd in run_result.get("commands") or []:
        if not isinstance(cmd, dict):
            continue
        if cmd.get("role") != "client":
            continue
        metrics = cmd.get("metrics")
        if isinstance(metrics, dict):
            out.append((str(cmd.get("name") or "client"), metrics))
    return out


def _extract_workload_metric(
    workload: str, client_metrics: List[Tuple[str, Dict[str, Any]]]
) -> Tuple[Optional[str], Optional[float], Dict[str, Any]]:
    """Return (metric_name, metric_value, extra_fields)."""

    extra: Dict[str, Any] = {}

    if workload == "nfv_service_chain":
        for name, metrics in client_metrics:
            if name == "nfv-traffic" or "traffic" in name:
                value = _as_float(metrics.get("avg_rate_pps"))
                if value is not None:
                    return "avg_rate_pps", value, extra
        # Fallback: any client metric that has avg_rate_pps
        for _name, metrics in client_metrics:
            value = _as_float(metrics.get("avg_rate_pps"))
            if value is not None:
                return "avg_rate_pps", value, extra
        return None, None, extra

    if workload == "load_balancer":
        for name, metrics in client_metrics:
            if name == "lb-client":
                value = _as_float(metrics.get("throughput_ops_per_s"))
                if value is not None:
                    lat = metrics.get("latency_us")
                    if isinstance(lat, dict):
                        for p in ("p50", "p95", "p99"):
                            if p in lat:
                                extra[f"latency_{p}_us"] = _as_float(lat.get(p))
                    extra["errors"] = _as_int(metrics.get("errors"))
                    return "throughput_ops_per_s", value, extra
        # Fallback: first client with throughput
        for _name, metrics in client_metrics:
            value = _as_float(metrics.get("throughput_ops_per_s"))
            if value is not None:
                return "throughput_ops_per_s", value, extra
        return None, None, extra

    if workload == "kv":
        # KV may have multiple client instances; sum throughput across them.
        throughputs: List[float] = []
        lat_p99: List[float] = []
        errors: List[int] = []
        for _name, metrics in client_metrics:
            t = _as_float(metrics.get("throughput_ops_per_s"))
            if t is None:
                t = _extract_memtier_ops(metrics)
            if t is not None:
                throughputs.append(t)
            lat = metrics.get("latency_us")
            if isinstance(lat, dict):
                p99 = _as_float(lat.get("p99"))
                if p99 is not None:
                    lat_p99.append(p99)
            err = _as_int(metrics.get("errors"))
            if err is not None:
                errors.append(err)

        if throughputs:
            extra["clients"] = len(throughputs)
            if lat_p99:
                extra["latency_p99_us"] = float(statistics.mean(lat_p99))
            if errors:
                extra["errors"] = int(sum(errors))
            return "throughput_ops_per_s", float(sum(throughputs)), extra
        return None, None, extra

    # Unknown workload: try generic fields
    for _name, metrics in client_metrics:
        for key in ("throughput_ops_per_s", "avg_rate_pps"):
            value = _as_float(metrics.get(key))
            if value is not None:
                return key, value, extra
    return None, None, extra


def _group_key_from_plan(plan: Dict[str, Any]) -> GroupKey:
    suite = _extract_suite(plan) or ""
    workload = str(plan.get("workload") or "")
    instr = _get_nested(plan, ["overrides", "instrumentation"]) or {}
    delta_us = _as_int(instr.get("delta_us"))
    pmu_events = _norm_pmu_events(instr.get("pmu_events"))
    token_rate = _as_int(instr.get("token_rate"))
    return GroupKey(suite=suite, workload=workload, delta_us=delta_us, pmu_events=pmu_events, token_rate=token_rate)


def analyze(root: Path, suite_filter: Optional[str]) -> Dict[str, Any]:
    by_group: Dict[GroupKey, Dict[str, Any]] = {}
    runs_scanned = 0
    runs_used = 0

    for artifact_dir in _walk_artifacts(root):
        plan_path = artifact_dir / "plan.json"
        rr_path = artifact_dir / "run_result.json"
        if not plan_path.exists() or not rr_path.exists():
            continue

        try:
            rr = _load_json(rr_path)
            plan = rr.get("plan") if isinstance(rr.get("plan"), dict) else _load_json(plan_path)
        except Exception:
            continue

        if not isinstance(plan, dict):
            continue

        runs_scanned += 1
        suite = _extract_suite(plan) or ""
        if suite_filter and suite_filter != suite:
            continue

        key = _group_key_from_plan(plan)
        mode = str(plan.get("mode") or "")

        client_metrics = _extract_client_metrics(rr)
        metric_name, metric_value, extra = _extract_workload_metric(key.workload, client_metrics)
        if metric_name is None or metric_value is None:
            continue

        group = by_group.setdefault(
            key,
            {
                **key.as_dict(),
                "metric": metric_name,
                "modes": {},
            },
        )
        modes = group["modes"]
        entry = modes.setdefault(mode, {"values": [], "extras": []})
        entry["values"].append(float(metric_value))
        if extra:
            entry["extras"].append(extra)

        # Host CPU usage (if present) is useful for overhead interpretation.
        cpu = _get_nested(plan, ["host_metrics", "cpu_usage_percent"]) or _get_nested(plan, ["plan", "host_metrics", "cpu_usage_percent"])
        if cpu is None:
            cpu = _get_nested(rr.get("plan"), ["host_metrics", "cpu_usage_percent"]) if isinstance(rr.get("plan"), dict) else None
        if cpu is not None:
            try:
                group.setdefault("cpu_usage_percent", {})[mode] = float(cpu)
            except Exception:
                pass

        runs_used += 1

    groups_out: List[Dict[str, Any]] = []
    for key, group in by_group.items():
        modes = group.get("modes") or {}
        baseline_vals = (modes.get("baseline") or {}).get("values") or []
        baseline_mean = _mean(baseline_vals)

        mode_summaries: Dict[str, Any] = {}
        for mode, payload in modes.items():
            vals = payload.get("values") or []
            vals_f = [float(v) for v in vals if v is not None]
            mode_summaries[mode] = {
                "n": len(vals_f),
                "mean": _mean(vals_f),
                "stdev": _stdev(vals_f),
                "values": vals_f,
            }

        overhead_pct: Dict[str, Optional[float]] = {}
        if baseline_mean and baseline_mean > 0:
            for mode in ("perf", "microsentinel"):
                m = mode_summaries.get(mode, {}).get("mean")
                if m is None:
                    overhead_pct[mode] = None
                else:
                    overhead_pct[mode] = float((baseline_mean - m) / baseline_mean * 100.0)
        else:
            overhead_pct = {"perf": None, "microsentinel": None}

        groups_out.append(
            {
                **{k: v for k, v in group.items() if k != "modes"},
                "summary": mode_summaries,
                "overhead_pct": overhead_pct,
            }
        )

    groups_out.sort(key=lambda g: (g.get("workload") or "", g.get("delta_us") or -1, g.get("token_rate") or -1, g.get("pmu_events") or ""))

    return {
        "ok": True,
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "artifact_root": str(root),
        "suite_filter": suite_filter,
        "runs_scanned": runs_scanned,
        "runs_used": runs_used,
        "groups": groups_out,
    }


def _write_csv(path: Path, report: Dict[str, Any]) -> None:
    import csv

    path.parent.mkdir(parents=True, exist_ok=True)

    fields = [
        "suite",
        "workload",
        "delta_us",
        "pmu_events",
        "token_rate",
        "metric",
        "baseline_mean",
        "perf_mean",
        "microsentinel_mean",
        "overhead_perf_pct",
        "overhead_microsentinel_pct",
        "baseline_n",
        "perf_n",
        "microsentinel_n",
        "baseline_cpu",
        "perf_cpu",
        "microsentinel_cpu",
    ]

    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for g in report.get("groups") or []:
            if not isinstance(g, dict):
                continue
            summary = g.get("summary") or {}
            baseline = summary.get("baseline") or {}
            perf = summary.get("perf") or {}
            ms = summary.get("microsentinel") or {}
            overhead = g.get("overhead_pct") or {}
            cpu_usage = g.get("cpu_usage_percent") or {}
            w.writerow(
                {
                    "suite": g.get("suite") or "",
                    "workload": g.get("workload") or "",
                    "delta_us": g.get("delta_us"),
                    "pmu_events": g.get("pmu_events") or "",
                    "token_rate": g.get("token_rate"),
                    "metric": g.get("metric") or "",
                    "baseline_mean": baseline.get("mean"),
                    "perf_mean": perf.get("mean"),
                    "microsentinel_mean": ms.get("mean"),
                    "overhead_perf_pct": overhead.get("perf"),
                    "overhead_microsentinel_pct": overhead.get("microsentinel"),
                    "baseline_n": baseline.get("n"),
                    "perf_n": perf.get("n"),
                    "microsentinel_n": ms.get("n"),
                    "baseline_cpu": cpu_usage.get("baseline"),
                    "perf_cpu": cpu_usage.get("perf"),
                    "microsentinel_cpu": cpu_usage.get("microsentinel"),
                }
            )


def main() -> int:
    ap = argparse.ArgumentParser(description="Analyze overhead experiments from artifacts")
    ap.add_argument("--artifact-root", default="artifacts/experiments", help="Artifacts directory to scan")
    ap.add_argument("--suite", default="overhead", help="Filter by plan.overrides.annotations.suite (use empty to disable)")
    ap.add_argument("--out", default=None, help="Write JSON report")
    ap.add_argument("--out-csv", default=None, help="Write CSV summary")
    args = ap.parse_args()

    root = Path(args.artifact_root)
    suite_filter = args.suite if args.suite else None

    report = analyze(root, suite_filter)

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
