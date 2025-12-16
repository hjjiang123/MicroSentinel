#!/usr/bin/env python3
"""Offline analysis for the scalability experiment (§5.7).

Suite: `experiments/configs/experiments/scalability.yaml`.

This suite currently scans sampling rates (`instrumentation.token_rate` a.k.a.
`samples_per_core`) and PMU event sets (`instrumentation.pmu_events`), and may
also vary `instrumentation.filters` (e.g., full vs tenant-filtered).

This script:
- Scans `artifacts/experiments/*`.
- Filters by `plan.overrides.annotations.suite` (default: scalability).
- Extracts KV throughput + p99 latency from `run_result.json` client metrics.
- Groups results by (workload, mode, token_rate, pmu_events, filter_mode).

Outputs:
- JSON report (per-run + grouped summary)
- CSV summary (one row per group)
- CSV points (one row per run)

Example:
  python3 -m experiments.automation.analyze_scalability \
    --artifact-root artifacts/experiments \
    --suite scalability \
    --out artifacts/experiments/scalability_summary.json \
    --out-csv artifacts/experiments/scalability_summary.csv \
    --out-csv-points artifacts/experiments/scalability_points.csv
"""

from __future__ import annotations

import argparse
import csv
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
    mode: str
    token_rate: Optional[int]
    pmu_events: str
    filter_mode: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "suite": self.suite,
            "workload": self.workload,
            "mode": self.mode,
            "token_rate": self.token_rate,
            "pmu_events": self.pmu_events,
            "filter_mode": self.filter_mode,
        }


def _walk_artifacts(root: Path) -> Iterable[Path]:
    if not root.exists():
        return
    for child in root.iterdir():
        if not child.is_dir():
            continue
        if (child / "plan.json").exists() or (child / "run_result.json").exists():
            yield child


def _extract_client_metrics(run_result: Dict[str, Any]) -> List[Tuple[str, Dict[str, Any]]]:
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


def _extract_memtier_ops(metrics: Dict[str, Any]) -> Optional[float]:
    candidates: List[float] = []

    for key in ("ALL STATS", "ALL_STATS", "all_stats", "stats"):
        rows = metrics.get(key)
        if isinstance(rows, list):
            for row in rows:
                if not isinstance(row, dict):
                    continue
                if "Ops/sec" in row:
                    v = _as_float(row.get("Ops/sec"))
                    if v is not None:
                        candidates.append(v)

    for k, v in metrics.items():
        if not isinstance(k, str):
            continue
        lk = k.lower()
        if "ops" in lk and "sec" in lk:
            fv = _as_float(v)
            if fv is not None:
                candidates.append(fv)

    return float(max(candidates)) if candidates else None


def _extract_kv_metrics(run_result: Dict[str, Any]) -> Dict[str, Any]:
    """Return {throughput_ops_per_s, latency_p99_us, errors} best-effort."""
    client_metrics = _extract_client_metrics(run_result)
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

    out: Dict[str, Any] = {}
    if throughputs:
        out["throughput_ops_per_s"] = float(sum(throughputs))
        out["clients"] = len(throughputs)
    if lat_p99:
        out["latency_p99_us"] = float(statistics.mean(lat_p99))
    if errors:
        out["errors"] = int(sum(errors))
    return out


def _extract_instr(plan: Dict[str, Any]) -> Dict[str, Any]:
    instr = _get_nested(plan, ["overrides", "instrumentation"])
    return instr if isinstance(instr, dict) else {}


def _extract_filter_mode(instr: Dict[str, Any]) -> str:
    flt = instr.get("filters")
    if isinstance(flt, dict):
        mode = flt.get("mode")
        return str(mode) if mode is not None else json.dumps(flt, sort_keys=True)
    if flt is None:
        return ""
    return str(flt)


def analyze(
    artifact_root: Path,
    suite_filter: Optional[str],
) -> Dict[str, Any]:
    per_run: List[Dict[str, Any]] = []
    points: List[Dict[str, Any]] = []
    groups: Dict[GroupKey, Dict[str, Any]] = {}

    runs_scanned = 0
    runs_used = 0

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

        phase = _get_nested(plan, ["overrides", "annotations", "phase"])
        if isinstance(phase, str) and phase.lower() == "warmup":
            continue

        workload = str(plan.get("workload") or "")
        mode = str(plan.get("mode") or "")
        instr = _extract_instr(plan)
        token_rate = _as_int(instr.get("token_rate"))
        pmu_events = _norm_pmu_events(instr.get("pmu_events"))
        filter_mode = _extract_filter_mode(instr)

        metrics: Dict[str, Any] = {}
        if workload == "kv":
            metrics = _extract_kv_metrics(rr)

        record = {
            "artifact_dir": str(artifact_dir),
            "ok": True,
            "suite": suite,
            "workload": workload,
            "mode": mode,
            "token_rate": token_rate,
            "pmu_events": pmu_events,
            "filter_mode": filter_mode,
            **metrics,
        }
        per_run.append(record)

        # A run is considered "used" if we have at least throughput.
        t = _as_float(metrics.get("throughput_ops_per_s"))
        if t is None:
            continue
        runs_used += 1

        key = GroupKey(
            suite=suite,
            workload=workload,
            mode=mode,
            token_rate=token_rate,
            pmu_events=pmu_events,
            filter_mode=filter_mode,
        )

        g = groups.setdefault(
            key,
            {
                **key.as_dict(),
                "values_throughput": [],
                "values_latency_p99": [],
                "values_errors": [],
            },
        )
        g["values_throughput"].append(float(t))
        p99 = _as_float(metrics.get("latency_p99_us"))
        if p99 is not None:
            g["values_latency_p99"].append(float(p99))
        err = _as_int(metrics.get("errors"))
        if err is not None:
            g["values_errors"].append(float(err))

        points.append(
            {
                **key.as_dict(),
                "artifact_dir": str(artifact_dir),
                "throughput_ops_per_s": float(t),
                "latency_p99_us": p99,
                "errors": err,
            }
        )

    summary: List[Dict[str, Any]] = []
    for _k, agg in groups.items():
        tv = [float(v) for v in agg.get("values_throughput") or []]
        lv = [float(v) for v in agg.get("values_latency_p99") or []]
        ev = [float(v) for v in agg.get("values_errors") or []]
        summary.append(
            {
                **{k: v for k, v in agg.items() if not k.startswith("values_")},
                "n": len(tv),
                "throughput_mean": _mean(tv),
                "throughput_stdev": _stdev(tv),
                "latency_p99_us_mean": _mean(lv) if lv else None,
                "latency_p99_us_stdev": _stdev(lv) if lv else None,
                "errors_mean": _mean(ev) if ev else None,
                "errors_stdev": _stdev(ev) if ev else None,
            }
        )

    summary.sort(key=lambda r: (r.get("filter_mode") or "", r.get("pmu_events") or "", r.get("token_rate") or -1))
    points.sort(key=lambda r: (r.get("filter_mode") or "", r.get("pmu_events") or "", r.get("token_rate") or -1))

    return {
        "ok": True,
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "artifact_root": str(artifact_root),
        "suite_filter": suite_filter,
        "runs_scanned": runs_scanned,
        "runs_used": runs_used,
        "summary": summary,
        "points": points,
        "per_run": per_run,
    }


def _write_csv_summary(path: Path, report: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fields = [
        "suite",
        "workload",
        "mode",
        "filter_mode",
        "pmu_events",
        "token_rate",
        "n",
        "throughput_mean",
        "throughput_stdev",
        "latency_p99_us_mean",
        "latency_p99_us_stdev",
        "errors_mean",
        "errors_stdev",
    ]
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for row in report.get("summary") or []:
            if not isinstance(row, dict):
                continue
            w.writerow({k: row.get(k) for k in fields})


def _write_csv_points(path: Path, report: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fields = [
        "suite",
        "workload",
        "mode",
        "filter_mode",
        "pmu_events",
        "token_rate",
        "artifact_dir",
        "throughput_ops_per_s",
        "latency_p99_us",
        "errors",
    ]
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for row in report.get("points") or []:
            if not isinstance(row, dict):
                continue
            w.writerow({k: row.get(k) for k in fields})


def main() -> int:
    ap = argparse.ArgumentParser(description="Analyze scalability experiment from artifacts")
    ap.add_argument("--artifact-root", default="artifacts/experiments", help="Artifacts directory to scan")
    ap.add_argument("--suite", default="scalability", help="Filter by plan.overrides.annotations.suite (empty disables)")
    ap.add_argument("--out", default=None, help="Write JSON report")
    ap.add_argument("--out-csv", default=None, help="Write summary CSV")
    ap.add_argument("--out-csv-points", default=None, help="Write per-run points CSV")
    args = ap.parse_args()

    suite_filter = args.suite if args.suite else None
    report = analyze(Path(args.artifact_root), suite_filter)

    if args.out:
        out_path = Path(args.out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    else:
        print(json.dumps(report, indent=2))

    if args.out_csv:
        _write_csv_summary(Path(args.out_csv), report)
    if args.out_csv_points:
        _write_csv_points(Path(args.out_csv_points), report)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
