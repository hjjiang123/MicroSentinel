#!/usr/bin/env python3
"""Generate paper figures for §5.1–§5.7 from experiment artifacts.

This is a thin "paper glue" wrapper around existing analysis scripts:
- §5.1: overhead
- §5.2: flow attribution accuracy
- §5.3: data-object attribution
- §5.4: false sharing
- §5.5: NUMA imbalance
- §5.6: branch mispredict
- §5.7: scalability

Outputs:
- CSV/JSON summaries under the output directory
- PNG + PDF figures under the output directory

Typical usage:
  python3 -m experiments.automation.plot_section5_figures \
    --artifact-root artifacts/experiments \
    --out-dir artifacts/experiments/figures_section5

Run a single experiment's figures:
    python3 experiments/automation/plot_section5_figures.py \
        --artifact-root artifacts/experiments \
        --out-dir artifacts/experiments/figures_section5 \
        --only 5.1

Skip a problematic experiment (e.g., flow accuracy requires truth + ClickHouse):
    python3 experiments/automation/plot_section5_figures.py \
        --artifact-root artifacts/experiments \
        --out-dir artifacts/experiments/figures_section5 \
        --skip 5.2 --continue-on-error

For each section, the script writes:
- The paper-style main figure(s) under out_dir
- A per-section folder (e.g. out_dir/5_1_overhead/) containing:
    - analysis CSV/JSON outputs
    - recorded_metrics.csv (flattened run_result/plan/monitor metrics)
    - metrics/*.png|pdf: one plot per numeric metric column
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import os
from pathlib import Path
import subprocess
import sys
from dataclasses import dataclass
from statistics import mean
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

# Allow running as either a module (-m) or a script (python3 path/to/script.py).
_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from experiments.automation.artifact_metrics import extract_recorded_metrics, load_artifact_run, walk_artifacts


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _as_float(v: Any) -> Optional[float]:
    if v is None or v == "":
        return None
    try:
        return float(v)
    except Exception:
        return None


def _as_int(v: Any) -> Optional[int]:
    if v is None or v == "":
        return None
    try:
        return int(v)
    except Exception:
        return None


def _walk_artifacts(root: Path) -> Iterable[Path]:
    # Back-compat wrapper (kept to minimize code churn).
    yield from walk_artifacts(root)


def _get_nested(mapping: Any, path: Sequence[str]) -> Any:
    cur = mapping
    for key in path:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(key)
    return cur


def _extract_suite(plan: Optional[Dict[str, Any]]) -> str:
    if not isinstance(plan, dict):
        return ""
    suite = (
        _get_nested(plan, ["overrides", "annotations", "suite"])
        or _get_nested(plan, ["annotations", "suite"])
        or plan.get("suite")
    )
    return str(suite) if suite else ""


def _run_module(module: str, args: List[str]) -> None:
    cmd = [sys.executable, "-m", module] + args
    subprocess.run(cmd, check=True)


def _read_csv(path: Path) -> List[Dict[str, str]]:
    with path.open("r", newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        return [dict(row) for row in reader]


def _ensure_matplotlib():
    try:
        import matplotlib  # noqa: F401
    except Exception as exc:
        raise RuntimeError(
            "matplotlib import failed. Install via: python3 -m pip install --user matplotlib"
        ) from exc


def _save_fig(fig, out_png: Path, out_pdf: Path) -> None:
    out_png.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(out_png, dpi=200, bbox_inches="tight")
    fig.savefig(out_pdf, bbox_inches="tight")


def _split_sections(value: Optional[str]) -> List[str]:
    if not value:
        return []
    parts = []
    for raw in str(value).split(","):
        s = raw.strip()
        if not s:
            continue
        # Allow both "5.1" and "5_1" input.
        s = s.replace("_", ".")
        parts.append(s)
    return parts


def _auto_plot_metrics_table(csv_path: Path, out_dir: Path, *, title_prefix: str = "") -> None:
    """Generate one plot per numeric column in a CSV table.

    Heuristic:
    - If a numeric x-axis exists (token_rate/delta_us), draw line plots.
    - Else, draw categorical bar plots using (workload/mode) or row index.
    """

    _ensure_matplotlib()
    import matplotlib.pyplot as plt

    rows = _read_csv(csv_path)
    if not rows:
        return

    # Determine numeric columns.
    def to_float(v: Any) -> Optional[float]:
        return _as_float(v)

    columns = sorted({k for r in rows for k in r.keys()})
    numeric_cols: List[str] = []
    for col in columns:
        if col in {"artifact_dir", "suite", "workload", "mode"}:
            continue
        vals = [to_float(r.get(col)) for r in rows]
        if any(v is not None for v in vals):
            numeric_cols.append(col)

    if not numeric_cols:
        return

    # Pick x-axis.
    x_field = None
    for cand in ("instrumentation.token_rate", "token_rate", "delta_us", "instrumentation.delta_us"):
        if cand in columns:
            x_field = cand
            break

    out_dir.mkdir(parents=True, exist_ok=True)

    for col in numeric_cols:
        ys: List[float] = []
        xs: List[Any] = []
        labels: List[str] = []

        if x_field:
            for r in rows:
                xv = _as_int(r.get(x_field))
                yv = to_float(r.get(col))
                if xv is None or yv is None:
                    continue
                xs.append(xv)
                ys.append(yv)
                labels.append(str(r.get("mode") or ""))
            if not xs:
                continue
            # Sort by x.
            order = sorted(range(len(xs)), key=lambda i: int(xs[i]))
            xs = [xs[i] for i in order]
            ys = [ys[i] for i in order]
            labels = [labels[i] for i in order]
            fig, ax = plt.subplots(1, 1, figsize=(10.5, 3.8))
            ax.plot(xs, ys, marker="o")
            ax.set_xlabel(x_field)
            ax.set_ylabel(col)
            ax.set_title(f"{title_prefix}{col}")
        else:
            # Categorical: (workload/mode) if available.
            for idx, r in enumerate(rows):
                yv = to_float(r.get(col))
                if yv is None:
                    continue
                w = (r.get("workload") or "").strip()
                m = (r.get("mode") or "").strip()
                if w or m:
                    xs.append(f"{w}/{m}".strip("/"))
                else:
                    xs.append(str(idx))
                ys.append(yv)
            if not xs:
                continue
            fig, ax = plt.subplots(1, 1, figsize=(max(10.5, 0.35 * len(xs)), 3.8))
            x_idx = list(range(len(xs)))
            ax.bar(x_idx, ys)
            ax.set_xticks(x_idx)
            ax.set_xticklabels(xs, rotation=20, ha="right")
            ax.set_ylabel(col)
            ax.set_title(f"{title_prefix}{col}")

        safe_name = col.replace("/", "_").replace(" ", "_").replace(":", "_")
        _save_fig(fig, out_dir / f"{safe_name}.png", out_dir / f"{safe_name}.pdf")
        plt.close(fig)


@dataclass(frozen=True)
class OverheadPoint:
    workload: str
    mode: str
    throughput: Optional[float]
    latency_p99_us: Optional[float]


def _extract_overhead_points(artifact_root: Path, suite: str = "overhead") -> List[OverheadPoint]:
    points: List[OverheadPoint] = []

    for artifact_dir in _walk_artifacts(artifact_root):
        print(f"Examining artifact: {artifact_dir}")
        plan_path = artifact_dir / "plan.json"
        rr_path = artifact_dir / "run_result.json"
        if not plan_path.exists() or not rr_path.exists():
            continue
        try:
            rr = _load_json(rr_path)
            plan = rr.get("plan") if isinstance(rr.get("plan"), dict) else _load_json(plan_path)
        except Exception:
            continue
        if not isinstance(plan, dict) or _extract_suite(plan) != suite:
            continue

        workload = str(plan.get("workload") or "")
        mode = str(plan.get("mode") or "")

        throughput: Optional[float] = None
        latency_p99_us: Optional[float] = None

        # Client metrics live in run_result.commands[].metrics.
        for cmd in rr.get("commands") or []:
            if not isinstance(cmd, dict) or cmd.get("role") != "client":
                continue
            metrics = cmd.get("metrics")
            if not isinstance(metrics, dict):
                continue

            t = _as_float(metrics.get("throughput_ops_per_s"))
            if t is not None:
                throughput = (throughput or 0.0) + t

            lat = metrics.get("latency_us")
            if isinstance(lat, dict):
                p99 = _as_float(lat.get("p99"))
                if p99 is not None:
                    # Conservative across clients: take max p99.
                    latency_p99_us = p99 if latency_p99_us is None else max(latency_p99_us, p99)

            # NFV traffic uses pps.
            if throughput is None:
                pps = _as_float(metrics.get("avg_rate_pps"))
                if pps is not None:
                    throughput = pps

        if throughput is None and latency_p99_us is None:
            continue
        points.append(OverheadPoint(workload=workload, mode=mode, throughput=throughput, latency_p99_us=latency_p99_us))

    return points


def _write_recorded_metrics_csv(artifact_root: Path, out_csv: Path, *, suite: str) -> None:
    """Dump all recorded metrics for the given suite into a CSV table."""
    import csv

    rows: List[Dict[str, Any]] = []
    for artifact_dir in _walk_artifacts(artifact_root):
        run = load_artifact_run(artifact_dir)
        if run is None:
            continue
        if _extract_suite(run.plan) != suite:
            continue
        rows.append(extract_recorded_metrics(run))

    if not rows:
        return

    # Build stable field order (common keys first).
    fields = sorted({k for r in rows for k in r.keys()})
    preferred = ["artifact_dir", "suite", "workload", "mode"]
    ordered = [k for k in preferred if k in fields] + [k for k in fields if k not in preferred]

    out_csv.parent.mkdir(parents=True, exist_ok=True)
    with out_csv.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=ordered)
        w.writeheader()
        for r in rows:
            w.writerow(r)


def _plot_5_1_overhead(artifact_root: Path, out_dir: Path) -> None:
    _ensure_matplotlib()
    import matplotlib.pyplot as plt
    # print("Extracting overhead points from artifacts ", artifact_root)
    pts = _extract_overhead_points(artifact_root, suite="overhead")
    if not pts:
        raise RuntimeError("No overhead points found (suite=overhead)")

    # group: workload -> mode -> list[values]
    by_workload: Dict[str, Dict[str, Dict[str, List[float]]]] = {}
    for p in pts:
        w = by_workload.setdefault(p.workload, {})
        m = w.setdefault(p.mode, {"throughput": [], "latency_p99_us": []})                    
        if p.throughput is not None:
            m["throughput"].append(p.throughput)
        if p.latency_p99_us is not None:
            m["latency_p99_us"].append(p.latency_p99_us)

    workloads = sorted(by_workload.keys())

    def _overhead_drop_pct(baseline: float, other: float) -> float:
        # For throughput (higher is better): percent drop.
        return (baseline - other) / baseline * 100.0

    def _overhead_increase_pct(baseline: float, other: float) -> float:
        # For latency (lower is better): percent increase.
        return (other - baseline) / baseline * 100.0

    def _mean_or_nan(xs: List[float]) -> float:
        return float(mean(xs)) if xs else float("nan")

    # Build bar data for perf/microsentinel vs baseline.
    modes = ["perf", "microsentinel"]

    thr_perf: List[float] = []
    thr_ms: List[float] = []
    lat_perf: List[float] = []
    lat_ms: List[float] = []

    for w in workloads:
        baseline_thr = _mean_or_nan(by_workload[w].get("baseline", {}).get("throughput", []))
        perf_thr = _mean_or_nan(by_workload[w].get("perf", {}).get("throughput", []))
        ms_thr = _mean_or_nan(by_workload[w].get("microsentinel", {}).get("throughput", []))

        if math.isfinite(baseline_thr) and baseline_thr > 0 and math.isfinite(perf_thr):
            thr_perf.append(_overhead_drop_pct(baseline_thr, perf_thr))
        else:
            thr_perf.append(float("nan"))
        if math.isfinite(baseline_thr) and baseline_thr > 0 and math.isfinite(ms_thr):
            thr_ms.append(_overhead_drop_pct(baseline_thr, ms_thr))
        else:
            thr_ms.append(float("nan"))

        baseline_lat = _mean_or_nan(by_workload[w].get("baseline", {}).get("latency_p99_us", []))
        perf_lat = _mean_or_nan(by_workload[w].get("perf", {}).get("latency_p99_us", []))
        ms_lat = _mean_or_nan(by_workload[w].get("microsentinel", {}).get("latency_p99_us", []))

        if math.isfinite(baseline_lat) and baseline_lat > 0 and math.isfinite(perf_lat):
            lat_perf.append(_overhead_increase_pct(baseline_lat, perf_lat))
        else:
            lat_perf.append(float("nan"))
        if math.isfinite(baseline_lat) and baseline_lat > 0 and math.isfinite(ms_lat):
            lat_ms.append(_overhead_increase_pct(baseline_lat, ms_lat))
        else:
            lat_ms.append(float("nan"))

    x = list(range(len(workloads)))
    width = 0.38

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(10.5, 3.8))

    ax1.bar([i - width / 2 for i in x], thr_perf, width, label="perf")
    ax1.bar([i + width / 2 for i in x], thr_ms, width, label="MicroSentinel")
    ax1.set_xticks(x)
    ax1.set_xticklabels(workloads, rotation=20, ha="right")
    ax1.set_ylabel("Throughput overhead (%)")
    ax1.set_title("§5.1 Throughput")
    ax1.axhline(0.0, color="black", linewidth=0.8)
    ax1.legend(frameon=False)

    ax2.bar([i - width / 2 for i in x], lat_perf, width, label="perf")
    ax2.bar([i + width / 2 for i in x], lat_ms, width, label="MicroSentinel")
    ax2.set_xticks(x)
    ax2.set_xticklabels(workloads, rotation=20, ha="right")
    ax2.set_ylabel("P99 latency increase (%)")
    ax2.set_title("§5.1 P99 latency")
    ax2.axhline(0.0, color="black", linewidth=0.8)

    # Main paper-style figure.
    _save_fig(fig, out_dir / "5_1_overhead.png", out_dir / "5_1_overhead.pdf")
    plt.close(fig)

    # Additionally: dump and plot *all recorded metrics* for this suite.
    section_dir = out_dir / "5_1_overhead"
    recorded_csv = section_dir / "recorded_metrics.csv"
    _write_recorded_metrics_csv(artifact_root, recorded_csv, suite="overhead")
    if recorded_csv.exists():
        _auto_plot_metrics_table(recorded_csv, section_dir / "metrics", title_prefix="§5.1 ")


def _collect_artifacts_for_suite(artifact_root: Path, suite: str) -> List[Path]:
    out: List[Path] = []
    for artifact_dir in _walk_artifacts(artifact_root):
        rr_path = artifact_dir / "run_result.json"
        plan_path = artifact_dir / "plan.json"
        if not rr_path.exists() and not plan_path.exists():
            continue
        try:
            if rr_path.exists():
                rr = _load_json(rr_path)
                plan = rr.get("plan") if isinstance(rr.get("plan"), dict) else (_load_json(plan_path) if plan_path.exists() else None)
            else:
                plan = _load_json(plan_path)
        except Exception:
            continue
        if not isinstance(plan, dict):
            continue
        if _extract_suite(plan) == suite:
            out.append(artifact_dir)
    return out


def _plot_5_2_flow_accuracy(artifact_root: Path, out_dir: Path, clickhouse: Optional[str]) -> None:
    _ensure_matplotlib()
    import matplotlib.pyplot as plt

    artifacts = _collect_artifacts_for_suite(artifact_root, "flow_accuracy")
    if not artifacts:
        raise RuntimeError("No artifacts found for suite=flow_accuracy")

    section_dir = out_dir / "5_2_flow_accuracy"
    section_dir.mkdir(parents=True, exist_ok=True)

    list_json = section_dir / "flow_accuracy_artifacts.json"
    list_json.parent.mkdir(parents=True, exist_ok=True)
    list_json.write_text(json.dumps({"artifacts": [str(p) for p in artifacts]}, indent=2), encoding="utf-8")

    out_csv = section_dir / "flow_accuracy_delta.csv"
    out_json = section_dir / "flow_accuracy_report.json"

    args = [
        "--artifacts",
        str(list_json),
        "--out",
        str(out_json),
        "--out-csv",
        str(out_csv),
    ]
    if clickhouse:
        args += ["--clickhouse", clickhouse]

    _run_module("experiments.automation.analyze_flow_accuracy", args)

    rows = _read_csv(out_csv)
    if not rows:
        raise RuntimeError("flow_accuracy_delta.csv is empty")

    deltas: List[int] = []
    cov_mean: List[float] = []
    cov_std: List[float] = []
    acc_mean: List[float] = []
    acc_std: List[float] = []

    for r in rows:
        d = _as_int(r.get("delta_us"))
        if d is None:
            continue
        deltas.append(d)
        cov_mean.append(_as_float(r.get("coverage_mean")) or 0.0)
        cov_std.append(_as_float(r.get("coverage_std")) or 0.0)
        acc_mean.append(_as_float(r.get("accuracy_mean")) or 0.0)
        acc_std.append(_as_float(r.get("accuracy_std")) or 0.0)

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(10.5, 3.8))

    ax1.errorbar(deltas, acc_mean, yerr=acc_std, marker="o")
    ax1.set_xlabel("Δ (us)")
    ax1.set_ylabel("Flow accuracy")
    ax1.set_title("§5.2 Accuracy vs Δ")
    ax1.set_ylim(0.0, 1.05)

    ax2.errorbar(deltas, cov_mean, yerr=cov_std, marker="o")
    ax2.set_xlabel("Δ (us)")
    ax2.set_ylabel("Coverage")
    ax2.set_title("§5.2 Coverage vs Δ")
    ax2.set_ylim(0.0, 1.05)

    _save_fig(fig, out_dir / "5_2_flow_accuracy.png", out_dir / "5_2_flow_accuracy.pdf")
    _save_fig(fig, section_dir / "5_2_flow_accuracy.png", section_dir / "5_2_flow_accuracy.pdf")
    plt.close(fig)

    # Auto-plot all numeric columns from the analysis CSV.
    _auto_plot_metrics_table(out_csv, section_dir / "metrics", title_prefix="§5.2 ")

    # Also dump & plot all recorded metrics from run artifacts (run_result/plan/pidstat/prom).
    recorded_csv = section_dir / "recorded_metrics.csv"
    _write_recorded_metrics_csv(artifact_root, recorded_csv, suite="flow_accuracy")
    if recorded_csv.exists():
        _auto_plot_metrics_table(recorded_csv, section_dir / "recorded", title_prefix="§5.2 recorded ")


def _plot_top_share_bar(
    csv_path: Path,
    out_png: Path,
    out_pdf: Path,
    title: str,
    mode_filter: Optional[str],
    label_field: str,
    share_field: str,
    topk: int = 10,
) -> None:
    _ensure_matplotlib()
    import matplotlib.pyplot as plt

    rows = _read_csv(csv_path)
    if mode_filter:
        rows = [r for r in rows if (r.get("mode") or "") == mode_filter]

    scored: List[Tuple[str, float]] = []
    for r in rows:
        label = (r.get(label_field) or "").strip() or "(unknown)"
        share = _as_float(r.get(share_field))
        if share is None:
            continue
        scored.append((label, share))

    scored.sort(key=lambda kv: kv[1], reverse=True)
    scored = scored[: max(1, int(topk))]
    if not scored:
        raise RuntimeError(f"No data rows found in {csv_path}")

    labels = [s[0] for s in scored]
    vals = [s[1] * 100.0 for s in scored]  # to percent

    fig, ax = plt.subplots(1, 1, figsize=(10.5, 3.8))
    y = list(range(len(labels)))[::-1]
    ax.barh(y, vals[::-1])
    ax.set_yticks(y)
    ax.set_yticklabels(labels[::-1])
    ax.set_xlabel("Share (%)")
    ax.set_title(title)

    _save_fig(fig, out_png, out_pdf)
    plt.close(fig)


def _plot_5_3_data_object(artifact_root: Path, out_dir: Path) -> None:
    section_dir = out_dir / "5_3_data_object"
    section_dir.mkdir(parents=True, exist_ok=True)
    out_csv = section_dir / "data_object_summary.csv"
    out_json = section_dir / "data_object_summary.json"
    _run_module(
        "experiments.automation.analyze_data_object",
        [
            "--artifact-root",
            str(artifact_root),
            "--suite",
            "data_object",
            "--out",
            str(out_json),
            "--out-csv",
            str(out_csv),
        ],
    )

    # Plot top object mappings by share.
    _plot_top_share_bar(
        csv_path=out_csv,
        out_png=out_dir / "5_3_data_object.png",
        out_pdf=out_dir / "5_3_data_object.pdf",
        title="§5.3 Top data objects by normalized cost share",
        mode_filter="microsentinel",
        label_field="mapping",
        share_field="share_mean",
        topk=10,
    )

    # Also emit the same top plot into the per-section directory.
    _plot_top_share_bar(
        csv_path=out_csv,
        out_png=section_dir / "5_3_data_object.png",
        out_pdf=section_dir / "5_3_data_object.pdf",
        title="§5.3 Top data objects by normalized cost share",
        mode_filter="microsentinel",
        label_field="mapping",
        share_field="share_mean",
        topk=10,
    )

    _auto_plot_metrics_table(out_csv, section_dir / "metrics", title_prefix="§5.3 ")

    recorded_csv = section_dir / "recorded_metrics.csv"
    _write_recorded_metrics_csv(artifact_root, recorded_csv, suite="data_object")
    if recorded_csv.exists():
        _auto_plot_metrics_table(recorded_csv, section_dir / "recorded", title_prefix="§5.3 recorded ")


def _plot_5_4_false_sharing(artifact_root: Path, out_dir: Path) -> None:
    section_dir = out_dir / "5_4_false_sharing"
    section_dir.mkdir(parents=True, exist_ok=True)
    out_objects = section_dir / "false_sharing_objects.csv"
    out_lines = section_dir / "false_sharing_lines.csv"
    out_json = section_dir / "false_sharing_summary.json"
    _run_module(
        "experiments.automation.analyze_false_sharing",
        [
            "--artifact-root",
            str(artifact_root),
            "--suite",
            "false_sharing",
            "--out",
            str(out_json),
            "--out-csv-lines",
            str(out_lines),
            "--out-csv-objects",
            str(out_objects),
        ],
    )

    _plot_top_share_bar(
        csv_path=out_objects,
        out_png=out_dir / "5_4_false_sharing.png",
        out_pdf=out_dir / "5_4_false_sharing.pdf",
        title="§5.4 Top false-sharing object mappings by share",
        mode_filter="microsentinel",
        label_field="mapping",
        share_field="share_mean",
        topk=10,
    )

    _plot_top_share_bar(
        csv_path=out_objects,
        out_png=section_dir / "5_4_false_sharing.png",
        out_pdf=section_dir / "5_4_false_sharing.pdf",
        title="§5.4 Top false-sharing object mappings by share",
        mode_filter="microsentinel",
        label_field="mapping",
        share_field="share_mean",
        topk=10,
    )

    _auto_plot_metrics_table(out_objects, section_dir / "metrics_objects", title_prefix="§5.4 objects ")
    _auto_plot_metrics_table(out_lines, section_dir / "metrics_lines", title_prefix="§5.4 lines ")

    recorded_csv = section_dir / "recorded_metrics.csv"
    _write_recorded_metrics_csv(artifact_root, recorded_csv, suite="false_sharing")
    if recorded_csv.exists():
        _auto_plot_metrics_table(recorded_csv, section_dir / "recorded", title_prefix="§5.4 recorded ")


def _plot_5_5_numa_imbalance(artifact_root: Path, out_dir: Path) -> None:
    _ensure_matplotlib()
    import matplotlib.pyplot as plt

    section_dir = out_dir / "5_5_numa_imbalance"
    section_dir.mkdir(parents=True, exist_ok=True)

    out_csv = section_dir / "numa_imbalance_summary.csv"
    out_nodes = section_dir / "numa_imbalance_nodes.csv"
    out_json = section_dir / "numa_imbalance_summary.json"

    _run_module(
        "experiments.automation.analyze_numa_imbalance",
        [
            "--artifact-root",
            str(artifact_root),
            "--suite",
            "numa_imbalance",
            "--out",
            str(out_json),
            "--out-csv",
            str(out_csv),
            "--out-csv-nodes",
            str(out_nodes),
        ],
    )

    rows = _read_csv(out_csv)
    rows = [r for r in rows if (r.get("mode") or "") == "microsentinel"]
    if not rows:
        raise RuntimeError("No microsentinel rows in numa_imbalance_summary.csv")

    # Group by numa_action.
    labels: List[str] = []
    remote: List[float] = []
    lat: List[float] = []
    for r in rows:
        act = (r.get("numa_action") or "").strip() or "(none)"
        rr = _as_float(r.get("remote_ratio_all_mean"))
        ll = _as_float(r.get("latency_p99_us_mean"))
        if rr is None:
            continue
        labels.append(act)
        remote.append(rr * 100.0)
        lat.append(ll or float("nan"))

    x = list(range(len(labels)))

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(10.5, 3.8))
    ax1.bar(x, remote)
    ax1.set_xticks(x)
    ax1.set_xticklabels(labels, rotation=20, ha="right")
    ax1.set_ylabel("Remote ratio (all) (%)")
    ax1.set_title("§5.5 Remote access ratio")

    ax2.bar(x, lat)
    ax2.set_xticks(x)
    ax2.set_xticklabels(labels, rotation=20, ha="right")
    ax2.set_ylabel("KV P99 latency (us)")
    ax2.set_title("§5.5 P99 latency")

    _save_fig(fig, out_dir / "5_5_numa_imbalance.png", out_dir / "5_5_numa_imbalance.pdf")
    _save_fig(fig, section_dir / "5_5_numa_imbalance.png", section_dir / "5_5_numa_imbalance.pdf")
    plt.close(fig)

    _auto_plot_metrics_table(out_csv, section_dir / "metrics", title_prefix="§5.5 summary ")
    _auto_plot_metrics_table(out_nodes, section_dir / "metrics_nodes", title_prefix="§5.5 nodes ")

    recorded_csv = section_dir / "recorded_metrics.csv"
    _write_recorded_metrics_csv(artifact_root, recorded_csv, suite="numa_imbalance")
    if recorded_csv.exists():
        _auto_plot_metrics_table(recorded_csv, section_dir / "recorded", title_prefix="§5.5 recorded ")


def _plot_5_6_branch_mispredict(artifact_root: Path, out_dir: Path) -> None:
    _ensure_matplotlib()
    import matplotlib.pyplot as plt

    section_dir = out_dir / "5_6_branch_mispredict"
    section_dir.mkdir(parents=True, exist_ok=True)

    out_csv = section_dir / "branch_mispredict_summary.csv"
    out_hot = section_dir / "branch_mispredict_hotspots.csv"
    out_json = section_dir / "branch_mispredict_summary.json"

    _run_module(
        "experiments.automation.analyze_branch_mispredict",
        [
            "--artifact-root",
            str(artifact_root),
            "--suite",
            "branch_mispredict",
            "--out",
            str(out_json),
            "--out-csv",
            str(out_csv),
            "--out-csv-hotspots",
            str(out_hot),
        ],
    )

    summary = _read_csv(out_csv)
    summary = [r for r in summary if (r.get("mode") or "") == "microsentinel"]
    if not summary:
        raise RuntimeError("No microsentinel rows in branch_mispredict_summary.csv")

    # Use client_variant as main x-axis.
    variants: List[str] = []
    share: List[float] = []
    p99: List[float] = []
    for r in summary:
        v = (r.get("client_variant") or "").strip() or "(unknown)"
        s = _as_float(r.get("branch_share_mean"))
        l = _as_float(r.get("lb_latency_p99_us_mean"))
        if s is None:
            continue
        variants.append(v)
        share.append(s * 100.0)
        p99.append(l or float("nan"))

    # Pick the variant with max branch share for hotspot breakdown.
    worst_variant = None
    if variants:
        worst_variant = variants[max(range(len(variants)), key=lambda i: share[i])]

    hotspots = _read_csv(out_hot)
    hotspots = [r for r in hotspots if (r.get("mode") or "") == "microsentinel" and (r.get("client_variant") or "").strip() == (worst_variant or "")]

    ranked: List[Tuple[str, float]] = []
    for r in hotspots:
        fn = (r.get("function") or "").strip() or "(unknown)"
        cost = _as_float(r.get("norm_cost_mean"))
        if cost is None:
            continue
        ranked.append((fn, cost))
    ranked.sort(key=lambda kv: kv[1], reverse=True)
    ranked = ranked[:10]

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(10.5, 3.8))

    x = list(range(len(variants)))
    ax1.bar(x, share)
    ax1.set_xticks(x)
    ax1.set_xticklabels(variants)
    ax1.set_ylabel("Branch-mispredict share (%)")
    ax1.set_title("§5.6 Branch cost share")

    ax1b = ax1.twinx()
    ax1b.plot(x, p99, marker="o", color="black")
    ax1b.set_ylabel("LB P99 latency (us)")

    if ranked:
        labels = [k for k, _v in ranked]
        vals = [v for _k, v in ranked]
        y = list(range(len(labels)))[::-1]
        ax2.barh(y, vals[::-1])
        ax2.set_yticks(y)
        ax2.set_yticklabels(labels[::-1])
    ax2.set_xlabel("norm_cost")
    ax2.set_title(f"§5.6 Hotspots (variant={worst_variant})")

    _save_fig(fig, out_dir / "5_6_branch_mispredict.png", out_dir / "5_6_branch_mispredict.pdf")
    _save_fig(fig, section_dir / "5_6_branch_mispredict.png", section_dir / "5_6_branch_mispredict.pdf")
    plt.close(fig)

    _auto_plot_metrics_table(out_csv, section_dir / "metrics_summary", title_prefix="§5.6 summary ")
    _auto_plot_metrics_table(out_hot, section_dir / "metrics_hotspots", title_prefix="§5.6 hotspots ")

    recorded_csv = section_dir / "recorded_metrics.csv"
    _write_recorded_metrics_csv(artifact_root, recorded_csv, suite="branch_mispredict")
    if recorded_csv.exists():
        _auto_plot_metrics_table(recorded_csv, section_dir / "recorded", title_prefix="§5.6 recorded ")


def _plot_5_7_scalability(artifact_root: Path, out_dir: Path) -> None:
    _ensure_matplotlib()
    import matplotlib.pyplot as plt

    section_dir = out_dir / "5_7_scalability"
    section_dir.mkdir(parents=True, exist_ok=True)

    out_csv = section_dir / "scalability_summary.csv"
    out_points = section_dir / "scalability_points.csv"
    out_json = section_dir / "scalability_summary.json"

    _run_module(
        "experiments.automation.analyze_scalability",
        [
            "--artifact-root",
            str(artifact_root),
            "--suite",
            "scalability",
            "--out",
            str(out_json),
            "--out-csv",
            str(out_csv),
            "--out-csv-points",
            str(out_points),
        ],
    )

    rows = _read_csv(out_csv)
    rows = [r for r in rows if (r.get("mode") or "") == "microsentinel"]
    if not rows:
        raise RuntimeError("No microsentinel rows in scalability_summary.csv")

    # Group by filter_mode and plot throughput/latency vs token_rate.
    by_filter: Dict[str, List[Dict[str, str]]] = {}
    for r in rows:
        fm = (r.get("filter_mode") or "").strip() or "(default)"
        by_filter.setdefault(fm, []).append(r)

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(10.5, 3.8))

    for fm, frs in sorted(by_filter.items(), key=lambda kv: kv[0]):
        pts: List[Tuple[int, float, float]] = []
        for r in frs:
            tr = _as_int(r.get("token_rate"))
            tp = _as_float(r.get("throughput_mean"))
            lp = _as_float(r.get("latency_p99_us_mean"))
            if tr is None or tp is None:
                continue
            pts.append((tr, tp, lp or float("nan")))
        pts.sort(key=lambda t: t[0])
        if not pts:
            continue
        xs = [p[0] for p in pts]
        ys_t = [p[1] for p in pts]
        ys_l = [p[2] for p in pts]
        ax1.plot(xs, ys_t, marker="o", label=fm)
        ax2.plot(xs, ys_l, marker="o", label=fm)

    ax1.set_xlabel("token_rate (samples/s/core)")
    ax1.set_ylabel("Throughput (ops/s)")
    ax1.set_title("§5.7 Throughput vs sampling rate")
    ax1.legend(frameon=False)

    ax2.set_xlabel("token_rate (samples/s/core)")
    ax2.set_ylabel("P99 latency (us)")
    ax2.set_title("§5.7 P99 latency vs sampling rate")
    ax2.legend(frameon=False)

    _save_fig(fig, out_dir / "5_7_scalability.png", out_dir / "5_7_scalability.pdf")
    _save_fig(fig, section_dir / "5_7_scalability.png", section_dir / "5_7_scalability.pdf")
    plt.close(fig)

    _auto_plot_metrics_table(out_csv, section_dir / "metrics_summary", title_prefix="§5.7 summary ")
    _auto_plot_metrics_table(out_points, section_dir / "metrics_points", title_prefix="§5.7 points ")

    recorded_csv = section_dir / "recorded_metrics.csv"
    _write_recorded_metrics_csv(artifact_root, recorded_csv, suite="scalability")
    if recorded_csv.exists():
        _auto_plot_metrics_table(recorded_csv, section_dir / "recorded", title_prefix="§5.7 recorded ")


def main() -> int:
    ap = argparse.ArgumentParser(description="Generate figures for MicroSentinel evaluation (§5.1–§5.7)")
    ap.add_argument("--artifact-root", default="artifacts/experiments", help="Artifact root to scan")
    ap.add_argument("--out-dir", default="artifacts/experiments/figures_section5", help="Output directory")
    ap.add_argument("--clickhouse", default=None, help="Override ClickHouse endpoint for flow accuracy analysis")
    ap.add_argument(
        "--only",
        default=None,
        help="Comma-separated sections to run (e.g., '5.1' or '5.1,5.3'). Default: run all.",
    )
    ap.add_argument(
        "--skip",
        default=None,
        help="Comma-separated sections to skip (e.g., '5.2' to avoid flow accuracy).",
    )
    ap.add_argument(
        "--list-sections",
        action="store_true",
        help="List supported sections and exit.",
    )
    ap.add_argument(
        "--continue-on-error",
        action="store_true",
        help="Continue running other sections if one fails.",
    )
    args = ap.parse_args()

    artifact_root = Path(args.artifact_root)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    # Record provenance.
    meta = {
        "artifact_root": str(artifact_root),
        "argv": sys.argv,
        "python": sys.version,
        "env": {"USER": os.environ.get("USER"), "SUDO_USER": os.environ.get("SUDO_USER")},
    }
    (out_dir / "figures_meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")

    sections: List[Tuple[str, str, Any]] = [
        ("5.1", "overhead", lambda: _plot_5_1_overhead(artifact_root, out_dir)),
        ("5.2", "flow_accuracy", lambda: _plot_5_2_flow_accuracy(artifact_root, out_dir, clickhouse=args.clickhouse)),
        ("5.3", "data_object", lambda: _plot_5_3_data_object(artifact_root, out_dir)),
        ("5.4", "false_sharing", lambda: _plot_5_4_false_sharing(artifact_root, out_dir)),
        ("5.5", "numa_imbalance", lambda: _plot_5_5_numa_imbalance(artifact_root, out_dir)),
        ("5.6", "branch_mispredict", lambda: _plot_5_6_branch_mispredict(artifact_root, out_dir)),
        ("5.7", "scalability", lambda: _plot_5_7_scalability(artifact_root, out_dir)),
    ]

    if args.list_sections:
        for sid, suite, _fn in sections:
            print(f"{sid}\t{suite}")
        return 0

    only = set(_split_sections(args.only)) if args.only else None
    skip = set(_split_sections(args.skip)) if args.skip else set()

    for sid, _suite, fn in sections:
        if only is not None and sid not in only:
            continue
        if sid in skip:
            continue
        try:
            fn()
        except Exception as exc:
            if args.continue_on_error:
                print(f"WARN: section {sid} failed: {type(exc).__name__}: {exc}")
                continue
            raise

    print(f"OK: wrote figures to {out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
