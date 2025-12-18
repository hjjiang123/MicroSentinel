#!/usr/bin/env python3
"""Helpers to extract *recorded* numeric metrics from artifact directories.

The goal is to support plotting without hard-coding every metric name.
We intentionally only rely on files already produced by the automation:
- run_result.json / plan.json
- monitor logs referenced by run_result.monitor_logs (pidstat/mpstat)
- agent_metrics.prom (Prometheus exposition)

This module is used by plot_section5_figures.py.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
import os
from typing import Any, Dict, Iterable, Iterator, List, Optional, Tuple


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def walk_artifacts(root: Path) -> Iterable[Path]:
    """Yield artifact run directories found under `root`.

    This function walks the tree rooted at `root` and yields any directory
    that contains either `plan.json` or `run_result.json`. It is recursive
    to support the suite-level layout `artifacts/experiments/<suite_run_dir>/<run_dir>`.
    """
    if not root.exists():
        return
    for dirpath, dirnames, filenames in os.walk(root):
        p = Path(dirpath)
        if (p / "plan.json").exists() or (p / "run_result.json").exists():
            yield p


def get_nested(mapping: Any, path: List[str]) -> Any:
    cur = mapping
    for key in path:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(key)
    return cur


def extract_suite(plan: Optional[Dict[str, Any]]) -> str:
    if not isinstance(plan, dict):
        return ""
    suite = (
        get_nested(plan, ["overrides", "annotations", "suite"])
        or get_nested(plan, ["annotations", "suite"])
        or plan.get("suite")
    )
    return str(suite) if suite else ""


def flatten_numeric(obj: Any, prefix: str = "") -> Dict[str, float]:
    """Flatten nested dict/list into {key: float} for numeric leaves.

    Keys use dotted paths, with list indices as [i].
    """

    out: Dict[str, float] = {}

    def emit(k: str, v: Any) -> None:
        if v is None:
            return
        if isinstance(v, bool):
            return
        if isinstance(v, (int, float)):
            out[k] = float(v)
            return
        if isinstance(v, str):
            # Try parsing common numeric strings.
            try:
                out[k] = float(v)
            except Exception:
                return

    def rec(cur: Any, cur_prefix: str) -> None:
        if isinstance(cur, dict):
            for kk, vv in cur.items():
                if not isinstance(kk, str):
                    continue
                nk = f"{cur_prefix}.{kk}" if cur_prefix else kk
                rec(vv, nk)
            return
        if isinstance(cur, list):
            for i, vv in enumerate(cur):
                nk = f"{cur_prefix}[{i}]" if cur_prefix else f"[{i}]"
                rec(vv, nk)
            return
        emit(cur_prefix, cur)

    rec(obj, prefix)
    return out


_PROM_LINE = re.compile(r"^([a-zA-Z_:][a-zA-Z0-9_:]*)(\{[^}]*\})?\s+([-+]?\d+(?:\.\d+)?(?:[eE][-+]?\d+)?)\s*$")


def parse_prometheus_exposition(text: str) -> Dict[str, float]:
    """Parse Prometheus text format into a flat metric dict.

    We ignore labels (i.e. treat each unique (name+labels) as its own key).
    """

    out: Dict[str, float] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = _PROM_LINE.match(line)
        if not m:
            continue
        name, labels, value = m.group(1), m.group(2), m.group(3)
        key = name + (labels or "")
        try:
            out[key] = float(value)
        except Exception:
            continue
    return out


def parse_agent_metrics_prom(path: Path) -> Dict[str, float]:
    if not path.exists():
        return {}
    try:
        return parse_prometheus_exposition(path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return {}


def parse_pidstat_avg(path: Path) -> Dict[int, Dict[str, float]]:
    """Parse `pidstat -ru` output and return per-pid averages.

    Returns: {pid: {"cpu_pct": ..., "rss_kb": ..., "vsz_kb": ...}}

    Best-effort: different pidstat versions vary in columns.
    """

    if not path.exists():
        return {}

    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except Exception:
        return {}

    header_cols: Optional[List[str]] = None
    idx_pid = idx_cpu = idx_rss = idx_vsz = None

    def update_indices(cols: List[str]) -> None:
        nonlocal header_cols, idx_pid, idx_cpu, idx_rss, idx_vsz
        header_cols = cols
        def find(col: str) -> Optional[int]:
            try:
                return cols.index(col)
            except ValueError:
                return None
        idx_pid = find("PID")
        idx_cpu = find("%CPU")
        idx_rss = find("RSS")
        idx_vsz = find("VSZ")

    out: Dict[int, Dict[str, float]] = {}

    for raw in lines:
        line = raw.strip()
        if not line:
            continue
        # Identify header rows.
        if " PID " in f" {line} " and "%CPU" in line and "UID" in line:
            cols = line.split()
            update_indices(cols)
            continue

        # We primarily want Average: lines.
        if not line.startswith("Average:"):
            continue
        if header_cols is None or idx_pid is None:
            continue

        tokens = line.split()
        # pidstat Average line format: Average: <UID> <PID> ...
        # Strip the leading Average: token.
        if tokens and tokens[0] == "Average:":
            tokens = tokens[1:]
        # Now tokens align with header (starting at UID).
        if len(tokens) < len(header_cols):
            continue

        try:
            pid = int(tokens[idx_pid])
        except Exception:
            continue
        row: Dict[str, float] = {}
        if idx_cpu is not None:
            try:
                row["cpu_pct"] = float(tokens[idx_cpu])
            except Exception:
                pass
        if idx_rss is not None:
            try:
                row["rss_kb"] = float(tokens[idx_rss])
            except Exception:
                pass
        if idx_vsz is not None:
            try:
                row["vsz_kb"] = float(tokens[idx_vsz])
            except Exception:
                pass
        if row:
            out[pid] = row

    return out


@dataclass(frozen=True)
class ArtifactRun:
    artifact_dir: Path
    plan: Dict[str, Any]
    run_result: Optional[Dict[str, Any]]


def load_artifact_run(artifact_dir: Path) -> Optional[ArtifactRun]:
    rr_path = artifact_dir / "run_result.json"
    plan_path = artifact_dir / "plan.json"
    if not rr_path.exists() and not plan_path.exists():
        return None
    try:
        rr = load_json(rr_path) if rr_path.exists() else None
    except Exception:
        rr = None
    try:
        plan = rr.get("plan") if (isinstance(rr, dict) and isinstance(rr.get("plan"), dict)) else (load_json(plan_path) if plan_path.exists() else None)
    except Exception:
        plan = None
    if not isinstance(plan, dict):
        return None
    return ArtifactRun(artifact_dir=artifact_dir, plan=plan, run_result=rr if isinstance(rr, dict) else None)


def extract_recorded_metrics(run: ArtifactRun) -> Dict[str, Any]:
    """Extract all recorded numeric metrics for a run.

    Output keys are stable-ish dotted names.
    """

    artifact_dir = run.artifact_dir
    rr = run.run_result or {}
    plan = run.plan

    base: Dict[str, Any] = {
        "artifact_dir": str(artifact_dir),
        "suite": extract_suite(plan),
        "workload": str(plan.get("workload") or ""),
        "mode": str(plan.get("mode") or ""),
    }

    # Plan-level numeric knobs (useful x-axes).
    instr = get_nested(plan, ["overrides", "instrumentation"])
    if isinstance(instr, dict):
        for k, v in instr.items():
            if isinstance(v, (int, float, str)):
                base[f"instrumentation.{k}"] = v

    # Host-level metrics (mpstat-derived currently).
    host_metrics = plan.get("host_metrics")
    if isinstance(host_metrics, dict):
        for k, v in host_metrics.items():
            base[f"host.{k}"] = v

    # Command metrics: flatten each client/server metrics dict.
    cmds = rr.get("commands")
    if isinstance(cmds, list):
        for cmd in cmds:
            if not isinstance(cmd, dict):
                continue
            name = str(cmd.get("name") or "command")
            role = str(cmd.get("role") or "")
            metrics = cmd.get("metrics")
            if isinstance(metrics, dict):
                flat = flatten_numeric(metrics)
                for kk, vv in flat.items():
                    base[f"cmd.{role}.{name}.{kk}"] = vv

    # Agent Prometheus metrics (if fetched).
    monitor_logs = rr.get("monitor_logs")
    agent_metrics_rel = None
    if isinstance(monitor_logs, dict):
        agent_metrics_rel = monitor_logs.get("agent_metrics")
    if isinstance(agent_metrics_rel, str) and agent_metrics_rel:
        prom_path = artifact_dir / agent_metrics_rel
        prom = parse_agent_metrics_prom(prom_path)
        for k, v in prom.items():
            base[f"agent_prom.{k}"] = v

    # pidstat averages -> map to recorded process names if possible.
    pidstat_rel = None
    if isinstance(monitor_logs, dict):
        pidstat_rel = monitor_logs.get("pidstat")
    proc_map = get_nested(plan, ["processes", "commands"])
    instr_proc = get_nested(plan, ["processes", "instrumentation"])

    if isinstance(pidstat_rel, str) and pidstat_rel:
        pid_rows = parse_pidstat_avg(artifact_dir / pidstat_rel)

        # instrumentation
        if isinstance(instr_proc, dict):
            pid = instr_proc.get("pid")
            try:
                pid_int = int(pid)
            except Exception:
                pid_int = 0
            if pid_int and pid_int in pid_rows:
                for kk, vv in pid_rows[pid_int].items():
                    base[f"pidstat.instrumentation.{kk}"] = vv

        # commands
        if isinstance(proc_map, dict):
            for name, entry in proc_map.items():
                if not isinstance(entry, dict):
                    continue
                pid = entry.get("pid")
                role = str(entry.get("role") or "")
                try:
                    pid_int = int(pid)
                except Exception:
                    continue
                row = pid_rows.get(pid_int)
                if not row:
                    continue
                for kk, vv in row.items():
                    base[f"pidstat.cmd.{role}.{name}.{kk}"] = vv

    return base
