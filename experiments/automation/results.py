#!/usr/bin/env python3
"""Helpers for aggregating workload run metrics."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple


@dataclass
class CommandMetric:
    name: str
    role: str
    log: str
    metrics_path: Optional[str] = None
    metrics: Optional[Dict] = None


@dataclass
class ResultRecorder:
    artifact_dir: Path
    plan: Dict
    commands: List[CommandMetric] = field(default_factory=list)
    monitor_logs: Dict[str, str] = field(default_factory=dict)

    def capture_command_metrics(self, procs: List[Tuple[object, object]]):
        # procs is List[(CommandSpec, Popen)] from workload_runner
        for spec, _proc in procs:
            record = CommandMetric(
                name=spec.name,
                role=spec.role,
                log=str((self.artifact_dir / spec.log_suffix).relative_to(self.artifact_dir)),
                metrics_path=str(spec.metrics_path.relative_to(self.artifact_dir)) if spec.metrics_path else None,
                metrics=_read_metrics(spec.metrics_path) if spec.metrics_path else None,
            )
            self.commands.append(record)

    def record_monitors(self, monitor_logs: Dict[str, str]):
        self.monitor_logs.update(monitor_logs)
        if "mpstat" in monitor_logs:
            path = Path(monitor_logs["mpstat"])
            usage = _parse_mpstat(path)
            if usage is not None:
                self.plan.setdefault("host_metrics", {})["cpu_usage_percent"] = usage

    def finalize(self):
        payload = {
            "plan": self.plan,
            "commands": [record.__dict__ for record in self.commands],
            "monitor_logs": {
                name: str(Path(path).relative_to(self.artifact_dir)) for name, path in self.monitor_logs.items()
            },
            "generated_at": datetime.utcnow().isoformat() + "Z",
        }
        (self.artifact_dir / "run_result.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")


def _read_metrics(path: Path) -> Optional[Dict]:
    if not path or not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None


def _parse_mpstat(path: Path) -> Optional[float]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except FileNotFoundError:
        return None
    avg_line = next((ln for ln in lines if ln.startswith("Average:")), None)
    if not avg_line:
        return None
    tokens = avg_line.split()
    # mpstat output: Average:  all  %usr %nice %sys %iowait %irq %soft %steal %guest %gnice %idle
    try:
        idle = float(tokens[-1])
    except (ValueError, IndexError):
        return None
    return max(0.0, min(100.0, 100.0 - idle))
