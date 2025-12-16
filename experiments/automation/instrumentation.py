#!/usr/bin/env python3
"""Observer modes: baseline, perf, MicroSentinel."""

from __future__ import annotations

import contextlib
import shlex
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, Optional

from experiments.automation.process_utils import managed_process


def _baseline_cmd(_ctx: Dict[str, str]) -> Optional[str]:
    return None


def _perf_cmd(ctx: Dict[str, str]) -> str:
    perf_bin = shutil.which("perf_5.10") or shutil.which("perf") or "perf"
    events = ctx.get("pmu_events") or "cycles,LLC-load-misses,branches"
    freq = ctx.get("freq", "2000")
    duration = ctx.get("duration", "60")
    perf_mode = ctx.get("perf_mode", "record")
    out_path = ctx.get("perf_output")
    if perf_mode == "stat":
        interval = ctx.get("perf_interval_ms", "1000")
        out_arg = f"-o {shlex.quote(out_path)}" if out_path else ""
        return (
            f"{perf_bin} stat -x, -I {interval} -a -e {events} {out_arg} -- sleep {duration}"
        )
    out_arg = f"-o {shlex.quote(out_path)}" if out_path else ""
    return f"{perf_bin} record -F {freq} -a -e {events} -g {out_arg} -- sleep {duration}"


def _microsentinel_cmd(ctx: Dict[str, str]) -> str:
    argv = [
        ctx["agent_bin"],
        f"--config={ctx['config_path']}",
    ]
    metrics_port = ctx.get("metrics_port")
    if metrics_port:
        argv.append(f"--metrics-port={metrics_port}")
    # instrumentation mode determines sentinel vs diagnostic behavior via config;
    # no extra CLI args are needed here beyond the supported flags above.
    return " ".join(argv)


@dataclass
class InstrumentationPlan:
    mode: str
    cmd_builder: Callable[[Dict[str, str]], Optional[str]]


DEFAULT_PLANS: Dict[str, InstrumentationPlan] = {
    "baseline": InstrumentationPlan(mode="baseline", cmd_builder=_baseline_cmd),
    "perf": InstrumentationPlan(mode="perf", cmd_builder=_perf_cmd),
    "microsentinel": InstrumentationPlan(mode="microsentinel", cmd_builder=_microsentinel_cmd),
}


def start_instrumentation(
    mode: str,
    log_dir: Path,
    context: Dict[str, str],
    custom_plan: Optional[InstrumentationPlan] = None,
):
    plan = custom_plan or DEFAULT_PLANS.get(mode)
    if plan is None:
        raise ValueError(f"unknown instrumentation mode {mode}")
    cmd = plan.cmd_builder(context)
    if not cmd:
        return contextlib.nullcontext()
    argv = shlex.split(cmd)
    log_path = log_dir / f"instrumentation_{mode}.log"
    return managed_process(f"instrumentation[{mode}]", argv, log_path=log_path)
