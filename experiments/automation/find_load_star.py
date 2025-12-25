#!/usr/bin/env python3
"""Find L* (load level) that yields a target CPU utilization band.

This utility automates Section 5.1.2 style calibration:
  - Run a workload in baseline mode
    - Parse host CPU usage from pidstat.log (tracked PIDs)
  - Adjust a workload-specific load knob
  - Step/binary-search until CPU is within [low, high]

Usage examples:
  python3 -m experiments.automation.find_load_star --workload nfv_service_chain --duration 60
  python3 -m experiments.automation.find_load_star --workload kv --knob connections_per_instance --min 16 --max 2048
"""

from __future__ import annotations

import argparse
import json
import math
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import yaml

from experiments.automation.process_utils import ProcessLaunchError
from experiments.automation.workload_runner import execute_workload


_DEFAULT_CONFIG_ROOT = Path("experiments/configs/workloads")


@dataclass
class RunPoint:
    value: int
    cpu_percent: Optional[float]
    artifact_dir: str
    error: Optional[str] = None


def _parse_target(value: float) -> float:
    """Accept either fraction (0..1) or percent (0..100)."""
    if value <= 1.0:
        return value * 100.0
    return value


def _load_yaml(path: Optional[str]) -> Dict:
    if not path:
        return {}
    p = Path(path)
    if not p.exists():
        return {}
    return yaml.safe_load(p.read_text(encoding="utf-8")) or {}


def _default_knob(workload: str) -> str:
    if workload == "kv":
        return "connections_per_instance"
    if workload == "load_balancer":
        return "flows"
    if workload == "nfv_service_chain":
        return "rate_pps"
    return "value"


def _knob_bounds_from_config(workload: str, knob: str, cfg: Dict) -> Tuple[Optional[int], Optional[int], Optional[int]]:
    """Return (start, min, max) best-effort based on workload YAML."""
    try:
        if workload == "kv" and knob in {"connections_per_instance", "instances"}:
            clients = cfg.get("clients") or {}
            start = int(clients.get(knob)) if clients.get(knob) is not None else None
            # Conservative defaults; user can override.
            if knob == "connections_per_instance":
                return start, 1, 4096
            return start, 1, 128
        if workload == "load_balancer" and knob == "flows":
            clients = cfg.get("clients") or {}
            start = int(clients.get("flows")) if clients.get("flows") is not None else None
            return start, 1, 8192
        if workload == "nfv_service_chain" and knob == "rate_pps":
            traffic = cfg.get("traffic_generator") or {}
            rates = traffic.get("rate_values") or traffic.get("rates") or []
            rates = [int(x) for x in rates if x is not None]
            if rates:
                rates_sorted = sorted(rates)
                start = rates_sorted[len(rates_sorted) // 2]
                return start, rates_sorted[0], rates_sorted[-1]
            return None, 1, 10_000_000
    except Exception:
        pass
    return None, None, None


def _build_workload_overrides(workload: str, knob: str, value: int) -> Dict:
    """Build the overrides structure expected by execute_workload()."""
    if workload == "kv":
        if knob not in {"connections_per_instance", "instances"}:
            raise ValueError("kv supports knobs: connections_per_instance, instances")
        return {"workload": {"clients": {knob: int(value)}}}
    if workload == "load_balancer":
        if knob != "flows":
            raise ValueError("load_balancer supports knob: flows")
        return {"workload": {"clients": {"flows": int(value)}}}
    if workload == "nfv_service_chain":
        if knob != "rate_pps":
            raise ValueError("nfv_service_chain supports knob: rate_pps")
        # Pass a single rate to traffic_gen.py via --rates.
        return {"workload": {"traffic": {"rate_values": [int(value)]}}}
    raise ValueError(f"Unsupported workload: {workload}")


def _read_cpu_percent(artifact_dir: Path) -> Optional[float]:
    """Return host CPU usage percent based on pidstat.log.

    We intentionally use pidstat (per-process CPU) instead of mpstat to
    avoid locale-dependent parsing and to align with per-run tracked PIDs.

        Method:
            1) Parse CPU count from the pidstat header: '(N CPU)' (best-effort)
            2) Parse per-sample rows for the %CPU table (must include the 'CPU' column)
            3) For each timestamp, sum %CPU of all rows that ran on the same core
            4) For each core, compute average utilization over all timestamps
            5) Return the maximum (busiest) core's average utilization

        Note: pidstat reports %CPU in units of 100% per CPU. This function returns a
        single-core utilization percentage (0..100) corresponding to the busiest core.
    """

    rr = artifact_dir / "run_result.json"
    pidstat_path = artifact_dir / "pidstat.log"
    if rr.exists():
        try:
            payload = json.loads(rr.read_text(encoding="utf-8"))
            monitor_logs = payload.get("monitor_logs") or {}
            rel = monitor_logs.get("pidstat")
            if isinstance(rel, str) and rel:
                candidate = artifact_dir / rel
                if candidate.exists():
                    pidstat_path = candidate
        except Exception:
            pass

    if not pidstat_path.exists():
        return None

    try:
        lines = pidstat_path.read_text(encoding="utf-8", errors="replace").splitlines()
    except Exception:
        return None
    
    # find how many lines of each test
    count_per_test = -1
    count_empty_lines = 0
    count_per_test_cpu = 0
    count_average_lines = 0
    for ln in lines:
        if ln.strip() == "":
            count_empty_lines += 1
            if count_empty_lines == 3:
                break
        else:
            count_per_test += 1
    for ln in lines:
        if "Average:" in ln:
            count_average_lines += 1
    count_per_test_cpu = count_per_test / 2 - 1
    print("Lines per test:", count_per_test)
    
    max_cpu_percent = 0.0
    for line in lines[5+count_per_test:4+2*count_per_test]:
        print("Processing line:", line)
        row = line.strip().split()
        # for i, token in enumerate(row):
        #     print("Token[{}]: {}".format(i, token))
        # print("Tokens in line:", len(row))
        if len(row) < 11:
            break
        cpu_percent = float(row[8])
        if cpu_percent > max_cpu_percent:
            max_cpu_percent = cpu_percent
    print("Max CPU percent:", max_cpu_percent)
    return max_cpu_percent


def _run_once(
    *,
    workload: str,
    config: Optional[str],
    duration: int,
    artifact_root: str,
    knob: str,
    value: int,
    perf_freq: int,
    agent_bin: str,
    agent_config: str,
    token_rate: Optional[int],
    metrics_port: int,
    extra_annotations: Dict[str, object],
) -> RunPoint:
    overrides = _build_workload_overrides(workload, knob, value)
    overrides = dict(overrides)
    overrides["annotations"] = {
        **(overrides.get("annotations") or {}),
        **extra_annotations,
        "tune.knob": knob,
        "tune.value": int(value),
    }
    try:
        print(f"[find_load_star] running {workload} with {knob}={value} token_rate={token_rate}")
        artifact_dir = Path(
            execute_workload(
                workload=workload,
                mode="baseline",
                duration=duration,
                config_override=config,
                dry_run=False,
                perf_freq=perf_freq,
                agent_bin=agent_bin,
                agent_config=agent_config,
                token_rate=token_rate,
                metrics_port=metrics_port,
                overrides=overrides,
                artifact_root=artifact_root,
            )
        )
        cpu = _read_cpu_percent(artifact_dir)
        return RunPoint(value=int(value), cpu_percent=cpu, artifact_dir=str(artifact_dir))
    except ProcessLaunchError as exc:
        return RunPoint(value=int(value), cpu_percent=None, artifact_dir="", error=str(exc))
    except BaseException as exc:
        return RunPoint(value=int(value), cpu_percent=None, artifact_dir="", error=f"{type(exc).__name__}: {exc}")


def _aggregate_cpu(points: List[RunPoint]) -> Optional[float]:
    vals = [p.cpu_percent for p in points if p.cpu_percent is not None]
    if not vals:
        return None
    vals.sort()
    return vals[len(vals) // 2]


def _in_band(cpu: float, low: float, high: float) -> bool:
    return low <= cpu <= high


def _score(cpu: float, low: float, high: float) -> float:
    """Lower is better; 0 means within band."""
    if cpu < low:
        return low - cpu
    if cpu > high:
        return cpu - high
    return 0.0


def find_load_star(args: argparse.Namespace) -> int:
    target_low = _parse_target(args.target_low)
    target_high = _parse_target(args.target_high)
    if target_low > target_high:
        target_low, target_high = target_high, target_low

    config_path = args.config
    if not config_path:
        candidate = _DEFAULT_CONFIG_ROOT / f"{args.workload}.yaml"
        if candidate.exists():
            config_path = str(candidate)
    cfg = _load_yaml(config_path)
    knob = args.knob or _default_knob(args.workload)
    start_cfg, min_cfg, max_cfg = _knob_bounds_from_config(args.workload, knob, cfg)
    start = int(args.start if args.start is not None else (start_cfg if start_cfg is not None else 1))
    min_value = int(args.min if args.min is not None else (min_cfg if min_cfg is not None else 1))
    max_value = int(args.max if args.max is not None else (max_cfg if max_cfg is not None else max(1, start)))
    if min_value < 1:
        min_value = 1
    if max_value < min_value:
        max_value = min_value
    start = max(min_value, min(max_value, start))

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    artifact_root = args.artifact_root or str(Path("artifacts/experiments") / f"find_load_star_{args.workload}_{ts}")
    Path(artifact_root).mkdir(parents=True, exist_ok=True)

    extra_annotations = {
        "tune.tool": "find_load_star",
        "tune.target_low": float(target_low),
        "tune.target_high": float(target_high),
        "tune.workload": args.workload,
    }

    def eval_value(v: int) -> Tuple[Optional[float], List[RunPoint]]:
        samples: List[RunPoint] = []
        for _ in range(max(1, int(args.samples_per_point))):
            samples.append(
                _run_once(
                    workload=args.workload,
                    config=args.config,
                    duration=args.duration,
                    artifact_root=artifact_root,
                    knob=knob,
                    value=v,
                    perf_freq=args.perf_freq,
                    agent_bin=args.agent_bin,
                    agent_config=args.agent_config,
                    token_rate=args.token_rate,
                    metrics_port=args.metrics_port,
                    extra_annotations=extra_annotations,
                )
            )
        return _aggregate_cpu(samples), samples

    all_points: List[RunPoint] = []
    cache: Dict[int, float] = {}

    def cached_eval(v: int) -> Optional[float]:
        if v in cache:
            return cache[v]
        cpu, samples = eval_value(v)
        all_points.extend(samples)
        if cpu is not None:
            cache[v] = cpu
        return cpu

    best_value: Optional[int] = None
    best_cpu: Optional[float] = None
    best_score = math.inf

    def update_best(v: int, cpu: Optional[float]) -> None:
        nonlocal best_value, best_cpu, best_score
        if cpu is None:
            return
        s = _score(cpu, target_low, target_high)
        if s < best_score:
            best_score, best_value, best_cpu = s, v, cpu

    # 1) Evaluate start.
    start_cpu = cached_eval(start)
    update_best(start, start_cpu)
    if start_cpu is not None and _in_band(start_cpu, target_low, target_high):
        return _write_summary_and_print(artifact_root, knob, target_low, target_high, best_value, best_cpu, all_points)

    # 2) Bracket by stepping.
    lo = start
    hi = start
    lo_cpu = start_cpu
    hi_cpu = start_cpu

    growth = float(args.growth)
    if growth <= 1.0:
        growth = 2.0

    # If too low, grow upper bound.
    if hi_cpu is not None and hi_cpu < target_low:
        while hi < max_value:
            lo, lo_cpu = hi, hi_cpu
            hi = min(max_value, max(hi + 1, int(math.ceil(hi * growth))))
            hi_cpu = cached_eval(hi)
            update_best(hi, hi_cpu)
            if hi_cpu is None:
                break
            if hi_cpu >= target_low:
                break

    # If too high, shrink lower bound.
    if lo_cpu is not None and lo_cpu > target_high:
        while lo > min_value:
            hi, hi_cpu = lo, lo_cpu
            lo = max(min_value, int(lo // growth))
            lo_cpu = cached_eval(lo)
            update_best(lo, lo_cpu)
            if lo_cpu is None:
                break
            if lo_cpu <= target_high:
                break

    # 3) Binary search within [lo, hi] when we have a sensible bracket.
    # We try to find any point in band; if not found, return the closest.
    if lo > hi:
        lo, hi = hi, lo

    for _ in range(int(args.max_iter)):
        if lo > hi:
            break
        mid = (lo + hi) // 2
        cpu = cached_eval(mid)
        update_best(mid, cpu)
        if cpu is None:
            break
        if _in_band(cpu, target_low, target_high):
            best_value, best_cpu = mid, cpu
            best_score = 0.0
            break
        if cpu < target_low:
            lo = mid + 1
        else:
            hi = mid - 1

    return _write_summary_and_print(artifact_root, knob, target_low, target_high, best_value, best_cpu, all_points)


def _write_summary_and_print(
    artifact_root: str,
    knob: str,
    target_low: float,
    target_high: float,
    best_value: Optional[int],
    best_cpu: Optional[float],
    points: List[RunPoint],
) -> int:
    out = Path(artifact_root) / "find_load_star_summary.json"
    payload = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "artifact_root": str(artifact_root),
        "knob": knob,
        "target_cpu_percent": {"low": target_low, "high": target_high},
        "best": {"value": best_value, "cpu_percent": best_cpu},
        "runs": [p.__dict__ for p in points],
    }
    out.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    # Human summary.
    print(f"[find_load_star] wrote {out}")
    if best_value is None or best_cpu is None:
        print("[find_load_star] failed to obtain cpu_percent; check pidstat availability and pidstat.log")
        return 2
    in_band = target_low <= best_cpu <= target_high
    print(
        "[find_load_star] best L*: "
        f"{knob}={best_value} cpu_percent={best_cpu:.2f} "
        f"target=[{target_low:.1f},{target_high:.1f}] in_band={in_band}"
    )
    return 0 if in_band else 1


def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Auto-search L* by targeting CPU utilization band (baseline mode)")
    ap.add_argument("--workload", choices=["kv", "load_balancer", "nfv_service_chain"], required=True)
    ap.add_argument("--config", help="Override workload config path (YAML)")
    ap.add_argument("--duration", type=int, default=60)

    ap.add_argument("--target-low", type=float, default=0.70, help="CPU low bound (0..1 or 0..100)")
    ap.add_argument("--target-high", type=float, default=0.80, help="CPU high bound (0..1 or 0..100)")

    ap.add_argument("--knob", help="Load knob name (workload-specific)")
    ap.add_argument("--start", type=int, help="Start value for the knob")
    ap.add_argument("--min", type=int, dest="min", help="Minimum knob value")
    ap.add_argument("--max", type=int, dest="max", help="Maximum knob value")
    ap.add_argument("--growth", type=float, default=2.0, help="Step growth factor for bracketing")
    ap.add_argument("--max-iter", type=int, default=12, help="Max binary-search iterations")
    ap.add_argument("--samples-per-point", type=int, default=1, help="Repeat runs per knob value; uses median CPU")

    ap.add_argument("--artifact-root", help="Write artifacts under this directory")

    # These are required by execute_workload signature, even in baseline.
    ap.add_argument("--perf-freq", type=int, default=2000)
    ap.add_argument("--agent-bin", default="build/agent/micro_sentinel_agent")
    ap.add_argument("--agent-config", default="agent/agent.conf")
    ap.add_argument("--token-rate", type=int, default=None)
    ap.add_argument("--metrics-port", type=int, default=9105)
    return ap.parse_args()


def main() -> int:
    return find_load_star(parse_args())


if __name__ == "__main__":
    raise SystemExit(main())
