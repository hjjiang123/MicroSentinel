#!/usr/bin/env python3
"""Run a named experiment suite defined in experiments/configs/experiments/*.yaml."""

from __future__ import annotations

import argparse
import contextlib
import json
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

import yaml

from experiments.automation.workload_runner import execute_workload

CONFIG_ROOT = Path("experiments/configs/experiments")
REPO_ROOT = Path(__file__).resolve().parents[2]


def load_suite(name: str, path_override: Optional[str] = None) -> dict:
    path = Path(path_override) if path_override else CONFIG_ROOT / f"{name}.yaml"
    return yaml.safe_load(path.read_text())


@dataclass
class SuiteRun:
    workload: str
    config: Optional[str]
    mode: str
    duration: int
    overrides: Dict
    repetitions: int


def deep_merge(base: Dict, extra: Dict) -> Dict:
    result = dict(base)
    for key, value in extra.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def expand_parameter_variants(params: Dict) -> List[Dict]:
    axes: List[List[Dict]] = []
    if params.get("delta_values_us"):
        axes.append([
            {"instrumentation": {"delta_us": value}}
            for value in params["delta_values_us"]
        ])
    if params.get("pmu_events"):
        axes.append([
            {"instrumentation": {"pmu_events": ",".join(events) if isinstance(events, list) else events}}
            for events in params["pmu_events"]
        ])
    if params.get("filters"):
        axes.append([
            {"instrumentation": {"filters": flt}}
            for flt in params["filters"]
        ])
    if params.get("numa_actions"):
        axes.append([
            {"workload": {"server": {"numa_policy": action.get("server_cmd_prefix")}}, "annotations": {"numa_action": action.get("description", "")}}
            for action in params["numa_actions"]
        ])
    if params.get("mutations"):
        axes.append([
            {"mutations": [mutation]}
            for mutation in params["mutations"]
        ])
    if params.get("client_variants"):
        axes.append([
            {"workload": {"clients": variant}, "annotations": {"client_variant": variant.get("name", "variant")}}
            for variant in params["client_variants"]
        ])
    if params.get("rate_scan"):
        scan = params["rate_scan"]
        samples = scan.get("samples_per_core", [])
        event_sets = scan.get("event_sets", []) or [None]
        axis: List[Dict] = []
        for rate in samples or [None]:
            for event_set in event_sets:
                override: Dict = {"instrumentation": {}}
                if rate is not None:
                    override["instrumentation"]["token_rate"] = rate
                if event_set:
                    override["instrumentation"]["pmu_events"] = ",".join(event_set)
                axis.append(override)
        axes.append(axis)
    variants = [{}]
    for axis in axes:
        variants = [deep_merge(base, option) for base in variants for option in axis]
    return variants or [{}]


def build_runs(suite: Dict, duration_override: Optional[int]) -> List[SuiteRun]:
    runs: List[SuiteRun] = []
    workloads = suite.get("workloads") or [
        {
            "name": suite["workload"],
            "config": suite.get("config"),
            "modes": suite.get("modes", ["microsentinel"]),
            "parameters": suite.get("parameters", {}),
        }
    ]
    base_overrides = suite.get("overrides", {})
    repetitions = suite.get("repetitions", 1)
    duration_default = duration_override or suite.get("run_s", 60)
    for workload in workloads:
        params = workload.get("parameters", {})
        variants = expand_parameter_variants(params)
        workload_overrides = workload.get("overrides", {})
        modes = workload.get("modes", suite.get("modes", ["microsentinel"]))
        for variant in variants:
            overrides = deep_merge(base_overrides, workload_overrides)
            overrides = deep_merge(overrides, variant)
            for mode in modes:
                runs.append(
                    SuiteRun(
                        workload=workload["name"],
                        config=workload.get("config"),
                        mode=mode,
                        duration=params.get("run_s", duration_default),
                        overrides=overrides,
                        repetitions=workload.get("repetitions", repetitions),
                    )
                )
    return runs


@contextlib.contextmanager
def apply_mutations(mutations: Optional[List[Dict]]):
    if not mutations:
        yield
        return
    applied: List[Path] = []
    try:
        for mutation in mutations:
            patch_path = REPO_ROOT / mutation.get("patch_file", "")
            if not patch_path.exists():
                raise FileNotFoundError(f"Patch not found: {patch_path}")
            subprocess.run(["git", "apply", str(patch_path)], cwd=REPO_ROOT, check=True)
            applied.append(patch_path)
        yield
    finally:
        for patch_path in reversed(applied):
            subprocess.run(["git", "apply", "-R", str(patch_path)], cwd=REPO_ROOT, check=True)


def run_suite(args):
    suite = load_suite(args.suite, args.config)
    artifacts: List[str] = []
    runs = build_runs(suite, args.duration)
    for suite_run in runs:
        for _ in range(suite_run.repetitions):
            overrides = deep_merge({}, suite_run.overrides)
            with apply_mutations(overrides.get("mutations")):
                artifact = execute_workload(
                    workload=suite_run.workload,
                    mode=suite_run.mode,
                    duration=suite_run.duration,
                    config_override=suite_run.config,
                    dry_run=args.dry_run,
                    perf_freq=args.perf_freq,
                    agent_bin=args.agent_bin,
                    agent_config=args.agent_config,
                    token_rate=args.token_rate,
                    metrics_port=args.metrics_port,
                    overrides=overrides,
                )
            if artifact:
                artifacts.append(artifact)
    if args.summary:
        Path(args.summary).write_text(json.dumps({"artifacts": artifacts}, indent=2), encoding="utf-8")


def parse_args():
    parser = argparse.ArgumentParser(description="Run an experiment suite")
    parser.add_argument("--suite", required=True)
    parser.add_argument("--config", help="Optional suite config path")
    parser.add_argument("--duration", type=int)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--perf-freq", type=int, default=2000)
    parser.add_argument("--agent-bin", default="build/agent/micro_sentinel_agent")
    parser.add_argument("--agent-config", default="config/micro_sentinel.toml")
    parser.add_argument("--token-rate", type=int, default=2000)
    parser.add_argument("--metrics-port", type=int, default=9105)
    parser.add_argument("--summary", help="Write JSON summary to path")
    return parser.parse_args()


if __name__ == "__main__":
    run_suite(parse_args())
