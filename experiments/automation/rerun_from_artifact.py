#!/usr/bin/env python3
"""Re-run a single workload using overrides extracted from an existing artifact.

This is a convenience tool to reproduce/salvage a single failed run without
re-running an entire suite.

Example:
  # Re-run in the same mode/duration as the artifact
  python3 experiments/automation/rerun_from_artifact.py \
    --artifact artifacts/experiments/kv_20251217_193825

  # Override mode (e.g. re-run perf run as baseline)
  python3 experiments/automation/rerun_from_artifact.py \
    --artifact artifacts/experiments/kv_20251217_193825 --mode baseline

Notes:
- The new run is written under artifacts/experiments/<workload>_<timestamp>.
- Requires the usual privileges for the requested mode (perf/microsentinel).
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, Optional

from experiments.automation.workload_runner import execute_workload


def _load_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--artifact", required=True, help="Existing artifact run dir containing plan.json")
    ap.add_argument("--mode", help="Override mode (baseline/perf/microsentinel)")
    ap.add_argument("--duration", type=int, help="Override duration seconds")
    ap.add_argument("--config", help="Override workload config path")
    ap.add_argument("--perf-freq", type=int, default=2000)
    ap.add_argument("--agent-bin", default="build/agent/micro_sentinel_agent")
    ap.add_argument("--agent-config", default="agent/agent.conf")
    ap.add_argument("--token-rate", type=int, default=None)
    ap.add_argument("--metrics-port", type=int, default=9105)
    args = ap.parse_args()

    run_dir = Path(args.artifact)
    plan_path = run_dir / "plan.json"
    if not plan_path.exists():
        raise SystemExit(f"plan.json not found: {plan_path}")

    plan = _load_json(plan_path)
    workload = str(plan.get("workload"))
    mode = str(args.mode or plan.get("mode") or "baseline")
    duration = int(args.duration or plan.get("duration") or 60)
    overrides: Optional[Dict] = plan.get("overrides") if isinstance(plan.get("overrides"), dict) else None

    execute_workload(
        workload=workload,
        mode=mode,
        duration=duration,
        config_override=args.config,
        dry_run=False,
        perf_freq=args.perf_freq,
        agent_bin=args.agent_bin,
        agent_config=args.agent_config,
        token_rate=args.token_rate,
        metrics_port=args.metrics_port,
        overrides=overrides,
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
