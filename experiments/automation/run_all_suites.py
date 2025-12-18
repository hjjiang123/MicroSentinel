#!/usr/bin/env python3
"""Run all experiment suites and validate resulting artifacts.

This script is designed for interactive use on a dev box where sudo may be
required for microsentinel (eBPF) mode.

Typical usage:
  # 1) Authenticate once (keeps a sudo ticket alive)
  sudo -v

  # 2) Run all suites (default)
  sudo -E python3 -m experiments.automation.run_all_suites

  # 3) Or run a subset
  sudo -E python3 -m experiments.automation.run_all_suites --suites flow_accuracy_smoke,scalability_smoke

Outputs:
  - artifacts/experiments/run_all_suites_<ts>.json (suite->artifact list + validation)
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

import yaml

from experiments.automation.run_suite import load_suite

CONFIG_ROOT = Path("experiments/configs/experiments")
ARTIFACT_ROOT = Path("artifacts/experiments")


@dataclass
class SuiteOutcome:
    suite: str
    status: str  # ok | failed
    artifacts: List[str]
    error: Optional[str] = None
    validation: Optional[Dict] = None


def _list_suites() -> List[str]:
    suites = [p.stem for p in CONFIG_ROOT.glob("*.yaml")]
    suites.sort()
    return suites


def _validate_run_dir(run_dir: str) -> Dict:
    cmd = [
        sys.executable,
        "experiments/automation/validate_artifacts.py",
        "--artifact-root",
        run_dir,
        "--fail-on-error",
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    # Always return the human summary; callers can inspect exit code if needed.
    return {
        "cmd": " ".join(cmd),
        "returncode": proc.returncode,
        "stdout": proc.stdout.strip(),
        "stderr": proc.stderr.strip(),
    }


def _run_suite(suite: str, extra_args: List[str]) -> Dict:
    cmd = [sys.executable, "-m", "experiments.automation.run_suite", "--suite", suite, *extra_args]
    proc = subprocess.run(cmd, text=True)
    return {
        "cmd": " ".join(cmd),
        "returncode": proc.returncode,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="Run all suites and validate artifacts")
    ap.add_argument(
        "--suites",
        help="Comma-separated suite names (default: all under experiments/configs/experiments)",
    )
    ap.add_argument(
        "--continue-on-error",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Continue running remaining suites even if one fails (default: true)",
    )
    ap.add_argument(
        "--summary-out",
        help="Write JSON summary to this path (default: artifacts/experiments/run_all_suites_<ts>.json)",
    )
    ap.add_argument(
        "--override-modes",
        help="Forwarded to run_suite.py (comma-separated); useful for baseline-only dry passes",
    )
    ap.add_argument("--duration", type=int, help="Forwarded to run_suite.py")
    ap.add_argument("--perf-freq", type=int, help="Forwarded to run_suite.py")
    ap.add_argument("--token-rate", type=int, help="Forwarded to run_suite.py")
    ap.add_argument("--metrics-port", type=int, help="Forwarded to run_suite.py")
    args = ap.parse_args()

    if args.suites:
        suites = [s.strip() for s in args.suites.split(",") if s.strip()]
    else:
        suites = _list_suites()

    extra_args: List[str] = []
    if args.override_modes:
        extra_args += ["--override-modes", args.override_modes]
    if args.duration is not None:
        extra_args += ["--duration", str(args.duration)]
    if args.perf_freq is not None:
        extra_args += ["--perf-freq", str(args.perf_freq)]
    if args.token_rate is not None:
        extra_args += ["--token-rate", str(args.token_rate)]
    if args.metrics_port is not None:
        extra_args += ["--metrics-port", str(args.metrics_port)]

    # Determine output path.
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_path = Path(args.summary_out) if args.summary_out else (ARTIFACT_ROOT / f"run_all_suites_{ts}.json")

    outcomes: List[SuiteOutcome] = []

    for suite in suites:
        # Quick sanity that suite exists.
        suite_path = CONFIG_ROOT / f"{suite}.yaml"
        if not suite_path.exists():
            outcomes.append(SuiteOutcome(suite=suite, status="failed", artifacts=[], error=f"suite config not found: {suite_path}"))
            if not args.continue_on_error:
                break
            continue

        print(f"[run_all_suites] [{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] running suite={suite}")
        summary_path = ARTIFACT_ROOT / f"{suite}_latest.json"
        run_args = [*extra_args, "--summary", str(summary_path)]

        run_info = _run_suite(suite, run_args)
        if run_info["returncode"] != 0:
            outcomes.append(SuiteOutcome(suite=suite, status="failed", artifacts=[], error=f"run_suite failed rc={run_info['returncode']}: {run_info['cmd']}"))
            if not args.continue_on_error:
                break
            continue

        try:
            summary = json.loads(summary_path.read_text(encoding="utf-8"))
        except Exception as exc:
            outcomes.append(SuiteOutcome(suite=suite, status="failed", artifacts=[], error=f"failed to read suite summary: {summary_path}: {exc}"))
            if not args.continue_on_error:
                break
            continue

        artifacts = [str(a) for a in (summary.get("artifacts") or [])]
        validations = {a: _validate_run_dir(a) for a in artifacts}

        # Mark suite failed if any run failed validation.
        any_validation_failed = any(v.get("returncode") not in (0, None) for v in validations.values())
        status = "failed" if any_validation_failed else "ok"
        error = None
        if any_validation_failed:
            error = "one or more runs failed validation (see validation.*.stdout/stderr)"

        outcomes.append(SuiteOutcome(suite=suite, status=status, artifacts=artifacts, error=error, validation=validations))

    report = {
        "timestamp": ts,
        "suites": suites,
        "outcomes": [o.__dict__ for o in outcomes],
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"[run_all_suites] wrote {out_path}")

    # Exit non-zero if any failed.
    if any(o.status != "ok" for o in outcomes):
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
