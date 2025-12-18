#!/usr/bin/env python3
"""Validate experiment artifacts for completeness and basic sanity.

This script is intentionally conservative: it checks that every run directory has
parsable JSON, referenced logs/metrics exist, remote fetch errors are surfaced,
and key numeric metrics are within plausible ranges.

It does *not* require ClickHouse.
"""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class Issue:
    level: str  # "error" | "warn"
    code: str
    message: str


def _read_json(path: Path) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    try:
        return json.loads(path.read_text(encoding="utf-8")), None
    except FileNotFoundError:
        return None, "missing"
    except json.JSONDecodeError as exc:
        return None, f"json_decode_error: {exc}"


def _exists(rel_or_abs: str, base: Path) -> bool:
    p = Path(rel_or_abs)
    if not p.is_absolute():
        p = base / p
    return p.exists()


def _sanity_metrics(metrics: Dict[str, Any]) -> List[Issue]:
    issues: List[Issue] = []

    if isinstance(metrics, dict) and not metrics:
        issues.append(Issue("error", "metrics_empty", "metrics JSON is an empty object"))
        return issues

    # Generic "non-empty" activity checks.
    activity_values: List[float] = []
    activity_keys = ("throughput_ops_per_s", "throughput", "pps", "qps", "operations")
    for key in activity_keys:
        if key not in metrics:
            continue
        try:
            value = float(metrics[key])
            activity_values.append(value)
            if key in {"throughput_ops_per_s", "throughput", "pps", "qps"} and value <= 0:
                issues.append(Issue("warn", "throughput_non_positive", f"{key}={value}"))
        except (TypeError, ValueError):
            issues.append(Issue("warn", "activity_not_numeric", f"{key}={metrics.get(key)!r}"))

    # If the metrics declare activity fields, require at least one to be > 0.
    if activity_values and max(activity_values) <= 0:
        issues.append(Issue("error", "metrics_no_activity", f"activity fields present but all <= 0: {activity_values}"))

    # Common LB/KV client schema.
    if "operations" in metrics and "errors" in metrics:
        try:
            ops = float(metrics["operations"]) or 0.0
            errs = float(metrics["errors"]) or 0.0
            if ops <= 0:
                issues.append(Issue("error", "operations_non_positive", f"operations={ops}"))
            if ops > 0 and errs / ops > 0.05:
                issues.append(Issue("warn", "high_error_ratio", f"errors/operations={errs/ops:.3f}"))
        except (TypeError, ValueError, ZeroDivisionError):
            pass

    latency = metrics.get("latency_us")
    if isinstance(latency, dict):
        def _get(name: str) -> Optional[float]:
            try:
                return float(latency[name])
            except Exception:
                return None

        p50 = _get("p50")
        p95 = _get("p95")
        p99 = _get("p99")
        if p50 is not None and p50 <= 0:
            issues.append(Issue("warn", "latency_non_positive", f"p50={p50}"))
        if None not in (p50, p95, p99):
            if not (p50 <= p95 <= p99):
                issues.append(Issue("warn", "latency_percentiles_inconsistent", f"p50={p50}, p95={p95}, p99={p99}"))

    return issues


def validate_run_dir(run_dir: Path) -> List[Issue]:
    issues: List[Issue] = []

    plan_path = run_dir / "plan.json"
    plan, plan_err = _read_json(plan_path)
    if plan_err:
        issues.append(Issue("error", "plan_missing_or_invalid", f"plan.json: {plan_err}"))
        return issues

    result_path = run_dir / "run_result.json"
    result, result_err = _read_json(result_path)
    if result_err:
        issues.append(Issue("error", "run_result_missing_or_invalid", f"run_result.json: {result_err}"))
        return issues

    # Check remote fetch errors recorded in plan.
    plan_obj = result.get("plan") if isinstance(result, dict) else None
    if isinstance(plan_obj, dict):
        runner_exc = plan_obj.get("runner_exception")
        if isinstance(runner_exc, dict) and (runner_exc.get("type") or runner_exc.get("message")):
            issues.append(
                Issue(
                    "error",
                    "runner_exception",
                    f"{runner_exc.get('type', 'Exception')}: {runner_exc.get('message', '')}".strip(),
                )
            )
        remote_errors = plan_obj.get("remote_fetch_errors")
        if isinstance(remote_errors, list) and remote_errors:
            issues.append(Issue("error", "remote_fetch_errors", f"remote_fetch_errors={len(remote_errors)}"))

    # Check monitor logs.
    monitor_logs = result.get("monitor_logs") if isinstance(result, dict) else None
    if isinstance(monitor_logs, dict):
        for name, rel in monitor_logs.items():
            if not _exists(str(rel), run_dir):
                issues.append(Issue("warn", "monitor_log_missing", f"{name}: {rel}"))

    # Check command logs + metrics.
    commands = result.get("commands") if isinstance(result, dict) else None
    if not isinstance(commands, list) or not commands:
        issues.append(Issue("error", "commands_missing", "run_result.commands missing/empty"))
        return issues

    for cmd in commands:
        if not isinstance(cmd, dict):
            continue
        name = str(cmd.get("name") or "<unknown>")

        log_rel = cmd.get("log")
        if isinstance(log_rel, str) and log_rel:
            if not _exists(log_rel, run_dir):
                issues.append(Issue("error", "command_log_missing", f"{name}: log={log_rel}"))

        metrics_rel = cmd.get("metrics_path")
        if metrics_rel is None:
            continue
        if isinstance(metrics_rel, str) and metrics_rel:
            if not _exists(metrics_rel, run_dir):
                issues.append(Issue("error", "metrics_file_missing", f"{name}: metrics_path={metrics_rel}"))
                continue
            metrics_path = (run_dir / metrics_rel) if not Path(metrics_rel).is_absolute() else Path(metrics_rel)
            metrics, metrics_err = _read_json(metrics_path)
            if metrics_err:
                issues.append(Issue("error", "metrics_invalid_json", f"{name}: {metrics_rel}: {metrics_err}"))
                continue
            # Sanity checks.
            if isinstance(metrics, dict):
                issues.extend(_sanity_metrics(metrics))

        # Also check embedded metrics presence when a metrics_path exists.
        if cmd.get("metrics") is None:
            issues.append(Issue("warn", "metrics_not_embedded", f"{name}: metrics_path present but metrics is null"))

    return issues


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--artifact-root", default="artifacts/experiments")
    ap.add_argument("--out", help="Optional JSON report path")
    ap.add_argument("--fail-on-error", action="store_true")
    args = ap.parse_args()

    root = Path(args.artifact_root)
    if not root.exists():
        raise SystemExit(f"artifact root not found: {root}")

    # Support validating either an artifact root containing many run dirs, or a single run dir.
    if root.is_dir() and (root / "plan.json").exists():
        run_dirs = [root]
    else:
        run_dirs = [p for p in root.iterdir() if p.is_dir() and (p / "plan.json").exists()]
        run_dirs.sort()

    report: Dict[str, Any] = {
        "artifact_root": str(root),
        "runs": [],
        "summary": {
            "total_runs": 0,
            "ok": 0,
            "errors": 0,
            "warnings": 0,
        },
    }

    had_error = False

    for run_dir in run_dirs:
        issues = validate_run_dir(run_dir)
        entry = {
            "run_dir": str(run_dir),
            "issues": [issue.__dict__ for issue in issues],
        }
        report["runs"].append(entry)

        report["summary"]["total_runs"] += 1
        if not issues:
            report["summary"]["ok"] += 1
        else:
            err_count = sum(1 for issue in issues if issue.level == "error")
            warn_count = sum(1 for issue in issues if issue.level == "warn")
            report["summary"]["errors"] += err_count
            report["summary"]["warnings"] += warn_count
            if err_count:
                had_error = True

    if args.out:
        Path(args.out).write_text(json.dumps(report, indent=2), encoding="utf-8")

    # Compact human output.
    summary = report["summary"]
    try:
        print(
            f"[validate_artifacts] runs={summary['total_runs']} ok={summary['ok']} errors={summary['errors']} warnings={summary['warnings']}"
        )
        if summary["errors"] or summary["warnings"]:
            for run in report["runs"]:
                issues = run["issues"]
                if not issues:
                    continue
                rel = run["run_dir"]
                print(f"- {rel}")
                for issue in issues:
                    print(f"  - {issue['level']}: {issue['code']}: {issue['message']}")
    except BrokenPipeError:
        # Common when piping to `head`; exit cleanly.
        return 0

    if args.fail_on_error and had_error:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
