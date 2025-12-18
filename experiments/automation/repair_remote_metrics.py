#!/usr/bin/env python3
"""Repair missing remote metrics in existing artifact directories.

This is meant to *salvage* runs where:
- The workload ran remotely and wrote metrics to a remote metrics_dir
- The local artifact dir was created as root (via sudo), but SCP was executed as
  an unprivileged user (to use that user's SSH keys), causing local writes to
  fail with Permission denied.

The script:
- Discovers run directories (single run dir, an artifact root scan, or a
  run_all_suites summary JSON)
- (Optionally) fixes ownership/permissions of the local artifact directory so
  the configured local_user can write into it
- Re-runs SCP pulls for all remote targets described in run_result.plan.commands
- Updates run_result.json (and plan.json if present) with the new
  remote_fetch_errors list

Usage examples:
  # 1) Repair a single run directory
  python3 experiments/automation/repair_remote_metrics.py \
    --artifact-root artifacts/experiments/load_balancer_20251217_131248 \
    --fix-perms --chown-user hjjiang

  # 2) Repair all runs from a run_all_suites summary (plus auto-discovered runs
  #    for that date under artifacts/experiments)
  python3 experiments/automation/repair_remote_metrics.py \
    --artifact-root artifacts/experiments \
    --summary-json artifacts/experiments/run_all_suites_20251217_205401.json \
    --fix-perms --chown-user hjjiang

Notes:
- For permission fixes when you are not root, the script uses `sudo -n`.
  Run `sudo -v` once in your terminal beforehand.
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple


REPO_ROOT = Path(__file__).resolve().parents[2]


@dataclass
class PullTarget:
    run_dir: Path
    command: str
    local_path: Path
    remote_src: str
    ssh_options: List[str]
    local_user: Optional[str]


def _as_path(value: str) -> Path:
    p = Path(value)
    if p.is_absolute():
        return p
    return (REPO_ROOT / p).resolve()


def _load_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _write_json(path: Path, obj: Dict[str, Any]) -> None:
    path.write_text(json.dumps(obj, indent=2, sort_keys=False) + "\n", encoding="utf-8")

def _try_read_metrics(path: Path) -> Optional[Dict[str, Any]]:
    try:
        if not path.exists():
            return None
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _resolve_metrics_path(run_dir: Path, metrics_path: str) -> Path:
    p = Path(metrics_path)
    if p.is_absolute():
        return p
    # Some plans store repo-relative paths like artifacts/experiments/...
    if metrics_path.startswith("artifacts/"):
        return (REPO_ROOT / metrics_path).resolve()
    # run_result.json typically stores paths relative to the run directory.
    return (run_dir / metrics_path).resolve()


def _embed_pulled_metrics(run_dir: Path, rr: Dict[str, Any]) -> None:
    """Populate rr['commands'][].metrics from metrics_path if missing."""
    commands = rr.get("commands")
    if not isinstance(commands, list):
        return
    for cmd in commands:
        if not isinstance(cmd, dict):
            continue
        metrics_path = cmd.get("metrics_path")
        if not isinstance(metrics_path, str) or not metrics_path:
            continue
        if cmd.get("metrics") is not None:
            continue
        metrics = _try_read_metrics(_resolve_metrics_path(run_dir, metrics_path))
        if isinstance(metrics, dict):
            cmd["metrics"] = metrics


def _sudo_prefix() -> List[str]:
    if os.geteuid() == 0:
        return []
    return ["sudo", "-n"]


def _run(cmd: List[str], *, check: bool = False) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, check=check, capture_output=True)


def _stat_uid_gid(path: Path) -> Tuple[int, int]:
    st = path.stat()
    return st.st_uid, st.st_gid


def _resolve_user_group(user: str, group: Optional[str]) -> Tuple[str, str]:
    if group:
        return user, group
    return user, user


def _fix_permissions(run_dir: Path, *, chown_user: str, chown_group: Optional[str], dry_run: bool) -> Optional[str]:
    """Best-effort: ensure run_dir and its immediate children are owned by user."""
    user, group = _resolve_user_group(chown_user, chown_group)

    # Only attempt if something is root-owned or not writable by the user.
    try:
        uid, _gid = _stat_uid_gid(run_dir)
    except Exception as exc:
        return f"stat_failed: {exc}"

    if uid != 0 and os.geteuid() != 0:
        # Non-root owned and we are not root; likely fine.
        return None

    if dry_run:
        return None

    # chown -R <user>:<group> run_dir
    cmd = [*_sudo_prefix(), "chown", "-R", f"{user}:{group}", str(run_dir)]
    try:
        _run(cmd, check=True)
    except subprocess.CalledProcessError as exc:
        stderr = exc.stderr.decode().strip() if exc.stderr else ""
        return f"chown_failed: {stderr or exc}"

    # chmod u+rwX,go+rX (0755-ish) to make sure directories are accessible.
    cmd = [*_sudo_prefix(), "chmod", "-R", "u+rwX,go+rX", str(run_dir)]
    try:
        _run(cmd, check=True)
    except subprocess.CalledProcessError as exc:
        stderr = exc.stderr.decode().strip() if exc.stderr else ""
        return f"chmod_failed: {stderr or exc}"

    return None


def _scp_pull(target: PullTarget, *, dry_run: bool) -> Optional[Dict[str, str]]:
    target.local_path.parent.mkdir(parents=True, exist_ok=True)

    scp_cmd = ["scp", *target.ssh_options, target.remote_src, str(target.local_path)]

    # Use the configured local_user to pick up that user's SSH keys.
    local_user = target.local_user
    if local_user and getpass.getuser() != local_user:
        scp_cmd = [*_sudo_prefix(), "-u", local_user, *scp_cmd]

    if dry_run:
        return None

    try:
        _run(scp_cmd, check=True)
        return None
    except subprocess.CalledProcessError as exc:
        stderr = exc.stderr.decode().strip() if exc.stderr else ""
        return {
            "command": target.command,
            "remote": target.remote_src,
            "local": str(target.local_path.relative_to(REPO_ROOT) if target.local_path.is_relative_to(REPO_ROOT) else target.local_path),
            "error": stderr,
        }


def _extract_pull_targets(run_dir: Path, rr: Dict[str, Any]) -> List[PullTarget]:
    plan = rr.get("plan") if isinstance(rr, dict) else None
    if not isinstance(plan, dict):
        return []
    commands = plan.get("commands")
    if not isinstance(commands, list):
        return []

    out: List[PullTarget] = []
    for cmd in commands:
        if not isinstance(cmd, dict):
            continue
        remote = cmd.get("remote")
        if not isinstance(remote, dict) or not remote.get("pull_metrics", True):
            continue

        host = remote.get("host")
        if not isinstance(host, str) or not host:
            continue
        ssh_options = remote.get("ssh_options")
        if not isinstance(ssh_options, list):
            ssh_options = ["-o", "BatchMode=yes"]

        local_user = remote.get("local_user")
        if local_user is not None and not isinstance(local_user, str):
            local_user = None

        name = str(cmd.get("name") or "<unknown>")

        # Primary metrics file.
        metrics_path = cmd.get("metrics_path")
        metrics_remote = cmd.get("metrics_remote_path")
        if isinstance(metrics_path, str) and metrics_path and isinstance(metrics_remote, str) and metrics_remote:
            local_path = _as_path(metrics_path)
            out.append(
                PullTarget(
                    run_dir=run_dir,
                    command=name,
                    local_path=local_path,
                    remote_src=f"{host}:{metrics_remote}",
                    ssh_options=list(ssh_options),
                    local_user=local_user,
                )
            )

        # Extra artifacts.
        extra = cmd.get("extra_artifacts")
        if isinstance(extra, list):
            for entry in extra:
                if not isinstance(entry, dict):
                    continue
                loc = entry.get("local")
                rem = entry.get("remote")
                if isinstance(loc, str) and loc and isinstance(rem, str) and rem:
                    local_path = _as_path(loc)
                    out.append(
                        PullTarget(
                            run_dir=run_dir,
                            command=name,
                            local_path=local_path,
                            remote_src=f"{host}:{rem}",
                            ssh_options=list(ssh_options),
                            local_user=local_user,
                        )
                    )

    return out


def _is_run_dir(path: Path) -> bool:
    return path.is_dir() and (path / "run_result.json").exists() and (path / "plan.json").exists()


def _discover_run_dirs(artifact_root: Path, *, summary_json: Optional[Path], date_prefix: Optional[str]) -> List[Path]:
    run_dirs: List[Path] = []

    if _is_run_dir(artifact_root):
        return [artifact_root]

    if summary_json:
        data = _load_json(summary_json)
        # Expected format from run_all_suites.py
        for oc in data.get("outcomes") or []:
            for p in oc.get("artifacts") or []:
                if isinstance(p, str):
                    d = (REPO_ROOT / p).resolve()
                    if _is_run_dir(d):
                        run_dirs.append(d)

        if not date_prefix and isinstance(data.get("timestamp"), str) and len(data["timestamp"]) >= 8:
            date_prefix = data["timestamp"][:8]

    if date_prefix and artifact_root.is_dir():
        # Include any other runs created for the same date (e.g. overhead runs
        # that were not captured in the summary due to rc!=0).
        pat = f"*_{date_prefix}_*"
        for child in sorted(artifact_root.glob(pat)):
            if _is_run_dir(child):
                run_dirs.append(child)

    # De-dup while preserving order.
    seen: set[Path] = set()
    uniq: List[Path] = []
    for d in run_dirs:
        if d not in seen:
            seen.add(d)
            uniq.append(d)
    return uniq


def main(argv: Optional[Sequence[str]] = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--artifact-root", required=True, help="Run dir or artifacts root directory")
    ap.add_argument("--summary-json", help="Path to run_all_suites_*.json to restrict/seed run list")
    ap.add_argument("--date-prefix", help="YYYYMMDD to scan under artifact-root (auto if summary-json provided)")
    ap.add_argument("--fix-perms", action="store_true", help="Attempt to chown/chmod local artifact dirs")
    ap.add_argument("--chown-user", default=None, help="User to own local artifact dirs (default: current user)")
    ap.add_argument("--chown-group", default=None, help="Group for local artifact dirs (default: same as user)")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--write-plan", action="store_true", help="Also update plan.json remote_fetch_errors")
    args = ap.parse_args(argv)

    artifact_root = _as_path(args.artifact_root)
    summary_json = _as_path(args.summary_json) if args.summary_json else None

    run_dirs = _discover_run_dirs(
        artifact_root,
        summary_json=summary_json,
        date_prefix=args.date_prefix,
    )

    if not run_dirs:
        print("[repair_remote_metrics] no run dirs found", file=sys.stderr)
        return 2

    chown_user = args.chown_user or getpass.getuser()

    summary: Dict[str, Any] = {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "artifact_root": str(artifact_root),
        "summary_json": str(summary_json) if summary_json else None,
        "runs": [],
    }

    ok = 0
    failed = 0

    for run_dir in run_dirs:
        rr_path = run_dir / "run_result.json"
        plan_path = run_dir / "plan.json"

        try:
            rr = _load_json(rr_path)
        except Exception as exc:
            summary["runs"].append({"run_dir": str(run_dir), "error": f"run_result_load_failed: {exc}"})
            failed += 1
            continue

        targets = _extract_pull_targets(run_dir, rr)
        if not targets:
            summary["runs"].append({"run_dir": str(run_dir), "skipped": True, "reason": "no_remote_targets"})
            continue

        perm_err = None
        if args.fix_perms:
            perm_err = _fix_permissions(run_dir, chown_user=chown_user, chown_group=args.chown_group, dry_run=args.dry_run)

        errors: List[Dict[str, str]] = []
        for t in targets:
            err = _scp_pull(t, dry_run=args.dry_run)
            if err:
                errors.append(err)

        # Update run_result.json plan.remote_fetch_errors.
        if isinstance(rr.get("plan"), dict):
            rr["plan"]["remote_fetch_errors"] = errors

        # If pulls succeeded, embed metrics content into rr.commands for offline analysis.
        if not errors:
            _embed_pulled_metrics(run_dir, rr)

        if not args.dry_run:
            _write_json(rr_path, rr)
            if args.write_plan and plan_path.exists():
                try:
                    plan = _load_json(plan_path)
                    if isinstance(plan, dict):
                        plan["remote_fetch_errors"] = errors
                        _write_json(plan_path, plan)
                except Exception:
                    pass

            # Write a small repair log.
            log_path = run_dir / "remote_fetch_repair.log"
            lines = []
            lines.append(f"run_dir={run_dir}")
            if perm_err:
                lines.append(f"perm_fix_error={perm_err}")
            lines.append(f"targets={len(targets)}")
            lines.append(f"errors={len(errors)}")
            for e in errors[:50]:
                lines.append(f"ERROR {e.get('command')} {e.get('remote')} -> {e.get('local')}: {e.get('error')}")
            log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

        run_rec = {
            "run_dir": str(run_dir),
            "targets": len(targets),
            "errors": len(errors),
        }
        if perm_err:
            run_rec["perm_fix_error"] = perm_err

        summary["runs"].append(run_rec)

        if errors:
            failed += 1
        else:
            ok += 1

    summary["ok"] = ok
    summary["failed"] = failed

    out_name = f"remote_repair_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    out_path = (artifact_root if artifact_root.is_dir() else artifact_root.parent) / out_name
    if not args.dry_run:
        _write_json(out_path, summary)
        print(f"[repair_remote_metrics] wrote {out_path}")

    print(f"[repair_remote_metrics] runs={len(run_dirs)} ok={ok} failed={failed}")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
