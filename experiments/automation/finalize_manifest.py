#!/usr/bin/env python3
"""Build a 'final usable runs' manifest for experiment artifacts.

Goal
- You ran suites and may have repaired remote pulls and/or re-ran a few failed
  points.
- This tool produces a single JSON manifest that:
  - validates each run dir
  - groups runs by suite (from overrides.annotations.suite)
  - maps failed runs to a replacement run when an equivalent run exists
    (same workload/mode/duration and same overrides)

This is intentionally lightweight and does not query ClickHouse.

Example:
  python3 experiments/automation/finalize_manifest.py \
    --artifact-root artifacts/experiments \
    --date-prefix 20251217 \
    --include-date-prefix 20251218 \
    --out artifacts/experiments/final_manifest_20251217.json

If you have run_all_suites_*.json:
  python3 experiments/automation/finalize_manifest.py \
    --artifact-root artifacts/experiments \
    --summary-json artifacts/experiments/run_all_suites_20251217_205401.json
"""

from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

from experiments.automation.validate_artifacts import validate_run_dir


@dataclass(frozen=True)
class RunKey:
    workload: str
    mode: str
    duration: int
    overrides_json: str


def _load_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _write_json(path: Path, obj: Dict[str, Any]) -> None:
    path.write_text(json.dumps(obj, indent=2, sort_keys=False) + "\n", encoding="utf-8")


def _is_run_dir(path: Path) -> bool:
    return path.is_dir() and (path / "plan.json").exists() and (path / "run_result.json").exists()


def _extract_suite(plan: Dict[str, Any]) -> str:
    ov = plan.get("overrides")
    if not isinstance(ov, dict):
        return "<unknown>"
    ann = ov.get("annotations")
    if not isinstance(ann, dict):
        return "<unknown>"
    suite = ann.get("suite")
    return str(suite) if suite else "<unknown>"


def _normalize_overrides(overrides: Any) -> Dict[str, Any]:
    return overrides if isinstance(overrides, dict) else {}


def _run_key(plan: Dict[str, Any]) -> RunKey:
    workload = str(plan.get("workload") or "")
    mode = str(plan.get("mode") or "")
    try:
        duration = int(plan.get("duration") or 0)
    except Exception:
        duration = 0
    overrides = _normalize_overrides(plan.get("overrides"))
    overrides_json = json.dumps(overrides, sort_keys=True, separators=(",", ":"))
    return RunKey(workload=workload, mode=mode, duration=duration, overrides_json=overrides_json)


def _iter_run_dirs(root: Path, prefixes: List[str]) -> List[Path]:
    dirs: List[Path] = []
    if _is_run_dir(root):
        return [root]
    if not root.exists():
        return []
    pats = []
    for p in prefixes:
        pats.append(f"*_{p}_*")
    if not pats:
        pats = ["*"]
    seen: set[Path] = set()
    for pat in pats:
        for child in root.glob(pat):
            if child in seen:
                continue
            if _is_run_dir(child):
                seen.add(child)
                dirs.append(child)
    return sorted(dirs)


def _dirs_from_summary(summary_json: Path) -> List[Path]:
    data = _load_json(summary_json)
    out: List[Path] = []
    for oc in data.get("outcomes") or []:
        for p in oc.get("artifacts") or []:
            if isinstance(p, str):
                d = Path(p)
                out.append(d)
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--artifact-root", required=True)
    ap.add_argument("--summary-json", help="Optional run_all_suites_*.json")
    ap.add_argument("--date-prefix", help="YYYYMMDD to include (e.g. 20251217)")
    ap.add_argument(
        "--include-date-prefix",
        action="append",
        default=[],
        help="Additional YYYYMMDD prefixes to include (can repeat)",
    )
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    root = Path(args.artifact_root)
    out_path = Path(args.out)

    prefixes: List[str] = []
    if args.date_prefix:
        prefixes.append(args.date_prefix)
    prefixes.extend(args.include_date_prefix or [])

    run_dirs: List[Path] = []
    summary_dirs: List[Path] = []
    if args.summary_json:
        sj = Path(args.summary_json)
        try:
            summary_dirs = [Path(p) for p in _dirs_from_summary(sj)]
        except Exception:
            summary_dirs = []
        # If timestamp is present, auto-add that date prefix.
        try:
            ts = _load_json(sj).get("timestamp")
            if isinstance(ts, str) and len(ts) >= 8:
                prefixes.append(ts[:8])
        except Exception:
            pass

    # Start with summary dirs (if any).
    for d in summary_dirs:
        dd = d if d.is_absolute() else Path(args.artifact_root) / d.name if (Path(args.artifact_root) / d.name).exists() else d
        dd = dd if dd.is_absolute() else Path(dd)
        if _is_run_dir(dd):
            run_dirs.append(dd)
        else:
            # Fallback: treat as repo-relative
            cand = Path.cwd() / d
            if _is_run_dir(cand):
                run_dirs.append(cand)

    # Add scans by date prefixes.
    run_dirs.extend(_iter_run_dirs(root, prefixes))

    # De-dup.
    seen: set[Path] = set()
    uniq: List[Path] = []
    for d in run_dirs:
        d = d.resolve()
        if d not in seen and _is_run_dir(d):
            seen.add(d)
            uniq.append(d)
    run_dirs = sorted(uniq)

    # Validate + build indices.
    records: List[Dict[str, Any]] = []
    ok_by_key: Dict[RunKey, List[Path]] = defaultdict(list)
    key_by_dir: Dict[Path, RunKey] = {}
    suite_by_dir: Dict[Path, str] = {}
    issues_by_dir: Dict[Path, List[Dict[str, str]]] = {}

    for d in run_dirs:
        plan = _load_json(d / "plan.json")
        suite = _extract_suite(plan)
        key = _run_key(plan)

        issues = validate_run_dir(d)
        errors = [i for i in issues if i.level == "error"]

        rec = {
            "run_dir": str(d),
            "suite": suite,
            "workload": key.workload,
            "mode": key.mode,
            "duration": key.duration,
            "ok": len(errors) == 0,
            "errors": [{"code": e.code, "message": e.message} for e in errors],
        }
        records.append(rec)

        key_by_dir[d] = key
        suite_by_dir[d] = suite
        issues_by_dir[d] = [{"level": i.level, "code": i.code, "message": i.message} for i in issues]

        if len(errors) == 0:
            ok_by_key[key].append(d)

    # Pick a replacement for failed runs when possible.
    replacements: Dict[str, str] = {}
    effective_runs: List[Dict[str, Any]] = []
    suite_counts = defaultdict(lambda: Counter())

    for rec in records:
        run_dir = Path(rec["run_dir"]).resolve()
        suite = rec["suite"]

        suite_counts[suite]["runs"] += 1
        suite_counts[suite]["ok"] += 1 if rec["ok"] else 0
        suite_counts[suite]["failed"] += 0 if rec["ok"] else 1

        eff = dict(rec)
        eff["effective_run_dir"] = rec["run_dir"]
        eff["effective_ok"] = rec["ok"]
        eff["replacement_reason"] = None

        if not rec["ok"]:
            key = key_by_dir.get(run_dir)
            cands = ok_by_key.get(key, []) if key else []
            cands = [c for c in cands if c != run_dir]
            if cands:
                # Prefer newest by directory name.
                chosen = sorted(cands, key=lambda p: p.name)[-1]
                replacements[str(run_dir)] = str(chosen)
                eff["effective_run_dir"] = str(chosen)
                eff["effective_ok"] = True
                eff["replacement_reason"] = "matched_by(workload,mode,duration,overrides)"

        effective_runs.append(eff)

    # Build suite -> effective ok set.
    suites: Dict[str, Any] = {}
    for eff in effective_runs:
        suite = eff["suite"]
        suites.setdefault(suite, {"runs": [], "effective_ok_runs": []})
        suites[suite]["runs"].append(eff)

    # Add effective_ok list per suite (unique).
    for suite, blob in suites.items():
        seen_eff: set[str] = set()
        for eff in blob["runs"]:
            if eff.get("effective_ok"):
                d = str(eff.get("effective_run_dir"))
                if d not in seen_eff:
                    seen_eff.add(d)
        blob["effective_ok_runs"] = sorted(seen_eff)

    manifest: Dict[str, Any] = {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "artifact_root": str(root.resolve()),
        "summary_json": args.summary_json,
        "included_date_prefixes": prefixes,
        "stats": {
            "runs_total": len(records),
            "runs_ok": sum(1 for r in records if r["ok"]),
            "runs_failed": sum(1 for r in records if not r["ok"]),
            "runs_effective_ok": sum(1 for r in effective_runs if r["effective_ok"]),
            "runs_replaced": len(replacements),
        },
        "suite_counts": {k: dict(v) for k, v in suite_counts.items()},
        "replacements": replacements,
        "suites": suites,
    }

    _write_json(out_path, manifest)
    print(f"[finalize_manifest] wrote {out_path}")
    print(
        f"[finalize_manifest] runs={manifest['stats']['runs_total']} ok={manifest['stats']['runs_ok']} failed={manifest['stats']['runs_failed']} replaced={manifest['stats']['runs_replaced']} effective_ok={manifest['stats']['runs_effective_ok']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
