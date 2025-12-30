#!/usr/bin/env python3
"""Launch a workload plus optional instrumentation according to YAML config."""

from __future__ import annotations

import argparse
import contextlib
import json
import math
import os
import pwd
import resource
import shlex
import shutil
import socket
import subprocess
import time
import sys
import urllib.error
import urllib.request
from copy import deepcopy
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import yaml

from experiments.automation.instrumentation import start_instrumentation
from experiments.automation.pmu_catalog import build_pmu_update
from experiments.automation.process_utils import managed_process, ProcessLaunchError
from experiments.automation.results import ResultRecorder


@dataclass
class RemoteSpec:
    host: str
    workdir: str = ""
    metrics_dir: Optional[str] = None
    pull_metrics: bool = True
    ssh_options: List[str] = field(default_factory=lambda: ["-o", "BatchMode=yes"])
    local_user: Optional[str] = None

    def metrics_target(self, filename: str) -> str:
        base = self.metrics_dir or self.workdir or "."
        base = base.rstrip("/")
        if not base or base == ".":
            return f"./{filename}"
        return f"{base}/{filename}"

    def wrap_command(self, argv: List[str]) -> List[str]:
        remote_cmd = " ".join(shlex.quote(arg) for arg in argv)

        # Ensure the remote metrics directory exists before running any command that
        # tries to write metrics/truth files there.
        if self.metrics_dir:
            metrics_dir = str(self.metrics_dir)
            if metrics_dir.startswith("~/") and " " not in metrics_dir:
                remote_cmd = f"mkdir -p {metrics_dir} && {remote_cmd}"
            else:
                remote_cmd = f"mkdir -p {shlex.quote(metrics_dir)} && {remote_cmd}"
        if self.workdir:
            if self.workdir.startswith("~/") and " " not in self.workdir:
                remote_cmd = f"cd {self.workdir} && {remote_cmd}"
            else:
                remote_cmd = f"cd {shlex.quote(self.workdir)} && {remote_cmd}"
        cmd = ["ssh", *self.ssh_options, self.host, remote_cmd]
        if self.local_user and os.geteuid() == 0:
            return ["sudo", "-u", self.local_user, *cmd]
        return cmd


@dataclass
class CommandSpec:
    name: str
    argv: List[str]
    log_suffix: str
    ready_wait: float = 1.0
    env: Optional[Dict[str, str]] = None
    metrics_path: Optional[Path] = None
    role: str = "aux"
    remote: Optional[RemoteSpec] = None
    metrics_remote_path: Optional[str] = None
    extra_artifacts: List[Tuple[Path, Optional[str]]] = field(default_factory=list)


CONFIG_ROOT = Path("experiments/configs/workloads")
ARTIFACT_ROOT = Path("artifacts/experiments")
INSTRUMENTATION_DEFAULTS_PATH = Path("experiments/configs/instrumentation/defaults.yaml")


def _load_instrumentation_defaults():
    if not INSTRUMENTATION_DEFAULTS_PATH.exists():
        return {}, {}, {}
    try:
        raw = yaml.safe_load(INSTRUMENTATION_DEFAULTS_PATH.read_text(encoding="utf-8"))
    except OSError:
        return {}, {}, {}
    if not isinstance(raw, dict):
        return {}, {}, {}
    defaults = raw.get("defaults") or {}
    workload_defaults = raw.get("workload_defaults") or {}
    object_maps = raw.get("object_map_presets") or {}
    return defaults, workload_defaults, object_maps


_GLOBAL_INSTRUMENTATION_DEFAULTS, _WORKLOAD_INSTRUMENTATION_DEFAULTS, _OBJECT_MAP_PRESETS = _load_instrumentation_defaults()


def _coerce_int(value, fallback):
    try:
        return int(value)
    except (TypeError, ValueError):
        return fallback


DEFAULT_TOKEN_RATE = _coerce_int(_GLOBAL_INSTRUMENTATION_DEFAULTS.get("token_rate"), 2000)


CLIENT_GRACE_S = 5


CAP_SYS_ADMIN = 21
CAP_BPF = 39


def _cap_eff_mask() -> int:
    try:
        status = Path("/proc/self/status").read_text(encoding="utf-8", errors="ignore")
        for line in status.splitlines():
            if line.startswith("CapEff:"):
                _, value = line.split(":", 1)
                return int(value.strip(), 16)
    except Exception:
        pass
    return 0


def _has_cap(cap_num: int) -> bool:
    mask = _cap_eff_mask()
    return bool(mask & (1 << cap_num))


def _read_sysctl_int(path: str) -> int:
    try:
        return int(Path(path).read_text(encoding="utf-8").strip())
    except Exception:
        return -1


def _format_memlock_bytes(value: int) -> str:
    if value < 0:
        return "unknown"
    if value == resource.RLIM_INFINITY:
        return "unlimited"
    # render as KiB for familiarity with `ulimit -l`
    return f"{value // 1024} KiB"


def _microsentinel_precheck(skip: bool = False) -> None:
    if skip:
        return

    issues: List[str] = []

    unpriv_bpf = _read_sysctl_int("/proc/sys/kernel/unprivileged_bpf_disabled")
    if os.geteuid() != 0 and unpriv_bpf == 1:
        issues.append("kernel.unprivileged_bpf_disabled=1 and runner is not root")

    # Most environments require CAP_SYS_ADMIN (older kernels) or CAP_BPF (newer kernels).
    if os.geteuid() != 0 and not (_has_cap(CAP_SYS_ADMIN) or _has_cap(CAP_BPF)):
        issues.append("missing CAP_SYS_ADMIN/CAP_BPF for loading eBPF programs")

    try:
        soft, hard = resource.getrlimit(resource.RLIMIT_MEMLOCK)
    except Exception:
        soft, hard = -1, -1

    # Try to raise memlock if possible (applies to child processes too).
    try:
        if hard not in (-1, resource.RLIM_INFINITY) and soft < hard:
            resource.setrlimit(resource.RLIMIT_MEMLOCK, (hard, hard))
            soft = hard
        elif hard == resource.RLIM_INFINITY and soft != resource.RLIM_INFINITY:
            resource.setrlimit(resource.RLIMIT_MEMLOCK, (resource.RLIM_INFINITY, resource.RLIM_INFINITY))
            soft = hard = resource.RLIM_INFINITY
    except Exception:
        pass

    # libbpf commonly fails with small memlock limits.
    if soft not in (-1, resource.RLIM_INFINITY) and soft < (64 * 1024 * 1024):
        issues.append(f"RLIMIT_MEMLOCK too low ({_format_memlock_bytes(soft)}; recommend unlimited)")

    if issues:
        msg = (
            "microsentinel mode needs eBPF program loading, but the environment is not ready:\n"
            + "\n".join(f"- {item}" for item in issues)
            + "\n\nFix options (pick one):\n"
            + "1) Run the suite/workload as root (recommended for experiments):\n"
            + "   sudo -E python3 -m experiments.automation.run_suite ...\n"
            + "2) Grant capabilities to the agent binary (advanced; may vary by kernel):\n"
            + "   sudo setcap cap_sys_admin,cap_bpf+ep build/agent/micro_sentinel_agent\n"
            + "3) Raise memlock (required on many systems):\n"
            + "   ulimit -l unlimited\n"
            + "\nIf you intentionally want to continue (agent may fall back to mock mode), set:\n"
            + "  overrides.instrumentation.bpf_skip_precheck=true\n"
        )
        raise ProcessLaunchError(msg)


def _build_instrumentation_overrides(workload_name: str, user_overrides: Optional[Dict[str, object]]):
    merged: Dict[str, object] = {}
    sources: Dict[str, str] = {}

    def _ingest(source: Optional[Dict[str, object]], label: str) -> None:
        if not isinstance(source, dict):
            return
        for key, value in source.items():
            merged[key] = deepcopy(value)
            sources[key] = label

    _ingest(_GLOBAL_INSTRUMENTATION_DEFAULTS, "global")
    _ingest(_WORKLOAD_INSTRUMENTATION_DEFAULTS.get(workload_name), "workload")
    _ingest(user_overrides, "user")

    preset_name = merged.pop("object_map_preset", None)
    if preset_name and not merged.get("object_map"):
        preset = _OBJECT_MAP_PRESETS.get(preset_name)
        if isinstance(preset, dict):
            merged["object_map"] = deepcopy(preset)
            sources["object_map"] = "preset"

    return merged, sources


def _log_progress(artifact_dir: Path, message: str) -> None:
    """Append a progress line to a per-run log so users can follow execution."""
    try:
        log_path = artifact_dir / "progress.log"
        log_path.parent.mkdir(parents=True, exist_ok=True)
        with log_path.open("a", encoding="utf-8") as f:
            ts = datetime.now().isoformat(timespec="seconds")
            f.write(f"[{ts}] {message}\n")
    except Exception:
        # Best-effort only: don't break experiments if logging fails.
        pass


def _parse_agent_config(path: Path) -> Dict[str, str]:
    values: Dict[str, str] = {}
    if not path.exists():
        return values
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" not in line:
                continue
            key, value = line.split("=", 1)
            values[key.strip()] = value.strip()
    except OSError:
        return {}
    return values


def _resolve_control_endpoint(config_path: str, overrides: Dict[str, object]) -> Tuple[str, int]:
    cfg_path = Path(config_path)
    conf_values = _parse_agent_config(cfg_path) if config_path else {}
    addr = overrides.get("control_address") or conf_values.get("control_address") or "127.0.0.1"
    port_value = overrides.get("control_port") or conf_values.get("control_port") or "9200"
    try:
        port = int(port_value)
    except (TypeError, ValueError):
        port = 9200
    return addr, port


def _wait_for_control_plane(address: str, port: int, timeout_s: float = 10.0) -> bool:
    """Best-effort readiness check for the agent control plane.

    We first wait for TCP accept, then try an HTTP POST "ping" that should
    deterministically return 400 from MicroSentinel's control plane.

    This avoids false positives where some other service is listening on the
    port (or a proxy is up but the agent isn't ready yet).
    """

    def _tcp_ready() -> bool:
        try:
            with socket.create_connection((address, port), timeout=1.0):
                return True
        except OSError:
            return False

    def _http_ping() -> bool:
        # Control plane only accepts POSTs; invalid mode returns 400.
        base_url = f"http://{address}:{port}"
        data = json.dumps({"mode": "__ping__"}).encode("utf-8")
        req = urllib.request.Request(
            f"{base_url}/api/v1/mode",
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=2.0):
                # If we get 200 here, it's also our control plane and it's ready.
                return True
        except urllib.error.HTTPError as exc:
            return exc.code == 400
        except Exception:
            return False

    deadline = time.time() + timeout_s
    while time.time() < deadline:
        if _tcp_ready() and _http_ping():
            return True
        time.sleep(0.25)
    return False


def _post_control_request(base_url: str, path: str, payload: Dict[str, object]) -> Tuple[bool, Optional[str]]:
    url = f"{base_url}{path}"
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    # Control plane can take a moment to become ready after the agent process
    # starts (especially when loading BPF). Be tolerant to transient failures.
    retry_delays_s = (0.2, 0.5, 1.0, 2.0)
    last_err: Optional[str] = None

    for attempt, delay in enumerate((0.0, *retry_delays_s), start=1):
        if delay:
            time.sleep(delay)
        try:
            with urllib.request.urlopen(req, timeout=5.0) as resp:
                # Drain body for keep-alive friendliness.
                try:
                    resp.read(1)
                except Exception:
                    pass
                return True, None
        except urllib.error.HTTPError as exc:
            # Include response body when possible for debugging.
            body = ""
            try:
                body = exc.read().decode("utf-8", errors="replace")
            except Exception:
                body = ""
            body = body.strip()
            last_err = f"HTTP {exc.code} {exc.reason} url={url}" + (f" body={body}" if body else "")
            if exc.code in (502, 503, 504) and attempt <= len(retry_delays_s) + 1:
                continue
            return False, last_err
        except urllib.error.URLError as exc:
            last_err = f"URLError url={url} err={exc}"
            # transient network/refused
            if attempt <= len(retry_delays_s) + 1:
                continue
            return False, last_err
        except Exception as exc:
            last_err = f"{type(exc).__name__} url={url} err={exc}"
            if attempt <= len(retry_delays_s) + 1:
                continue
            return False, last_err
    return False, last_err


def _fetch_prometheus_metrics(artifact_dir: Path, address: str, port: int) -> Optional[Path]:
    url = f"http://{address}:{port}/metrics"
    try:
        with urllib.request.urlopen(url, timeout=3.0) as resp:
            body = resp.read().decode("utf-8", errors="replace")
    except Exception:
        return None
    out = artifact_dir / "agent_metrics.prom"
    try:
        out.write_text(body, encoding="utf-8")
        return out
    except Exception:
        return None


def _normalize_filter_specs(raw_filters) -> List[Dict[str, str]]:
    if not raw_filters:
        return []
    if isinstance(raw_filters, (str, dict)):
        candidates = [raw_filters]
    elif isinstance(raw_filters, list):
        candidates = raw_filters
    else:
        return []
    normalized: List[Dict[str, str]] = []
    for entry in candidates:
        if isinstance(entry, dict):
            spec = {"type": entry.get("type"), "value": entry.get("value")}
            if spec["type"] and spec["value"]:
                normalized.append(spec)
            continue
        if isinstance(entry, str):
            try:
                parsed = json.loads(entry)
            except json.JSONDecodeError:
                parsed = {"type": "flow", "value": entry}
            if isinstance(parsed, list):
                for item in parsed:
                    if isinstance(item, dict) and item.get("type") and item.get("value"):
                        normalized.append({"type": item["type"], "value": item["value"]})
                continue
            if isinstance(parsed, dict):
                if parsed.get("type") and parsed.get("value"):
                    normalized.append({"type": parsed["type"], "value": parsed["value"]})
                continue
    return normalized


def _parse_int_field(value) -> Optional[int]:
    if value is None:
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            base = 16 if value.lower().startswith("0x") else 10
            return int(value, base)
        except ValueError:
            return None
    return None


def _prepare_object_requests(spec: Dict[str, object]) -> Tuple[List[Dict[str, object]], List[str]]:
    if not spec:
        return [], []
    warnings: List[str] = []
    requests: List[Dict[str, object]] = []

    def _ingest(entry: Dict[str, object], default_type: str) -> None:
        if not isinstance(entry, dict):
            warnings.append("object_map entry is not a dictionary; skipping")
            return
        name = entry.get("name") or entry.get("label") or entry.get("symbol")
        pid = _parse_int_field(entry.get("pid"))
        address = _parse_int_field(entry.get("address"))
        size = _parse_int_field(entry.get("size")) or _parse_int_field(entry.get("bytes"))
        obj_type = entry.get("type") or default_type
        if not name:
            warnings.append("object_map entry missing name/symbol label; skipping")
            return
        if not pid:
            warnings.append(f"object_map entry '{name}' missing pid; cannot register")
            return
        if not address:
            warnings.append(f"object_map entry '{name}' missing address; cannot register")
            return
        request = {
            "pid": pid,
            "address": address,
            "name": name,
            "type": obj_type,
        }
        if size:
            request["size"] = size
        requests.append(request)

    for entry in spec.get("globals", []):
        _ingest(entry, "global")
    for entry in spec.get("heaps", []):
        _ingest(entry, "heap")
    return requests, warnings


def _configure_microsentinel_agent(
    agent_config_path: str,
    overrides: Dict[str, object],
    artifact_dir: Path,
):
    if not overrides:
        return
    relevant = False
    for key in ("token_rate", "delta_us", "filters", "pmu_events", "object_map"):
        value = overrides.get(key)
        if value:
            relevant = True
            break
    if not relevant:
        return
    control_addr, control_port = _resolve_control_endpoint(agent_config_path, overrides)
    if not _wait_for_control_plane(control_addr, control_port):
        _log_progress(
            artifact_dir,
            f"[runner] control plane {control_addr}:{control_port} unreachable; skipped instrumentation overrides",
        )
        return
    base_url = f"http://{control_addr}:{control_port}"
    bucket_payload: Dict[str, object] = {}
    token_rate = overrides.get("token_rate")
    try:
        token_rate_int = int(token_rate) if token_rate is not None else None
    except (TypeError, ValueError):
        token_rate_int = None
    if token_rate_int and token_rate_int > 0:
        bucket_payload["sentinel_samples_per_sec"] = token_rate_int
        bucket_payload["diagnostic_samples_per_sec"] = token_rate_int
    delta_value = overrides.get("delta_us")
    try:
        delta_int = int(delta_value) if delta_value is not None else None
    except (TypeError, ValueError):
        delta_int = None
    if delta_int and delta_int > 0:
        bucket_payload["hard_drop_ns"] = delta_int * 1000
    if bucket_payload:
        ok, err = _post_control_request(base_url, "/api/v1/token-bucket", bucket_payload)
        if ok:
            _log_progress(artifact_dir, f"[runner] applied token bucket override {bucket_payload}")
        else:
            _log_progress(
                artifact_dir,
                f"[runner] failed to apply token bucket override {bucket_payload}: {err}",
            )
    filter_specs = _normalize_filter_specs(overrides.get("filters"))
    if filter_specs:
        payload = {"targets": filter_specs}
        ok, err = _post_control_request(base_url, "/api/v1/targets", payload)
        if ok:
            _log_progress(artifact_dir, f"[runner] applied filter override {payload}")
        else:
            _log_progress(artifact_dir, f"[runner] failed to apply filter override {payload}: {err}")
    pmu_events = overrides.get("pmu_events") or []
    if pmu_events:
        pmu_payload, warnings = build_pmu_update(pmu_events)
        for warn in warnings:
            _log_progress(artifact_dir, f"[runner] {warn}")
        if pmu_payload:
            ok, err = _post_control_request(base_url, "/api/v1/pmu-config", pmu_payload)
            if ok:
                _log_progress(artifact_dir, f"[runner] applied PMU override {pmu_payload}")
            else:
                _log_progress(
                    artifact_dir,
                    f"[runner] failed to apply PMU override {pmu_payload}: {err}",
                )
        object_map = overrides.get("object_map")
        if object_map:
            map_path = artifact_dir / "object_map_config.json"
            try:
                map_path.write_text(json.dumps(object_map, indent=2), encoding="utf-8")
            except OSError as exc:
                _log_progress(artifact_dir, f"[runner] failed to write object_map_config.json: {exc}")
            requests, warnings = _prepare_object_requests(object_map)
            for warn in warnings:
                _log_progress(artifact_dir, f"[runner] {warn}")
            if not requests:
                _log_progress(artifact_dir, "[runner] object_map override captured; no entries posted")
            for req in requests:
                ok, err = _post_control_request(base_url, "/api/v1/symbols/data", req)
                if ok:
                    _log_progress(artifact_dir, f"[runner] registered data object {req['name']}@0x{req['address']:x}")
                else:
                    _log_progress(
                        artifact_dir,
                        f"[runner] failed to register data object {req['name']}@0x{req['address']:x}: {err}",
                    )

def _split_cmd(cmd):
    if isinstance(cmd, (list, tuple)):
        return list(cmd)
    return shlex.split(str(cmd))


def _apply_prefix(cmd: List[str], prefix: Optional[str]) -> List[str]:
    if not prefix:
        return cmd
    prefix_cmd = _split_cmd(prefix)
    return prefix_cmd + cmd


def _format_artifact_name(template: str, **kwargs) -> str:
    try:
        return template.format(**kwargs)
    except Exception:
        return template


def _resolve_output_path(artifact_dir: Path, path_str: str) -> Path:
    path = Path(path_str)
    if not path.is_absolute():
        path = artifact_dir / path
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def ensure_artifact_dir(workload: str, artifact_root: Optional[Path] = None) -> Path:
    root = artifact_root or ARTIFACT_ROOT
    root.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    base = f"{workload}_{timestamp}"

    # Avoid collisions when multiple runs start within the same second.
    # Historically we used second-resolution timestamps, so keep that naming
    # scheme but add a suffix when needed.
    for attempt in range(0, 1000):
        suffix = "" if attempt == 0 else f"_{attempt}"
        path = root / f"{base}{suffix}"
        try:
            path.mkdir(parents=True, exist_ok=False)
            return path
        except FileExistsError:
            continue

    raise RuntimeError(f"failed to allocate unique artifact dir under {root} for {base}")


def _metric_path(artifact_dir: Path, stem: str) -> Path:
    path = artifact_dir / f"{stem}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def load_config(workload: str, override_path: Optional[str]) -> Dict:
    if override_path:
        cfg_path = Path(override_path)
    else:
        cfg_path = CONFIG_ROOT / f"{workload}.yaml"
    if not cfg_path.exists():
        raise FileNotFoundError(f"workload config not found: {cfg_path}")
    return yaml.safe_load(cfg_path.read_text())


def _external_command(cmd: str, env: Optional[Dict[str, str]] = None) -> CommandSpec:
    return CommandSpec(name="external", argv=_split_cmd(cmd), log_suffix="external.log", env=env)


def _build_remote_spec(cfg: Optional[Dict]) -> Optional[RemoteSpec]:
    if not cfg:
        return None
    if "host" not in cfg:
        raise ValueError("remote config requires 'host'")
    host = str(cfg["host"])
    user = cfg.get("user")
    if user and "@" not in host:
        host = f"{user}@{host}"
    # If the runner is invoked via sudo, avoid trying to SSH as root unless
    # the config explicitly requests it.
    sudo_user = None
    if os.geteuid() == 0:
        sudo_user = os.environ.get("SUDO_USER")
        if sudo_user == "root":
            sudo_user = None

    if os.geteuid() == 0 and "@" not in host and not user:
        if sudo_user and sudo_user != "root":
            host = f"{sudo_user}@{host}"
    ssh_options = cfg.get("ssh_options")
    if ssh_options is not None:
        options = list(ssh_options)
    else:
        options = ["-o", "BatchMode=yes"]
    return RemoteSpec(
        host=host,
        workdir=cfg.get("workdir", ""),
        metrics_dir=cfg.get("metrics_dir"),
        pull_metrics=cfg.get("pull_metrics", True),
        ssh_options=options,
        local_user=str(cfg.get("local_user") or sudo_user) if (cfg.get("local_user") or sudo_user) else None,
    )


def _resolve_metrics_destination(metrics_path: Path, remote: Optional[RemoteSpec]) -> Tuple[str, Optional[str]]:
    if not remote:
        return str(metrics_path), None
    remote_path = remote.metrics_target(metrics_path.name)
    return remote_path, remote_path


def _wrap_remote_command(cmd: List[str], remote: Optional[RemoteSpec]) -> List[str]:
    if not remote:
        return cmd
    if cmd and cmd[0].endswith("ssh"):
        raise ValueError(
            "Command already contains an ssh prefix but a remote host is configured; remove the manual SSH wrapper."
        )
    return remote.wrap_command(cmd)


def _serialize_command_spec(spec: CommandSpec) -> Dict:
    data = asdict(spec)
    if data.get("metrics_path"):
        data["metrics_path"] = str(data["metrics_path"])
    if data.get("extra_artifacts"):
        serialized = []
        for entry in spec.extra_artifacts:
            local, remote = entry
            serialized.append({"local": str(local), "remote": remote})
        data["extra_artifacts"] = serialized
    return data


def _ensure_dir_writable_by_user(path: Path, user: str) -> None:
    if os.geteuid() != 0:
        return
    try:
        pw = pwd.getpwnam(user)
    except KeyError:
        return
    try:
        if path.exists() and path.is_dir():
            os.chown(path, pw.pw_uid, pw.pw_gid)
            os.chmod(path, 0o755)
    except Exception:
        # Best-effort: do not fail the whole run on permission fixes.
        return


def _collect_remote_metrics(commands: List[CommandSpec], artifact_dir: Path) -> Tuple[Optional[Path], List[Dict]]:
    log_path = artifact_dir / "remote_fetch.log"
    errors: List[Dict] = []
    had_activity = False

    def _remote_file_size_bytes(remote: RemoteSpec, remote_path: str) -> Optional[int]:
        """Best-effort: return remote file size in bytes (via `stat -c %s`)."""
        try:
            stat_cmd = remote.wrap_command(["stat", "-c", "%s", remote_path])
            if remote.local_user and os.geteuid() == 0:
                stat_cmd = ["sudo", "-u", remote.local_user, *stat_cmd]
            cp = subprocess.run(stat_cmd, check=False, capture_output=True, text=True)
            if cp.returncode != 0:
                return None
            out = (cp.stdout or "").strip()
            if out.isdigit():
                return int(out)
            return None
        except Exception:
            return None

    with log_path.open("w", encoding="utf-8") as log:
        for spec in commands:
            if not spec.remote or not spec.remote.pull_metrics:
                continue
            targets: List[Tuple[Path, str]] = []
            if spec.metrics_path and spec.metrics_remote_path:
                targets.append((spec.metrics_path, spec.metrics_remote_path))
            for local_path, remote_path in spec.extra_artifacts:
                if remote_path:
                    targets.append((local_path, remote_path))
            if not targets:
                continue
            for local_path, remote_path in targets:
                had_activity = True
                local_path.parent.mkdir(parents=True, exist_ok=True)
                if spec.remote.local_user and os.geteuid() == 0:
                    _ensure_dir_writable_by_user(local_path.parent, spec.remote.local_user)
                remote_src = f"{spec.remote.host}:{remote_path}"

                # NEW: print/log remote file size before copying
                size_bytes = _remote_file_size_bytes(spec.remote, remote_path)
                while size_bytes == 0:
                    # Retry once after a short delay if size is zero (file may be
                    # in the process of being finalized on the remote side).
                    time.sleep(0.5)
                    print(f"[runner] retrying size check for remote file {remote_src} (was zero)")
                    size_bytes = _remote_file_size_bytes(spec.remote, remote_path)
                ts = datetime.now().isoformat(timespec="seconds")
                size_str = "unknown" if size_bytes is None else str(size_bytes)
                msg = f"[{ts}]   remote_size_bytes={size_str} path={remote_src}"
                print(msg)
                log.write(msg + "\n")
                
                scp_cmd = ["scp", *spec.remote.ssh_options, remote_src, str(local_path)]
                if spec.remote.local_user and os.geteuid() == 0:
                    scp_cmd = ["sudo", "-u", spec.remote.local_user, *scp_cmd]
                ts = datetime.now().isoformat(timespec="seconds")
                log.write(f"[{ts}] COPY {spec.name} {remote_src} -> {local_path}\n")
                try:
                    subprocess.run(scp_cmd, check=True, capture_output=True, text=True)
                    ts = datetime.now().isoformat(timespec="seconds")
                    log.write(f"[{ts}]   status=ok\n")
                except subprocess.CalledProcessError as exc:
                    stderr = exc.stderr.decode().strip() if exc.stderr else ""
                    ts = datetime.now().isoformat(timespec="seconds")
                    log.write(f"[{ts}]   status=error msg={stderr}\n")
                    errors.append(
                        {
                            "command": spec.name,
                            "remote": remote_src,
                            "local": str(local_path),
                            "error": stderr,
                        }
                    )
    if not had_activity:
        log_path.unlink(missing_ok=True)
        return None, []
    return log_path, errors


def build_kv_commands(
    cfg: Dict,
    duration: int,
    artifact_dir: Path,
    overrides: Optional[Dict] = None,
) -> List[CommandSpec]:
    overrides = overrides or {}
    specs: List[CommandSpec] = []
    server = cfg["server"].copy()
    server_override = overrides.get("server")
    if not isinstance(server_override, dict):
        server_override = {}
    server.update(server_override)
    impl = server.get("implementation", "builtin")
    if impl == "memcached":
        cmd = [server.get("binary", "memcached")]
        # memcached refuses to run as root unless -u is supplied.
        if os.geteuid() == 0:
            cmd += ["-u", str(server.get("run_as_user") or os.environ.get("SUDO_USER") or "nobody")]
        cmd += [
            "-l",
            server.get("bind_address", "0.0.0.0"),
            "-p",
            str(server.get("port", 7000)),
            "-t",
            str(server.get("threads", 16)),
            "-m",
            str(server.get("memory_mb", 1024)),
            "-c",
            str(server.get("max_connections", 4096)),
        ]
    elif impl == "external":
        cmd = _split_cmd(server["command"])
    else:  # builtin python async server
        cmd = _split_cmd(server["binary"]) + [
            "--host",
            server.get("bind_address", "0.0.0.0"),
            "--port",
            str(server.get("port", 7000)),
            "--key-space",
            str(server.get("dataset", {}).get("key_space", 1_000_000)),
            "--value-size",
            str(server.get("dataset", {}).get("value_size_bytes", 256)),
            "--zipf-theta",
            str(server.get("request_mix", {}).get("zipf_theta", 1.0)),
        ]
    server_extra: List[Tuple[Path, Optional[str]]] = []
    truth_file = server.get("truth_file")
    if truth_file and impl != "memcached":
        truth_path = _resolve_output_path(artifact_dir, truth_file)
        cmd += ["--truth-file", str(truth_path)]
        if server.get("truth_limit"):
            cmd += ["--truth-limit", str(server["truth_limit"])]
        server_extra.append((truth_path, None))
    elif truth_file and impl == "memcached":
        _log_progress(
            artifact_dir,
            "[runner] kv-server implementation=memcached does not support --truth-file/--truth-limit; ignoring truth_file",
        )
    cmd = _apply_prefix(cmd, server.get("numa_policy"))
    specs.append(
        CommandSpec(
            "kv-server",
            cmd,
            "kv_server.log",
            ready_wait=server.get("ready_wait", 2.0),
            role="server",
            extra_artifacts=server_extra,
        )
    )

    client_cfg = cfg["clients"].copy()
    client_override = overrides.get("clients")
    if not isinstance(client_override, dict):
        client_override = {}
    client_cfg.update(client_override)
    remote = _build_remote_spec(client_cfg.get("remote"))
    impl = client_cfg.get("implementation", "builtin")
    for idx in range(client_cfg.get("instances", 1)):
        metrics_path = _metric_path(artifact_dir, f"kv_client_{idx}")
        metrics_arg, remote_metrics = _resolve_metrics_destination(metrics_path, remote)
        extra_artifacts: List[Tuple[Path, Optional[str]]] = []
        annotations_arg: Optional[str] = None
        annotations_template = client_cfg.get("annotations_file")
        if annotations_template and impl != "memtier":
            formatted = _format_artifact_name(annotations_template, idx=idx)
            annotation_path = _resolve_output_path(artifact_dir, formatted)
            annotations_arg, annotation_remote = _resolve_metrics_destination(annotation_path, remote)
            if remote and annotation_remote == remote_metrics:
                # Avoid clobbering the main metrics file on the remote host.
                annotation_remote = remote.metrics_target(f"kv_client_{idx}_annotations.json")
                annotations_arg = annotation_remote
            extra_artifacts.append((annotation_path, annotation_remote))
        if impl == "memtier":
            cmd = _split_cmd(client_cfg.get("binary", "memtier_benchmark")) + [
                "--server",
                server.get("bind_address", "127.0.0.1"),
                "--port",
                str(server.get("port", 7000)),
                "--protocol",
                client_cfg.get("protocol", "memcache_text"),
                "--requests",
                str(client_cfg.get("requests", 0)),
                "--clients",
                str(client_cfg.get("connections_per_instance", 64)),
                "--test-time",
                str(duration),
                "--json-out-file",
                metrics_arg,
            ]
            if client_cfg.get("ratio"):
                cmd += ["--ratio", client_cfg["ratio"]]
        else:
            cmd = _split_cmd(client_cfg["generator"]) + [
                "--host",
                server.get("bind_address", "127.0.0.1"),
                "--port",
                str(server.get("port", 7000)),
                "--connections",
                str(client_cfg.get("connections_per_instance", 64)),
                "--duration",
                str(duration),
                "--get-ratio",
                str(client_cfg.get("request_mix", {}).get("get_ratio", 0.95)),
                "--value-size",
                str(server.get("dataset", {}).get("value_size_bytes", 256)),
                "--key-space",
                str(server.get("dataset", {}).get("key_space", 1_000_000)),
                "--metrics-file",
                metrics_arg,
            ]
            if annotations_arg:
                cmd += ["--annotations-file", annotations_arg]
        cmd = _wrap_remote_command(cmd, remote)
        specs.append(
            CommandSpec(
                f"kv-client-{idx}",
                cmd,
                f"kv_client_{idx}.log",
                ready_wait=0.5,
                metrics_path=metrics_path,
                role="client",
                remote=remote,
                metrics_remote_path=remote_metrics,
                extra_artifacts=extra_artifacts,
            )
        )
    return specs


def _write_haproxy_cfg(lb: Dict, artifact_dir: Path) -> Path:
    cfg_path = artifact_dir / "haproxy.cfg"
    backends = lb.get("backends", [])
    lines = [
        "global",
        "    maxconn 4096",
        "defaults",
        "    mode tcp",
        "    timeout connect 5s",
        "    timeout client  30s",
        "    timeout server  30s",
        "frontend fe_lb",
        f"    bind {lb.get('bind_address', '0.0.0.0')}:{lb.get('port', 7100)}",
        "    default_backend be_pool",
        "backend be_pool",
    ]
    for idx, backend in enumerate(backends):
        lines.append(
            f"    server srv{idx} {backend['host']}:{backend['port']} check maxconn {backend.get('maxconn', 1024)}"
        )
    cfg_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return cfg_path


def build_lb_commands(
    cfg: Dict,
    duration: int,
    artifact_dir: Path,
    overrides: Optional[Dict] = None,
) -> List[CommandSpec]:
    overrides = overrides or {}
    specs: List[CommandSpec] = []
    lb = cfg["lb_node"].copy()
    lb_override = overrides.get("lb_node")
    if not isinstance(lb_override, dict):
        lb_override = {}
    lb.update(lb_override)
    impl = lb.get("implementation", "builtin")
    if impl == "haproxy":
        cfg_path = _write_haproxy_cfg(lb, artifact_dir)
        cmd = _split_cmd(lb.get("binary", "haproxy")) + ["-f", str(cfg_path), "-db"]
    elif impl == "external":
        cmd = _split_cmd(lb["command"])
    elif impl == "hot_native":
        # Build and run the native C++ LB hot server used by §5.2 flow attribution accuracy.
        # We compile into the artifact dir for reproducibility.
        out_dir = artifact_dir / "bin"
        out_dir.mkdir(parents=True, exist_ok=True)
        out_bin = out_dir / "lb_hot_server"
        src = Path("experiments/workloads/lb/lb_hot_server.cpp")
        build_cmd = [
            "g++",
            "-O2",
            "-g",
            "-std=c++20",
            "-pthread",
            str(src),
            "-o",
            str(out_bin),
        ]
        specs.append(CommandSpec("lb-hot-build", build_cmd, "lb_hot_build.log", ready_wait=0.1, role="build"))

        cmd = [
            str(out_bin),
            "--host",
            lb.get("bind_address", "0.0.0.0"),
            "--port",
            str(lb.get("port", 7100)),
            "--workers",
            str(lb.get("workers", 8)),
        ]

        # Strict hot_func_i mapping parameters.
        hot_funcs = lb.get("hot_funcs")
        hot_bytes = lb.get("hot_bytes_per_func")
        hot_stride = lb.get("hot_stride")
        hot_rounds = lb.get("hot_rounds")
        payload_bytes = lb.get("payload_bytes")
        flow_tag_bytes = lb.get("flow_tag_bytes")
        if payload_bytes is not None:
            cmd += ["--payload-bytes", str(payload_bytes)]
        if flow_tag_bytes is not None:
            cmd += ["--flow-tag-bytes", str(flow_tag_bytes)]
        if hot_funcs is not None:
            cmd += ["--hot-funcs", str(hot_funcs)]
        if hot_bytes is not None:
            cmd += ["--hot-bytes-per-func", str(hot_bytes)]
        if hot_stride is not None:
            cmd += ["--hot-stride", str(hot_stride)]
        if hot_rounds is not None:
            cmd += ["--hot-rounds", str(hot_rounds)]
    else:
        cmd = _split_cmd(lb["binary"]) + [
            "--host",
            lb.get("bind_address", "0.0.0.0"),
            "--port",
            str(lb.get("port", 7100)),
            "--workers",
            str(lb.get("workers", 8)),
        ]
        for backend in lb.get("backends", []):
            cmd += ["--backend", f"{backend['host']}:{backend['port']}"]

        # Optional synthetic cache-miss generator for flow attribution accuracy
        # experiments. Defaults to disabled when not set in config.
        hot_bytes = lb.get("hot_bytes_per_slot")
        hot_slots = lb.get("hot_slots")
        hot_rounds = lb.get("hot_rounds")
        if hot_bytes is not None:
            cmd += ["--hot-bytes-per-slot", str(hot_bytes)]
        if hot_slots is not None:
            cmd += ["--hot-slots", str(hot_slots)]
        if hot_rounds is not None:
            cmd += ["--hot-rounds", str(hot_rounds)]
    cmd = _apply_prefix(cmd, lb.get("numa_policy"))
    specs.append(CommandSpec("lb-node", cmd, "lb.log", ready_wait=2.0, role="server"))

    backend_stub = cfg.get("backend_stub", {})
    for idx, backend in enumerate(lb.get("backends", [])):
        stub_impl = backend_stub.get("implementation", "builtin")
        if stub_impl == "external":
            backend_cmd = _split_cmd(backend_stub["command"]).copy()
        else:
            backend_cmd = _split_cmd(backend_stub.get("binary", "python3 experiments/workloads/lb/backend_echo.py")) + [
                "--host",
                backend.get("host", "127.0.0.1"),
                "--port",
                str(backend.get("port")),
                "--workers",
                str(backend_stub.get("workers", 4)),
            ]
        specs.append(
            CommandSpec(
                f"lb-backend-{idx}", backend_cmd, f"lb_backend_{idx}.log", ready_wait=1.0, role="backend"
            )
        )

    client = cfg["clients"].copy()
    client_override = overrides.get("clients")
    if not isinstance(client_override, dict):
        client_override = {}
    client.update(client_override)
    metrics_path = _metric_path(artifact_dir, "lb_client")
    remote = _build_remote_spec(client.get("remote"))
    metrics_arg, remote_metrics = _resolve_metrics_destination(metrics_path, remote)
    extra_artifacts: List[Tuple[Path, Optional[str]]] = []
    truth_path = None
    truth_remote_path = None
    if client.get("ground_truth_log"):
        truth_path = _resolve_output_path(artifact_dir, client["ground_truth_log"])
        truth_arg, truth_remote_path = _resolve_metrics_destination(truth_path, remote)
        extra_artifacts.append((truth_path, truth_remote_path))
    else:
        truth_arg = None

    # If the client runs remotely, proactively remove any stale remote metrics/truth
    # from previous runs. This prevents the fetch phase from copying leftover large
    # files when the remote client fails early.
    if remote:
        remote_paths = [remote_metrics]
        if truth_remote_path:
            remote_paths.append(truth_remote_path)
        clean_cmd = remote.wrap_command(["rm", "-f", *remote_paths])
        specs.append(CommandSpec("lb-client-remote-clean", clean_cmd, "lb_client_remote_clean.log", ready_wait=0.1, role="build"))
    impl = client.get("implementation", "builtin")
    rate = client.get("rate")
    # If the client will be run on a remote host and we intend to pass --rate,
    # stage the local builtin generator onto the remote so it supports the same args.
    if remote and remote.workdir and rate is not None:
        gen = client.get("generator", "")
        # Expect generator like: "python3 experiments/workloads/lb/lb_client.py"
        if isinstance(gen, str) and gen.strip().endswith("experiments/workloads/lb/lb_client.py"):
            local_path = Path("experiments/workloads/lb/lb_client.py")
            if local_path.exists():
                target_dir = Path(remote.workdir) / "experiments" / "workloads" / "lb"
                target_path = f"{str(target_dir)}/lb_client.py"
                # IMPORTANT: when the suite is run with sudo (for eBPF), SSH/SCP
                # must still use the invoking user's credentials/known_hosts.
                # RemoteSpec.local_user captures that and _collect_remote_metrics
                # already respects it; do the same here.
                mkdir_cmd = remote.wrap_command(["mkdir", "-p", str(target_dir)])
                scp_cmd = ["scp", *remote.ssh_options, str(local_path), f"{remote.host}:{target_path}"]
                if remote.local_user and os.geteuid() == 0:
                    scp_cmd = ["sudo", "-u", remote.local_user, *scp_cmd]
                specs.append(CommandSpec("lb-client-deploy-mkdir", mkdir_cmd, "lb_client_deploy_mkdir.log", ready_wait=0.1))
                specs.append(CommandSpec("lb-client-deploy-scp", scp_cmd, "lb_client_deploy_scp.log", ready_wait=0.1))
    if impl == "wrk":
        url = client.get("url", f"http://{lb.get('bind_address', '127.0.0.1')}:{lb.get('port', 7100)}")
        cmd = _split_cmd(client.get("binary", "wrk")) + [
            "-c",
            str(client.get("flows", 256)),
            "-d",
            f"{duration}s",
            "-t",
            str(client.get("threads", 8)),
            url,
        ]
        cmd += ["--latency"]
        if client.get("script"):
            cmd += ["--script", client["script"]]
        if client.get("json_output", True):
            cmd += ["--output", metrics_arg]
    else:
        cmd = _split_cmd(client["generator"]) + [
            "--host",
            lb.get("bind_address", "127.0.0.1"),
            "--port",
            str(lb.get("port", 7100)),
            "--flows",
            str(client.get("flows", 256)),
            "--duration",
            str(duration),
            "--metrics-file",
            metrics_arg,
        ]
        # Optional strict flow tagging for function-level attribution.
        flow_tag_bytes = client.get("flow_tag_bytes")
        expected_prefix = client.get("expected_function_prefix")
        if flow_tag_bytes is not None:
            cmd += ["--flow-tag-bytes", str(flow_tag_bytes)]
        if expected_prefix is not None:
            cmd += ["--expected-function-prefix", str(expected_prefix)]
        # forward an optional per-workload total rate to the client generator
        if rate is not None:
            cmd += ["--rate", str(rate)]
    if truth_path:
        cmd += ["--ground-truth-log", truth_arg]
    cmd = _wrap_remote_command(cmd, remote)
    specs.append(
        CommandSpec(
            "lb-client",
            cmd,
            "lb_client.log",
            ready_wait=0.5,
            metrics_path=metrics_path,
            role="client",
            remote=remote,
            metrics_remote_path=remote_metrics,
            extra_artifacts=extra_artifacts,
        )
    )
    return specs


def build_nfv_commands(
    cfg: Dict,
    duration: int,
    artifact_dir: Path,
    overrides: Optional[Dict] = None,
) -> List[CommandSpec]:
    overrides = overrides or {}
    specs: List[CommandSpec] = []
    chain = cfg["chain"]
    stages = chain.get("stages", [])
    prev_port = 9000
    chain_host = chain.get("host", "127.0.0.1")
    chain_next_host = chain.get("next_host", chain_host)
    for idx, stage in enumerate(stages):
        stage_impl = stage.get("implementation", "builtin")
        listen_port = prev_port
        next_port = listen_port + 1
        listen_host = stage.get("listen_host", chain_host)
        next_host = stage.get("next_host", chain_next_host)
        is_terminal = idx == len(stages) - 1
        if stage_impl == "external":
            stage_cmd = _split_cmd(stage["command"])
        else:
            stage_cmd = _split_cmd(stage["binary"]) + [
                "--listen-host",
                listen_host,
                "--listen-port",
                str(listen_port),
                "--name",
                stage["name"],
            ]
            if not is_terminal:
                stage_cmd += [
                    "--next-host",
                    next_host,
                    "--next-port",
                    str(next_port),
                ]
            if stage.get("policy_file"):
                stage_cmd += ["--policy", stage["policy_file"]]
        stage_extra: List[Tuple[Path, Optional[str]]] = []
        if stage.get("truth_log"):
            truth_path = _resolve_output_path(artifact_dir, stage["truth_log"])
            stage_cmd += ["--truth-log", str(truth_path)]
            if stage.get("truth_limit"):
                stage_cmd += ["--truth-limit", str(stage["truth_limit"])]
            stage_extra.append((truth_path, None))
        specs.append(
            CommandSpec(
                stage["name"], stage_cmd, f"nfv_{stage['name']}.log", ready_wait=1.0, extra_artifacts=stage_extra
            )
        )
        prev_port = next_port

    traffic = cfg.get("traffic_generator", {}).copy()
    traffic_override = overrides.get("traffic")
    if not isinstance(traffic_override, dict):
        traffic_override = {}
    traffic.update(traffic_override)
    metrics_path = _metric_path(artifact_dir, "nfv_traffic")
    remote = _build_remote_spec(traffic.get("remote"))
    metrics_arg, remote_metrics = _resolve_metrics_destination(metrics_path, remote)
    truth_log = traffic.get("truth_log")
    truth_limit = traffic.get("truth_limit")
    impl = traffic.get("implementation", "builtin")
    target_host = traffic.get("target_host", "127.0.0.1")
    rate_values = traffic.get("rate_values") or traffic.get("rates")
    packet_sizes = traffic.get("packet_size_bytes") or traffic.get("packet_sizes")
    dst_ports = traffic.get("dst_ports")
    tenants = traffic.get("tenants")
    truth_path: Optional[Path] = None
    truth_remote: Optional[str] = None
    truth_arg: Optional[str] = None
    if truth_log:
        truth_path = _resolve_output_path(artifact_dir, truth_log)
        truth_arg, truth_remote = _resolve_metrics_destination(truth_path, remote)
    if impl == "pktgen":
        cmd = _split_cmd(traffic.get("binary", "pktgen")) + [
            "--interface",
            traffic.get("interface", "eth0"),
            "--rate",
            str(traffic.get("rate_pps", 1_000_000)),
            "--size",
            str(traffic.get("packet_size", 64)),
            "--duration",
            str(duration),
            "--stats-file",
            metrics_arg,
        ]
    else:
        cmd = _split_cmd(traffic["binary"]) + [
            "--target-host",
            target_host,
            "--target-port",
            str(traffic.get("target_port", 9000)),
            "--duration",
            str(duration),
            "--metrics-file",
            metrics_arg,
        ]
        if rate_values:
            cmd += ["--rates", ",".join(str(value) for value in rate_values)]
        if packet_sizes:
            cmd += ["--packet-sizes", ",".join(str(value) for value in packet_sizes)]
        if dst_ports:
            cmd += ["--dst-ports", ",".join(str(port) for port in dst_ports)]
        if tenants:
            cmd += ["--tenants", ",".join(tenants)]
    if truth_arg:
        cmd += ["--truth-log", truth_arg]
    if truth_limit:
        cmd += ["--truth-limit", str(truth_limit)]
    cmd = _wrap_remote_command(cmd, remote)
    extra_artifacts: List[Tuple[Path, Optional[str]]] = []
    if truth_path:
        extra_artifacts.append((truth_path, truth_remote))
    specs.append(
        CommandSpec(
            "nfv-traffic",
            cmd,
            "nfv_traffic.log",
            ready_wait=0.5,
            metrics_path=metrics_path,
            role="client",
            remote=remote,
            metrics_remote_path=remote_metrics,
            extra_artifacts=extra_artifacts,
        )
    )
    return specs


BUILDERS = {
    "kv": build_kv_commands,
    "load_balancer": build_lb_commands,
    "nfv_service_chain": build_nfv_commands,
}


def build_commands(
    cfg: Dict,
    duration: int,
    artifact_dir: Path,
    overrides: Optional[Dict] = None,
) -> List[CommandSpec]:
    workload = cfg.get("workload")
    builder = BUILDERS.get(workload)
    if builder is None:
        raise ValueError(f"unsupported workload {workload}")
    return builder(cfg, duration, artifact_dir, overrides)


def _launch_monitors(
    duration: int,
    artifact_dir: Path,
    stack: contextlib.ExitStack,
    tracked_procs: List[int],
) -> Dict[str, str]:
    monitor_logs: Dict[str, str] = {}
    interval = 1
    count = max(1, math.ceil(duration / interval)) + 1
    if shutil.which("mpstat"):
        log_path = artifact_dir / "mpstat.log"
        stack.enter_context(
            managed_process(
                "mpstat",
                ["mpstat", str(interval), str(count)],
                log_path=log_path,
                ready_wait=0.1,
            )
        )
        monitor_logs["mpstat"] = str(log_path)
    if shutil.which("pidstat") and tracked_procs:
        log_path = artifact_dir / "pidstat.log"
        pid_arg = ",".join(str(pid) for pid in tracked_procs)
        stack.enter_context(
            managed_process(
                "pidstat",
                ["pidstat", "-ru", str(interval), str(count), "-p", pid_arg],
                log_path=log_path,
                ready_wait=0.1,
            )
        )
        monitor_logs["pidstat"] = str(log_path)
    return monitor_logs


def _capture_host_facts(artifact_dir: Path) -> None:
    def _run(argv: List[str]) -> Optional[str]:
        try:
            cp = subprocess.run(argv, check=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            return cp.stdout.strip()
        except Exception:
            return None

    facts: Dict[str, object] = {
        "timestamp_utc": datetime.utcnow().isoformat() + "Z",
        "uname": _run(["uname", "-a"]),
        "kernel_release": _run(["uname", "-r"]),
        "cmdline": (Path("/proc/cmdline").read_text(encoding="utf-8").strip() if Path("/proc/cmdline").exists() else None),
        "lscpu": _run(["lscpu"]),
        "numactl_hardware": _run(["numactl", "--hardware"]) if shutil.which("numactl") else None,
        "perf_event_paranoid": (Path("/proc/sys/kernel/perf_event_paranoid").read_text(encoding="utf-8").strip()
                                 if Path("/proc/sys/kernel/perf_event_paranoid").exists() else None),
        "numa_balancing": (Path("/proc/sys/kernel/numa_balancing").read_text(encoding="utf-8").strip()
                           if Path("/proc/sys/kernel/numa_balancing").exists() else None),
    }

    try:
        (artifact_dir / "host_facts.json").write_text(json.dumps(facts, indent=2), encoding="utf-8")
    except Exception:
        pass


def execute_workload(
    workload: str,
    mode: str,
    duration: int,
    config_override: Optional[str],
    dry_run: bool,
    perf_freq: int,
    agent_bin: str,
    agent_config: str,
    token_rate: int,
    metrics_port: int,
    overrides: Optional[Dict] = None,
    artifact_root: Optional[str] = None,
):
    overrides = overrides or {}
    cfg = load_config(workload, config_override)
    root_path = Path(artifact_root) if artifact_root else None
    artifact_dir = ensure_artifact_dir(cfg["workload"], artifact_root=root_path)
    _log_progress(artifact_dir, f"[runner] starting workload={cfg['workload']} mode={mode} duration={duration}s")
    ts = datetime.now().isoformat(timespec="seconds")
    print(f"[{ts}] Workload={cfg['workload']} Mode={mode} Duration={duration}s Artifacts={artifact_dir}")
    _capture_host_facts(artifact_dir)
    _log_progress(artifact_dir, "[runner] building command plan")
    commands = build_commands(cfg, duration, artifact_dir, overrides.get("workload"))
    plan = {
        "workload": cfg["workload"],
        "mode": mode,
        "duration": duration,
        "artifact_dir": str(artifact_dir),
        "commands": [_serialize_command_spec(c) for c in commands],
        "overrides": overrides,
    }
    (artifact_dir / "plan.json").write_text(json.dumps(plan, indent=2), encoding="utf-8")
    _log_progress(artifact_dir, "[runner] wrote plan.json")

    if dry_run:
        _log_progress(artifact_dir, "[runner] dry-run mode; no processes launched")
        try:
            print(json.dumps(plan, indent=2))
        except BrokenPipeError:
            # Common when piping to `head`; exit cleanly.
            pass
        return str(artifact_dir)

    user_instr_overrides = overrides.get("instrumentation") or {}
    instr_overrides, instr_sources = _build_instrumentation_overrides(cfg["workload"], user_instr_overrides)
    perf_freq_value = instr_overrides.get("perf_freq", perf_freq)
    token_rate_source = instr_sources.get("token_rate")
    if token_rate is not None:
        token_rate_value = token_rate
        token_rate_requested = True
    elif "token_rate" in instr_overrides:
        token_rate_value = _coerce_int(instr_overrides["token_rate"], DEFAULT_TOKEN_RATE)
        token_rate_requested = token_rate_source in {"user", "workload"}
    else:
        token_rate_value = DEFAULT_TOKEN_RATE
        token_rate_requested = False
    metrics_port_value = instr_overrides.get("metrics_port", metrics_port)
    pmu_events_override = instr_overrides.get("pmu_events")
    pmu_event_list: List[str] = []
    pmu_events = ""
    if isinstance(pmu_events_override, str):
        pmu_events = pmu_events_override
        pmu_event_list = [part.strip() for part in pmu_events_override.split(",") if part.strip()]
    elif isinstance(pmu_events_override, (list, tuple)):
        pmu_event_list = [str(part).strip() for part in pmu_events_override if str(part).strip()]
        pmu_events = ",".join(pmu_event_list)
    elif pmu_events_override:
        pmu_events = str(pmu_events_override)
    delta_value = instr_overrides.get("delta_us")
    filters_value = instr_overrides.get("filters", [])
    recorder = ResultRecorder(artifact_dir, plan)
    perf_output_path = str((artifact_dir / "perf.data").resolve())
    context = {
        "freq": str(perf_freq_value),
        "duration": str(duration),
        "agent_bin": agent_bin,
        "config_path": agent_config,
        "mode_name": mode,
        "token_rate": str(token_rate_value),
        "metrics_port": str(metrics_port_value),
        "pmu_events": pmu_events,
        "delta_us": str(delta_value or ""),
        "filters": json.dumps(filters_value),
        "perf_mode": instr_overrides.get("perf_mode", "record"),
        "perf_interval_ms": str(instr_overrides.get("perf_interval_ms", 1000)),
        "perf_output": perf_output_path,
    }
    filters_runtime = filters_value if instr_sources.get("filters") in {"user", "workload"} else None
    ms_runtime_overrides = {
        "token_rate": token_rate_value if token_rate_requested else None,
        "delta_us": delta_value if delta_value is not None else None,
        "filters": filters_runtime,
        "pmu_events": pmu_event_list,
        "object_map": instr_overrides.get("object_map"),
        "control_address": instr_overrides.get("control_address"),
        "control_port": instr_overrides.get("control_port"),
    }

    running: List[Tuple[CommandSpec, object]] = []
    monitor_logs: Dict[str, str] = {}
    captured_exception: Optional[BaseException] = None
    instrumentation_proc = None

    try:
        with contextlib.ExitStack() as stack:
            _log_progress(artifact_dir, f"[runner] starting instrumentation mode={mode}")

            if mode == "microsentinel":
                _microsentinel_precheck(skip=bool(instr_overrides.get("bpf_skip_precheck", False)))

            perf_skip_precheck = bool(instr_overrides.get("perf_skip_precheck", False))
            if mode == "perf" and not perf_skip_precheck:
                paranoid_path = Path("/proc/sys/kernel/perf_event_paranoid")
                if paranoid_path.exists() and os.geteuid() != 0:
                    try:
                        paranoid = int(paranoid_path.read_text(encoding="utf-8").strip())
                    except Exception:
                        paranoid = None
                    # perf -a CPU-wide sampling generally requires CAP_PERFMON or relaxed paranoid.
                    if paranoid is not None and paranoid >= 1:
                        msg = (
                            "perf mode requires system-wide perf_event access, but kernel.perf_event_paranoid is "
                            f"{paranoid} and the runner is not root. "
                            "Either run with sufficient capabilities (e.g. sudo / CAP_PERFMON), or relax sysctl, e.g.:\n"
                            "  sudo sysctl -w kernel.perf_event_paranoid=0\n"
                            "(use -1 if you need kernel profiling)."
                        )
                        _log_progress(artifact_dir, f"[runner] precheck failed: {msg}")
                        raise ProcessLaunchError(msg)

            # Track the instrumentation process PID so pidstat can attribute CPU/RSS.
            instrumentation_proc = stack.enter_context(start_instrumentation(mode, artifact_dir, context))
            if mode == "microsentinel":
                _configure_microsentinel_agent(agent_config, ms_runtime_overrides, artifact_dir)

            # Build steps (e.g., compiling native workloads) must complete before
            # we launch long-running workload processes.
            build_specs = [spec for spec in commands if str(spec.role) == "build"]
            run_specs = [spec for spec in commands if str(spec.role) != "build"]
            for spec in build_specs:
                log_path = artifact_dir / spec.log_suffix
                log_path.parent.mkdir(parents=True, exist_ok=True)
                with open(log_path, "w", encoding="utf-8") as f:
                    f.write(f"[launcher] running build step {spec.name}: {' '.join(spec.argv)}\n")
                    f.flush()
                    env = os.environ.copy()
                    if spec.env:
                        env.update(spec.env)
                    cp = subprocess.run(spec.argv, stdout=f, stderr=subprocess.STDOUT, env=env, check=False)
                    if cp.returncode != 0:
                        raise ProcessLaunchError(f"{spec.name} failed with code {cp.returncode}")

            for spec in run_specs:
                log_path = artifact_dir / spec.log_suffix
                proc = stack.enter_context(
                    managed_process(
                        spec.name,
                        spec.argv,
                        log_path=log_path,
                        env=spec.env,
                        ready_wait=spec.ready_wait,
                    )
                )
                running.append((spec, proc))

            # Record PIDs for downstream analysis (pidstat parsing, per-role CPU/RSS, etc).
            try:
                plan.setdefault("processes", {})
                if instrumentation_proc is not None:
                    plan["processes"]["instrumentation"] = {
                        "pid": int(getattr(instrumentation_proc, "pid", 0) or 0),
                        "mode": mode,
                    }
                plan["processes"]["commands"] = {
                    str(spec.name): {"pid": int(getattr(proc, "pid", 0) or 0), "role": str(spec.role)}
                    for spec, proc in running
                }
            except Exception:
                pass

            _log_progress(artifact_dir, "[runner] all workload processes started")
            tracked_pids: List[int] = []
            try:
                if instrumentation_proc is not None and getattr(instrumentation_proc, "pid", None):
                    tracked_pids.append(int(instrumentation_proc.pid))
            except Exception:
                pass
            tracked_pids.extend([int(proc.pid) for _, proc in running if getattr(proc, "pid", None)])
            monitor_logs = _launch_monitors(duration, artifact_dir, stack, tracked_pids)
            _log_progress(artifact_dir, "[runner] host monitors started; entering steady-state run")
            time.sleep(duration)

            # Allow client-side generators a brief grace period to flush metrics/truth
            # before the ExitStack teardown terminates all managed processes.
            for spec, proc in running:
                if spec.role != "client":
                    continue
                try:
                    proc.wait(timeout=CLIENT_GRACE_S)
                except Exception:
                    pass
    except BaseException as exc:
        captured_exception = exc
        _log_progress(artifact_dir, f"[runner] exception: {type(exc).__name__}: {exc}")
    finally:
        _log_progress(artifact_dir, "[runner] collecting remote metrics")
        try:
            # time.sleep(5)  # allow remote files to settle
            remote_log, remote_errors = _collect_remote_metrics(commands, artifact_dir)
            if remote_log:
                monitor_logs["remote_fetch"] = str(remote_log)
            if remote_errors:
                plan.setdefault("remote_fetch_errors", []).extend(remote_errors)
        except Exception as exc:
            plan.setdefault("remote_fetch_errors", []).append(
                {"error": f"remote metrics collection failed: {type(exc).__name__}: {exc}"}
            )

        recorder.record_monitors(monitor_logs)
        recorder.capture_command_metrics(running)

        if mode == "microsentinel":
            # metrics may be bound separately; default to 127.0.0.1 unless overridden.
            metrics_addr = instr_overrides.get("metrics_address") or "127.0.0.1"
            try:
                metrics_port_int = int(metrics_port_value)
            except Exception:
                metrics_port_int = 9105
            metrics_path = _fetch_prometheus_metrics(artifact_dir, str(metrics_addr), metrics_port_int)
            if metrics_path:
                monitor_logs["agent_metrics"] = str(metrics_path)

        if captured_exception is not None:
            plan["runner_exception"] = {
                "type": type(captured_exception).__name__,
                "message": str(captured_exception),
            }
        recorder.finalize()
        _log_progress(artifact_dir, "[runner] run_result.json written")

    if captured_exception is not None:
        raise captured_exception
    _log_progress(artifact_dir, "[runner] run complete")
    return str(artifact_dir)


def run_workload(args):
    try:
        execute_workload(
            workload=args.workload,
            mode=args.mode,
            duration=args.duration,
            config_override=args.config,
            dry_run=args.dry_run,
            perf_freq=args.perf_freq,
            agent_bin=args.agent_bin,
            agent_config=args.agent_config,
            token_rate=args.token_rate,
            metrics_port=args.metrics_port,
            artifact_root=args.artifact_root,
        )
    except ProcessLaunchError as exc:
        print(f"[workload_runner] error: {exc}", file=sys.stderr)
        print("[workload_runner] hint: check artifacts/experiments/<run>/instrumentation_*.log for details", file=sys.stderr)
        raise SystemExit(2)


def parse_args():
    parser = argparse.ArgumentParser(description="Run a MicroSentinel workload")
    parser.add_argument("--workload", choices=BUILDERS.keys(), required=True)
    parser.add_argument("--mode", choices=["baseline", "perf", "microsentinel"], default="baseline")
    parser.add_argument("--duration", type=int, default=60)
    parser.add_argument("--config", help="Override workload config path")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--perf-freq", type=int, default=2000)
    parser.add_argument("--agent-bin", default="build/agent/micro_sentinel_agent")
    parser.add_argument("--agent-config", default="agent/agent.conf")
    parser.add_argument("--token-rate", type=int, default=None)
    parser.add_argument("--metrics-port", type=int, default=9105)
    parser.add_argument(
        "--artifact-root",
        default=None,
        help="Override artifact root (default: artifacts/experiments). Useful for grouping a suite run into its own directory.",
    )
    return parser.parse_args()


if __name__ == "__main__":
    run_workload(parse_args())
