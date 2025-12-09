#!/usr/bin/env python3
"""Launch a workload plus optional instrumentation according to YAML config."""

from __future__ import annotations

import argparse
import contextlib
import json
import math
import shlex
import shutil
import subprocess
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import yaml

from experiments.automation.instrumentation import start_instrumentation
from experiments.automation.process_utils import managed_process
from experiments.automation.results import ResultRecorder


@dataclass
class RemoteSpec:
    host: str
    workdir: str = ""
    metrics_dir: Optional[str] = None
    pull_metrics: bool = True
    ssh_options: List[str] = field(default_factory=lambda: ["-o", "BatchMode=yes"])

    def metrics_target(self, filename: str) -> str:
        base = self.metrics_dir or self.workdir or "."
        base = base.rstrip("/")
        if not base or base == ".":
            return f"./{filename}"
        return f"{base}/{filename}"

    def wrap_command(self, argv: List[str]) -> List[str]:
        remote_cmd = " ".join(shlex.quote(arg) for arg in argv)
        if self.workdir:
            if self.workdir.startswith("~/") and " " not in self.workdir:
                remote_cmd = f"cd {self.workdir} && {remote_cmd}"
            else:
                remote_cmd = f"cd {shlex.quote(self.workdir)} && {remote_cmd}"
        return ["ssh", *self.ssh_options, self.host, remote_cmd]


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


def ensure_artifact_dir(workload: str) -> Path:
    ARTIFACT_ROOT.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    path = ARTIFACT_ROOT / f"{workload}_{timestamp}"
    path.mkdir(parents=True, exist_ok=True)
    return path


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
    ssh_options = cfg.get("ssh_options")
    if ssh_options is not None:
        options = list(ssh_options)
    else:
        options = ["-o", "BatchMode=yes"]
    return RemoteSpec(
        host=cfg["host"],
        workdir=cfg.get("workdir", ""),
        metrics_dir=cfg.get("metrics_dir"),
        pull_metrics=cfg.get("pull_metrics", True),
        ssh_options=options,
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


def _collect_remote_metrics(commands: List[CommandSpec], artifact_dir: Path) -> Tuple[Optional[Path], List[Dict]]:
    log_path = artifact_dir / "remote_fetch.log"
    errors: List[Dict] = []
    had_activity = False
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
                remote_src = f"{spec.remote.host}:{remote_path}"
                scp_cmd = ["scp", *spec.remote.ssh_options, remote_src, str(local_path)]
                log.write(f"COPY {spec.name} {remote_src} -> {local_path}\n")
                try:
                    subprocess.run(scp_cmd, check=True, capture_output=True)
                    log.write("  status=ok\n")
                except subprocess.CalledProcessError as exc:
                    stderr = exc.stderr.decode().strip() if exc.stderr else ""
                    log.write(f"  status=error msg={stderr}\n")
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
    server_override = overrides.get("server", {})
    server.update(server_override)
    impl = server.get("implementation", "builtin")
    if impl == "memcached":
        cmd = [
            server.get("binary", "memcached"),
            "-l",
            server.get("bind_address", "0.0.0.0"),
            "-p",
            str(server.get("port", 7000)),
            "-t",
            str(server.get("threads", 16)),
            "-m",
            str(server.get("memory_mb", 1024)),
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
    if truth_file:
        truth_path = _resolve_output_path(artifact_dir, truth_file)
        cmd += ["--truth-file", str(truth_path)]
        if server.get("truth_limit"):
            cmd += ["--truth-limit", str(server["truth_limit"])]
        server_extra.append((truth_path, None))
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
    client_cfg.update(overrides.get("clients", {}))
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
    lb.update(overrides.get("lb_node", {}))
    impl = lb.get("implementation", "builtin")
    if impl == "haproxy":
        cfg_path = _write_haproxy_cfg(lb, artifact_dir)
        cmd = _split_cmd(lb.get("binary", "haproxy")) + ["-f", str(cfg_path), "-db"]
    elif impl == "external":
        cmd = _split_cmd(lb["command"])
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
    client.update(overrides.get("clients", {}))
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
    impl = client.get("implementation", "builtin")
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

    traffic = cfg["traffic_generator"].copy()
    traffic.update(overrides.get("traffic", {}))
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
):
    overrides = overrides or {}
    cfg = load_config(workload, config_override)
    artifact_dir = ensure_artifact_dir(cfg["workload"])
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

    if dry_run:
        print(json.dumps(plan, indent=2))
        return str(artifact_dir)

    instr_overrides = overrides.get("instrumentation", {})
    perf_freq_value = instr_overrides.get("perf_freq", perf_freq)
    token_rate_value = instr_overrides.get("token_rate", token_rate)
    metrics_port_value = instr_overrides.get("metrics_port", metrics_port)
    pmu_events = instr_overrides.get("pmu_events", "")
    if isinstance(pmu_events, list):
        pmu_events = ",".join(pmu_events)
    recorder = ResultRecorder(artifact_dir, plan)
    context = {
        "freq": str(perf_freq_value),
        "duration": str(duration),
        "agent_bin": agent_bin,
        "config_path": agent_config,
        "mode_name": mode,
        "token_rate": str(token_rate_value),
        "metrics_port": str(metrics_port_value),
        "pmu_events": pmu_events,
        "delta_us": str(instr_overrides.get("delta_us", "")),
        "filters": json.dumps(instr_overrides.get("filters", [])),
        "perf_mode": instr_overrides.get("perf_mode", "record"),
        "perf_interval_ms": str(instr_overrides.get("perf_interval_ms", 1000)),
    }

    with contextlib.ExitStack() as stack:
        stack.enter_context(start_instrumentation(mode, artifact_dir, context))
        running: List[Tuple[CommandSpec, object]] = []
        for spec in commands:
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
        monitor_logs = _launch_monitors(duration, artifact_dir, stack, [proc.pid for _, proc in running])
        time.sleep(duration)

    remote_log, remote_errors = _collect_remote_metrics(commands, artifact_dir)
    if remote_log:
        monitor_logs["remote_fetch"] = str(remote_log)
    if remote_errors:
        plan.setdefault("remote_fetch_errors", remote_errors)
    recorder.record_monitors(monitor_logs)
    recorder.capture_command_metrics(running)
    recorder.finalize()
    return str(artifact_dir)


def run_workload(args):
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
    )


def parse_args():
    parser = argparse.ArgumentParser(description="Run a MicroSentinel workload")
    parser.add_argument("--workload", choices=BUILDERS.keys(), required=True)
    parser.add_argument("--mode", choices=["baseline", "perf", "microsentinel"], default="baseline")
    parser.add_argument("--duration", type=int, default=60)
    parser.add_argument("--config", help="Override workload config path")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--perf-freq", type=int, default=2000)
    parser.add_argument("--agent-bin", default="build/agent/micro_sentinel_agent")
    parser.add_argument("--agent-config", default="config/micro_sentinel.toml")
    parser.add_argument("--token-rate", type=int, default=2000)
    parser.add_argument("--metrics-port", type=int, default=9105)
    return parser.parse_args()


if __name__ == "__main__":
    run_workload(parse_args())
