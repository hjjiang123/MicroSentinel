#!/usr/bin/env python3
"""Utility helpers for launching long-running workloads and observers."""

from __future__ import annotations

import os
import signal
import subprocess
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Dict, Iterable, Iterator, List, Optional


class ProcessLaunchError(RuntimeError):
    pass


@contextmanager
def managed_process(
    name: str,
    argv: List[str],
    log_path: Optional[Path] = None,
    cwd: Optional[Path] = None,
    env: Optional[Dict[str, str]] = None,
    ready_wait: float = 1.0,
) -> Iterator[subprocess.Popen]:
    """Spawn a subprocess and make sure it is cleaned up."""
    stdout = None
    if log_path:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        stdout = open(log_path, "w", encoding="utf-8")
        # Write a small header so users can see what was launched.
        launch_line = f"[launcher] starting {name}: {' '.join(argv)}\n"
        stdout.write(launch_line)
        stdout.flush()
    proc = subprocess.Popen(argv, cwd=cwd, env=env, stdout=stdout, stderr=subprocess.STDOUT)
    try:
        time.sleep(ready_wait)
        if proc.poll() is not None:
            raise ProcessLaunchError(f"{name} exited early with code {proc.returncode}")
        yield proc
    finally:
        _terminate_process(proc, name)
        if stdout:
            stdout.close()


def _terminate_process(proc: subprocess.Popen, name: str, timeout: float = 5.0) -> None:
    if proc.poll() is not None:
        return
    proc.terminate()
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()


def expand_with_env(template: str, extra_env: Optional[Dict[str, str]] = None) -> str:
    env = os.environ.copy()
    if extra_env:
        env.update(extra_env)
    return os.path.expandvars(template)
