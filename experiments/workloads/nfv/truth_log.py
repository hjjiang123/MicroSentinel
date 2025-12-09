#!/usr/bin/env python3
"""Helpers for emitting lightweight ground-truth logs from NFV stages."""

from __future__ import annotations

import json
from pathlib import Path
from threading import Lock
from typing import Dict, List, Optional


class TruthRecorder:
    def __init__(self, path: Optional[str], limit: int = 1000):
        self._path = Path(path) if path else None
        self._limit = limit
        self._events: List[Dict] = []
        self._lock = Lock()

    def record(self, event: Dict):
        if not self._path:
            return
        with self._lock:
            if len(self._events) >= self._limit:
                return
            self._events.append(event)

    def dump(self):
        if not self._path:
            return
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.write_text(json.dumps(self._events, indent=2), encoding="utf-8")