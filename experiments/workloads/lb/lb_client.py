#!/usr/bin/env python3

import argparse
import asyncio
import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple


def percentile(values: List[float], pct: float) -> float:
    if not values:
        return 0.0
    if pct <= 0:
        return values[0]
    if pct >= 100:
        return values[-1]
    k = (len(values) - 1) * (pct / 100.0)
    f = int(k)
    c = min(f + 1, len(values) - 1)
    if f == c:
        return values[f]
    d0 = values[f] * (c - k)
    d1 = values[c] * (k - f)
    return d0 + d1


@dataclass
class FlowResult:
    flow_id: int
    operations: int
    latencies_us: List[float]
    errors: int
    ground_truth: Optional[List[Tuple[int, int]]] = None


async def flow_task(
    host: str,
    port: int,
    duration: int,
    payload: bytes,
    flow_id: int,
    truth_buffer: Optional[List[Tuple[int, int]]],
) -> FlowResult:
    deadline = time.monotonic() + duration
    latencies: List[float] = []
    operations = 0
    errors = 0

    try:
        reader, writer = await asyncio.open_connection(host, port)
    except Exception:
        return FlowResult(0, [], 1)

    try:
        while time.monotonic() < deadline:
            start = time.perf_counter_ns()
            writer.write(payload)
            await writer.drain()
            await reader.readexactly(len(payload))
            end = time.perf_counter_ns()
            latencies.append((end - start) / 1_000.0)
            operations += 1
            if truth_buffer is not None:
                truth_buffer.append((start, end))
    except Exception:
        errors += 1
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

    return FlowResult(flow_id, operations, latencies, errors, truth_buffer)


def aggregate(results: Iterable[FlowResult], duration: int) -> Dict[str, object]:
    ops = sum(r.operations for r in results)
    latencies: List[float] = []
    errors = sum(r.errors for r in results)
    for r in results:
        latencies.extend(r.latencies_us)
    latencies.sort()

    payload = {
        "operations": ops,
        "duration_s": duration,
        "throughput_ops_per_s": ops / duration if duration else 0.0,
        "errors": errors,
    }
    if latencies:
        payload["latency_us"] = {
            "p50": percentile(latencies, 50),
            "p95": percentile(latencies, 95),
            "p99": percentile(latencies, 99),
        }
    return payload


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="HAProxy / L4 LB stress client")
    parser.add_argument("--host", default="127.0.0.1", help="LB VIP to target")
    parser.add_argument("--port", type=int, default=7100, help="LB port to target")
    parser.add_argument("--flows", type=int, default=128, help="Concurrent TCP flows")
    parser.add_argument("--duration", type=int, default=60, help="Test duration in seconds")
    parser.add_argument("--payload", type=int, default=512, help="Bytes per request")
    parser.add_argument("--metrics-file", help="Optional JSON file to write metrics to")
    parser.add_argument("--ground-truth-log", help="Optional JSON file with per-flow request windows")
    return parser.parse_args()


def _write_ground_truth(path: str, results: Iterable[FlowResult]) -> None:
    events = []
    for res in results:
        if not res.ground_truth:
            continue
        events.append(
            {
                "flow_id": res.flow_id,
                "events": [
                    {"start_ns": start, "end_ns": end}
                    for start, end in res.ground_truth
                ],
            }
        )
    if not events:
        return
    Path(path).write_text(json.dumps(events, indent=2), encoding="utf-8")


async def main() -> None:
    args = parse_args()
    payload = b"m" * args.payload
    truth_buffers: Optional[List[List[Tuple[int, int]]]] = None
    if args.ground_truth_log:
        truth_buffers = [[] for _ in range(args.flows)]

    tasks = [
        asyncio.create_task(
            flow_task(
                args.host,
                args.port,
                args.duration,
                payload,
                idx,
                truth_buffers[idx] if truth_buffers is not None else None,
            )
        )
        for idx in range(args.flows)
    ]

    results = await asyncio.gather(*tasks, return_exceptions=False)
    summary = aggregate(results, args.duration)

    output = json.dumps(summary, indent=2)
    if args.metrics_file:
        Path(args.metrics_file).write_text(output, encoding="utf-8")
    else:
        print(output)
    if args.ground_truth_log:
        _write_ground_truth(args.ground_truth_log, results)


if __name__ == "__main__":
    asyncio.run(main())
