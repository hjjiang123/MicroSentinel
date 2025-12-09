#!/usr/bin/env python3
import argparse
import asyncio
import json
import random
import statistics
import time
from pathlib import Path
from typing import List, Optional


def _percentile(values, pct):
    if not values:
        return 0.0
    ordered = sorted(values)
    idx = int(round((pct / 100.0) * (len(ordered) - 1)))
    idx = max(0, min(len(ordered) - 1, idx))
    return ordered[idx]


async def send_loop(
    host: str,
    port: int,
    conn_id: int,
    args,
    latency_hist,
    op_counter,
    annotations: Optional[List[dict]],
):
    reader, writer = await asyncio.open_connection(host, port)
    random.seed(conn_id)
    value_blob = b"y" * args.value_size
    key_range = range(args.key_space)

    while True:
        op = "GET" if random.random() < args.get_ratio else "SET"
        key = random.choice(key_range)
        cmd = f"{op} k{key}"
        if op == "SET":
            cmd += f" {len(value_blob)}"
        cmd += "\n"
        start = time.perf_counter_ns()
        writer.write(cmd.encode())
        await writer.drain()
        if op == "SET":
            writer.write(value_blob)
            writer.write(b"\n")
            await writer.drain()
            await reader.readline()
        else:
            await reader.readline()
        end = time.perf_counter_ns()
        latency_hist.append((end - start) / 1e3)
        op_counter.append(1)
        if annotations is not None:
            annotations.append(
                {
                    "connection": conn_id,
                    "op": op,
                    "key": key,
                    "start_ns": start,
                    "end_ns": end,
                }
            )


async def main():
    parser = argparse.ArgumentParser(description="KV load generator")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=7000)
    parser.add_argument("--connections", type=int, default=64)
    parser.add_argument("--duration", type=int, default=60)
    parser.add_argument("--get-ratio", type=float, default=0.95)
    parser.add_argument("--value-size", type=int, default=256)
    parser.add_argument("--key-space", type=int, default=1_000_000)
    parser.add_argument("--metrics-file", help="Optional JSON metrics output path")
    parser.add_argument("--annotations-file", help="Optional JSON timeline for per-connection operations")
    args = parser.parse_args()

    latency_hist = []
    op_counter: list[int] = []
    annotation_buffers: Optional[List[List[dict]]] = None
    if args.annotations_file:
        annotation_buffers = [[] for _ in range(args.connections)]

    tasks = [
        asyncio.create_task(
            send_loop(
                args.host,
                args.port,
                i,
                args,
                latency_hist,
                op_counter,
                annotation_buffers[i] if annotation_buffers is not None else None,
            )
        )
        for i in range(args.connections)
    ]

    await asyncio.sleep(args.duration)
    for t in tasks:
        t.cancel()
    try:
        await asyncio.gather(*tasks)
    except asyncio.CancelledError:
        pass

    summary = {}
    total_ops = len(op_counter)
    if latency_hist:
        summary["latency_us"] = {
            "p50": statistics.median(latency_hist),
            "p95": _percentile(latency_hist, 95),
            "p99": _percentile(latency_hist, 99),
        }
    if total_ops and args.duration:
        summary["throughput_ops_per_s"] = total_ops / args.duration
    summary["operations"] = total_ops
    summary["duration_s"] = args.duration
    if args.metrics_file:
        Path(args.metrics_file).write_text(json.dumps(summary, indent=2), encoding="utf-8")
    else:
        print(json.dumps(summary, indent=2))
    if args.annotations_file and annotation_buffers is not None:
        payload = [
            {"connection": idx, "events": buf}
            for idx, buf in enumerate(annotation_buffers)
            if buf
        ]
        Path(args.annotations_file).write_text(json.dumps(payload, indent=2), encoding="utf-8")


if __name__ == "__main__":
    asyncio.run(main())
