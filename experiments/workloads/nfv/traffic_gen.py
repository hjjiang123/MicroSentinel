#!/usr/bin/env python3
import argparse
import asyncio
import json
import random
import time
from itertools import cycle
from pathlib import Path

from truth_log import TruthRecorder


async def traffic_loop(args, truth: TruthRecorder):
    transport, _ = await asyncio.get_running_loop().create_datagram_endpoint(
        asyncio.DatagramProtocol, remote_addr=(args.target_host, args.target_port)
    )
    tenants = args.tenants.split(",")
    rate_cycle = cycle(args.rates)
    packet_sizes = args.packet_sizes
    start = time.time()
    sent = 0
    rate_history = []
    while time.time() - start < args.duration:
        rate = next(rate_cycle)
        rate_history.append(rate)
        interval = 1.0 / rate if rate else 0.001
        pkt = {
            "tenant": random.choice(tenants),
            "size": random.choice(packet_sizes),
            "dst_port": random.choice(args.dst_ports),
            "src": f"10.0.{random.randint(0, 255)}.{random.randint(1, 254)}",
        }
        data = json.dumps(pkt).encode()
        transport.sendto(data)
        sent += 1
        truth.record(
            {
                "ts_ns": time.perf_counter_ns(),
                "tenant": pkt["tenant"],
                "size": pkt["size"],
                "dst_port": pkt["dst_port"],
                "src": pkt["src"],
            }
        )
        await asyncio.sleep(interval)
    transport.close()
    duration = time.time() - start
    avg_rate = sent / duration if duration > 0 else 0
    return {
        "packets": sent,
        "duration_s": duration,
        "avg_rate_pps": avg_rate,
        "rate_sequence": rate_history,
        "packet_sizes": packet_sizes,
    }


def parse_args():
    parser = argparse.ArgumentParser(description="NFV traffic generator")
    parser.add_argument("--target-host", default="127.0.0.1")
    parser.add_argument("--target-port", type=int, default=9000)
    parser.add_argument("--duration", type=int, default=60)
    parser.add_argument("--rates", default="1000,2000,4000")
    parser.add_argument("--packet-sizes", default="64,256,1500")
    parser.add_argument("--tenants", default="tenant-a,tenant-b,tenant-c")
    parser.add_argument("--dst-ports", default="80,443,8443")
    parser.add_argument("--truth-log", help="Optional JSON file for emitted packet metadata")
    parser.add_argument("--truth-limit", type=int, default=8192)
    parser.add_argument("--metrics-file", help="Optional JSON file for aggregate generator stats")
    return parser.parse_args()


def parse_int_list(value: str):
    return [int(x.strip()) for x in value.split(",") if x.strip()]


async def main():
    args = parse_args()
    print("Starting traffic generator with args:", args)
    args.rates = parse_int_list(args.rates)
    args.packet_sizes = parse_int_list(args.packet_sizes)
    args.dst_ports = parse_int_list(args.dst_ports)
    truth = TruthRecorder(args.truth_log, args.truth_limit)
    summary = await traffic_loop(args, truth)
    truth.dump()
    if args.metrics_file:
        metrics_path = Path(args.metrics_file).expanduser()
        metrics_path.parent.mkdir(parents=True, exist_ok=True)
        if not metrics_path.exists():
            metrics_path.touch()
        Path(args.metrics_file).write_text(json.dumps(summary, indent=2), encoding="utf-8")


if __name__ == "__main__":
    asyncio.run(main())
