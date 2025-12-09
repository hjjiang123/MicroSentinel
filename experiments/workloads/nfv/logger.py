#!/usr/bin/env python3
import argparse
import asyncio
import json
import time
from collections import Counter

from truth_log import TruthRecorder


class LoggerProtocol(asyncio.DatagramProtocol):
    def __init__(self, truth: TruthRecorder, stage_name: str):
        super().__init__()
        self.stats = Counter()
        self.last_emit = time.time()
        self.truth = truth
        self.stage_name = stage_name

    def datagram_received(self, data: bytes, addr):
        pkt = json.loads(data.decode())
        tenant = pkt.get("tenant", "default")
        self.stats[tenant] += 1
        now = time.time()
        if now - self.last_emit > 5:
            self.last_emit = now
            print(f"Logger stats: {dict(self.stats)}")
            self.truth.record(
                {
                    "stage": self.stage_name,
                    "ts_ns": time.perf_counter_ns(),
                    "stats": dict(self.stats),
                }
            )


def parse_args():
    parser = argparse.ArgumentParser(description="NFV logger stage")
    parser.add_argument("--listen-host", default="127.0.0.1")
    parser.add_argument("--listen-port", type=int, default=9003)
    parser.add_argument("--name", default="logger")
    parser.add_argument("--truth-log", help="Optional JSON file for logger snapshots")
    parser.add_argument("--truth-limit", type=int, default=1024)
    return parser.parse_args()


async def main():
    args = parse_args()
    truth = TruthRecorder(args.truth_log, args.truth_limit)
    protocol = LoggerProtocol(truth, args.name)
    loop = asyncio.get_running_loop()
    transport, _ = await loop.create_datagram_endpoint(
        lambda: protocol, local_addr=(args.listen_host, args.listen_port)
    )
    print(f"Logger listening on {args.listen_host}:{args.listen_port}")
    try:
        await asyncio.sleep(3600 * 24)
    finally:
        transport.close()
        truth.dump()


if __name__ == "__main__":
    asyncio.run(main())
