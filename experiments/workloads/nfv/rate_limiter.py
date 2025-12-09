#!/usr/bin/env python3
import argparse
import asyncio
import json
import time
from collections import defaultdict

from truth_log import TruthRecorder


class TokenBucket:
    def __init__(self, rate: float, burst: float):
        self.rate = rate
        self.capacity = burst
        self.tokens = burst
        self.last = time.time()

    def consume(self, cost: float) -> bool:
        now = time.time()
        delta = now - self.last
        self.last = now
        self.tokens = min(self.capacity, self.tokens + delta * self.rate)
        if self.tokens >= cost:
            self.tokens -= cost
            return True
        return False


class RateLimiterProtocol(asyncio.DatagramProtocol):
    def __init__(
        self,
        rate_per_tenant: float,
        next_host: str,
        next_port: int,
        truth: TruthRecorder,
        stage_name: str,
    ):
        super().__init__()
        self.next_host = next_host
        self.next_port = next_port
        self.rate_per_tenant = rate_per_tenant
        self.transport = None
        self.buckets = defaultdict(lambda: TokenBucket(rate_per_tenant, rate_per_tenant))
        self.dropped = 0
        self.forwarded = 0
        self.truth = truth
        self.stage_name = stage_name

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = transport

    def datagram_received(self, data: bytes, addr):
        pkt = json.loads(data.decode())
        tenant = pkt.get("tenant", "default")
        size = pkt.get("size", 64)
        bucket = self.buckets[tenant]
        cost = size / 64.0
        if bucket.consume(cost):
            self.forwarded += 1
            self.transport.sendto(data, (self.next_host, self.next_port))
            action = "forward"
        else:
            self.dropped += 1
            action = "drop"
        self.truth.record(
            {
                "stage": self.stage_name,
                "ts_ns": time.perf_counter_ns(),
                "tenant": tenant,
                "size": size,
                "action": action,
                "tokens_remaining": bucket.tokens,
            }
        )


def parse_args():
    parser = argparse.ArgumentParser(description="NFV rate limiter stage")
    parser.add_argument("--listen-host", default="127.0.0.1")
    parser.add_argument("--listen-port", type=int, default=9002)
    parser.add_argument("--next-host", default="127.0.0.1")
    parser.add_argument("--next-port", type=int, default=9003)
    parser.add_argument("--rate", type=float, default=20000.0, help="tokens per second")
    parser.add_argument("--name", default="rate_limiter")
    parser.add_argument("--truth-log", help="Optional JSON file for limiter decisions")
    parser.add_argument("--truth-limit", type=int, default=4096)
    return parser.parse_args()


async def main():
    args = parse_args()
    truth = TruthRecorder(args.truth_log, args.truth_limit)
    protocol = RateLimiterProtocol(args.rate, args.next_host, args.next_port, truth, args.name)
    loop = asyncio.get_running_loop()
    transport, _ = await loop.create_datagram_endpoint(
        lambda: protocol, local_addr=(args.listen_host, args.listen_port)
    )
    print(f"Rate limiter listening on {args.listen_host}:{args.listen_port}")
    try:
        await asyncio.sleep(3600 * 24)
    finally:
        transport.close()
        truth.dump()


if __name__ == "__main__":
    asyncio.run(main())
