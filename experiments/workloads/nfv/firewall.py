#!/usr/bin/env python3
import argparse
import asyncio
import ipaddress
import json
import time
from pathlib import Path
from typing import List

import yaml

from truth_log import TruthRecorder


class FirewallProtocol(asyncio.DatagramProtocol):
    def __init__(
        self,
        allowed_ports: List[int],
        blocked_cidrs: List[str],
        next_host: str,
        next_port: int,
        truth: TruthRecorder,
        stage_name: str,
    ):
        super().__init__()
        self.allowed_ports = set(allowed_ports)
        self.blocked_networks = [ipaddress.ip_network(c) for c in blocked_cidrs]
        self.next_host = next_host
        self.next_port = next_port
        self.transport = None
        self.dropped = 0
        self.forwarded = 0
        self.truth = truth
        self.stage_name = stage_name

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = transport

    def datagram_received(self, data: bytes, addr):
        pkt = json.loads(data.decode())
        src_ip = ipaddress.ip_address(pkt.get("src", "0.0.0.0"))
        dst_port = int(pkt.get("dst_port", 0))
        ts = time.perf_counter_ns()
        decision = "forward"
        reason = "allowed"
        if self.allowed_ports and dst_port not in self.allowed_ports:
            self.dropped += 1
            decision = "drop"
            reason = "dst_port"
        if any(src_ip in net for net in self.blocked_networks):
            self.dropped += 1
            decision = "drop"
            reason = "blocked_src"
        event = {
            "stage": self.stage_name,
            "ts_ns": ts,
            "action": decision,
            "src": str(src_ip),
            "dst_port": dst_port,
            "reason": reason,
        }
        self.truth.record(event)
        if decision == "drop":
            return
        self.forwarded += 1
        self.transport.sendto(data, (self.next_host, self.next_port))


def parse_args():
    parser = argparse.ArgumentParser(description="NFV firewall stage")
    parser.add_argument("--listen-host", default="127.0.0.1")
    parser.add_argument("--listen-port", type=int, default=9000)
    parser.add_argument("--next-host", default="127.0.0.1")
    parser.add_argument("--next-port", type=int, default=9001)
    parser.add_argument("--policy", required=True)
    parser.add_argument("--name", default="firewall")
    parser.add_argument("--truth-log", help="Optional JSON file for firewall decisions")
    parser.add_argument("--truth-limit", type=int, default=2048)
    return parser.parse_args()


async def main():
    args = parse_args()
    policy = yaml.safe_load(Path(args.policy).read_text())
    truth = TruthRecorder(args.truth_log, args.truth_limit)
    protocol = FirewallProtocol(
        allowed_ports=policy.get("allowed_ports", []),
        blocked_cidrs=policy.get("blocked_cidrs", []),
        next_host=args.next_host,
        next_port=args.next_port,
        truth=truth,
        stage_name=args.name,
    )
    loop = asyncio.get_running_loop()
    transport, _ = await loop.create_datagram_endpoint(
        lambda: protocol, local_addr=(args.listen_host, args.listen_port)
    )
    print(f"Firewall listening on {args.listen_host}:{args.listen_port}")
    try:
        await asyncio.sleep(3600 * 24)
    finally:
        transport.close()
        truth.dump()


if __name__ == "__main__":
    asyncio.run(main())
