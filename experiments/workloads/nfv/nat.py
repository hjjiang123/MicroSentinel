#!/usr/bin/env python3
import argparse
import asyncio
import json
import time

from truth_log import TruthRecorder


class NatProtocol(asyncio.DatagramProtocol):
    def __init__(self, next_host: str, next_port: int, pool_prefix: str, truth: TruthRecorder, stage_name: str):
        super().__init__()
        self.next_host = next_host
        self.next_port = next_port
        self.pool_prefix = pool_prefix
        self.transport = None
        self.counter = 0
        self.truth = truth
        self.stage_name = stage_name

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = transport

    def datagram_received(self, data: bytes, addr):
        pkt = json.loads(data.decode())
        prev_src = pkt.get("src")
        new_src = f"{self.pool_prefix}.{self.counter % 254 + 1}"
        pkt["src"] = new_src
        self.counter += 1
        out = json.dumps(pkt).encode()
        self.transport.sendto(out, (self.next_host, self.next_port))
        self.truth.record(
            {
                "stage": self.stage_name,
                "ts_ns": time.perf_counter_ns(),
                "old_src": prev_src,
                "new_src": new_src,
            }
        )


def parse_args():
    parser = argparse.ArgumentParser(description="NFV NAT stage")
    parser.add_argument("--listen-host", default="127.0.0.1")
    parser.add_argument("--listen-port", type=int, default=9001)
    parser.add_argument("--next-host", default="127.0.0.1")
    parser.add_argument("--next-port", type=int, default=9002)
    parser.add_argument("--pool-prefix", default="192.0.2")
    parser.add_argument("--name", default="nat")
    parser.add_argument("--truth-log", help="Optional JSON file for NAT translations")
    parser.add_argument("--truth-limit", type=int, default=4096)
    return parser.parse_args()


async def main():
    args = parse_args()
    truth = TruthRecorder(args.truth_log, args.truth_limit)
    protocol = NatProtocol(args.next_host, args.next_port, args.pool_prefix, truth, args.name)
    loop = asyncio.get_running_loop()
    transport, _ = await loop.create_datagram_endpoint(
        lambda: protocol, local_addr=(args.listen_host, args.listen_port)
    )
    print(f"NAT listening on {args.listen_host}:{args.listen_port}")
    try:
        await asyncio.sleep(3600 * 24)
    finally:
        transport.close()
        truth.dump()


if __name__ == "__main__":
    asyncio.run(main())
