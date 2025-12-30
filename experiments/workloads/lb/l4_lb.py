#!/usr/bin/env python3
import argparse
import asyncio
import hashlib
import itertools
import socket
import struct
from dataclasses import dataclass
from typing import List, Optional, Tuple


class L4LoadBalancer:
    def __init__(self, backend_endpoints: List[Tuple[str, int]]):
        self._backends = backend_endpoints
        self._rr = itertools.cycle(self._backends)

    def next_backend(self) -> Tuple[str, int]:
        return next(self._rr)


MS_FNV64_OFFSET = 1469598103934665603
MS_FNV64_PRIME = 1099511628211


def _fnv64_mix(h: int, data: int) -> int:
    h ^= (data & 0xFFFFFFFFFFFFFFFF)
    h = (h * MS_FNV64_PRIME) & 0xFFFFFFFFFFFFFFFF
    return h


def _ipv4_be32(addr: str) -> int:
    return struct.unpack("I", socket.inet_aton(addr))[0]


def compute_ms_flow_id_v4(src_ip: str, dst_ip: str, src_port: int, dst_port: int, proto: int = 6, direction: int = 0) -> int:
    """Match bpf/micro_sentinel_kern.bpf.c::hash_flow_tuple() for IPv4.

    Note: kernel stores IPv4 addrs in network byte order (be32) without ntohl.
    Ports are stored in host order (after bpf_ntohs).
    """

    h = MS_FNV64_OFFSET
    h = _fnv64_mix(h, direction)
    h = _fnv64_mix(h, proto)
    h = _fnv64_mix(h, ((src_port & 0xFFFF) << 32) | (dst_port & 0xFFFF))
    h = _fnv64_mix(h, ((_ipv4_be32(src_ip) & 0xFFFFFFFF) << 32) | (_ipv4_be32(dst_ip) & 0xFFFFFFFF))
    return h if h != 0 else 1


@dataclass
class HotConfig:
    bytes_per_slot: int
    slots: int
    rounds: int


class HotCacheMissor:
    def __init__(self, cfg: HotConfig):
        self._cfg = cfg
        self._enabled = cfg.bytes_per_slot > 0 and cfg.slots > 0 and cfg.rounds > 0
        self._buffers: List[bytearray] = []
        # Keep a live dependency so the interpreter can't DCE the whole path.
        self._sink = 0

        if not self._enabled:
            return

        fill = bytes([i & 0xFF for i in range(256)])
        for slot in range(cfg.slots):
            buf = bytearray(cfg.bytes_per_slot)
            for off in range(0, len(buf), len(fill)):
                buf[off : off + len(fill)] = fill
            # Per-slot perturbation so different slots aren't identical.
            if len(buf) >= 8:
                buf[0] = slot & 0xFF
            self._buffers.append(buf)

    def enabled(self) -> bool:
        return self._enabled

    def touch_flow(self, flow_id: int) -> None:
        if not self._enabled:
            return
        slot = int(flow_id % self._cfg.slots)
        buf = self._buffers[slot]

        # Hashing scans the whole buffer in C, generating predictable cache pressure.
        # Digest is folded into _sink to keep this work observable.
        local_sink = self._sink
        for _ in range(self._cfg.rounds):
            d = hashlib.blake2b(buf, digest_size=16).digest()
            local_sink ^= int.from_bytes(d[:8], byteorder="little", signed=False)
        self._sink = local_sink


async def pipe_stream(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    try:
        while True:
            data = await reader.read(4096)
            if not data:
                break
            writer.write(data)
            await writer.drain()
    except asyncio.CancelledError:
        pass
    finally:
        writer.close()
        await writer.wait_closed()


async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, lb: L4LoadBalancer):
    # Best-effort flow id computation (IPv4 only). This is used only for
    # selecting the per-flow cache-miss working set.
    flow_id: Optional[int] = None
    try:
        peer = writer.get_extra_info("peername")
        local = writer.get_extra_info("sockname")
        if isinstance(peer, tuple) and isinstance(local, tuple) and len(peer) >= 2 and len(local) >= 2:
            src_ip, src_port = peer[0], int(peer[1])
            dst_ip, dst_port = local[0], int(local[1])
            if ":" not in src_ip and ":" not in dst_ip:
                flow_id = compute_ms_flow_id_v4(src_ip, dst_ip, src_port, dst_port, proto=6, direction=0)
    except Exception:
        flow_id = None

    backend_host, backend_port = lb.next_backend()
    backend_reader, backend_writer = await asyncio.open_connection(backend_host, backend_port)

    # Wrap the upstream direction so we can inject per-flow cache pressure on
    # each request chunk while still forwarding bytes.
    async def pipe_up_with_hot() -> None:
        try:
            while True:
                data = await reader.read(4096)
                if not data:
                    break
                if hot is not None and hot.enabled() and flow_id is not None:
                    hot.touch_flow(flow_id)
                backend_writer.write(data)
                await backend_writer.drain()
        except asyncio.CancelledError:
            pass
        finally:
            backend_writer.close()
            await backend_writer.wait_closed()

    task_down = asyncio.create_task(pipe_stream(backend_reader, writer))
    task_up = asyncio.create_task(pipe_up_with_hot())
    await asyncio.wait({task_down, task_up}, return_when=asyncio.FIRST_COMPLETED)
    for task in (task_down, task_up):
        task.cancel()


def parse_args():
    parser = argparse.ArgumentParser(description="Async TCP load balancer")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=7100)
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--backend", action="append", required=True, help="backend host:port")
    parser.add_argument(
        "--hot-bytes-per-slot",
        type=int,
        default=0,
        help="If >0, enable per-flow cache-miss generator by hashing a buffer of this size (bytes) per slot",
    )
    parser.add_argument("--hot-slots", type=int, default=0, help="Number of per-flow working-set slots")
    parser.add_argument("--hot-rounds", type=int, default=1, help="How many full-buffer scans to do per forwarded chunk")
    return parser.parse_args()


async def main():
    args = parse_args()
    backends = []
    for item in args.backend:
        host, port = item.split(":")
        backends.append((host, int(port)))
    lb = L4LoadBalancer(backends)
    global hot
    hot = None
    if args.hot_bytes_per_slot and args.hot_bytes_per_slot > 0:
        slots = int(args.hot_slots) if args.hot_slots and args.hot_slots > 0 else 64
        rounds = int(args.hot_rounds) if args.hot_rounds and args.hot_rounds > 0 else 1
        hot = HotCacheMissor(HotConfig(bytes_per_slot=int(args.hot_bytes_per_slot), slots=slots, rounds=rounds))
    server = await asyncio.start_server(lambda r, w: handle_client(r, w, lb), host=args.host, port=args.port)
    hot_desc = "disabled" if hot is None or not hot.enabled() else f"{args.hot_bytes_per_slot}B x {slots} slots x {rounds} rounds"
    print(f"LB listening on {args.host}:{args.port} with {len(backends)} backends (hot={hot_desc})")
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
