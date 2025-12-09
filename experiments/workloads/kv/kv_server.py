#!/usr/bin/env python3
import argparse
import asyncio
import json
import os
import random
import string
import time
from pathlib import Path
from typing import Dict, Tuple

DEFAULT_VALUE = b"x" * 256


class KVStore:
    def __init__(self, key_space: int, value_size: int):
        self._value_size = value_size
        self._store: Dict[bytes, bytes] = {}
        for key_id in range(key_space):
            key = f"k{key_id}".encode()
            self._store[key] = os.urandom(value_size)

    def get(self, key: bytes) -> bytes:
        return self._store.get(key, DEFAULT_VALUE)

    def set(self, key: bytes, value: bytes) -> None:
        self._store[key] = value


def _zipf_key(key_space: int, theta: float) -> int:
    # simple rejection sampler for reproducible hot keys
    while True:
        rank = random.randint(1, key_space)
        prob = 1 / (rank ** theta)
        if random.random() < prob:
            return rank


def _random_key(key_space: int, theta: float) -> bytes:
    key_id = _zipf_key(key_space, theta)
    return f"k{key_id}".encode()


async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, store: KVStore):
    addr = writer.get_extra_info("peername")
    while True:
        header = await reader.readline()
        if not header:
            break
        parts = header.decode().strip().split()
        if len(parts) < 2:
            continue
        op, key = parts[0], parts[1].encode()
        if op == "GET":
            writer.write(store.get(key))
            writer.write(b"\n")
        elif op == "SET":
            payload_len = int(parts[2]) if len(parts) > 2 else store._value_size
            payload = await reader.readexactly(payload_len)
            store.set(key, payload)
            writer.write(b"OK\n")
        await writer.drain()
    writer.close()
    await writer.wait_closed()


def parse_args():
    parser = argparse.ArgumentParser(description="Async KV server for MicroSentinel experiments")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=7000)
    parser.add_argument("--key-space", type=int, default=1_000_000)
    parser.add_argument("--value-size", type=int, default=256)
    parser.add_argument("--zipf-theta", type=float, default=1.0)
    parser.add_argument("--truth-file", help="Optional JSON file describing dataset objects")
    parser.add_argument("--truth-limit", type=int, default=1024)
    return parser.parse_args()


def _write_truth_snapshot(store: KVStore, path: str, limit: int) -> None:
    entries = []
    for idx, (key, value) in enumerate(store._store.items()):
        entries.append(
            {
                "key": key.decode(),
                "value_addr": hex(id(value)),
                "value_len": len(value),
            }
        )
        if idx + 1 >= limit:
            break
    Path(path).write_text(json.dumps({"objects": entries}, indent=2), encoding="utf-8")


async def main():
    args = parse_args()
    store = KVStore(args.key_space, args.value_size)
    if args.truth_file:
        _write_truth_snapshot(store, args.truth_file, args.truth_limit)
    server = await asyncio.start_server(
        lambda r, w: handle_client(r, w, store), host=args.host, port=args.port
    )
    addrs = ", ".join(str(sock.getsockname()) for sock in server.sockets)
    print(f"KV server listening on {addrs}")
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
