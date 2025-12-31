#!/usr/bin/env python3

import argparse
import asyncio
import random
import struct
import time
import sys

async def worker(host, port, duration, tag, payload_size):
    deadline = time.time() + duration
    try:
        reader, writer = await asyncio.open_connection(host, port)
    except Exception as e:
        print(f"Connection failed: {e}", file=sys.stderr)
        return

    # Prepare payload with tag in first 4 bytes
    # Tag is 0, 1, 2, 3
    payload = bytearray(payload_size)
    struct.pack_into("<I", payload, 0, tag)
    
    while time.time() < deadline:
        try:
            writer.write(payload)
            await writer.drain()
            data = await reader.readexactly(payload_size)
        except Exception:
            break
            
    writer.close()
    await writer.wait_closed()

async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=7100)
    parser.add_argument("--connections", type=int, default=16)
    parser.add_argument("--duration", type=int, default=10)
    parser.add_argument("--payload-size", type=int, default=512)
    # Ignore extra args passed by runner
    parser.add_argument("--key-space", type=int, default=0)
    parser.add_argument("--value-size", type=int, default=0)
    parser.add_argument("--zipf-theta", type=float, default=0.0)
    parser.add_argument("--request-mix", type=str, default="")
    
    args, unknown = parser.parse_known_args()

    tasks = []
    # Distribute tags 0-3 across connections
    for i in range(args.connections):
        tag = i % 4
        tasks.append(worker(args.host, args.port, args.duration, tag, args.payload_size))

    await asyncio.gather(*tasks)

if __name__ == "__main__":
    asyncio.run(main())
