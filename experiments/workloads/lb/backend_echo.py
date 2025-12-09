#!/usr/bin/env python3
import argparse
import asyncio


async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    peer = writer.get_extra_info("peername")
    try:
        while data := await reader.read(4096):
            writer.write(data)
            await writer.drain()
    finally:
        writer.close()
        await writer.wait_closed()


def parse_args():
    parser = argparse.ArgumentParser(description="Echo backend for LB workload")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=7201)
    parser.add_argument("--workers", type=int, default=2)
    return parser.parse_args()


async def main():
    args = parse_args()
    server = await asyncio.start_server(handle, host=args.host, port=args.port)
    print(f"Backend echo listening on {args.host}:{args.port}")
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
