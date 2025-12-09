#!/usr/bin/env python3
import argparse
import asyncio
import itertools
from typing import List, Tuple


class L4LoadBalancer:
    def __init__(self, backend_endpoints: List[Tuple[str, int]]):
        self._backends = backend_endpoints
        self._rr = itertools.cycle(self._backends)

    def next_backend(self) -> Tuple[str, int]:
        return next(self._rr)


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
    backend_host, backend_port = lb.next_backend()
    backend_reader, backend_writer = await asyncio.open_connection(backend_host, backend_port)
    task_down = asyncio.create_task(pipe_stream(backend_reader, writer))
    task_up = asyncio.create_task(pipe_stream(reader, backend_writer))
    await asyncio.wait({task_down, task_up}, return_when=asyncio.FIRST_COMPLETED)
    for task in (task_down, task_up):
        task.cancel()


def parse_args():
    parser = argparse.ArgumentParser(description="Async TCP load balancer")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=7100)
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--backend", action="append", required=True, help="backend host:port")
    return parser.parse_args()


async def main():
    args = parse_args()
    backends = []
    for item in args.backend:
        host, port = item.split(":")
        backends.append((host, int(port)))
    lb = L4LoadBalancer(backends)
    server = await asyncio.start_server(lambda r, w: handle_client(r, w, lb), host=args.host, port=args.port)
    print(f"LB listening on {args.host}:{args.port} with {len(backends)} backends")
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
