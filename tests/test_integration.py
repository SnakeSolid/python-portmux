"""End-to-end integration test.

Stands up a real echo target, a real ``Server`` (with a control listener), and
a real ``Client``, then asserts data round-trips through a forward.
"""

from __future__ import annotations

import argparse
import asyncio

from portmux.app.client import Client
from portmux.app.server import Server


def _args(mode: str, **overrides) -> argparse.Namespace:
    base = dict(
        mode=mode,
        token="test-token",
        forward=[],
        allow=[],
        allow_all=True,
        window_size=8192,
        max_frame_size=1024,
        keepalive=30.0,
        log_level="info",
        connect="",
        listen="",
        reconnect=None,
        keep_streams=False,
    )
    base.update(overrides)
    return argparse.Namespace(**base)


async def _free_port() -> int:
    srv = await asyncio.start_server(asyncio.Protocol, "127.0.0.1", 0)
    port = srv.sockets[0].getsockname()[1]
    srv.close()
    await srv.wait_closed()
    return port


async def _echo(reader, writer):
    """Echo server: returns everything it reads back verbatim."""
    try:
        while True:
            data = await reader.read(4096)
            if not data:
                break
            writer.write(data)
            await writer.drain()
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


async def _wait_for(cond, timeout=5.0, interval=0.01):
    deadline = asyncio.get_event_loop().time() + timeout
    while not cond():
        if asyncio.get_event_loop().time() > deadline:
            raise TimeoutError()
        await asyncio.sleep(interval)


async def test_end_to_end_data_round_trip():
    # Target echo server.
    target_port = await _free_port()
    target = await asyncio.start_server(_echo, "127.0.0.1", target_port)

    # Forward listener (on the client side) + control listener (server side).
    forward_from = await _free_port()
    control_port = await _free_port()

    server_args = _args("server", listen=f"127.0.0.1:{control_port}")
    client_args = _args(
        "client",
        connect=f"127.0.0.1:{control_port}",
        forward=[f"127.0.0.1:{forward_from}:127.0.0.1:{target_port}"],
    )

    server = Server(server_args)
    await server.start_listeners()
    control = await asyncio.start_server(server.handle_control, "127.0.0.1", control_port)

    client = Client(client_args)
    await client.start_listeners()
    session_task = asyncio.create_task(client.session())

    try:
        # Let the client connect, handshake, and create the control tunnel.
        await _wait_for(lambda: client.tunnel is not None)

        # Send data through the forward: local -> control -> target -> back.
        reader, writer = await asyncio.open_connection("127.0.0.1", forward_from)
        payload = b"ping" * 100  # 400 bytes
        writer.write(payload)
        await writer.drain()

        got = await reader.readexactly(len(payload))
        assert got == payload

        writer.close()
        await writer.wait_closed()
    finally:
        session_task.cancel()
        await asyncio.gather(session_task, return_exceptions=True)

        for srv in client.servers:
            srv.close()
        for srv in server.servers:
            srv.close()
        control.close()
        target.close()
        await asyncio.gather(
            *(s.wait_closed() for s in client.servers),
            *(s.wait_closed() for s in server.servers),
            control.wait_closed(),
            target.wait_closed(),
            return_exceptions=True,
        )
