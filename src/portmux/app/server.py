"""Server side: accepts control connections and serves local forwards."""

from __future__ import annotations

import argparse
import asyncio
import functools
import logging

from portmux.app.dispatcher import on_local_connection
from portmux.app.handshake import server_handshake
from portmux.core.tunnel import Tunnel
from portmux.util.parse import AllowPolicy, parse_forward, parse_host_port

LOG = logging.getLogger("tunnel")


class Server:
    """Server side: accepts control connections and serves local forwards."""

    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.allow = AllowPolicy(args.allow, args.allow_all)
        self.tunnel: Tunnel | None = None
        self.servers: list[asyncio.AbstractServer] = []

    async def start_listeners(self) -> None:
        for spec in self.args.forward:
            bind_host, bind_port, target_host, target_port = parse_forward(spec)
            handler = functools.partial(
                self._on_local_connection,
                target_host=target_host,
                target_port=target_port,
            )
            server = await asyncio.start_server(handler, bind_host, bind_port)
            self.servers.append(server)
            LOG.info(
                "forwarding %s:%d -> %s:%d",
                bind_host,
                bind_port,
                target_host,
                target_port,
            )

    async def _on_local_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        target_host: str,
        target_port: int,
    ) -> None:
        await on_local_connection(
            self.tunnel, self.args, reader, writer, target_host, target_port
        )

    async def handle_control(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        peer = writer.get_extra_info("peername")
        LOG.info("incoming control connection from %s", peer)

        tunnel = Tunnel(
            reader,
            writer,
            is_client=False,
            args=self.args,
            allow=self.allow,
        )

        try:
            await server_handshake(tunnel, self.args.token)
        except Exception as exc:
            LOG.warning("handshake with %s failed: %s", peer, exc)
            writer.close()
            return

        LOG.info("control connection established with %s", peer)
        self.tunnel = tunnel

        try:
            await tunnel.run()
        finally:
            for stream in list(tunnel.streams.values()):
                stream.close("control connection lost")
            tunnel.streams.clear()
            if self.tunnel is tunnel:
                self.tunnel = None
            LOG.info("control connection with %s closed", peer)


async def run_server(args: argparse.Namespace) -> int:
    server = Server(args)
    await server.start_listeners()

    host, port = parse_host_port(args.listen)
    control = await asyncio.start_server(server.handle_control, host, port)
    LOG.info("listening on %s:%d", host, port)

    async with control:
        await control.serve_forever()
    return 0
