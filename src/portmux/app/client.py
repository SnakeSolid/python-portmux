"""Client side: owns the persistent stream table and local listeners."""

from __future__ import annotations

import argparse
import asyncio
import functools
import logging

from portmux.app.dispatcher import on_local_connection
from portmux.app.handshake import client_handshake
from portmux.core.stream import Stream
from portmux.core.tunnel import Tunnel
from portmux.util.parse import AllowPolicy, parse_forward, parse_host_port
from portmux.util.socket import set_tcp_nodelay

LOG = logging.getLogger("tunnel")


class Client:
    """Client side: owns the persistent stream table and local listeners."""

    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.allow = AllowPolicy(args.allow, args.allow_all)
        self.streams: dict[int, Stream] = {}
        self.next_id = 1
        self.tunnel: Tunnel | None = None
        self.servers: list[asyncio.AbstractServer] = []

    # -- listeners ----------------------------------------------------------

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

    # -- sessions -----------------------------------------------------------

    async def session(self) -> int:
        """Run one control-connection session.  Returns 0 only on clean stop."""
        host, port = parse_host_port(self.args.connect)
        try:
            reader, writer = await asyncio.open_connection(host, port)
            set_tcp_nodelay(writer)
        except OSError as exc:
            LOG.error("cannot connect to %s:%d: %s", host, port, exc)
            return 1

        tunnel = Tunnel(
            reader,
            writer,
            is_client=True,
            args=self.args,
            streams=self.streams,
            allow=self.allow,
            next_id=self.next_id,
        )

        try:
            await client_handshake(tunnel, self.args.token)
        except Exception as exc:
            LOG.error("handshake failed: %s", exc)
            writer.close()
            return 1

        LOG.info("control connection established to %s:%d", host, port)
        self.tunnel = tunnel

        # Re-open streams preserved from a previous session.
        for stream in list(self.streams.values()):
            if stream.closed:
                self.streams.pop(stream.id, None)
                continue
            if stream.initiator and stream.target is not None:
                stream.reopen(tunnel)
            else:
                stream.close("control connection lost")

        try:
            await tunnel.run()
        finally:
            self.next_id = tunnel.next_id
            self.tunnel = None
            if self.args.keep_streams:
                for stream in list(self.streams.values()):
                    stream.detach()
            else:
                for stream in list(self.streams.values()):
                    stream.close("control connection lost")
                self.streams.clear()

        LOG.info("control connection lost")
        return 1


async def run_client(args: argparse.Namespace) -> int:
    client = Client(args)
    await client.start_listeners()

    if args.reconnect is None:
        return await client.session()

    while True:
        await client.session()
        LOG.info("reconnecting in %.1f seconds", args.reconnect)
        await asyncio.sleep(args.reconnect)
