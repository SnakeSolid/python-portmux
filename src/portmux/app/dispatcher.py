"""Shared helpers for spinning up outbound streams from local listeners.

Both ``Client`` and ``Server`` accept local TCP connections on ``--forward``
listeners, turn them into streams initiated across the control connection, and
forward them to a remote target. The logic is identical, so it lives here once.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
from typing import TYPE_CHECKING

from portmux.core.stream import Stream
from portmux.util.socket import set_tcp_nodelay

if TYPE_CHECKING:
    from portmux.core.tunnel import Tunnel

LOG = logging.getLogger("tunnel")


def spawn_outgoing_stream(
    tunnel: Tunnel,
    args: argparse.Namespace,
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    target: tuple[str, int],
) -> Stream:
    """Create an initiator-side stream and start it."""
    stream_id = tunnel.alloc_id()
    stream = Stream(
        stream_id,
        reader,
        writer,
        args,
        initiator=True,
        streams=tunnel.streams,
        target=target,
    )
    tunnel.streams[stream_id] = stream
    stream.attach(tunnel)
    stream.start()
    LOG.debug(
        "spawned incoming local connection as stream %d -> %s:%d",
        stream_id,
        target[0],
        target[1],
    )
    return stream


async def on_local_connection(
    tunnel: Tunnel | None,
    args: argparse.Namespace,
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    target_host: str,
    target_port: int,
) -> None:
    """Handle a locally accepted connection by spawning an initiator stream."""
    set_tcp_nodelay(writer)
    if tunnel is None:
        LOG.warning("no active control connection, rejecting local connection")
        writer.close()
        return
    try:
        spawn_outgoing_stream(tunnel, args, reader, writer, (target_host, target_port))
    except Exception as exc:
        LOG.warning("could not create stream: %s", exc)
        writer.close()
