"""Small helpers for tuning the underlying sockets of asyncio streams."""

from __future__ import annotations

import asyncio
import logging
import socket

LOG = logging.getLogger("tunnel")


def set_tcp_nodelay(writer: asyncio.StreamWriter) -> None:
    """Disable Nagle's algorithm on the socket backing *writer*.

    Asyncio's ``StreamWriter`` exposes the raw socket via ``get_extra_info``.
    Not every transport is backed by a TCP socket, so failures are logged and
    swallowed rather than propagated.
    """
    try:
        sock = writer.get_extra_info("socket")
        if sock is not None:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    except Exception as exc:  # pragma: no cover - defensive
        LOG.debug("could not set TCP_NODELAY: %s", exc)
