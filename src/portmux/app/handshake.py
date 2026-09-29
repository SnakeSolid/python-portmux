"""HELLO handshake exchange over a fresh control connection."""

from __future__ import annotations

import asyncio
import hmac
import logging

from portmux.protocol.constants import (
    F_HELLO,
    F_HELLO_ERR,
    F_HELLO_OK,
    HANDSHAKE_TIMEOUT,
    HELLO_ERR_OTHER,
    HELLO_ERR_TOKEN,
    HELLO_ERR_VERSION,
    PROTOCOL_VERSION,
)
from portmux.protocol.errors import HandshakeError
from portmux.protocol.framing import Frame, encode_frame, read_frame
from portmux.protocol.hello import decode_hello, encode_hello

LOG = logging.getLogger("tunnel")


async def client_handshake(tunnel, token: str) -> None:
    """Perform the client side of the HELLO exchange."""
    tunnel.writer.write(encode_frame(Frame(F_HELLO, 0, encode_hello(token))))
    await tunnel.writer.drain()

    try:
        frame = await asyncio.wait_for(
            read_frame(tunnel.reader, tunnel.max_frame_size), HANDSHAKE_TIMEOUT
        )
    except TimeoutError:
        raise HandshakeError("timeout waiting for HELLO_OK")

    if frame.stream_id != 0:
        raise HandshakeError("unexpected stream id in handshake reply")
    if frame.type == F_HELLO_OK:
        return
    if frame.type == F_HELLO_ERR:
        reason = frame.payload[0] if frame.payload else HELLO_ERR_OTHER
        raise HandshakeError(f"server rejected handshake (reason {reason})")
    raise HandshakeError(f"unexpected frame 0x{frame.type:02x} during handshake")


async def server_handshake(tunnel, token: str) -> None:
    """Perform the server side of the HELLO exchange."""
    try:
        frame = await asyncio.wait_for(
            read_frame(tunnel.reader, tunnel.max_frame_size), HANDSHAKE_TIMEOUT
        )
    except TimeoutError:
        raise HandshakeError("timeout waiting for HELLO")

    if frame.type != F_HELLO or frame.stream_id != 0:
        raise HandshakeError("expected HELLO frame")

    version, received = decode_hello(frame.payload)

    if version != PROTOCOL_VERSION:
        tunnel.writer.write(encode_frame(Frame(F_HELLO_ERR, 0, bytes([HELLO_ERR_VERSION]))))
        await tunnel.writer.drain()
        raise HandshakeError(f"protocol version mismatch ({version})")

    if not hmac.compare_digest(received, token):
        tunnel.writer.write(encode_frame(Frame(F_HELLO_ERR, 0, bytes([HELLO_ERR_TOKEN]))))
        await tunnel.writer.drain()
        raise HandshakeError("invalid token")

    tunnel.writer.write(encode_frame(Frame(F_HELLO_OK, 0)))
    await tunnel.writer.drain()
