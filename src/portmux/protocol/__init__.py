"""Wire-protocol primitives: framing, payload helpers, constants, errors.

Dependencies: this package depends only on the Python standard library and on
other ``portmux.protocol`` modules. It must not import from ``core`` or
``app``.
"""

from __future__ import annotations

from portmux.protocol.constants import (
    CONNECT_TIMEOUT,
    CONTROL_FRAME_TYPES,
    CREDIT_FLUSH_INTERVAL,
    F_CLOSE,
    F_DATA,
    F_FIN,
    F_HELLO,
    F_HELLO_ERR,
    F_HELLO_OK,
    F_OPEN,
    F_OPEN_ERR,
    F_OPEN_OK,
    F_PING,
    F_PONG,
    F_WINDOW_UPDATE,
    HANDSHAKE_TIMEOUT,
    HELLO_ERR_OTHER,
    HELLO_ERR_TOKEN,
    HELLO_ERR_VERSION,
    OPEN_ERR_DNS,
    OPEN_ERR_FORBIDDEN,
    OPEN_ERR_OTHER,
    OPEN_ERR_REFUSED,
    OPEN_ERR_TIMEOUT,
    OPEN_TIMEOUT,
    PROTOCOL_VERSION,
    STREAM_FRAME_TYPES,
)
from portmux.protocol.errors import HandshakeError, OpenFailure, ProtocolError
from portmux.protocol.framing import Frame, HEADER, encode_frame, read_frame
from portmux.protocol.hello import decode_hello, encode_hello
from portmux.protocol.open import decode_open, encode_open

__all__ = [
    "CONNECT_TIMEOUT",
    "CONTROL_FRAME_TYPES",
    "CREDIT_FLUSH_INTERVAL",
    "F_CLOSE",
    "F_DATA",
    "F_FIN",
    "F_HELLO",
    "F_HELLO_ERR",
    "F_HELLO_OK",
    "F_OPEN",
    "F_OPEN_ERR",
    "F_OPEN_OK",
    "F_PING",
    "F_PONG",
    "F_WINDOW_UPDATE",
    "Frame",
    "HANDSHAKE_TIMEOUT",
    "HEADER",
    "HELLO_ERR_OTHER",
    "HELLO_ERR_TOKEN",
    "HELLO_ERR_VERSION",
    "HandshakeError",
    "OPEN_ERR_DNS",
    "OPEN_ERR_FORBIDDEN",
    "OPEN_ERR_OTHER",
    "OPEN_ERR_REFUSED",
    "OPEN_ERR_TIMEOUT",
    "OPEN_TIMEOUT",
    "OpenFailure",
    "PROTOCOL_VERSION",
    "ProtocolError",
    "STREAM_FRAME_TYPES",
    "decode_hello",
    "decode_open",
    "encode_frame",
    "encode_hello",
    "encode_open",
    "read_frame",
]
