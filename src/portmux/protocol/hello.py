"""HELLO payload helpers: version + token_len + token.

The payload layout is ``version(2 BE) token_len(2 BE) token(UTF-8)``.
"""

from __future__ import annotations

import struct

from portmux.protocol.constants import PROTOCOL_VERSION
from portmux.protocol.errors import HandshakeError


def encode_hello(token: str, version: int = PROTOCOL_VERSION) -> bytes:
    """Build a HELLO payload for the client -> server exchange."""
    token_bytes = token.encode("utf-8")
    return struct.pack("!HH", version, len(token_bytes)) + token_bytes


def decode_hello(payload: bytes) -> tuple[int, str]:
    """Parse a HELLO payload; raises HandshakeError on malformed input.

    Returns ``(version, token)``.
    """
    if len(payload) < 4:
        raise HandshakeError("malformed HELLO payload")
    version, token_len = struct.unpack_from("!HH", payload, 0)
    if len(payload) != 4 + token_len:
        raise HandshakeError("malformed HELLO payload")
    try:
        token = payload[4 : 4 + token_len].decode("utf-8")
    except UnicodeDecodeError:
        token = ""
    return version, token
