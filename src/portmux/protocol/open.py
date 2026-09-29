"""OPEN payload helpers: encode/decode host:port."""

from __future__ import annotations

import struct

from portmux.protocol.errors import ProtocolError


def encode_open(host: str, port: int) -> bytes:
    """Build an OPEN payload: host_len(2) host port(2)."""
    host_bytes = host.encode("utf-8")
    return struct.pack("!H", len(host_bytes)) + host_bytes + struct.pack("!H", port)


def decode_open(payload: bytes) -> tuple[str, int]:
    """Parse an OPEN payload."""
    if len(payload) < 4:
        raise ProtocolError("malformed OPEN payload")
    host_len = struct.unpack_from("!H", payload, 0)[0]
    if len(payload) != 2 + host_len + 2:
        raise ProtocolError("malformed OPEN payload")
    try:
        host = payload[2 : 2 + host_len].decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ProtocolError("OPEN host is not valid UTF-8") from exc
    port = struct.unpack_from("!H", payload, 2 + host_len)[0]
    return host, port
