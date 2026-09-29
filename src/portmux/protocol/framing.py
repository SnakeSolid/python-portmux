"""Frame serialization: the fixed header, encode/decode helpers."""

from __future__ import annotations

import asyncio
import struct
from dataclasses import dataclass

from portmux.protocol.errors import ProtocolError

# type(1) flags(1) stream_id(4) length(4)
HEADER = struct.Struct("!BBII")


@dataclass
class Frame:
    """A single protocol frame."""

    type: int
    stream_id: int = 0
    payload: bytes = b""
    flags: int = 0


def encode_frame(frame: Frame) -> bytes:
    """Serialize a frame to bytes (header + payload)."""
    payload = frame.payload or b""
    return HEADER.pack(frame.type, frame.flags, frame.stream_id, len(payload)) + payload


async def read_frame(reader: asyncio.StreamReader, max_frame_size: int) -> Frame:
    """Read and decode exactly one frame from *reader*."""
    header = await reader.readexactly(HEADER.size)
    ftype, flags, stream_id, length = HEADER.unpack(header)
    if length > max_frame_size:
        raise ProtocolError(f"frame payload too large: {length} > {max_frame_size}")
    payload = await reader.readexactly(length) if length else b""
    return Frame(type=ftype, stream_id=stream_id, payload=payload, flags=flags)
