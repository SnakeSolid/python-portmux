"""Protocol-level tests: framing, OPEN payloads, host/port parsing."""

from __future__ import annotations

import asyncio
import struct

import pytest

from portmux.protocol import Frame, HEADER, ProtocolError, encode_frame, read_frame
from portmux.protocol.open import decode_open, encode_open
from portmux.util.parse import parse_forward, parse_host_port


# --- Frame encoding / decoding -----------------------------------------------


@pytest.mark.parametrize(
    "ftype,flags,stream_id,payload",
    [
        (0x01, 0, 0, b""),
        (0x20, 0, 5, b"hello"),
        (0x11, 1, 2 ** 31 + 17, b"x" * 100),
        (0x30, 0, 0, b""),
    ],
)
def test_frame_round_trip(ftype, flags, stream_id, payload):
    frame = Frame(type=ftype, flags=flags, stream_id=stream_id, payload=payload)
    blob = encode_frame(frame)

    # Header is 10 bytes: type(1) flags(1) stream_id(4) length(4)
    assert len(blob) == 10 + len(payload)
    t2, f2, sid2, length2 = HEADER.unpack(blob[:10])
    assert (t2, f2, sid2, length2) == (ftype, flags, stream_id, len(payload))
    assert blob[10:] == payload


def test_frame_empty_payload_round_trip():
    blob = encode_frame(Frame(type=0x21, stream_id=3))
    # payload defaults to b"", header says length 0
    assert HEADER.unpack(blob[:10])[3] == 0
    assert blob[10:] == b""


async def test_read_frame_round_trip():
    frame = Frame(type=0x20, stream_id=7, payload=b"payload-bytes")
    reader = asyncio.StreamReader()
    reader.feed_data(encode_frame(frame))
    reader.feed_eof()

    decoded = await read_frame(reader, max_frame_size=1 << 20)
    assert decoded == frame


async def test_read_frame_rejects_oversized_payload():
    frame = Frame(type=0x20, stream_id=1, payload=b"x" * 100)
    reader = asyncio.StreamReader()
    reader.feed_data(encode_frame(frame))
    reader.feed_eof()

    with pytest.raises(ProtocolError):
        await read_frame(reader, max_frame_size=16)


# --- OPEN payload ------------------------------------------------------------


@pytest.mark.parametrize(
    "host,port",
    [
        ("example.com", 443),
        ("db.internal", 5432),
        ("127.0.0.1", 1),
        ("", 0),
        ("very-" + "x" * 200 + ".example", 65535),
    ],
)
def test_open_payload_round_trip(host, port):
    payload = encode_open(host, port)
    host2, port2 = decode_open(payload)
    assert host2 == host
    assert port2 == port


def test_decode_open_malformed_too_short():
    with pytest.raises(ProtocolError):
        decode_open(b"\x00")


def test_decode_open_malformed_length_mismatch():
    # host_len says 5 but not enough bytes follow
    payload = struct.pack("!H", 5) + b"abc"
    with pytest.raises(ProtocolError):
        decode_open(payload)


def test_decode_open_invalid_utf8():
    payload = struct.pack("!H", 2) + b"\xff\xfe" + struct.pack("!H", 1)
    with pytest.raises(ProtocolError):
        decode_open(payload)


# --- Host:port / forward parsing --------------------------------------------


@pytest.mark.parametrize(
    "spec,expected",
    [
        ("host:80", ("host", 80)),
        ("127.0.0.1:1", ("127.0.0.1", 1)),
        ("a.b.c:65535", ("a.b.c", 65535)),
    ],
)
def test_parse_host_port_ok(spec, expected):
    assert parse_host_port(spec) == expected


@pytest.mark.parametrize("spec", ["", "novalue", "a:b:c", ":80", "host:"])
def test_parse_host_port_invalid(spec):
    with pytest.raises(ValueError):
        parse_host_port(spec)


def test_parse_forward_ok():
    assert parse_forward("127.0.0.1:9000:example.com:443") == (
        "127.0.0.1",
        9000,
        "example.com",
        443,
    )


@pytest.mark.parametrize("spec", ["a:b:c", "a:b:c:d:e", ":b:c:d", "a:b::d"])
def test_parse_forward_invalid(spec):
    with pytest.raises(ValueError):
        parse_forward(spec)
