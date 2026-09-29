"""Tests for AllowPolicy, PriorityWriter, and stream-id allocation."""

from __future__ import annotations

import asyncio

from portmux.core.tunnel import Tunnel
from portmux.core.writer import PriorityWriter
from portmux.protocol import Frame
from portmux.util.parse import AllowPolicy


# --- AllowPolicy -------------------------------------------------------------


def test_allow_all_allows_everything():
    policy = AllowPolicy(allowed=None, allow_all=True)
    assert policy.check("anything.com", 1)
    assert policy.check("127.0.0.1", 9999)


def test_allow_all_denies_unknown_by_default():
    policy = AllowPolicy(allowed=None, allow_all=False)
    assert not policy.check("example.com", 443)


def test_allow_specific_host_port():
    policy = AllowPolicy(allowed=["example.com:443"], allow_all=False)
    assert policy.check("example.com", 443)
    assert not policy.check("example.com", 80)
    assert not policy.check("other.com", 443)


def test_allow_is_case_insensitive_on_host():
    policy = AllowPolicy(allowed=["EXAMPLE.com:443"], allow_all=False)
    assert policy.check("example.com", 443)
    assert policy.check("EXAMPLE.COM", 443)


def test_allow_multiple_specs():
    policy = AllowPolicy(allowed=["a:1", "b:2"], allow_all=False)
    assert policy.check("a", 1)
    assert policy.check("b", 2)
    assert not policy.check("c", 3)


# --- PriorityWriter ----------------------------------------------------------


def test_priority_writer_high_before_low():
    pw = PriorityWriter()
    pw.push(Frame(1))  # low
    pw.push(Frame(2, stream_id=0), high=True)  # high, pushed later
    first = asyncio.run(pw.get())
    second = asyncio.run(pw.get())
    assert first.type == 2  # high frame drained first
    assert second.type == 1


def test_priority_writer_fifo_within_priority():
    pw = PriorityWriter()
    pw.push(Frame(1), high=False)
    pw.push(Frame(2), high=False)
    pw.push(Frame(3), high=True)
    pw.push(Frame(4), high=True)

    order = []
    for _ in range(4):
        order.append(asyncio.run(pw.get()).type)

    # All high first (in insertion order), then all low (in insertion order)
    assert order == [3, 4, 1, 2]


async def test_priority_writer_get_blocking_then_wake():
    pw = PriorityWriter()
    task = asyncio.get_event_loop().create_task(pw.get())
    await asyncio.sleep(0)
    assert not task.done()  # blocks while empty
    pw.push(Frame(7))
    frame = await task
    assert frame.type == 7


def test_priority_writer_high_priority_first_across_mixed_order():
    pw = PriorityWriter()
    pw.push(Frame(1), high=False)
    pw.push(Frame(9), high=True)
    pw.push(Frame(2), high=False)
    pw.push(Frame(8), high=True)

    order = []
    # Simulate a consumer draining alternately to reflect real get() loop
    for _ in range(4):
        order.append(asyncio.run(pw.get()).type)
    # 9 and 8 (high) then 1 and 2 (low)
    assert order[:2] == [9, 8]
    assert order[2:] == [1, 2]


# --- Tunnel.alloc_id ---------------------------------------------------------


def _make_args(**overrides):
    class Args:
        window_size = 262144
        max_frame_size = 65536
        keepalive = 30.0
        allow = []
        allow_all = True
        token = "t"
        forward = []
        connect = "h:1"
        listen = "h:1"
        reconnect = None
        keep_streams = False
        mode = "client"
        log_level = "info"

    a = Args()
    for k, v in overrides.items():
        setattr(a, k, v)
    return a


def _make_tunnel(is_client, start_next=None):
    reader, writer = None, None  # not used by alloc_id
    return Tunnel(
        reader,
        writer,
        is_client=is_client,
        args=_make_args(),
        next_id=start_next,
    )


def test_alloc_id_client_assigns_odd_ids():
    tunnel = _make_tunnel(is_client=True)
    assert tunnel.alloc_id() == 1
    assert tunnel.alloc_id() == 3
    assert tunnel.alloc_id() == 5


def test_alloc_id_server_assigns_even_ids():
    tunnel = _make_tunnel(is_client=False)
    assert tunnel.alloc_id() == 2
    assert tunnel.alloc_id() == 4
    assert tunnel.alloc_id() == 6


def test_alloc_id_wraparound_keeps_parity():
    # Client IDs stay odd across the wrap; the counter must never return 0.
    tunnel = _make_tunnel(is_client=True, start_next=0xFFFFFFFD)
    assert tunnel.alloc_id() == 0xFFFFFFFD
    assert tunnel.alloc_id() == 0xFFFFFFFF
    assert tunnel.alloc_id() == 1  # wrapped
    assert tunnel.alloc_id() == 3


def test_alloc_id_client_never_returns_zero():
    # Start the counter such that it wraps through 0; the reset rule avoids 0.
    tunnel = _make_tunnel(is_client=True, start_next=0xFFFFFFFE)
    assert tunnel.alloc_id() == 0xFFFFFFFE
    # (0xFFFFFFFE + 2) & 0xFFFFFFFF == 0 -> reset to 1
    assert tunnel.alloc_id() == 1


def test_alloc_id_server_never_returns_zero():
    tunnel = _make_tunnel(is_client=False, start_next=0xFFFFFFFE)
    assert tunnel.alloc_id() == 0xFFFFFFFE
    # wraps through 0 -> reset to even stream id 2
    assert tunnel.alloc_id() == 2
