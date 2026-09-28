#!/usr/bin/env python3
"""
tunnel.py - a TCP port forwarding tunnel with a custom binary multiplexing
protocol over a single TCP control connection.

Works in two modes:

    * ``client`` - connects to the peer, may use ``--reconnect`` /
      ``--keep-streams``.
    * ``server`` - listens for the control connection.

After the HELLO handshake both sides are completely symmetric: each side may
have local listeners (``--forward``) whose accepted connections become logical
streams carried over the control connection.

Only the Python standard library is used.
"""

from __future__ import annotations

import argparse
import asyncio
import collections
import functools
import hmac
import logging
import socket
import struct
import sys
import time
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

LOG = logging.getLogger("tunnel")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

PROTOCOL_VERSION = 1

HANDSHAKE_TIMEOUT = 10.0     # seconds to wait for HELLO / HELLO_OK
CONNECT_TIMEOUT = 30.0       # seconds to wait for the target TCP connection
OPEN_TIMEOUT = 30.0          # seconds to wait for OPEN_OK / OPEN_ERR
CREDIT_FLUSH_INTERVAL = 0.05  # 50 ms window-update aggregation timer

# --- frame types -----------------------------------------------------------
F_HELLO = 0x01
F_HELLO_OK = 0x02
F_HELLO_ERR = 0x03

F_OPEN = 0x10
F_OPEN_OK = 0x11
F_OPEN_ERR = 0x12
F_DATA = 0x20
F_WINDOW_UPDATE = 0x21
F_FIN = 0x22
F_CLOSE = 0x23

F_PING = 0x30
F_PONG = 0x31

CONTROL_FRAME_TYPES = frozenset({F_HELLO, F_HELLO_OK, F_HELLO_ERR, F_PING, F_PONG})
STREAM_FRAME_TYPES = frozenset(
    {F_OPEN, F_OPEN_OK, F_OPEN_ERR, F_DATA, F_WINDOW_UPDATE, F_FIN, F_CLOSE}
)

# --- HELLO_ERR reasons -----------------------------------------------------
HELLO_ERR_VERSION = 0x01
HELLO_ERR_TOKEN = 0x02
HELLO_ERR_OTHER = 0x03

# --- OPEN_ERR reasons ------------------------------------------------------
OPEN_ERR_REFUSED = 0x01
OPEN_ERR_TIMEOUT = 0x02
OPEN_ERR_DNS = 0x03
OPEN_ERR_FORBIDDEN = 0x04
OPEN_ERR_OTHER = 0x05

# type(1) flags(1) stream_id(4) length(4)
HEADER = struct.Struct("!BBII")


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------

class ProtocolError(Exception):
    """Any protocol violation: the control connection is closed immediately."""


class HandshakeError(Exception):
    """The HELLO exchange failed."""


class OpenFailure(Exception):
    """Internal helper carrying an OPEN_ERR reason code."""

    def __init__(self, reason: int) -> None:
        super().__init__(f"open failure (reason {reason})")
        self.reason = reason


# ---------------------------------------------------------------------------
# Frames
# ---------------------------------------------------------------------------

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
        raise ProtocolError(
            f"frame payload too large: {length} > {max_frame_size}"
        )
    payload = await reader.readexactly(length) if length else b""
    return Frame(type=ftype, stream_id=stream_id, payload=payload, flags=flags)


def encode_open(host: str, port: int) -> bytes:
    """Build an OPEN payload: host_len(2) host port(2)."""
    host_bytes = host.encode("utf-8")
    return struct.pack("!H", len(host_bytes)) + host_bytes + struct.pack("!H", port)


def decode_open(payload: bytes) -> Tuple[str, int]:
    """Parse an OPEN payload."""
    if len(payload) < 4:
        raise ProtocolError("malformed OPEN payload")
    host_len = struct.unpack_from("!H", payload, 0)[0]
    if len(payload) != 2 + host_len + 2:
        raise ProtocolError("malformed OPEN payload")
    try:
        host = payload[2:2 + host_len].decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ProtocolError("OPEN host is not valid UTF-8") from exc
    port = struct.unpack_from("!H", payload, 2 + host_len)[0]
    return host, port


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

def parse_host_port(spec: str) -> Tuple[str, int]:
    """Parse ``HOST:PORT`` (IPv4 or hostname only, no brackets)."""
    if spec.count(":") != 1:
        raise ValueError(f"invalid HOST:PORT value: {spec!r}")
    host, port_str = spec.split(":")
    if not host:
        raise ValueError(f"empty host in {spec!r}")
    return host, int(port_str)


def parse_forward(spec: str) -> Tuple[str, int, str, int]:
    """Parse ``BIND_HOST:BIND_PORT:TARGET_HOST:TARGET_PORT``."""
    parts = spec.split(":")
    if len(parts) != 4:
        raise ValueError(
            f"invalid --forward value {spec!r}: expected "
            "BIND_HOST:BIND_PORT:TARGET_HOST:TARGET_PORT"
        )
    bind_host, bind_port, target_host, target_port = parts
    if not bind_host or not target_host:
        raise ValueError(f"invalid --forward value {spec!r}")
    return bind_host, int(bind_port), target_host, int(target_port)


class AllowPolicy:
    """Decides whether an OPEN request may be served."""

    def __init__(self, allowed: Optional[List[str]], allow_all: bool) -> None:
        self.allow_all = allow_all
        self._allowed = set()
        for spec in allowed or []:
            host, port = parse_host_port(spec)
            self._allowed.add((host.lower(), port))

    def check(self, host: str, port: int) -> bool:
        if self.allow_all:
            return True
        return (host.lower(), port) in self._allowed


class PriorityWriter:
    """Two-queue (high / normal) writer used for the control connection."""

    def __init__(self) -> None:
        self._high: collections.deque = collections.deque()
        self._low: collections.deque = collections.deque()
        self._event = asyncio.Event()

    def push(self, frame: Frame, high: bool = False) -> None:
        if high:
            self._high.append(frame)
        else:
            self._low.append(frame)
        self._event.set()

    async def get(self) -> Frame:
        while True:
            if self._high:
                return self._high.popleft()
            if self._low:
                return self._low.popleft()
            self._event.clear()
            await self._event.wait()


async def connect_target(host: str, port: int):
    """Open a TCP connection to the target, IPv4 only."""
    try:
        return await asyncio.wait_for(
            asyncio.open_connection(host, port, family=socket.AF_INET),
            timeout=CONNECT_TIMEOUT,
        )
    except asyncio.TimeoutError:
        raise OpenFailure(OPEN_ERR_TIMEOUT)
    except socket.gaierror:
        raise OpenFailure(OPEN_ERR_DNS)
    except ConnectionRefusedError:
        raise OpenFailure(OPEN_ERR_REFUSED)
    except OSError:
        raise OpenFailure(OPEN_ERR_OTHER)


# ---------------------------------------------------------------------------
# Stream
# ---------------------------------------------------------------------------

class Stream:
    """One logical stream = one local TCP socket on each side."""

    def __init__(
        self,
        stream_id: int,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        args: argparse.Namespace,
        initiator: bool,
        streams: Dict[int, "Stream"],
        target: Optional[Tuple[str, int]] = None,
    ) -> None:
        self.id = stream_id
        self.reader = reader
        self.writer = writer
        self.window = args.window_size
        self.max_frame_size = args.max_frame_size
        self.initiator = initiator
        self.target = target
        self.streams = streams

        self.tunnel: Optional["Tunnel"] = None
        self.closed = False
        self.fin_sent = False
        self.fin_received = False
        self.send_done = False
        self.recv_done = False

        self.send_credit = args.window_size
        self.pending_credit = 0
        self.credit_event = asyncio.Event()
        self.ready_event = asyncio.Event()
        self.open_result = asyncio.Event()
        self.open_error: Optional[int] = None

        self.incoming: asyncio.Queue = asyncio.Queue()

        self._open_task: Optional[asyncio.Task] = None
        self._send_task: Optional[asyncio.Task] = None
        self._recv_task: Optional[asyncio.Task] = None

    # -- lifecycle ----------------------------------------------------------

    def start(self) -> None:
        """Start the stream tasks."""
        if self.initiator:
            self._open_task = asyncio.ensure_future(self._open_handshake())
        else:
            self.ready_event.set()
        self._send_task = asyncio.ensure_future(self._local_to_remote())
        self._recv_task = asyncio.ensure_future(self._remote_to_local())

    def attach(self, tunnel: "Tunnel") -> None:
        """Bind the stream to a (new) control connection."""
        self.tunnel = tunnel
        self.send_credit = self.window
        self.credit_event.set()

    def detach(self) -> None:
        """Control connection lost; keep the stream alive for a reconnect."""
        self.tunnel = None
        self.ready_event.clear()
        self.send_credit = self.window
        self.pending_credit = 0
        self.credit_event.set()
        if self._open_task is not None and not self._open_task.done():
            self._open_task.cancel()
        self._open_task = None

    def reopen(self, tunnel: "Tunnel") -> None:
        """Re-send OPEN for this stream on a freshly established tunnel."""
        if self.closed:
            return
        self.attach(tunnel)
        self.ready_event.clear()
        self.open_result.clear()
        self.open_error = None
        if self._open_task is not None and not self._open_task.done():
            self._open_task.cancel()
        self._open_task = asyncio.ensure_future(self._open_handshake())

    # -- outgoing -----------------------------------------------------------

    async def _open_handshake(self) -> None:
        """Send OPEN and wait for the peer's verdict."""
        tunnel = self.tunnel
        if tunnel is None or self.target is None:
            return
        tunnel.send_frame(
            Frame(F_OPEN, self.id, encode_open(self.target[0], self.target[1])),
            high=True,
        )
        try:
            await asyncio.wait_for(self.open_result.wait(), OPEN_TIMEOUT)
        except asyncio.TimeoutError:
            LOG.warning("stream %d: OPEN timed out", self.id)
            self.close("open timeout", send_close=True)
            return
        except asyncio.CancelledError:
            raise

        if self.open_error is not None:
            LOG.info("stream %d: OPEN rejected (reason %d)", self.id, self.open_error)
            self.close("open rejected")
            return

        self.ready_event.set()
        # If the local side already hit EOF while we were (re)opening,
        # the peer still has to learn about it.
        if self.fin_sent and self.tunnel is not None:
            self.tunnel.send_frame(Frame(F_FIN, self.id), high=True)

    async def _local_to_remote(self) -> None:
        """Read from the local socket and ship DATA over the tunnel."""
        try:
            while not self.closed:
                data = await self.reader.read(self.max_frame_size)
                if not data:
                    break
                await self._send_data(data)
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # connection reset, ...
            LOG.debug("stream %d: local read error: %s", self.id, exc)
            self.send_done = True
            self.close("local read error", send_close=True)
            return

        self.send_done = True
        self._send_fin()
        self.maybe_finish()

    async def _send_data(self, data: bytes) -> None:
        view = memoryview(data)
        while view and not self.closed:
            await self.ready_event.wait()
            if self.closed:
                return
            await self._wait_credit()
            if self.closed:
                return
            chunk_len = min(len(view), self.send_credit, self.max_frame_size)
            if chunk_len <= 0:
                continue
            chunk = bytes(view[:chunk_len])
            view = view[chunk_len:]
            self.send_credit -= chunk_len
            if self.send_credit <= 0:
                self.credit_event.clear()
            tunnel = self.tunnel
            if tunnel is None:
                return
            tunnel.send_frame(Frame(F_DATA, self.id, chunk), high=False)

    async def _wait_credit(self) -> None:
        while self.send_credit <= 0 and not self.closed:
            self.credit_event.clear()
            await self.credit_event.wait()

    def _send_fin(self) -> None:
        if self.fin_sent or self.closed:
            return
        self.fin_sent = True
        if self.tunnel is not None:
            self.tunnel.send_frame(Frame(F_FIN, self.id), high=True)

    # -- incoming -----------------------------------------------------------

    async def _remote_to_local(self) -> None:
        """Write DATA coming from the peer into the local socket."""
        try:
            while True:
                if self.closed:
                    return
                if self.pending_credit:
                    try:
                        data = await asyncio.wait_for(
                            self.incoming.get(), CREDIT_FLUSH_INTERVAL
                        )
                    except asyncio.TimeoutError:
                        self._flush_credit()
                        continue
                else:
                    data = await self.incoming.get()

                if data is None:
                    break

                self.writer.write(data)
                await self.writer.drain()
                self.pending_credit += len(data)
                if self.pending_credit >= max(1, self.window // 2):
                    self._flush_credit()
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            LOG.debug("stream %d: local write error: %s", self.id, exc)
            self.recv_done = True
            self.close("local write error", send_close=True)
            return

        # The peer half-closed: propagate the EOF to the local socket.
        try:
            if self.writer.can_write_eof():
                self.writer.write_eof()
        except Exception:
            pass
        if not self.fin_received:
            self._flush_credit()
        self.recv_done = True
        self.maybe_finish()

    def _flush_credit(self) -> None:
        if self.pending_credit <= 0 or self.closed:
            return
        tunnel = self.tunnel
        if tunnel is None:
            return
        amount = self.pending_credit
        self.pending_credit = 0
        tunnel.send_frame(
            Frame(F_WINDOW_UPDATE, self.id, struct.pack("!I", amount)), high=True
        )

    # -- callbacks from the tunnel -----------------------------------------

    def on_open_ok(self) -> None:
        self.open_error = None
        self.open_result.set()

    def on_open_err(self, reason: int) -> None:
        self.open_error = reason
        self.open_result.set()

    def on_data(self, payload: bytes) -> None:
        if self.closed:
            return
        self.incoming.put_nowait(payload)

    def on_window_update(self, credit: int) -> None:
        if self.closed:
            return
        self.send_credit += credit
        if self.send_credit > 0:
            self.credit_event.set()

    def on_fin(self) -> None:
        if self.fin_received or self.closed:
            return
        self.fin_received = True
        # Sentinel: all previously queued DATA is written before the EOF.
        self.incoming.put_nowait(None)

    # -- closing ------------------------------------------------------------

    def maybe_finish(self) -> None:
        if self.closed:
            return
        if self.fin_sent and self.fin_received and self.send_done and self.recv_done:
            LOG.debug("stream %d: closed cleanly", self.id)
            self._teardown()

    def close(self, reason: str = "", send_close: bool = False) -> None:
        if self.closed:
            return
        LOG.debug("stream %d: closing (%s)", self.id, reason or "no reason")
        if send_close and self.tunnel is not None:
            self.tunnel.send_frame(Frame(F_CLOSE, self.id), high=True)
        self._teardown()

    def _teardown(self) -> None:
        if self.closed:
            return
        self.closed = True
        self.ready_event.set()
        self.credit_event.set()

        current = asyncio.current_task()
        for task in (self._open_task, self._send_task, self._recv_task):
            if task is not None and task is not current and not task.done():
                task.cancel()

        try:
            self.writer.close()
        except Exception:
            pass

        self.streams.pop(self.id, None)


# ---------------------------------------------------------------------------
# Tunnel (control connection)
# ---------------------------------------------------------------------------

class Tunnel:
    """Owns the control connection and the stream table."""

    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        is_client: bool,
        args: argparse.Namespace,
        streams: Optional[Dict[int, Stream]] = None,
        allow: Optional[AllowPolicy] = None,
        next_id: Optional[int] = None,
    ) -> None:
        self.reader = reader
        self.writer = writer
        self.is_client = is_client
        self.args = args
        self.streams: Dict[int, Stream] = streams if streams is not None else {}
        self.allow = allow or AllowPolicy(args.allow, args.allow_all)
        self.max_frame_size = args.max_frame_size

        self.next_id = next_id if next_id is not None else (1 if is_client else 2)
        self.pw = PriorityWriter()
        self.last_pong = time.monotonic()

        self._closed = asyncio.Event()
        self._stopped = False
        self._tasks: List[asyncio.Task] = []

    # -- id allocation ------------------------------------------------------

    def alloc_id(self) -> int:
        stream_id = self.next_id
        self.next_id = (self.next_id + 2) & 0xFFFFFFFF
        if self.next_id == 0:
            self.next_id = 1 if self.is_client else 2
        return stream_id

    # -- sending ------------------------------------------------------------

    def send_frame(self, frame: Frame, high: bool = False) -> bool:
        if self._stopped:
            return False
        self.pw.push(frame, high=high)
        return True

    def remove_stream(self, stream_id: int) -> None:
        self.streams.pop(stream_id, None)

    # -- main loop ----------------------------------------------------------

    async def run(self) -> None:
        """Serve the control connection until it dies."""
        self._tasks = [
            asyncio.ensure_future(self._writer_loop()),
            asyncio.ensure_future(self._reader_loop()),
            asyncio.ensure_future(self._keepalive_loop()),
        ]
        try:
            await self._closed.wait()
        finally:
            self._stopped = True
            for task in self._tasks:
                task.cancel()
            await asyncio.gather(*self._tasks, return_exceptions=True)
            try:
                self.writer.close()
            except Exception:
                pass

    def _fail(self) -> None:
        self._closed.set()

    async def _writer_loop(self) -> None:
        try:
            while True:
                frame = await self.pw.get()
                self.writer.write(encode_frame(frame))
                await self.writer.drain()
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            LOG.info("control writer stopped: %s", exc)
            self._fail()

    async def _reader_loop(self) -> None:
        try:
            while True:
                frame = await read_frame(self.reader, self.max_frame_size)
                await self._handle_frame(frame)
        except asyncio.CancelledError:
            raise
        except asyncio.IncompleteReadError:
            LOG.info("control connection closed by peer")
        except ProtocolError as exc:
            LOG.error("protocol error: %s", exc)
        except Exception as exc:
            LOG.info("control connection error: %s", exc)
        finally:
            self._fail()

    async def _keepalive_loop(self) -> None:
        interval = float(self.args.keepalive)
        if interval <= 0:
            return
        try:
            while True:
                await asyncio.sleep(interval)
                if time.monotonic() - self.last_pong > 3 * interval:
                    LOG.warning("keepalive timeout, dropping control connection")
                    self._fail()
                    return
                self.send_frame(Frame(F_PING, 0), high=True)
        except asyncio.CancelledError:
            raise

    # -- frame dispatch -----------------------------------------------------

    async def _handle_frame(self, frame: Frame) -> None:
        if frame.stream_id == 0:
            if frame.type not in CONTROL_FRAME_TYPES:
                raise ProtocolError(f"frame 0x{frame.type:02x} on control stream")
            self._handle_control(frame)
            return

        if frame.type not in STREAM_FRAME_TYPES:
            raise ProtocolError(f"unknown frame type 0x{frame.type:02x}")

        if frame.type == F_OPEN:
            await self._handle_open(frame)
            return

        stream = self.streams.get(frame.stream_id)
        if stream is None:
            LOG.debug(
                "ignoring frame 0x%02x for unknown stream %d",
                frame.type,
                frame.stream_id,
            )
            return

        if frame.type == F_OPEN_OK:
            stream.on_open_ok()
        elif frame.type == F_OPEN_ERR:
            reason = frame.payload[0] if frame.payload else OPEN_ERR_OTHER
            stream.on_open_err(reason)
        elif frame.type == F_DATA:
            stream.on_data(frame.payload)
        elif frame.type == F_WINDOW_UPDATE:
            if len(frame.payload) != 4:
                raise ProtocolError("malformed WINDOW_UPDATE payload")
            stream.on_window_update(struct.unpack("!I", frame.payload)[0])
        elif frame.type == F_FIN:
            stream.on_fin()
        elif frame.type == F_CLOSE:
            stream.close("peer sent CLOSE")

    def _handle_control(self, frame: Frame) -> None:
        if frame.type == F_PING:
            self.send_frame(Frame(F_PONG, 0), high=True)
        elif frame.type == F_PONG:
            self.last_pong = time.monotonic()
        else:
            raise ProtocolError(
                f"unexpected control frame 0x{frame.type:02x} after handshake"
            )

    async def _handle_open(self, frame: Frame) -> None:
        stream_id = frame.stream_id
        if stream_id in self.streams:
            raise ProtocolError(f"OPEN for already active stream {stream_id}")

        host, port = decode_open(frame.payload)

        if not self.allow.check(host, port):
            LOG.info("OPEN %s:%d rejected by policy", host, port)
            self.send_frame(
                Frame(F_OPEN_ERR, stream_id, bytes([OPEN_ERR_FORBIDDEN])), high=True
            )
            return

        try:
            reader, writer = await connect_target(host, port)
        except OpenFailure as exc:
            LOG.info("OPEN %s:%d failed (reason %d)", host, port, exc.reason)
            self.send_frame(
                Frame(F_OPEN_ERR, stream_id, bytes([exc.reason])), high=True
            )
            return

        stream = Stream(
            stream_id,
            reader,
            writer,
            self.args,
            initiator=False,
            streams=self.streams,
        )
        stream.attach(self)
        self.streams[stream_id] = stream
        stream.start()
        LOG.info("stream %d: connected to %s:%d", stream_id, host, port)
        self.send_frame(Frame(F_OPEN_OK, stream_id), high=True)


# ---------------------------------------------------------------------------
# Handshake
# ---------------------------------------------------------------------------

async def client_handshake(tunnel: Tunnel, token: str) -> None:
    """Perform the client side of the HELLO exchange."""
    token_bytes = token.encode("utf-8")
    payload = struct.pack("!HH", PROTOCOL_VERSION, len(token_bytes)) + token_bytes
    tunnel.writer.write(encode_frame(Frame(F_HELLO, 0, payload)))
    await tunnel.writer.drain()

    try:
        frame = await asyncio.wait_for(
            read_frame(tunnel.reader, tunnel.max_frame_size), HANDSHAKE_TIMEOUT
        )
    except asyncio.TimeoutError:
        raise HandshakeError("timeout waiting for HELLO_OK")

    if frame.stream_id != 0:
        raise HandshakeError("unexpected stream id in handshake reply")
    if frame.type == F_HELLO_OK:
        return
    if frame.type == F_HELLO_ERR:
        reason = frame.payload[0] if frame.payload else HELLO_ERR_OTHER
        raise HandshakeError(f"server rejected handshake (reason {reason})")
    raise HandshakeError(f"unexpected frame 0x{frame.type:02x} during handshake")


async def server_handshake(tunnel: Tunnel, token: str) -> None:
    """Perform the server side of the HELLO exchange."""
    try:
        frame = await asyncio.wait_for(
            read_frame(tunnel.reader, tunnel.max_frame_size), HANDSHAKE_TIMEOUT
        )
    except asyncio.TimeoutError:
        raise HandshakeError("timeout waiting for HELLO")

    if frame.type != F_HELLO or frame.stream_id != 0:
        raise HandshakeError("expected HELLO frame")
    if len(frame.payload) < 4:
        raise HandshakeError("malformed HELLO payload")

    version, token_len = struct.unpack_from("!HH", frame.payload, 0)
    if len(frame.payload) != 4 + token_len:
        raise HandshakeError("malformed HELLO payload")

    if version != PROTOCOL_VERSION:
        tunnel.writer.write(
            encode_frame(Frame(F_HELLO_ERR, 0, bytes([HELLO_ERR_VERSION])))
        )
        await tunnel.writer.drain()
        raise HandshakeError(f"protocol version mismatch ({version})")

    try:
        received = frame.payload[4:4 + token_len].decode("utf-8")
    except UnicodeDecodeError:
        received = ""

    if not hmac.compare_digest(received, token):
        tunnel.writer.write(
            encode_frame(Frame(F_HELLO_ERR, 0, bytes([HELLO_ERR_TOKEN])))
        )
        await tunnel.writer.drain()
        raise HandshakeError("invalid token")

    tunnel.writer.write(encode_frame(Frame(F_HELLO_OK, 0)))
    await tunnel.writer.drain()


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------

def spawn_outgoing_stream(
    tunnel: Tunnel,
    args: argparse.Namespace,
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    target: Tuple[str, int],
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
    return stream


class Client:
    """Client side: owns the persistent stream table and local listeners."""

    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.allow = AllowPolicy(args.allow, args.allow_all)
        self.streams: Dict[int, Stream] = {}
        self.next_id = 1
        self.tunnel: Optional[Tunnel] = None
        self.servers: List[asyncio.AbstractServer] = []

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
        tunnel = self.tunnel
        if tunnel is None:
            LOG.warning("no active control connection, rejecting local connection")
            writer.close()
            return
        try:
            spawn_outgoing_stream(
                tunnel, self.args, reader, writer, (target_host, target_port)
            )
        except Exception as exc:
            LOG.warning("could not create stream: %s", exc)
            writer.close()

    # -- sessions -----------------------------------------------------------

    async def session(self) -> int:
        """Run one control-connection session.  Returns 0 only on clean stop."""
        host, port = parse_host_port(self.args.connect)
        try:
            reader, writer = await asyncio.open_connection(host, port)
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


# ---------------------------------------------------------------------------
# Server
# ---------------------------------------------------------------------------

class Server:
    """Server side: accepts control connections and serves local forwards."""

    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.allow = AllowPolicy(args.allow, args.allow_all)
        self.tunnel: Optional[Tunnel] = None
        self.servers: List[asyncio.AbstractServer] = []

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
        tunnel = self.tunnel
        if tunnel is None:
            LOG.warning("no active control connection, rejecting local connection")
            writer.close()
            return
        try:
            spawn_outgoing_stream(
                tunnel, self.args, reader, writer, (target_host, target_port)
            )
        except Exception as exc:
            LOG.warning("could not create stream: %s", exc)
            writer.close()

    async def handle_control(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        peer = writer.get_extra_info("peername")
        LOG.info("incoming control connection from %s", peer)

        tunnel = Tunnel(
            reader,
            writer,
            is_client=False,
            args=self.args,
            allow=self.allow,
        )

        try:
            await server_handshake(tunnel, self.args.token)
        except Exception as exc:
            LOG.warning("handshake with %s failed: %s", peer, exc)
            writer.close()
            return

        LOG.info("control connection established with %s", peer)
        self.tunnel = tunnel

        try:
            await tunnel.run()
        finally:
            for stream in list(tunnel.streams.values()):
                stream.close("control connection lost")
            tunnel.streams.clear()
            if self.tunnel is tunnel:
                self.tunnel = None
            LOG.info("control connection with %s closed", peer)


async def run_server(args: argparse.Namespace) -> int:
    server = Server(args)
    await server.start_listeners()

    host, port = parse_host_port(args.listen)
    control = await asyncio.start_server(server.handle_control, host, port)
    LOG.info("listening on %s:%d", host, port)

    async with control:
        await control.serve_forever()
    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tunnel.py",
        description="TCP port forwarding tunnel over a single TCP connection.",
    )
    sub = parser.add_subparsers(dest="mode", required=True)

    def add_common(sp: argparse.ArgumentParser) -> None:
        sp.add_argument("--token", required=True, help="shared secret (required)")
        sp.add_argument(
            "--forward",
            action="append",
            default=[],
            metavar="BIND_HOST:BIND_PORT:TARGET_HOST:TARGET_PORT",
            help="local forward (repeatable)",
        )
        sp.add_argument(
            "--allow",
            action="append",
            default=[],
            metavar="HOST:PORT",
            help="allow a specific target (repeatable)",
        )
        sp.add_argument(
            "--allow-all", action="store_true", help="allow any target"
        )
        sp.add_argument(
            "--window-size",
            type=int,
            default=262144,
            metavar="BYTES",
            help="flow-control window size (default 262144)",
        )
        sp.add_argument(
            "--max-frame-size",
            type=int,
            default=65536,
            metavar="BYTES",
            help="maximum frame payload (default 65536)",
        )
        sp.add_argument(
            "--keepalive",
            type=float,
            default=30.0,
            metavar="SECONDS",
            help="PING period (default 30)",
        )
        sp.add_argument(
            "--log-level", default="info", help="logging level (default info)"
        )

    client = sub.add_parser("client", help="connect to the peer")
    add_common(client)
    client.add_argument(
        "--connect", required=True, metavar="HOST:PORT", help="server address"
    )
    client.add_argument(
        "--reconnect",
        type=float,
        default=None,
        metavar="SECONDS",
        help="reconnect every N seconds",
    )
    client.add_argument(
        "--keep-streams",
        action="store_true",
        help="preserve active streams between reconnects (requires --reconnect)",
    )

    server = sub.add_parser("server", help="accept a peer connection")
    add_common(server)
    server.add_argument(
        "--listen", required=True, metavar="HOST:PORT", help="listening address"
    )

    return parser


def setup_logging(level: str) -> None:
    numeric = getattr(logging, str(level).upper(), None)
    if not isinstance(numeric, int):
        numeric = logging.INFO
    logging.basicConfig(
        level=numeric,
        format="%(asctime)s %(levelname)-7s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    setup_logging(args.log_level)

    # Validation -----------------------------------------------------------
    if args.allow and args.allow_all:
        parser.error("--allow and --allow-all are mutually exclusive")
    if args.window_size <= 0:
        parser.error("--window-size must be positive")
    if args.max_frame_size <= 0:
        parser.error("--max-frame-size must be positive")
    if args.keepalive < 0:
        parser.error("--keepalive must not be negative")

    if args.mode == "client":
        if args.keep_streams and args.reconnect is None:
            parser.error("--keep-streams requires --reconnect")

    # Parse configuration strings early so that errors surface immediately.
    try:
        for spec in args.allow:
            parse_host_port(spec)
        for spec in args.forward:
            parse_forward(spec)
        if args.mode == "client":
            parse_host_port(args.connect)
        else:
            parse_host_port(args.listen)
    except ValueError as exc:
        parser.error(str(exc))

    try:
        if args.mode == "client":
            return asyncio.run(run_client(args))
        return asyncio.run(run_server(args))
    except KeyboardInterrupt:
        LOG.info("interrupted")
        return 0


if __name__ == "__main__":
    sys.exit(main())
