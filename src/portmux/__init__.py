#!/usr/bin/env python3
"""Single-file TCP port forwarding tunnel over a custom binary protocol.

This tool is similar to SSH local/remote port forwarding. Two instances of the
script run on the two endpoints:

  * server – listens for the control connection on ``--listen``;
  * client – connects to the server on ``--connect`` and forwards local ports.

After the initial handshake both endpoints behave symmetrically. Every local TCP
connection accepted on a forwarded bind port becomes a *stream* multiplexed over
the single control connection; the peer turns it into a TCP connection to the
target host:port given in the OPEN request.

The wire protocol is entirely binary. Only the Python standard library is used.
Only IPv4 addresses and bare hostnames are supported (no IPv6 anywhere).

Frame format (fixed 10-byte header + variable payload):

    type(1) flags(1) stream_id(4 BE) length(4 BE) payload[length]

Control frames (stream_id == 0):
    0x01 HELLO       version(2 BE) token_len(2 BE) token(UTF-8)
    0x02 HELLO_OK    (empty)
    0x03 HELLO_ERR   reason(1): 1 version / 2 token / 3 other
    0x30 PING
    0x31 PONG

Stream frames (stream_id != 0):
    0x10 OPEN          host_len(2 BE) host(UTF-8) port(2 BE)
    0x11 OPEN_OK       (empty)
    0x12 OPEN_ERR      reason(1): 1 refused / 2 timeout / 3 dns / 4 forbidden / 5 other
    0x20 DATA          arbitrary bytes
    0x21 WINDOW_UPDATE credit(4 BE)
    0x22 FIN           (empty)
    0x23 CLOSE         (empty)
"""

from __future__ import annotations

import argparse
import asyncio
import errno
import logging
import signal
import socket
import struct
import sys
from dataclasses import dataclass, field

log = logging.getLogger("tunnel")

# ---------------------------------------------------------------------------
# Protocol constants
# ---------------------------------------------------------------------------

PROTOCOL_VERSION = 1
HELLO_TIMEOUT = 10.0

# Frame types
HELLO = 0x01
HELLO_OK = 0x02
HELLO_ERR = 0x03
OPEN = 0x10
OPEN_OK = 0x11
OPEN_ERR = 0x12
DATA = 0x20
WINDOW_UPDATE = 0x21
FIN = 0x22
CLOSE = 0x23
PING = 0x30
PONG = 0x31

# OPEN_ERR reasons
RC_REFUSED = 0x01
RC_TIMEOUT = 0x02
RC_DNS = 0x03
RC_FORBIDDEN = 0x04
RC_OTHER = 0x05

# HELLO_ERR reasons
HF_VERSION = 0x01
HF_TOKEN = 0x02
HF_OTHER = 0x03

_STREAM_CTRL = {OPEN_OK, OPEN_ERR, WINDOW_UPDATE, FIN, CLOSE}

HEADER_STRUCT = struct.Struct("!BBII")
HEADER_LEN = HEADER_STRUCT.size  # 10
READ_CHUNK = 65536


class ProtocolError(Exception):
    """A protocol / frame-format violation. Closes the control connection."""


# ---------------------------------------------------------------------------
# Address helpers
# ---------------------------------------------------------------------------


def host_ok(host: str) -> bool:
    """Return True if *host* is an IPv4 address or a bare hostname (no IPv6)."""
    host = host.strip()
    if not host:
        return False
    if ":" in host:              # IPv6 literal or bracketed address
        return False
    if "[" in host or "]" in host:
        return False
    if "/" in host or any(ch.isspace() for ch in host):
        return False
    return True


def _port(text: str, what: str) -> int:
    try:
        p = int(text)
    except ValueError:
        raise ValueError(f"{what}: invalid port {text!r}")
    if not (0 <= p <= 65535):
        raise ValueError(f"{what}: port {p} out of range")
    return p


def parse_host_port(text: str, what: str) -> tuple[str, int]:
    parts = text.split(":")
    if len(parts) != 2:
        raise ValueError(f"{what}: expected HOST:PORT, got {text!r}")
    host, port_s = parts
    if not host_ok(host):
        raise ValueError(f"{what}: invalid host {host!r} (IPv6 not supported)")
    return host, _port(port_s, what)


def parse_forward(text: str) -> tuple[tuple[str, int], tuple[str, int]]:
    parts = text.split(":")
    if len(parts) != 4:
        raise ValueError(
            f"--forward: expected BIND_HOST:BIND_PORT:TARGET_HOST:TARGET_PORT, got {text!r}"
        )
    bh, bp, th, tp = parts
    if not host_ok(bh):
        raise ValueError(f"--forward: invalid bind host {bh!r}")
    if not host_ok(th):
        raise ValueError(f"--forward: invalid target host {th!r}")
    return (bh, _port(bp, "--forward")), (th, _port(tp, "--forward"))


# ---------------------------------------------------------------------------
# Framing
# ---------------------------------------------------------------------------


@dataclass
class Frame:
    type: int
    flags: int
    stream_id: int
    payload: bytes

    def to_bytes(self) -> bytes:
        return HEADER_STRUCT.pack(self.type, self.flags, self.stream_id,
                                  len(self.payload)) + self.payload


class FrameDecoder:
    """Incremental decoder producing complete frames from a byte stream.

    If a header announces a length larger than ``max_frame_size`` a
    ProtocolError is raised (immediate control connection closure).
    """

    def __init__(self, max_frame_size: int):
        self._max = max_frame_size
        self._buf = bytearray()
        self._want = HEADER_LEN

    def feed(self, data: bytes) -> list[Frame]:
        self._buf.extend(data)
        frames: list[Frame] = []
        while True:
            if self._want == HEADER_LEN:
                if len(self._buf) < HEADER_LEN:
                    break
                _, _, _, flen = HEADER_STRUCT.unpack_from(self._buf, 0)
                if flen > self._max:
                    raise ProtocolError(
                        f"frame length {flen} exceeds max frame size {self._max}"
                    )
                self._want = HEADER_LEN + flen
            if len(self._buf) < self._want:
                break
            ftype, fflags, fstream, flen = HEADER_STRUCT.unpack_from(self._buf, 0)
            payload = bytes(self._buf[HEADER_LEN:self._want])
            frames.append(Frame(ftype, fflags, fstream, payload))
            del self._buf[:self._want]
            self._want = HEADER_LEN
        return frames


# ---------------------------------------------------------------------------
# Allow policy
# ---------------------------------------------------------------------------


class AllowPolicy:
    def __init__(self, allow_all: bool, allow_list: list[tuple[str, int]]):
        self.allow_all = allow_all
        self.allow_list = list(allow_list)

    def allowed(self, host: str, port: int) -> bool:
        if self.allow_all:
            return True
        return (host, port) in self.allow_list


# ---------------------------------------------------------------------------
# Stream
# ---------------------------------------------------------------------------


@dataclass
class Stream:
    """State for a single logical stream within one control connection.

    ``reader``/``writer`` are the *local* socket endpoints (the accepted local
    connection on the initiator, or the dialed target connection on the peer).
    """

    stream_id: int
    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter
    window_size: int
    send_credit: int          # remaining outbound credit (bytes left before pause)
    peer_is_initiator: bool = False

    pending_ack: int = 0      # inbound bytes since last WINDOW_UPDATE
    fin_sent: bool = False
    fin_received: bool = False
    closed: bool = False

    data_q: asyncio.Queue = field(default_factory=asyncio.Queue)
    credit_event: asyncio.Event = field(default_factory=asyncio.Event)

    send_task: asyncio.Task|None = None
    recv_task: asyncio.Task|None = None

    # Target for the OPEN (used by --keep-streams to re-OPEN after a reconnect).
    target: tuple[str, int]|None = None

    def __post_init__(self):
        self.credit_event.set()


# ---------------------------------------------------------------------------
# Config bundle
# ---------------------------------------------------------------------------


@dataclass
class Config:
    token: str
    forwards: list
    window_size: int
    max_frame_size: int
    keepalive: float


# ---------------------------------------------------------------------------
# Tunnel: one control connection
# ---------------------------------------------------------------------------


class Tunnel:
    """Manages one control connection, its stream table and its two write queues.

    A single reader loop consumes every frame. DATA frames are routed to the
    owning stream's ``data_q``; a per-stream receive task drains that queue and
    writes to the local socket. Per-stream send tasks read from the local socket
    and produce DATA frames.

    Outbound frames go to one of two queues: *high* for control frames and
    *normal* for DATA, so control frames always overtake bulk data.
    """

    def __init__(self, reader, writer, *, is_client, cfg: Config, allow_policy):
        self.reader = reader
        self.writer = writer
        self.is_client = is_client
        self.cfg = cfg
        self.allow_policy = allow_policy

        # Client uses odd stream ids, server even ids.
        self.next_stream_id = 1 if is_client else 2

        self.streams: dict[int, Stream] = {}
        self.decoder = FrameDecoder(cfg.max_frame_size)

        self.high_queue: asyncio.Queue[Frame] = asyncio.Queue()
        self.normal_queue: asyncio.Queue[Frame] = asyncio.Queue()

        self.connected = False
        self._pong_event: asyncio.Event|None = None
        self._tasks: list[asyncio.Task] = []
        self._close_tasks: list[asyncio.Task] = []
        self._writer_task: asyncio.Task|None = None
        self._torn = False

    # -- outbound -----------------------------------------------------------

    def send_control(self, f: Frame) -> None:
        if self.connected:
            self.high_queue.put_nowait(f)

    def send_data(self, f: Frame) -> None:
        if self.connected:
            self.normal_queue.put_nowait(f)

    def send_ordered(self, f: Frame) -> None:
        """Send a control frame that must follow that stream's DATA.

        FIN (half-close) shares a direction with DATA and must not overtake the
        stream's own queued DATA, otherwise the peer would treat the FIN as a
        boundary and drop the trailing payload. Out-of-band control frames
        (WINDOW_UPDATE, PING, OPEN_OK, ...) still use send_control() so they
        keep priority over other streams' data.
        """
        if self.connected:
            self.normal_queue.put_nowait(f)

    # -- handshake ----------------------------------------------------------

    async def _read_exact(self, n: int) -> bytes:
        return await self.reader.readexactly(n)

    async def client_handshake(self) -> bool:
        """Client side: send HELLO, wait for HELLO_OK / HELLO_ERR."""
        t = self.cfg.token.encode("utf-8")
        payload = struct.pack("!HH", PROTOCOL_VERSION, len(t)) + t
        try:
            self.writer.write(encode_frame(Frame(HELLO, 0, 0, payload)))
            await self.writer.drain()
            header = await self._read_exact(HEADER_LEN)
            ftype, _flags, fstream, flen = HEADER_STRUCT.unpack(header)
            if fstream != 0 or flen > self.cfg.max_frame_size:
                raise ProtocolError("bad handshake reply header")
            body = await self._read_exact(flen)
            if ftype == HELLO_OK:
                log.info("handshake OK")
                return True
            if ftype == HELLO_ERR:
                reason = body[0] if body else HF_OTHER
                log.info("server rejected handshake (reason 0x%02x)", reason)
                return False
            raise ProtocolError("unexpected reply to HELLO")
        except (asyncio.IncompleteReadError, EOFError, ConnectionError, OSError) as exc:
            log.error("handshake I/O error: %s", exc)
            return False

    async def server_handshake(self) -> bool:
        """Server side: wait for and validate the client's HELLO."""
        log.info("waiting for HELLO from client")
        try:
            header = await asyncio.wait_for(self._read_exact(HEADER_LEN), HELLO_TIMEOUT)
        except (TimeoutError, asyncio.IncompleteReadError, EOFError,
                ConnectionError, OSError):
            log.info("handshake failed (no HELLO within timeout)")
            return False
        ftype, _flags, fstream, flen = HEADER_STRUCT.unpack(header)
        if fstream != 0 or flen > self.cfg.max_frame_size or ftype != HELLO:
            self._send_hello_err(HF_OTHER)
            return False
        try:
            body = await self._read_exact(flen)
        except (asyncio.IncompleteReadError, EOFError, ConnectionError):
            return False
        if len(body) < 4:
            self._send_hello_err(HF_OTHER)
            return False
        version = struct.unpack_from("!H", body, 0)[0]
        token_len = struct.unpack_from("!H", body, 2)[0]
        if 4 + token_len > len(body):
            self._send_hello_err(HF_OTHER)
            return False
        token = body[4:4 + token_len].decode("utf-8", "replace")
        if version != PROTOCOL_VERSION:
            log.info("handshake rejected: incompatible version %d", version)
            self._send_hello_err(HF_VERSION)
            return False
        if token != self.cfg.token:
            log.info("handshake rejected: invalid token")
            self._send_hello_err(HF_TOKEN)
            return False
        # The connection is not yet "established", so write HELLO_OK directly
        # rather than via the (not-yet-running) writer pump's control queue.
        try:
            self.writer.write(encode_frame(Frame(HELLO_OK, 0, 0, b"")))
            await self.writer.drain()
        except (ConnectionError, OSError):
            return False
        log.info("handshake OK")
        return True

    def _send_hello_err(self, reason: int) -> None:
        try:
            self.writer.write(encode_frame(Frame(HELLO_ERR, 0, 0, bytes([reason]))))
        except (ConnectionError, OSError):
            pass

    # -- main read loop -----------------------------------------------------

    async def read_frames_until_eof(self) -> None:
        """Consume frames from the reader until EOF or a protocol error."""
        try:
            while True:
                chunk = await self.reader.read(READ_CHUNK)
                if not chunk:
                    break
                for f in self.decoder.feed(chunk):
                    await self._handle_frame(f)
        except (asyncio.IncompleteReadError, EOFError, ConnectionError, OSError) as exc:
            log.debug("read loop ended: %s", exc)
        except ProtocolError as exc:
            log.error("protocol error: %s", exc)
        finally:
            self.connected = False

    def run_context(self) -> None:
        """Start the writer pump and keepalive for an established connection."""
        self.connected = True
        self._writer_task = asyncio.create_task(self._writer_pump())
        if self.cfg.keepalive and self.cfg.keepalive > 0:
            self._tasks.append(asyncio.create_task(self._keepalive_loop()))

    # -- frame dispatch -----------------------------------------------------

    async def _handle_frame(self, f: Frame) -> None:
        if f.stream_id == 0:
            await self._handle_control(f)
        else:
            await self._handle_stream(f)

    async def _handle_control(self, f: Frame) -> None:
        ft = f.type
        if ft == PING:
            self.send_control(Frame(PONG, 0, 0, b""))
        elif ft == PONG:
            ev = self._pong_event
            if ev is not None:
                ev.set()
        elif ft in (HELLO, HELLO_OK, HELLO_ERR):
            raise ProtocolError(f"unexpected handshake frame 0x{ft:02x}")
        else:
            raise ProtocolError(f"unknown control frame type 0x{ft:02x}")

    async def _handle_stream(self, f: Frame) -> None:
        sid = f.stream_id
        if f.type == OPEN:
            if sid in self.streams:
                raise ProtocolError(f"OPEN for already-active stream {sid}")
            await self._on_open(f)
            return

        stream = self.streams.get(sid)
        if stream is None:
            # DATA for an unknown stream is ignored (race during closure).
            if f.type in (_STREAM_CTRL | {DATA}):
                log.debug("ignoring 0x%02x for unknown stream %d", f.type, sid)
            else:
                raise ProtocolError(f"unknown stream frame type 0x{f.type:02x}")
            return

        ft = f.type
        if ft == OPEN_OK:
            await self._on_open_ok(stream)
        elif ft == OPEN_ERR:
            reason = f.payload[0] if f.payload else RC_OTHER
            await self._on_open_err(stream, reason)
        elif ft == WINDOW_UPDATE:
            if len(f.payload) != 4:
                raise ProtocolError("WINDOW_UPDATE payload must be 4 bytes")
            credit = struct.unpack("!I", f.payload)[0]
            if credit == 0:
                raise ProtocolError("WINDOW_UPDATE with zero credit")
            stream.send_credit += credit
            stream.credit_event.set()
        elif ft == DATA:
            stream.data_q.put_nowait(f)
        elif ft == FIN:
            if stream.fin_received:
                raise ProtocolError(f"duplicate FIN on stream {sid}")
            stream.fin_received = True
            # Queue the FIN so the receive-relay drains all preceding DATA and
            # then half-closes the local socket (write_eof) in the correct order.
            stream.data_q.put_nowait(f)
            self._try_finish(stream)
        elif ft == CLOSE:
            await self.close_stream(stream, "remote CLOSE")
        else:
            raise ProtocolError(f"unknown stream frame type 0x{ft:02x}")

    # -- OPEN handling ------------------------------------------------------

    async def _dial(self, host, port) -> tuple:
        try:
            r, w = await asyncio.open_connection(host, port)
            return None, r, w
        except (TimeoutError):
            return RC_TIMEOUT, None, None
        except (socket.gaierror, UnicodeError, ValueError) as exc:
            log.warning("DNS failure for %s:%d: %s", host, port, exc)
            return RC_DNS, None, None
        except OSError as exc:
            if getattr(exc, "errno", None) in (errno.ECONNREFUSED, errno.ECONNRESET):
                return RC_REFUSED, None, None
            log.warning("cannot connect to %s:%d: %s", host, port, exc)
            return RC_OTHER, None, None

    async def _on_open(self, f: Frame) -> None:
        payload = f.payload
        if len(payload) < 4:
            raise ProtocolError("OPEN payload too short")
        host_len = struct.unpack_from("!H", payload, 0)[0]
        if 2 + host_len + 2 > len(payload):
            raise ProtocolError("OPEN payload truncated")
        host = payload[2:2 + host_len].decode("utf-8", "replace")
        port = struct.unpack_from("!H", payload, 2 + host_len)[0]
        sid = f.stream_id

        # Allow policy is checked BEFORE any connection attempt.
        if not self.allow_policy.allowed(host, port):
            log.info("OPEN for %s:%d forbidden by allow policy", host, port)
            self.send_control(Frame(OPEN_ERR, 0, sid, bytes([RC_FORBIDDEN])))
            return

        reason, peer_r, peer_w = await self._dial(host, port)
        if peer_r is None:
            self.send_control(Frame(OPEN_ERR, 0, sid, bytes([reason])))
            return

        stream = Stream(sid, peer_r, peer_w, self.cfg.window_size,
                        self.cfg.window_size, target=(host, port))
        self.streams[sid] = stream
        self.send_control(Frame(OPEN_OK, 0, sid, b""))
        self._start_relay(stream)
        log.info("stream %d open -> %s:%d", sid, host, port)

    async def _on_open_ok(self, stream: Stream) -> None:
        # If this is a re-OPEN of a preserved stream, swap in the preserved
        # local sockets (which our reader/writer fields may already reference).
        log.debug("stream %d accepted by peer", stream.stream_id)
        self._start_relay(stream)

    async def _on_open_err(self, stream: Stream, reason: int) -> None:
        log.info("stream %d open rejected (reason 0x%02x)", stream.stream_id, reason)
        await self.close_stream(stream, "OPEN rejected by peer")

    def _start_relay(self, stream: Stream) -> None:
        if stream.send_task is None or stream.send_task.done():
            stream.send_task = asyncio.create_task(self._relay_to_peer(stream))
        if stream.recv_task is None or stream.recv_task.done():
            stream.recv_task = asyncio.create_task(self._relay_from_peer(stream))

    # -- relay ----------------------------------------------------------------

    async def _relay_to_peer(self, stream: Stream) -> None:
        """Local socket -> DATA frames over the control connection."""
        sid = stream.stream_id
        try:
            while not stream.closed:
                if stream.send_credit <= 0:
                    # No credit left: block until a WINDOW_UPDATE replenishes it.
                    # Clear the event and re-check to avoid a missed-wakeup race
                    # (the WINDOW_UPDATE handler sets the event after adding
                    # credit).
                    stream.credit_event.clear()
                    if stream.send_credit <= 0:
                        await stream.credit_event.wait()
                    if stream.closed:
                        return
                    continue
                n = min(self.cfg.max_frame_size, stream.send_credit)
                chunk = await stream.reader.read(n)
                if chunk == b"":
                    # EOF on the local socket -> half-close this direction.
                    # Send FIN on the ordered (data) queue so it cannot overtake
                    # this stream's own DATA frames on the wire.
                    if not stream.fin_sent:
                        stream.fin_sent = True
                        self.send_ordered(Frame(FIN, 0, sid, b""))
                    self._try_finish(stream)
                    return
                stream.send_credit -= len(chunk)
                self.send_data(Frame(DATA, 0, sid, chunk))
        except (asyncio.CancelledError, ConnectionError, OSError):
            pass
        finally:
            if not stream.closed and not stream.fin_sent:
                # Local socket died unexpectedly -> request full close. Run the
                # teardown as a separate task: ``close_stream`` cancels this
                # stream's relay tasks, so awaiting it here from inside
                # ``_relay_to_peer`` (itself a relay task) would self-cancel and
                # drop the un-awaited half of the teardown.
                self.send_control(Frame(CLOSE, 0, sid, b""))
                self._start_close(stream, "local socket read error")

    async def _relay_from_peer(self, stream: Stream) -> None:
        """Peer data -> local socket, with flow-control acks and finalization."""
        sid = stream.stream_id
        try:
            while not stream.closed:
                f = await stream.data_q.get()
                if stream.closed:
                    break
                if f.type == DATA:
                    stream.writer.write(f.payload)
                    await stream.writer.drain()
                    stream.pending_ack += len(f.payload)
                    if stream.pending_ack >= stream.window_size // 2:
                        self.send_control(Frame(
                            WINDOW_UPDATE, 0, sid,
                            struct.pack("!I", stream.pending_ack)))
                        stream.pending_ack = 0
                elif f.type == FIN:
                    # All DATA preceding this FIN has been flushed in order.
                    # Now safely half-close the write side of the local socket.
                    self._half_close_recv(stream)
                    break
        except (asyncio.CancelledError, ConnectionError, OSError, RuntimeError):
            pass
        finally:
            if stream.pending_ack > 0 and not stream.closed:
                self.send_control(Frame(WINDOW_UPDATE, 0, sid,
                                        struct.pack("!I", stream.pending_ack)))
                stream.pending_ack = 0
            if not stream.closed:
                self._try_finish(stream)

    # -- half-close / close --------------------------------------------------

    def _half_close_recv(self, stream: Stream) -> None:
        """FIN received: shutdown(SHUT_WR) on the local socket."""
        try:
            stream.writer.write_eof()
        except (ConnectionError, OSError, AttributeError):
            pass

    def _start_close(self, stream: Stream, why: str) -> None:
        """Spawn (and track) an asynchronous stream teardown task."""
        t = asyncio.create_task(self.close_stream(stream, why))
        self._close_tasks.append(t)

    def _try_finish(self, stream: Stream) -> None:
        """Close the stream once both directions have fully finished.

        Called from both relay tasks at their natural completion. It only fires
        once the peer->local queue is drained, so trailing DATA frames are never
        dropped before finalization.
        """
        if (not stream.closed and stream.fin_sent and stream.fin_received
                and stream.data_q.empty()):
            self.send_control(Frame(CLOSE, 0, stream.stream_id, b""))
            self._start_close(stream, "both FINs exchanged")

    async def close_stream(self, stream: Stream, why: str) -> None:
        if stream.closed:
            return
        stream.closed = True
        log.debug("closing stream %d: %s", stream.stream_id, why)
        current = asyncio.current_task()
        relay_tasks = []
        for t in (stream.send_task, stream.recv_task):
            # Never cancel ourselves (close_stream may be invoked from within a
            # relay task); cancelling the current task would abort this teardown
            # before it can await the peer relay task.
            if t is not None and t is not current and not t.done():
                t.cancel()
                relay_tasks.append(t)
        try:
            stream.writer.close()
        except (ConnectionError, OSError):
            pass
        await asyncio.gather(*relay_tasks, return_exceptions=True)
        try:
            await stream.writer.wait_closed()
        except (ConnectionError, OSError, asyncio.CancelledError):
            pass
        self.streams.pop(stream.stream_id, None)

    # -- writer pump ----------------------------------------------------------

    async def _writer_pump(self) -> None:
        pending_getters: set[asyncio.Task] = set()
        try:
            while True:
                if not self.high_queue.empty():
                    self.writer.write(self.high_queue.get_nowait().to_bytes())
                    await self.writer.drain()
                    continue
                if not self.normal_queue.empty():
                    self.writer.write(self.normal_queue.get_nowait().to_bytes())
                    await self.writer.drain()
                    continue
                # Nothing ready: wait for either queue (high preferred). The
                # losing ``Queue.get()`` task is cancelled so it can't stay
                # suspended. (The hot path here matches a plain two-task wait.)
                high_t = asyncio.create_task(self.high_queue.get())
                normal_t = asyncio.create_task(self.normal_queue.get())
                pending_getters = {high_t, normal_t}
                done, pending = await asyncio.wait(
                    {high_t, normal_t}, return_when=asyncio.FIRST_COMPLETED)
                for t in pending:
                    t.cancel()
                for t in done:
                    self.writer.write(t.result().to_bytes())
                await self.writer.drain()
        except (asyncio.CancelledError, ConnectionError, OSError, EOFError):
            pass
        finally:
            # If this pump is cancelled/errors mid-wait, the (uncancelled, still
            # pending) queue-getters from that last iteration would otherwise be
            # reported as "Task was destroyed but it is pending". Reap them.
            for t in pending_getters:
                if not t.done():
                    t.cancel()
            if pending_getters:
                await asyncio.gather(*pending_getters, return_exceptions=True)

    # -- keepalive -------------------------------------------------------------

    async def _keepalive_loop(self) -> None:
        interval = float(self.cfg.keepalive)
        misses = 0
        try:
            while self.connected:
                await asyncio.sleep(interval)
                if not self.connected:
                    return
                self._pong_event = asyncio.Event()
                self.send_control(Frame(PING, 0, 0, b""))
                try:
                    await asyncio.wait_for(self._pong_event.wait(), interval * 3)
                    misses = 0
                except TimeoutError:
                    misses += 1
                    log.warning("keepalive miss %d (no PONG)", misses)
                    if misses >= 3:
                        log.warning("control considered dead")
                        self.connected = False
                        try:
                            self.writer.close()
                        except (ConnectionError, OSError):
                            pass
                        return
        except asyncio.CancelledError:
            pass

    # -- teardown --------------------------------------------------------------

    async def shutdown_conn(self) -> None:
        """Close the control socket and all streams. Idempotent."""
        if self._torn:
            return
        self._torn = True
        self.connected = False
        streams = list(self.streams.values())
        for stream in streams:
            await self.close_stream(stream, "teardown")
        tasks = [self._writer_task] + [t for t in self._tasks if t is not self._writer_task]
        for t in tasks:
            if t is not None and not t.done():
                t.cancel()
        if tasks:
            await asyncio.gather(*(t for t in tasks if t is not None),
                                 return_exceptions=True)
        # Reap any asynchronously-spawned stream teardown tasks so they do not
        # remain pending (and warn "Task was destroyed") at loop teardown.
        close_tasks = [t for t in self._close_tasks if not t.done()]
        if close_tasks:
            await asyncio.gather(*close_tasks, return_exceptions=True)
        self._close_tasks.clear()
        try:
            self.writer.close()
        except (ConnectionError, OSError):
            pass

    # -- keep-streams helpers ---------------------------------------------------

    def take_preserved(self) -> list:
        """Detach streams that should survive a control break (client, keep-streams).

        Returns a list of ``PreservedStream`` records. The relay tasks are
        cancelled but the local sockets are NOT closed, so the user connection
        stays alive and can be re-attached after a reconnect.
        """
        preserved = []
        for sid, s in list(self.streams.items()):
            if s.target is None:
                continue
            for t in (s.send_task, s.recv_task):
                if t is not None and not t.done():
                    t.cancel()
            s.closed = True  # detach from this (dead) control connection
            preserved.append(PreservedStream(
                sid, s.reader, s.writer, s.target, s.fin_sent))
            self.streams.pop(sid, None)
        return preserved


# ---------------------------------------------------------------------------
# PreservedStream (for --keep-streams on the client)
# ---------------------------------------------------------------------------


@dataclass
class PreservedStream:
    stream_id: int
    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter
    target: tuple[str, int]
    fin_sent: bool = False

    def close(self) -> None:
        try:
            self.writer.close()
        except (ConnectionError, OSError):
            pass


# ---------------------------------------------------------------------------
# Forward listener
# ---------------------------------------------------------------------------


class ForwardListener:
    """Accepts local TCP connections and turns each into an OPEN on a tunnel."""

    def __init__(self, bind: tuple[str, int], target: tuple[str, int]):
        self.bind = bind
        self.target = target
        self.tunnel: Tunnel|None = None
        self.server: asyncio.Server|None = None

    async def start(self, tunnel: Tunnel|None) -> None:
        self.tunnel = tunnel
        self.server = await asyncio.start_server(self._on_client, self.bind[0],
                                                 self.bind[1])
        log.info("forwarding %s:%d -> %s:%d",
                 self.bind[0], self.bind[1], self.target[0], self.target[1])

    async def stop(self) -> None:
        if self.server is not None:
            self.server.close()
            # Deliberately do NOT await ``wait_closed()`` here. In 3.12+ that
            # waits for every accepted local connection to be fully dropped, but
            # those sockets are owned by streams (which may stay half-open, or
            # be preserved by ``--keep-streams``), not by this listener. We only
            # need to stop accepting new connections; existing sockets are
            # closed (or preserved) by the tunnel teardown.
            self.server = None

    async def _on_client(self, reader, writer) -> None:
        tunnel = self.tunnel
        if tunnel is None or not tunnel.connected:
            log.warning("no active tunnel; dropping connection on %s", self.bind[0])
            writer.close()
            return
        sid = tunnel.next_stream_id
        tunnel.next_stream_id += 2
        th, tp = self.target
        bytes_host = th.encode("utf-8")
        payload = (struct.pack("!H", len(bytes_host)) + bytes_host
                   + struct.pack("!H", tp))
        stream = Stream(sid, reader, writer, tunnel.cfg.window_size,
                        tunnel.cfg.window_size, target=self.target)
        tunnel.streams[sid] = stream
        tunnel.send_control(Frame(OPEN, 0, sid, payload))
        log.debug("stream %d: OPEN %s:%d", sid, th, tp)


# ---------------------------------------------------------------------------
# Application
# ---------------------------------------------------------------------------


class App:
    def __init__(self, args):
        self.args = args
        self.allow_policy = AllowPolicy(args.allow_all, args.allows)
        self.forwards = args.forwards
        self.tunnel: Tunnel|None = None
        self._preserved: list[PreservedStream] = []
        # Server mode: active per-connection handler tasks.
        self._conn_tasks: set[asyncio.Task] = set()

    def _make_config(self) -> Config:
        return Config(
            token=self.args.token,
            forwards=self.forwards,
            window_size=self.args.window_size,
            max_frame_size=self.args.max_frame_size,
            keepalive=self.args.keepalive,
        )

    async def _start_forwards(self, tunnel: Tunnel) -> list[ForwardListener]:
        listeners = []
        try:
            for bind, target in self.forwards:
                fl = ForwardListener(bind, target)
                await fl.start(tunnel)
                listeners.append(fl)
        except OSError as exc:
            await self._stop_forwards(listeners)
            raise exc
        return listeners

    async def _stop_forwards(self, listeners: list[ForwardListener]) -> None:
        for fl in listeners:
            await fl.stop()

    # -- client ---------------------------------------------------------------

    async def run_client(self) -> int:
        host, port = self.args.connect
        reconnect = self.args.reconnect
        keep_streams = self.args.keep_streams

        while True:
            # (Re)connect to the server.
            try:
                r, w = await asyncio.open_connection(host, port)
            except (OSError, ConnectionError) as exc:
                log.error("cannot connect to %s:%d: %s", host, port, exc)
                if reconnect is None:
                    return 1
                await self._sleep_cancel(reconnect)
                continue

            tunnel = Tunnel(r, w, is_client=True, cfg=self._make_config(),
                            allow_policy=self.allow_policy)
            self.tunnel = tunnel
            log.info("connected to %s:%d", host, port)

            ok = await tunnel.client_handshake()
            if not ok:
                await tunnel.shutdown_conn()
                # Handshake failed: preserved streams can't carry over.
                self._close_preserved()
                if reconnect is None:
                    return 1
                await self._sleep_cancel(reconnect)
                continue

            # Start local forward listeners.
            listeners = await self._start_forwards(tunnel)
            tunnel.run_context()

            # Re-OPEN any streams preserved across a previous break.
            if keep_streams and self._preserved:
                await self._reopen_preserved(tunnel)

            try:
                # Serve until the control connection drops.
                await tunnel.read_frames_until_eof()
            finally:
                # Preserve streams (if requested) before tearing down, so that
                # shutdown_conn does not close the local sockets we keep. This
                # also runs on signal cancellation, guaranteeing cleanup.
                await self._stop_forwards(listeners)
                if keep_streams:
                    surviving = tunnel.take_preserved()
                    # Drop previously preserved streams we can no longer keep.
                    self._close_preserved()
                    self._preserved = surviving
                else:
                    self._close_preserved()
                await tunnel.shutdown_conn()

            if reconnect is None:
                log.error("control connection lost and --reconnect not set")
                self._close_preserved()
                return 1
            log.info("reconnecting in %.1fs", reconnect)
            await self._sleep_cancel(reconnect)

    async def _reopen_preserved(self, tunnel: Tunnel) -> None:
        for p in list(self._preserved):
            # Re-create the stream record on the new tunnel using the preserved
            # local sockets. OPEN_OK will then find it and start the relay; an
            # OPEN_ERR closes the preserved local connection.
            if p.stream_id not in tunnel.streams:
                stream = Stream(p.stream_id, p.reader, p.writer,
                                tunnel.cfg.window_size, tunnel.cfg.window_size,
                                target=p.target, fin_sent=p.fin_sent)
                tunnel.streams[p.stream_id] = stream
            th, tp = p.target
            bytes_host = th.encode("utf-8")
            payload = (struct.pack("!H", len(bytes_host)) + bytes_host
                       + struct.pack("!H", tp))
            tunnel.send_control(Frame(OPEN, 0, p.stream_id, payload))
            log.debug("re-OPEN preserved stream %d -> %s:%d", p.stream_id, th, tp)
        # Preserved streams are handed to the tunnel; the app no longer owns them.
        self._preserved = []

    def _close_preserved(self) -> None:
        for p in self._preserved:
            p.close()
        self._preserved = []

    async def _sleep_cancel(self, secs: float) -> None:
        try:
            await asyncio.sleep(secs)
        except asyncio.CancelledError:
            # TODO: the same exception raised
            raise

    # -- server ---------------------------------------------------------------

    async def run_server(self) -> int:
        host, port = self.args.listen
        listeners = []

        # Server's own local forwards; they attach to whichever control
        # connection is currently active.
        for bind, target in self.forwards:
            fl = ForwardListener(bind, target)
            try:
                await fl.start(None)
            except OSError as exc:
                log.error("cannot bind %s:%d: %s", bind[0], bind[1], exc)
                await self._stop_forwards(listeners)
                return 1
            listeners.append(fl)

        # Server-side local forwards created a stream with an id computed from
        # the tunnel's counter; ForwardListener picks it up dynamically.
        async def handle_conn(reader, writer):
            peer = writer.get_extra_info("peername")
            log.info("control connection from %r", peer)
            tunnel = Tunnel(reader, writer, is_client=False, cfg=self._make_config(),
                            allow_policy=self.allow_policy)
            self.tunnel = tunnel
            for fl in listeners:
                fl.tunnel = tunnel
            try:
                ok = await tunnel.server_handshake()
                if not ok:
                    return
                tunnel.run_context()
                await tunnel.read_frames_until_eof()
            finally:
                await tunnel.shutdown_conn()
                for fl in listeners:
                    fl.tunnel = None
                if self.tunnel is tunnel:
                    self.tunnel = None
                log.info("control connection closed")

        async def _connection_wrapper(reader, writer):
            task = asyncio.current_task()
            if not task:
                return
            self._conn_tasks.add(task)
            try:
                await handle_conn(reader, writer)
            finally:
                self._conn_tasks.discard(task)

        server = await asyncio.start_server(_connection_wrapper, host, port)
        log.info("server listening on %s:%d", host, port)
        try:
            # ``asyncio.start_server`` already begins accepting connections, so
            # we do not call ``server.serve_forever()``. That method swallows
            # ``CancelledError`` internally and then blocks in its own
            # ``wait_closed()`` until every accepted client handler finishes, so
            # on shutdown the CancelledError would never reach this ``finally``
            # block (we would deadlock waiting on connections we can't yet
            # cancel). Instead we idle here and let cancellation propagate, then
            # tear down the connection handlers before closing the server.
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            pass
        finally:
            # Stop the accept loop and any remaining per-connection handlers.
            for t in list(self._conn_tasks):
                t.cancel()
            if self._conn_tasks:
                await asyncio.gather(*list(self._conn_tasks), return_exceptions=True)
            server.close()
            # Safe now: every accepted client handler has finished, so nothing
            # is left for ``wait_closed()`` to block on.
            await server.wait_closed()
            await self._stop_forwards(listeners)
        return 0


# ---------------------------------------------------------------------------
# CLI / entry point
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="tunnel",
        description="TCP port forwarding tunnel over a binary multiplexed protocol.",
    )
    sub = p.add_subparsers(dest="mode", required=True)

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--token", required=True, help="shared secret token")
    common.add_argument("--forward", action="append", default=[],
                        metavar="BIND_HOST:BIND_PORT:TARGET_HOST:TARGET_PORT",
                        help="local forward; repeatable")
    common.add_argument("--allow", action="append", default=[],
                        metavar="HOST:PORT", help="allowed target; repeatable")
    common.add_argument("--allow-all", action="store_true", help="allow any target")
    common.add_argument("--window-size", type=int, default=262144,
                        help="flow-control window size (default 262144)")
    common.add_argument("--max-frame-size", type=int, default=65536,
                        help="max frame payload (default 65536)")
    common.add_argument("--keepalive", type=float, default=30.0,
                        help="PING interval seconds (default 30)")
    common.add_argument("--log-level", default="info",
                        choices=["debug", "info", "warning", "error"],
                        help="logging level (default info)")

    c = sub.add_parser("client", parents=[common])
    c.add_argument("--connect", required=True, metavar="HOST:PORT", help="server address")
    c.add_argument("--reconnect", type=float, metavar="SECONDS",
                   help="reconnect every N seconds after control break")
    c.add_argument("--keep-streams", action="store_true",
                   help="preserve active streams across reconnects")

    s = sub.add_parser("server", parents=[common])
    s.add_argument("--listen", required=True, metavar="HOST:PORT", help="listening address")
    return p


def _validate(args) -> None:
    if args.forward:
        args.forwards = [parse_forward(x) for x in args.forward]
    else:
        args.forwards = []
    if args.allow:
        args.allows = [parse_host_port(x, "--allow") for x in args.allow]
    else:
        args.allows = []
    if args.allow_all and args.allow:
        _fail("--allow and --allow-all are mutually exclusive")
    if args.window_size <= 0 or args.max_frame_size <= 0:
        _fail("--window-size and --max-frame-size must be positive")
    if args.token == "":
        _fail("--token must not be empty")
    if args.mode == "client":
        args.connect = parse_host_port(args.connect, "--connect")
        if args.keep_streams and args.reconnect is None:
            _fail("--keep-streams requires --reconnect")
    else:
        args.listen = parse_host_port(args.listen, "--listen")
        if getattr(args, "keep_streams", False):
            _fail("--keep-streams is client-only")


def _fail(msg: str):
    print(f"error: {msg}", file=sys.stderr)
    sys.exit(2)


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    logging.basicConfig(level=getattr(logging, args.log_level.upper()),
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    try:
        _validate(args)
    except ValueError as exc:
        _fail(str(exc))

    app = App(args)
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    stop = asyncio.Event()
    try:
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                loop.add_signal_handler(sig, stop.set)
            except (NotImplementedError, RuntimeError):
                pass
        main_task = asyncio.ensure_future(
            app.run_client() if args.mode == "client" else app.run_server())

        async def _wait() -> int:
            signal_task = asyncio.ensure_future(stop.wait())
            try:
                done, _ = await asyncio.wait(
                    {main_task, signal_task}, return_when=asyncio.FIRST_COMPLETED)
                if signal_task in done and not main_task.done():
                    log.info("received shutdown signal")
                    main_task.cancel()
                    try:
                        await main_task
                    except asyncio.CancelledError:
                        pass
                    return 0
                return main_task.result()
            finally:
                # Avoid leaving a dangling Event.wait() task that would be
                # reported as "destroyed but still pending" when the main task
                # finishes first (e.g. a failed handshake / connect error).
                if not signal_task.done():
                    signal_task.cancel()

        return loop.run_until_complete(_wait())
    except KeyboardInterrupt:
        return 130
    finally:
        try:
            loop.close()
        except RuntimeError:
            pass


def encode_frame(f: Frame) -> bytes:
    return f.to_bytes()


if __name__ == "__main__":
    sys.exit(main())
