"""The control connection: owns the TCP socket, stream table, and frame loops."""

from __future__ import annotations

import argparse
import asyncio
import logging
import struct
import time

from portmux.core.connect import connect_target
from portmux.core.stream import Stream
from portmux.core.writer import PriorityWriter
from portmux.protocol.constants import (
    CONTROL_FRAME_TYPES,
    F_CLOSE,
    F_DATA,
    F_FIN,
    F_OPEN,
    F_OPEN_ERR,
    F_OPEN_OK,
    F_PING,
    F_PONG,
    F_WINDOW_UPDATE,
    OPEN_ERR_FORBIDDEN,
    OPEN_ERR_OTHER,
    STREAM_FRAME_TYPES,
)
from portmux.protocol.errors import OpenFailure, ProtocolError
from portmux.protocol.framing import Frame, encode_frame, read_frame
from portmux.protocol.open import decode_open
from portmux.util.parse import AllowPolicy

LOG = logging.getLogger("tunnel")


class Tunnel:
    """Owns the control connection and the stream table."""

    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        is_client: bool,
        args: argparse.Namespace,
        streams: dict[int, Stream] | None = None,
        allow: AllowPolicy | None = None,
        next_id: int | None = None,
    ) -> None:
        self.reader = reader
        self.writer = writer
        self.is_client = is_client
        self.args = args
        self.streams: dict[int, Stream] = streams if streams is not None else {}
        self.allow = allow or AllowPolicy(args.allow, args.allow_all)
        self.max_frame_size = args.max_frame_size

        self.next_id = next_id if next_id is not None else (1 if is_client else 2)
        self.pw = PriorityWriter()
        self.last_pong = time.monotonic()

        self._closed = asyncio.Event()
        self._stopped = False
        self._tasks: list[asyncio.Task] = []

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
        while True:
            await asyncio.sleep(interval)
            if time.monotonic() - self.last_pong > 3 * interval:
                LOG.warning("keepalive timeout, dropping control connection")
                self._fail()
                return
            self.send_frame(Frame(F_PING, 0), high=True)
            LOG.debug("sending PING")

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
            LOG.debug("received PING, replying PONG")
            self.send_frame(Frame(F_PONG, 0), high=True)
        elif frame.type == F_PONG:
            self.last_pong = time.monotonic()
            LOG.debug("received PONG")
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
