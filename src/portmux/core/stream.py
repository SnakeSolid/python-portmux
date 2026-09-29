"""One logical stream: a local TCP socket on each side multiplexed over a tunnel.

``Stream`` depends on ``Tunnel`` only through its ``tunnel`` attribute (the
control connection), so it never imports ``core.tunnel`` at runtime.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import struct
from typing import TYPE_CHECKING

from portmux.protocol.constants import (
    CREDIT_FLUSH_INTERVAL,
    F_CLOSE,
    F_DATA,
    F_FIN,
    F_OPEN,
    F_WINDOW_UPDATE,
    OPEN_TIMEOUT,
)
from portmux.protocol.framing import Frame
from portmux.protocol.open import encode_open

if TYPE_CHECKING:
    from portmux.core.tunnel import Tunnel

LOG = logging.getLogger("tunnel")


class Stream:
    """One logical stream = one local TCP socket on each side."""

    def __init__(
        self,
        stream_id: int,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        args: argparse.Namespace,
        initiator: bool,
        streams: dict[int, Stream],
        target: tuple[str, int] | None = None,
    ) -> None:
        self.id = stream_id
        self.reader = reader
        self.writer = writer
        self.window = args.window_size
        self.max_frame_size = args.max_frame_size
        self.initiator = initiator
        self.target = target
        self.streams = streams

        self.tunnel: Tunnel | None = None
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
        self.open_error: int | None = None

        self.incoming: asyncio.Queue = asyncio.Queue()

        self._open_task: asyncio.Task | None = None
        self._send_task: asyncio.Task | None = None
        self._recv_task: asyncio.Task | None = None

    # -- lifecycle ----------------------------------------------------------

    def start(self) -> None:
        """Start the stream tasks."""
        if self.initiator:
            self._open_task = asyncio.ensure_future(self._open_handshake())
        else:
            self.ready_event.set()
        self._send_task = asyncio.ensure_future(self._local_to_remote())
        self._recv_task = asyncio.ensure_future(self._remote_to_local())

    def attach(self, tunnel: Tunnel) -> None:
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

    def reopen(self, tunnel: Tunnel) -> None:
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
        LOG.debug(
            "stream %d: sending OPEN for %s:%d",
            self.id,
            self.target[0],
            self.target[1],
        )
        tunnel.send_frame(
            Frame(F_OPEN, self.id, encode_open(self.target[0], self.target[1])),
            high=True,
        )
        try:
            await asyncio.wait_for(self.open_result.wait(), OPEN_TIMEOUT)
        except TimeoutError:
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
            LOG.debug("stream %d: sent %d bytes of DATA", self.id, len(chunk))

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
                    except TimeoutError:
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
        LOG.debug("stream %d: received %d bytes of DATA", self.id, len(payload))
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
