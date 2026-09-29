"""Two-queue (high / normal) writer for the control connection."""

from __future__ import annotations

import asyncio
import collections

from portmux.protocol.framing import Frame


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
