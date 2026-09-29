"""Protocol-level exceptions."""

from __future__ import annotations


class ProtocolError(Exception):
    """Any protocol violation: the control connection is closed immediately."""


class HandshakeError(Exception):
    """The HELLO exchange failed."""


class OpenFailure(Exception):
    """Internal helper carrying an OPEN_ERR reason code."""

    def __init__(self, reason: int) -> None:
        super().__init__(f"open failure (reason {reason})")
        self.reason = reason
