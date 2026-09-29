"""portmux - a TCP port forwarding tunnel over a single multiplexed connection.

Two instances (``client`` and ``server``) establish one control connection and
carry many logical streams over it using a custom binary protocol. After the
HELLO handshake both sides are fully symmetric.

The implementation is split into focused subpackages:

* ``portmux.protocol`` - wire format, frame serialization, payload helpers.
* ``portmux.util``     - parsing, allow-policy, CLI, logging.
* ``portmux.core``     - the control connection (``Tunnel``) and ``Stream``.
* ``portmux.app``      - client/server roles, handshake, and the entry point.

Only the Python standard library is used.
"""

from __future__ import annotations

from portmux.app.cli import main

__all__ = ["main"]
