"""Wire-protocol constants: version, frame types, and timing defaults."""

from __future__ import annotations

PROTOCOL_VERSION = 1

HANDSHAKE_TIMEOUT = 10.0  # seconds to wait for HELLO / HELLO_OK
CONNECT_TIMEOUT = 30.0  # seconds to wait for the target TCP connection
OPEN_TIMEOUT = 30.0  # seconds to wait for OPEN_OK / OPEN_ERR
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
