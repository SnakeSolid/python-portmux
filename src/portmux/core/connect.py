"""Connect to a target host, translating failures to OpenFailure reasons."""

from __future__ import annotations

import asyncio
import socket

from portmux.protocol.constants import (
    CONNECT_TIMEOUT,
    OPEN_ERR_DNS,
    OPEN_ERR_OTHER,
    OPEN_ERR_REFUSED,
    OPEN_ERR_TIMEOUT,
)
from portmux.protocol.errors import OpenFailure
from portmux.util.socket import set_tcp_nodelay


async def connect_target(host: str, port: int):
    """Open a TCP connection to the target, IPv4 only."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, family=socket.AF_INET),
            timeout=CONNECT_TIMEOUT,
        )
        set_tcp_nodelay(writer)
        return reader, writer
    except TimeoutError:
        raise OpenFailure(OPEN_ERR_TIMEOUT)
    except socket.gaierror:
        raise OpenFailure(OPEN_ERR_DNS)
    except ConnectionRefusedError:
        raise OpenFailure(OPEN_ERR_REFUSED)
    except OSError:
        raise OpenFailure(OPEN_ERR_OTHER)
