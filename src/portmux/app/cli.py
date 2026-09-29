"""CLI entry point: argument parsing, validation, and dispatch."""

from __future__ import annotations

import asyncio
import logging

import portmux.app.client
import portmux.app.server
from portmux.util.argvec import build_parser, validate_args
from portmux.util.logging import setup_logging

LOG = logging.getLogger("tunnel")


def run(mode: str, args) -> int:
    """Dispatch to the requested mode's run loop."""
    if mode == "client":
        return asyncio.run(portmux.app.client.run_client(args))
    return asyncio.run(portmux.app.server.run_server(args))


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    setup_logging(args.log_level)

    validate_args(parser, args)

    try:
        return run(args.mode, args)
    except KeyboardInterrupt:
        LOG.info("interrupted")
        return 0
