"""CLI argument parsing and validation."""

from __future__ import annotations

import argparse

from portmux.util.parse import parse_forward, parse_host_port


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="portmux",
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
        sp.add_argument("--allow-all", action="store_true", help="allow any target")
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


def validate_args(parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    """Validate mutually-exclusive flags, numeric ranges, and config syntax.

    Calls ``parser.error`` on the first problem, which raises SystemExit.
    """
    if args.allow and args.allow_all:
        parser.error("--allow and --allow-all are mutually exclusive")
    if args.window_size <= 0:
        parser.error("--window-size must be positive")
    if args.max_frame_size <= 0:
        parser.error("--max-frame-size must be positive")
    if args.keepalive < 0:
        parser.error("--keepalive must not be negative")

    if args.mode == "client" and args.keep_streams and args.reconnect is None:
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
