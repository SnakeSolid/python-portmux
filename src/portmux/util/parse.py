"""Parsing helpers and the OPEN allow policy."""

from __future__ import annotations


def parse_host_port(spec: str) -> tuple[str, int]:
    """Parse ``HOST:PORT`` (IPv4 or hostname only, no brackets)."""
    if spec.count(":") != 1:
        raise ValueError(f"invalid HOST:PORT value: {spec!r}")
    host, port_str = spec.split(":")
    if not host:
        raise ValueError(f"empty host in {spec!r}")
    return host, int(port_str)


def parse_forward(spec: str) -> tuple[str, int, str, int]:
    """Parse ``BIND_HOST:BIND_PORT:TARGET_HOST:TARGET_PORT``."""
    parts = spec.split(":")
    if len(parts) != 4:
        raise ValueError(
            f"invalid --forward value {spec!r}: expected "
            "BIND_HOST:BIND_PORT:TARGET_HOST:TARGET_PORT"
        )
    bind_host, bind_port, target_host, target_port = parts
    if not bind_host or not target_host:
        raise ValueError(f"invalid --forward value {spec!r}")
    return bind_host, int(bind_port), target_host, int(target_port)


class AllowPolicy:
    """Decides whether an OPEN request may be served."""

    def __init__(self, allowed: list[str] | None, allow_all: bool) -> None:
        self.allow_all = allow_all
        self._allowed = set()
        for spec in allowed or []:
            host, port = parse_host_port(spec)
            self._allowed.add((host.lower(), port))

    def check(self, host: str, port: int) -> bool:
        if self.allow_all:
            return True
        return (host.lower(), port) in self._allowed
