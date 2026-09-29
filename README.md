# portmux

**portmux** is a TCP port forwarding tunnel — similar in spirit to SSH local/remote
port forwarding — but it multiplexes every logical stream over a **single control
connection** using a strictly binary protocol. It has no external dependencies and
runs on the Python standard library (`asyncio`, `struct`, `argparse`, `logging`).

- **Client / server** roles only determine who dials whom during the initial
  handshake. After the control connection is established, both sides behave
  symmetrically.
- **Binary framing** with flow control, half-close, keepalive, and an optional
  allow-list policy on the forwarding side.

## Features

- Single control TCP connection carrying many multiplexed logical streams.
- Configurable **flow-control window** per direction with `WINDOW_UPDATE` credit
  accounting and aggregation.
- Proper **half-close** (`FIN` / `shutdown(SHUT_WR)`), plus immediate full close
  (`CLOSE`) on error.
- **Keepalive** (`PING` / `PONG`) to detect dead control connections.
- **Allow policy** (`--allow` / `--allow-all`) to restrict which upstream targets
  the forwarding side may connect to.
- Client **auto-reconnect** with optional stream preservation (`--keep-streams`).
- Authentication via a shared **`--token`**.

## Requirements

- Python ≥ 3.12
- [uv](https://docs.astral.sh/uv/) (for installs; the runtime itself needs no
  third-party packages)

## Installation

```bash
uv sync
```

Alternatively, install it as a package:

```bash
uv pip install .
```

Once installed, the `portmux` console script is available. When developing from
the source tree you can also run it directly:

```bash
python -m portmux
```

## Usage

`portmux` has two subcommands, `client` and `server`, plus a set of shared options.

### Server

The server listens for incoming control connections, authenticates them with the
token, and forwards accepted streams to the targets allowed by the policy.

```bash
portmux server \
  --listen 0.0.0.0:9000 \
  --token s3cr3t \
  --allow example.com:443 \
  --allow db.internal:5432
```

| Option | Description |
|--------|-------------|
| `--listen HOST:PORT` | Address to listen for control connections (required). |

### Client

The client connects to the server and creates local listeners that forward traffic
to the targets defined by `--forward`.

```bash
portmux client \
  --connect 10.0.0.5:9000 \
  --token s3cr3t \
  --forward 127.0.0.1:12345:example.com:443 \
  --forward 127.0.0.1:15432:db.internal:5432 \
  --reconnect 5
```

| Option | Description |
|--------|-------------|
| `--connect HOST:PORT` | Server address to connect to (required). |
| `--reconnect SECONDS` | Reconnect every N seconds after a control-connection break. |
| `--keep-streams` | Preserve active streams across reconnects (requires `--reconnect`). |

### Common options

| Option | Default | Description |
|--------|---------|-------------|
| `--token TOKEN` | — | Shared secret for the handshake (required). |
| `--forward BIND_HOST:BIND_PORT:TARGET_HOST:TARGET_PORT` | — | Define a local TCP forward (repeatable). |
| `--allow HOST:PORT` | — | Allow forwarding to this target (repeatable). |
| `--allow-all` | — | Allow forwarding to any target. Mutually exclusive with `--allow`. |
| `--window-size BYTES` | `262144` | Flow-control window size. |
| `--max-frame-size BYTES` | `65536` | Maximum frame payload size. |
| `--keepalive SECONDS` | `30` | `PING` interval. |
| `--log-level LEVEL` | `info` | Logging level: `debug`, `info`, `warning`, `error`. |

## A typical end-to-end example

**1. Start the server** on a host, allowing connections to a specific backend:

```bash
portmux server \
  --listen 0.0.0.0:9000 \
  --token s3cr3t \
  --allow example.com:443
```

**2. Start the client** locally, exposing a local tunnel to the allowed backend
and reconnecting automatically on breakage:

```bash
portmux client \
  --connect server.example.net:9000 \
  --token s3cr3t \
  --forward 127.0.0.1:12345:example.com:443 \
  --reconnect 5
```

**3. Use the tunnel** — any client connecting to `127.0.0.1:12345` is now
forwarded, over the single token-authenticated control connection, to
`example.com:443`.

## How it works

At a high level:

```mermaid
sequenceDiagram
    participant C as Client
    participant S as Server
    C->>S: TCP connect
    C->>S: HELLO (version, token)
    S-->>C: HELLO_OK (or HELLO_ERR)
    Note over C,S: Control connection established
    C->>C: listen on --forward binds
    C->>S: OPEN (host, port) for each new stream
    S-->>C: OPEN_OK (or OPEN_ERR)
    C->>S: DATA / WINDOW_UPDATE / FIN / CLOSE
    S-->>C: DATA / WINDOW_UPDATE / FIN / CLOSE
    Note over C,S: Sends PING periodically; expects PONG
```

Key protocol details:

- **Control frames** (`stream_id = 0`): `HELLO`, `HELLO_OK`, `HELLO_ERR`, `PING`,
  `PONG`.
- **Stream frames** (`stream_id != 0`): `OPEN`, `OPEN_OK`, `OPEN_ERR`, `DATA`,
  `WINDOW_UPDATE`, `FIN`, `CLOSE`.
- **Stream IDs**: 32-bit unsigned; `0` is reserved. The client generates **odd**
  IDs, the server generates **even** IDs.
- **Frame format**: a fixed 10-byte header (`type` 1B, `flags` 1B, `stream_id` 4B
  BE, `length` 4B BE) followed by the payload.
- **Flow control** is per-direction-per-stream; the sender pauses when its credit
  is exhausted until a `WINDOW_UPDATE` replenishes it.
- **Half-close**: a side that reads EOF sends `FIN`; the peer performs
  `shutdown(SHUT_WR)`. A full close happens only after both directions have
  exchanged `FIN` (or via an immediate `CLOSE` on error).
- **Control-connection break**: by default all streams are closed; the client may
  reconnect with `--reconnect`, optionally preserving streams with `--keep-streams`.
- Control frames are prioritized over `DATA` on the wire.

Only **TCP** is supported (no UDP), and only **domain names and IPv4** addresses
are allowed (no IPv6, no `[brackets]`). Target connections are opened with
`socket.AF_INET`, and TCP_NODELAY is enabled on every socket (control, target,
and local listeners).

## Behavior on control-connection break

- **Default** — all active streams are closed; with `--reconnect N` the client
  retries every N seconds while the server keeps listening; without `--reconnect`
  the process exits non-zero.
- **`--keep-streams`** (client only, requires `--reconnect`) — active streams are
  preserved and re-opened (`OPEN`) after the control connection is restored.
  In-flight data not yet sent before the break is lost.

## Development

The full framing and protocol specification used to implement this tool lives in
[`docs/arhitecture.md`](docs/arhitecture.md). Protocol version is **1** (compared
for equality; no feature negotiation).

The runtime is split into focused subpackages under `src/portmux/`:

| Package | Responsibility |
|---------|----------------|
| `portmux.protocol` | Wire format: frame serialization, payload helpers, constants, errors. |
| `portmux.util` | Parsing, allow policy, CLI argument building, logging, socket helpers. |
| `portmux.core` | The control connection (`Tunnel`), `Stream`, `PriorityWriter`, target connector. |
| `portmux.app` | Client/server roles, handshake, the dispatcher, and the CLI entry point. |

Although `pyproject.toml` declares an `asyncio` dependency, the runtime uses only
the Python standard library; pure-stdlib packaging could drop that dependency.

Run the test/validation suite with:

```bash
uv run pytest
```

## License

[MIT](./LICENSE) © 2026 Shabanov Anton.
