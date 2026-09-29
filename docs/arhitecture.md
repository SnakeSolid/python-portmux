# Architecture

This document describes the architecture and wire protocol of **portmux**, a TCP
port forwarding tunnel that multiplexes many logical streams over a single
control connection using a strictly binary protocol. It is the reference
specification used to implement the tool.

Everything is implemented in **Python** with only the **standard library**
(`asyncio`, `struct`, `argparse`, `logging`, `socket`, `hmac`). The mode
(`client`/`server`) determines only who dials whom during the initial handshake;
after that both sides behave symmetrically.

---

## 1. Overview

Two instances of the tool (client and server) establish one **control
connection**. Over it, a strictly binary multiplexing protocol carries many
logical **streams**. Each local TCP connection accepted by one side becomes a
stream whose data is sent over the control connection and, on the other side,
turned into a TCP connection to a remote host.

Only TCP is supported. IPv6 is **not** supported anywhere — not in `--forward`,
not in `--allow`, not in `OPEN` — and only domain names and IPv4 addresses are
allowed. Target connections are opened with `family=socket.AF_INET`
(`core/connect.py`), which enforces IPv4 even if the host text could otherwise
resolve to an IPv6 address.

No JSON or other text format is used in the protocol; everything is binary.

## 2. Roles and Identifiers

- **Client** initiates the TCP connection.
- **Server** listens for TCP and accepts the connection.
- **Stream ID** — a 32-bit unsigned integer identifying a logical stream within
  one control connection.
  - `0` is reserved for control messages.
  - Client generates **odd** IDs (starts at 1); server generates **even** IDs
    (starts at 2).
  - Allocation increments by 2 (`alloc_id` in `core/tunnel.py`) and wraps
    through `0` by resetting to `1` (client) or `2` (server), preserving parity.

## 3. Handshake

1. Server listens on `--listen HOST:PORT` (`app/server.py::run_server`).
2. Client connects to `--connect HOST:PORT` (`app/client.py::session`).
3. After the TCP handshake the **client** sends `HELLO`. The server waits for
   `HELLO` (`app/handshake.py`).
4. The server checks the protocol version and token:
   - OK → `HELLO_OK`;
   - otherwise → `HELLO_ERR` and closes the connection.
   - The token comparison uses `hmac.compare_digest` (constant-time).
5. After `HELLO_OK` both sides consider the connection established and start
   serving streams; each side starts the listeners defined by `--forward`.

If `HELLO` / `HELLO_OK` is not received within **10 s** (`HANDSHAKE_TIMEOUT`),
the connection is closed with a `HandshakeError`.

The protocol version is **1** (`PROTOCOL_VERSION`), compared for equality; there
is no feature negotiation.

## 4. Frame Format

Every frame has a fixed 10-byte header and a variable-length payload:

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     type      |     flags     |                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
|                         stream_id                             |
+                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                               |           length              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
|                               |          payload ...          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

| Field | Size | Description |
|-------|------|-------------|
| type | 1 byte | frame type |
| flags | 1 byte | reserved, 0 |
| stream_id | 4 bytes, big-endian | stream ID, 0 for control |
| length | 4 bytes, big-endian | payload length in bytes |
| payload | length bytes | frame data |

The header is `struct.Struct("!BBII")` (`protocol/framing.py`). The default
maximum payload is 64 KiB (`--max-frame-size`); a frame with
`length > max_frame_size` raises a `ProtocolError` and closes the control
connection.

## 5. Frame Types

### Control (stream_id = 0)

| Code | Name | Payload | Purpose |
|------|------|---------|---------|
| 0x01 | `HELLO` | version (2 BE), token_len (2 BE), token (UTF-8) | first frame from client |
| 0x02 | `HELLO_OK` | empty | server accepted handshake |
| 0x03 | `HELLO_ERR` | reason (1 byte) | server rejected handshake |
| 0x30 | `PING` | empty | liveness check |
| 0x31 | `PONG` | empty | response to PING |

`HELLO_ERR.reason`:

- `0x01` — incompatible version
- `0x02` — invalid token
- `0x03` — other

### Stream (stream_id != 0)

| Code | Name | Payload | Direction |
|------|------|---------|-----------|
| 0x10 | `OPEN` | host_len (2 BE), host (UTF-8), port (2 BE) | initiator → peer |
| 0x11 | `OPEN_OK` | empty | peer → initiator |
| 0x12 | `OPEN_ERR` | reason (1 byte) | peer → initiator |
| 0x20 | `DATA` | arbitrary bytes | both directions |
| 0x21 | `WINDOW_UPDATE` | credit (4 BE) | both directions |
| 0x22 | `FIN` | empty | both directions, half-close |
| 0x23 | `CLOSE` | empty | both directions, full close |

`OPEN_ERR.reason`:

- `0x01` — connection refused
- `0x02` — timeout
- `0x03` — DNS error
- `0x04` — target forbidden by allow policy
- `0x05` — other error

`OPEN` payload field order is `host_len, host, port`, where `host` is a domain
or IPv4 in text form.

## 6. Stream Lifecycle

1. Side A accepts a TCP connection on one of its `--forward` listeners, allocates
   a stream ID, and creates a `Stream` record (`app/dispatcher.py`,
   `core/stream.py`).
2. A sends `OPEN` to the peer with the target host:port.
3. Side B:
   - checks the allow policy (`AllowPolicy.check` in `util/parse.py`);
   - calls `connect_target(host, port)` (`core/connect.py`);
   - on success sends `OPEN_OK`; on failure sends `OPEN_ERR` with a reason.
4. On `OPEN_ERR` the initiator closes the local socket and removes the stream.
5. After `OPEN_OK` (or immediately for the non-initiating side) both sides run a
   bidirectional relay:
   - local socket → `DATA` over the control connection;
   - `DATA` from the control connection → local socket.

   On the initiating side the relay waits for `OPEN_OK` before sending `DATA`;
   on the responding side the relay starts immediately.

6. **Half-close.** A side reading EOF from the local socket sends `FIN` and
   stops reading. A side receiving `FIN` calls `writer.write_eof()` on its local
   socket; data in the opposite direction continues.
7. Full stream closure — when both sides have sent and received `FIN` and all
   `DATA` in both directions is delivered, `Stream.maybe_finish()` tears the
   stream down cleanly.
8. **`CLOSE`** — immediate full stream closure on error (e.g. a target socket
   dying unexpectedly). Both sides close the sockets and remove the stream.
9. Control-connection break — all active streams are forcibly closed (see §9).

## 7. Flow Control

Each direction of each stream has an independent window:

- Initial window: `--window-size` bytes (default 256 KiB).
- The sender keeps a `send_credit` counter per stream. Before sending `DATA` it
  decreases `send_credit` by the chunk length; when credit is exhausted it waits
  on `credit_event` until a `WINDOW_UPDATE` replenishes it.
- The receiver counts processed bytes in `pending_credit` and sends
  `WINDOW_UPDATE` with the processed amount. Aggregation:
  - when `pending_credit >= window // 2`, or
  - on a 50 ms timer (`CREDIT_FLUSH_INTERVAL`) when `pending_credit` is non-zero
    (implemented via `asyncio.wait_for(self.incoming.get(), 0.05)` in
    `core/stream.py::_remote_to_local`).

`DATA` is split into `max_frame_size` chunks accounting for the current credit.
`WINDOW_UPDATE` is sent on the high-priority queue.

## 8. Half-Close

- EOF from the local socket → `FIN`; the side stops reading that socket.
- `FIN` received → `writer.write_eof()` on the corresponding local socket
  (propagates EOF to the peer's opposite socket).
- Each side keeps reading its socket and sending `DATA` in the opposite direction
  until EOF.
- When both sides have sent and received `FIN` (and both relay tasks finished),
  the stream closes cleanly.
- A sent `FIN` is remembered and re-sent after a reconnect/reopen if the local
  side already reached EOF (§9).

`CLOSE` closes the stream entirely at once without waiting for the opposite EOF.

## 9. Behavior on Control-Connection Break

Default (without `--keep-streams`):

- All active streams are closed: local sockets are closed and stream records are
  removed.
- With `--reconnect N` the client retries every N seconds while the server keeps
  listening.
- Without `--reconnect` the process exits non-zero.

With `--keep-streams` (client only, requires `--reconnect`):

- Active streams are preserved and detached (`Stream.detach`), keeping their
  local sockets open.
- After the control connection is restored and `HELLO_OK` succeeds, both sides
  re-send `OPEN` for preserved streams (`Stream.reopen`).
- On `OPEN_ERR` the corresponding stream is closed.
- Data not sent before the break is lost — no delivery guarantees.

`--keep-streams` without `--reconnect` is rejected at argument validation with a
non-zero exit.

## 10. Keepalive

- Each side periodically (default every 30 s, `--keepalive`, a float) sends
  `PING` on stream_id 0.
- If `PONG` is not received within **3 × interval**, the control connection is
  considered dead and handled per §9. (`_keepalive_loop` in `core/tunnel.py`.)
- `--keepalive 0` disables the keepalive loop.

## 11. Allow Policy

- `--allow HOST:PORT` allows a specific target; repeatable.
- `--allow-all` allows any target.
- `--allow` and `--allow-all` are mutually exclusive (validated up front).
- If neither is given, all `OPEN` requests are rejected with `OPEN_ERR 0x04`.
- The lookup is case-insensitive on the host (`AllowPolicy`).
- The check runs before `connect_target`.

IPv6 is not supported: `HOST` may be a domain name or IPv4.

## 12. CLI

Two subcommands `client` and `server`, plus shared options (`arqparse` in
`util/argvec.py`). The public entry points are the `portmux` console script and
`python -m portmux`.

### Common parameters

| Parameter | Description | Default |
|-----------|-------------|---------|
| `--token TOKEN` | shared secret, required | — |
| `--forward BIND_HOST:BIND_PORT:TARGET_HOST:TARGET_PORT` | forward; repeatable | — |
| `--allow HOST:PORT` | allowed target; repeatable | — |
| `--allow-all` | allow any targets | — |
| `--window-size BYTES` | flow-control window size | 262144 |
| `--max-frame-size BYTES` | maximum frame payload | 65536 |
| `--keepalive SECONDS` | PING period (float) | 30 |
| `--log-level LEVEL` | logging level: `debug`, `info`, `warning`, `error` | info |

### `client`

| Parameter | Description |
|-----------|-------------|
| `--connect HOST:PORT` | server address, required |
| `--reconnect SECONDS` | try to reconnect every N seconds |
| `--keep-streams` | preserve active streams between reconnects (requires `--reconnect`) |

### `server`

| Parameter | Description |
|-----------|-------------|
| `--listen HOST:PORT` | listening address, required |

### Example

```bash
# server
portmux server \
  --listen 0.0.0.0:9000 \
  --token s3cr3t \
  --allow example.com:443 \
  --allow db.internal:5432

# client
portmux client \
  --connect 10.0.0.5:9000 \
  --token s3cr3t \
  --forward 127.0.0.1:12345:example.com:443 \
  --forward 127.0.0.1:15432:db.internal:5432 \
  --reconnect 5
```

## 13. Other Rules

- Any protocol violation (unknown type, too-large length, a stream frame on
  stream_id 0, `OPEN` for an already-active stream, malformed
  `WINDOW_UPDATE`/`OPEN`/`HELLO` payload, etc.) raises a `ProtocolError` and
  closes the control connection immediately.
- `DATA` order within one stream is preserved.
- Order between different streams is not guaranteed.
- Control frames (`OPEN_OK`, `OPEN_ERR`, `WINDOW_UPDATE`, `FIN`, `CLOSE`,
  `PING`, `PONG`) are sent with priority over `DATA`. This is implemented with
  `PriorityWriter` (`core/writer.py`), a two-queue (high/low) writer.
- `DATA` for an unknown stream_id is ignored (a possible race during stream
  closure).
- `--forward` and `--allow` accept IPv4 and hostname only, no square brackets.
  Malformed values are rejected during argument validation, before the event
  loop starts.
- `set_tcp_nodelay` is applied to every socket (control, target, and local
  listeners) to disable Nagle's algorithm.

---

## Project layout

The implementation is a multi-file package (not a single script) under
`src/portmux/`:

```
src/portmux/
├── __init__.py            # package docstring, re-exports `main`
├── __main__.py            # `python -m portmux`
└── app/
│   ├── cli.py             # main(), argument dispatch
│   ├── client.py          # Client: listeners + reconnect session loop
│   ├── server.py          # Server: listeners + control connection handling
│   ├── dispatcher.py      # shared outbound-stream spawning for both roles
│   └── handshake.py       # client_handshake / server_handshake
├── core/
│   ├── tunnel.py          # Tunnel: control connection, stream table, loops
│   ├── stream.py          # Stream: one local socket pair, flow control, relaying
│   ├── writer.py          # PriorityWriter: high/low queues
│   └── connect.py         # connect_target: IPv4-only connect + reason mapping
├── protocol/
│   ├── constants.py       # version, frame types, reason codes, timeouts
│   ├── framing.py         # Frame dataclass, encode_frame / read_frame
│   ├── hello.py           # HELLO payload encode/decode
│   ├── open.py            # OPEN payload encode/decode
│   └── errors.py          # ProtocolError, HandshakeError, OpenFailure
└── util/
    ├── argvec.py          # argparse parser + argument validation
    ├── parse.py           # parse_host_port, parse_forward, AllowPolicy
    ├── socket.py          # set_tcp_nodelay
    └── logging.py         # setup_logging
```

Dependency rules:

- `protocol` imports only the standard library and other `protocol` modules.
- `core` imports `protocol` and `util` (for `parse`).
- `app` imports `core` and `protocol`.
- `util` is dependency-free except for the stdlib (`argparse`, `socket`, ...).

`Tunnel` and `Stream` are intentionally decoupled: `Stream` references the
controlling `Tunnel` only through an attribute (never imported at runtime), which
is what lets a stream be detached and re-attached across reconnects.
