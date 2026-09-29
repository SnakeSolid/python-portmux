# Wire Protocol & Connection Model

This document describes the **binary wire protocol** used over the control
connection and the **client/server connection lifecycle** in `portmux`. It is a
grounded reference for anyone integrating with the protocol at the byte level or
debugging connection and handshake behavior.

Compared against the protocol specification in
[`arhitecture.md`](./arhitecture.md), this document is written from the actual
implementation in `src/portmux/__init__.py`. Where anything in the spec and the
code differ, the code is authoritative.

---

## 1. Transport overview

The two roles are only meaningful during connection setup:

- **Client** — dials the control connection and always speaks first (`HELLO`).
- **Server** — listens and accepts the control connection, then validates the
  `HELLO`.

Once the handshake completes, **both sides are symmetric**: either side may open
logical streams from its own local listeners (`--forward`). The only difference
left is the **stream ID space** (see [Stream IDs](#4-stream-ids)).

The underlying transport is **TCP only**. Hosts may be a domain name or an IPv4
address in text form — **no IPv6, no `[brackets]`**.

Framing is **strictly binary**. There is no JSON, XML, or any text protocol on
the wire. Every message is a fixed structure: a 10-byte header followed by an
optional payload.

---

## 2. Message format (frame)

Every message on the control connection is a single **frame** with a **fixed
10-byte header** followed by a **variable-length payload**.

Layout:

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

In the implementation this is built with
`struct.Struct("!BBII")`, i.e. big-endian `type`, `flags`, `stream_id`,
`length`.

| Field | Size            | Type            | Description                          |
|-------|-----------------|-----------------|--------------------------------------|
| `type` | 1 byte         | uint8           | Frame type (see table below).        |
| `flags` | 1 byte        | uint8           | Reserved; always `0`.                |
| `stream_id` | 4 bytes    | uint32, BE      | Logical stream ID; `0` = control.    |
| `length` | 4 bytes      | uint32, BE      | Payload length in bytes (0 allowed). |
| `payload` | `length` bytes | raw bytes     | Frame data (absent when `length == 0`). |

### Frame size limit

A frame whose `length` exceeds `--max-frame-size` (default **64 KiB**) is a
protocol violation. The reader raises `ProtocolError` and the control
connection is closed immediately.

### Frame-type codes

| Code   | Name            | stream_id | Payload                 | Notes                            |
|--------|-----------------|-----------|-------------------------|----------------------------------|
| `0x01` | `HELLO`         | 0         | `version`(2 BE) `token_len`(2 BE) `token`(UTF-8) | First frame from the client. |
| `0x02` | `HELLO_OK`      | 0         | empty                   | Server accepts the handshake.    |
| `0x03` | `HELLO_ERR`     | 0         | `reason`(1 byte)        | Server rejects the handshake.    |
| `0x10` | `OPEN`          | stream    | `host_len`(2 BE) `host`(UTF-8) `port`(2 BE) | Request to open a stream to a target. |
| `0x11` | `OPEN_OK`       | stream    | empty                   | Peer connected to the target.    |
| `0x12` | `OPEN_ERR`      | stream    | `reason`(1 byte)        | Peer could not connect to target. |
| `0x20` | `DATA`          | stream    | arbitrary bytes         | Application payload, both ways.  |
| `0x21` | `WINDOW_UPDATE` | stream    | `credit`(4 BE)          | Flow-control credit replenishment. |
| `0x22` | `FIN`           | stream    | empty                   | Half-close (EOF from a socket).  |
| `0x23` | `CLOSE`         | stream    | empty                   | Immediate full close / error.    |
| `0x30` | `PING`          | 0         | empty                   | Liveness probe.                  |
| `0x31` | `PONG`          | 0         | empty                   | Liveness response.               |

The codebase classifies these into:

- **Control frames** (`stream_id == 0`): `HELLO`, `HELLO_OK`, `HELLO_ERR`,
  `PING`, `PONG`.
- **Stream frames** (`stream_id != 0`): `OPEN`, `OPEN_OK`, `OPEN_ERR`, `DATA`,
  `WINDOW_UPDATE`, `FIN`, `CLOSE`.

### Payload encodings

- **`HELLO` payload** — `version` (uint16 BE), then `token_len` (uint16 BE),
  then `token` encoded as UTF-8.
- **`OPEN` payload** — `host_len` (uint16 BE), then `host` as UTF-8, then
  `port` (uint16 BE). Field order is exactly `host_len, host, port`. The
  receiver validates that `len(payload) == 2 + host_len + 2` and that the host
  decodes as UTF-8.
- **`HELLO_ERR` reason**:
  - `0x01` — incompatible protocol version
  - `0x02` — invalid token
  - `0x03` — other
- **`OPEN_ERR` reason**:
  - `0x01` — connection refused
  - `0x02` — timeout
  - `0x03` — DNS error
  - `0x04` — target forbidden by allow policy
  - `0x05` — other error
- **`WINDOW_UPDATE` payload** — a single uint32 BE `credit` value.

---

## 3. Binary encoding example

All integers are **big-endian**. A `DATA` frame delivering the 3 bytes `A B C`
on stream 5:

| `type` | `flags` | `stream_id`      | `length`         | payload  |
|--------|---------|------------------|------------------|----------|
| `0x20` | `0x00`  | `00 00 00 05`    | `00 00 00 03`    | `41 42 43` |

A `PING` control probe has no payload:

| `type` | `flags` | `stream_id`      | `length`         | payload |
|--------|---------|------------------|------------------|---------|
| `0x30` | `0x00`  | `00 00 00 00`    | `00 00 00 00`    | —       |

---

## 4. Stream IDs

- The stream ID is a **32-bit unsigned integer**.
- **`0` is reserved** for control frames.
- The **client allocates odd IDs** (`1, 3, 5, ...`).
- The **server allocates even IDs** (`2, 4, 6, ...`).
- Each side owns a monotonically increasing counter and allocates
  `next_id += 2` when it opens a stream locally. The counter is masked to 32
  bits and wraps past `0xFFFFFFFF`.

Because only the handshake decides who runs the client side (`next_id` starts at
`1` for the client, `2` for the server), both sides agree on a disjoint ID
space with no collisions.

---

## 5. Connection lifecycle

### 5.1 Setup

1. The **server** listens for control connections on `--listen HOST:PORT`.
2. The **client** dials the server at `--connect HOST:PORT`.
3. After the TCP handshake, the **client sends `HELLO`** first
   (`version = 1`, token as UTF-8). The server waits for `HELLO`.
4. The server validates the frame:

   - **Protocol version mismatch** → sends `HELLO_ERR` reason `0x01`, closes.
   - **Token mismatch** (compared with `hmac.compare_digest`) → sends
     `HELLO_ERR` reason `0x02`, closes.
   - **Success** → sends `HELLO_OK`, and both sides treat the control
     connection as established.

5. If the server does not receive `HELLO` within **10 seconds**
   (`HANDSHAKE_TIMEOUT`), or the client does not receive `HELLO_OK` within 10
   seconds, the handshake times out and the connection is closed.

Protocol version is **1** and is compared for **equality only** — there is no
feature negotiation.

### 5.2 Between handshakes — keepalive

After the handshake only `PING` / `PONG` reuse `stream_id = 0`:

- Every `--keepalive` seconds (default **30 s**) each side sends `PING`.
- On receiving `PING` the peer immediately replies `PONG` (queued at high
  priority).
- On receiving `PONG` the sender records the time. If no `PONG` is seen for
  more than **3 × the keepalive interval**, the control connection is declared
  dead and torn down (see [5.5](#55-detecting-and-handling-a-broken-control-connection)).
- Setting `--keepalive 0` disables the keepalive loop.

### 5.3 Both sides are symmetric after handshake

Once `HELLO_OK` is exchanged, either side:

- starts its local `--forward` listeners, and
- may open or accept logical streams.

The `server` typically has no `--forward` (it only forwards targets allowed by
policy via `OPEN`), while the `client` sets up local listeners, but the protocol
itself treats them identically.

### 5.4 Running the control connection

The `Tunnel` object runs three concurrent loops:

- **Writer loop** — drains a two-priority queue and writes frames to the
  socket.
- **Reader loop** — reads frames and dispatches them to the stream table.
- **Keepalive loop** — sends `PING` and enforces the liveness timeout.

Control/stream-management frames (`OPEN_OK`, `OPEN_ERR`, `WINDOW_UPDATE`, `FIN`,
`CLOSE`, `PING`, `PONG`) are always queued at **high priority**, while `DATA`
frames are queued at **normal (low) priority**. The writer therefore favors
control frames over data on the wire.

### 5.5 Detecting and handling a broken control connection

The control connection dies when:

- the peer closes the TCP connection (incomplete read while blocking for a
  header),
- a `ProtocolError` is raised (malformed frame, unknown type, oversized
  payload, out-of-order control frame, or `OPEN` for an already-active stream),
- the reader loop catches any other I/O error, or
- the keepalive timeout fires.

When the tunnel shuts down, whether streams are preserved depends on the mode:

- **Server** — all streams are closed (`stream.close`) immediately.
- **Client without `--keep-streams`** — all streams are closed and the stream
  table cleared; if `--reconnect` is not set, the process exits non-zero.
- **Client with `--keep-streams`** (requires `--reconnect`) — live streams are
  *detached* (their sockets stay open) and re-opened after reconnecting —
  see [Client reconnection](#6-client-reconnection).

---

## 6. Client reconnection

When the client runs with `--reconnect N`:

1. Its local `--forward` listeners stay up across reconnects. Any local
   connection that arrives while there is **no active control connection** is
   rejected and closed.
2. After the control connection breaks, the client waits `N` seconds and dials
   again, re-running the handshake.
3. If `--keep-streams` is set, surviving streams are `reopen`ed — the client
   re-sends `OPEN`, and the server dials the target again. On `OPEN_ERR` that
   stream is closed.

Without `--reconnect`, the client exits with a non-zero status after a break.

`--keep-streams` without `--reconnect` is a configuration error and is rejected
at startup.

### Data loss caveat

There are **no delivery guarantees**. Application data that was handed to the
transport but not yet written before the control connection breaks may be
**lost**. Stream preservation preserves the *TCP sessions*, not inflight
bytes.

---

## 7. Stream lifecycle

1. Side A accepts a TCP connection on one of its `--forward` listeners,
   allocates a stream ID (odd if client, even if server), and creates a
   `Stream` record.
2. A sends `OPEN` (with target `host:port`) and waits up to
   `OPEN_TIMEOUT` (30 s) for the verdict.
3. Side B:
   - applies its **allow policy**; if not allowed, replies `OPEN_ERR` reason
     `0x04` (forbidden);
   - otherwise connects to the target (`CONNECT_TIMEOUT` of 30 s, IPv4 only):
     - refused → `OPEN_ERR` `0x01`
     - timeout → `OPEN_ERR` `0x02`
     - DNS error (`socket.gaierror`) → `OPEN_ERR` `0x03`
     - other OS error → `OPEN_ERR` `0x05`
   - on success replies `OPEN_OK`.
4. On `OPEN_ERR`, side A closes the local socket and removes the stream. On
   `OPEN_OK`, both sides begin relaying.
5. Relay is bidirectional: local socket → `DATA`, and `DATA` → local socket.

### Flow control

Each stream has an independent window **per direction**:

- Both sides start with `send_credit = --window-size` (default 256 KiB).
- The sender decrements `send_credit` by each `DATA` payload length and pauses
  (waits on a credit event) once `send_credit == 0`.
- The receiver accumulates processed bytes and sends `WINDOW_UPDATE` with the
  credited amount. Credit is flushed when the accumulated total reaches **at
  least half the window**, or after a **50 ms** aggregation timer
  (`CREDIT_FLUSH_INTERVAL`).
- The sender increments `send_credit` on `WINDOW_UPDATE` and resumes.

The A→B and B→A windows are independent.

### Half-close and full close

- **EOF** from the local socket → the side sends `FIN` and stops reading that
  socket. Its own `send_done` becomes set.
- Receiving `FIN` → the peer performs a half-close (`write_eof()`) on its local
  socket and keeps sending `DATA` in the opposite direction until EOF. It
  records `recv_done`.
- The stream closes **cleanly** when both sides have both sent and received
  `FIN` and all data is flushed (`fin_sent && fin_received && send_done &&
  recv_done`).
- **`CLOSE`** is an immediate full close used on errors (e.g. a local read or
  write error, or peer `CLOSE`). It closes both sockets without waiting for the
  opposite EOF.

---

## 8. Protocol violations (hard closes)

The following are **connection-fatal** — the reader raises `ProtocolError` and
takes the whole control connection down per [5.5](#55-detecting-and-handling-a-broken-control-connection):

- A frame on `stream_id == 0` whose type is not a control type.
- A frame whose `length > --max-frame-size`.
- A `stream_id == 0` frame other than `HELLO_OK`/`PING`/`PONG` after the
  handshake (the `_handle_control` path).
- A `WINDOW_UPDATE` with a payload that is not exactly 4 bytes.
- An `OPEN` for an already-active stream ID.
- A malformed `OPEN` payload (bad host length, bad UTF-8).
- An **unknown frame type** on a non-zero stream ID.

Other robustness rules:

- A `DATA` frame for an unknown (already-closed) stream is **silently ignored**
  — this is a deliberate tolerance of a closure race, not an error.
- `DATA` order within one stream is preserved; ordering across different
  streams is not guaranteed.

---

## 9. One-line summary

TCP control connection → client sends `HELLO(version=1, token)` → server replies
`HELLO_OK` (or `HELLO_ERR`) → symmetric bidirectional multiplexing of logical
streams using 10-byte binary headers, per-direction flow control, `PING`/`PONG`
keepalive, and `FIN`/`CLOSE` for graceful and abrupt teardown.
