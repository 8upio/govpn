# Architecture Research

**Domain:** Embeddable Go library implementing the server side of the OpenVPN protocol (`github.com/8upio/govpn`, package `ovpn`)
**Researched:** 2026-08-22
**Confidence:** HIGH (Go stdlib/`net`/`crypto/tls` mechanics, general architecture shape) / MEDIUM (exact OpenVPN wire-format numbers — must be re-verified against `ssl.c`/`crypto.c` before/while coding, per PROJECT.md's own constraint)

## Standard Architecture

### System Overview

```
┌──────────────────────────────────────────────────────────────────────────┐
│  Transport (caller-owned)                                                │
│  net.PacketConn (UDP socket, port 1194) — passed into srv.Serve(pc)      │
└───────────────────────────────┬────────────────────────────────────────-┘
                                 │ ReadFrom (single reader goroutine)
┌────────────────────────────────▼───────────────────────────────────────-┐
│  L1 — UDP Mux / Session Router  (ovpn package, unexported)               │
│  peek [opcode+keyid byte][session-id] → lookup/create session            │
│  new HARD_RESET_CLIENT → allocate Session + spawn control goroutine      │
│  known session-id → non-blocking send into session inbox channel        │
└───────────────────────────────┬────────────────────────────────────────-┘
                                 │ per-session dispatch (by opcode)
                 ┌───────────────┴────────────────┐
                 ▼                                  ▼
┌────────────────────────────────┐   ┌──────────────────────────────────┐
│ L2 — Control Channel            │   │ L2 — Data Channel                 │
│ internal/tlscrypt: unwrap        │   │ internal/datachannel:              │
│ internal/wire: parse header      │   │  parse header, AEAD open,         │
│ internal/reliable: ACK+reorder   │   │  replay-window check              │
│ internal/controlconn: net.Conn   │   │  (pure decrypt/encrypt, no I/O)   │
│  ⇒ crypto/tls.Server(...)        │   │                                    │
│  ⇒ Key Method 2 (internal/keys)  │   │                                    │
└───────────────────────────────┬─┘   └────────────────┬───────────────────┘
                                 │ derived KeySet                │ plaintext IP
                                 └───────────────┬────────────────┘
                                                  ▼
                                  ┌───────────────────────────────┐
                                  │ L3 — Session (exported)         │
                                  │ io.ReadWriteCloser of raw IP    │
                                  │ pkts; AssignedIP; OnSession cb  │
                                  └───────────────┬─────────────────┘
                                                  ▼
                     ┌────────────────────────────┴─────────────────────────┐
                     ▼                                                      ▼
        ┌────────────────────────────┐                    ┌──────────────────────────────┐
        │ Scenario A: TUN device       │                    │ Scenario B: netstack package    │
        │ io.Copy(tun, sess) / (sess,tun)│                    │ (github.com/8upio/govpn/netstack)│
        │ caller's responsibility        │                    │ ListenUDP/ListenTCP/ICMP echo,  │
        │                                │                    │ IP→Session routing table         │
        └────────────────────────────┘                    └──────────────────────────────┘
```

### Component Responsibilities

| Component | Responsibility | Typical Implementation |
|-----------|----------------|-------------------------|
| Server / UDP mux | Owns the single `net.PacketConn`, demuxes inbound datagrams to sessions, creates sessions on `HARD_RESET_CLIENT`, drives outbound writes | one reader goroutine + `map[sessionKey]*session` guarded by `sync.RWMutex` |
| `internal/wire` | Encode/decode opcode byte, session-id, packet-id, ACK array, data-channel header — pure structs/functions, no I/O | plain Go structs + `encoding/binary` |
| `internal/tlscrypt` | Wrap/unwrap control-channel packets with the static tls-crypt key (AES-256-CTR + HMAC-SHA256 per spec) | pure functions over `[]byte` |
| `internal/reliable` | ACK tracking, retransmission timers, in-order reassembly of control-channel payload stream | mutex-guarded window state + `time.AfterFunc`, injectable clock for tests |
| `internal/controlconn` | Adapts wire+tlscrypt+reliable+the real UDP transport into a `net.Conn` that `crypto/tls` can drive | `io.Pipe`-backed reader, deadline support via timers |
| `internal/keys` | Key Method 2 PRF/key expansion (OpenVPN's own two-stage HMAC construction, **not** `ExportKeyingMaterial`) | pure function `deriveKeys(preMaster, cRandom, sRandom) KeySet`, golden-vector tested against `ssl.c`/`crypto.c` |
| `internal/datachannel` | AEAD encrypt/decrypt (AES-256-GCM), packet-id sequencing, replay-window rejection | pure functions over `[]byte` + a small bitmap/window struct |
| `ovpn` (root, exported) | `Config`, `Server`, `Session`, `NewServer`, `Serve` — glues everything above into the public contract | thin orchestration layer over the internal packages |
| `netstack` (sibling package, exported) | UDP/TCP/ICMP userspace stack consuming `Session` as plain `io.ReadWriteCloser`; IP-routing table (assigned tunnel IP → session) | IP/UDP/TCP header parse+build, `ListenUDP`/`ListenTCP`, ICMP echo responder |
| `examples/…` | Demonstrates end-to-end usage (`ovpn` + `netstack` + TCP-served HTTP), own `main` package | plain `package main`, imports the two libraries like any external consumer |

## Recommended Project Structure

```
github.com/8upio/govpn/
├── go.mod                       # module github.com/8upio/govpn — stdlib deps only
├── config.go                    # Config struct, validation (Cipher fixed check, Network, TLSConfig, TLSCryptKey)
├── server.go                    # Server struct, NewServer, Serve(net.PacketConn), session table + mux
├── session.go                   # exported Session type (io.ReadWriteCloser), AssignedIP, Close semantics
├── doc.go                       # package-level godoc: usage example from PROJECT.md
│
├── internal/
│   ├── wire/                    # opcode constants, header encode/decode — no I/O, pure
│   │   ├── opcode.go
│   │   ├── control.go           # P_CONTROL_V1 / P_ACK_V1 header (session-id, packet-id, ack array)
│   │   ├── data.go              # P_DATA_V2 header (peer-id, packet-id)
│   │   └── wire_test.go         # fixtures from real packet captures
│   │
│   ├── tlscrypt/                # tls-crypt wrap/unwrap (AES-256-CTR + HMAC-SHA256)
│   │   ├── tlscrypt.go
│   │   └── tlscrypt_test.go     # vectors from a real client capture
│   │
│   ├── reliable/                # ACK tracking, retransmission, reorder buffer
│   │   ├── reliable.go          # Send(payload), OnReceive(pktID,payload), OnAck(ids)
│   │   ├── clock.go             # injectable clock interface for fast tests
│   │   └── reliable_test.go     # synthetic loss/reorder/duplicate scenarios, fake clock
│   │
│   ├── controlconn/              # net.Conn adapter: wire+tlscrypt+reliable ⇒ crypto/tls
│   │   ├── conn.go               # Read/Write/Close/Deadlines over io.Pipe + reliable layer
│   │   └── conn_test.go          # loopback UDP pair, no real OpenVPN client needed
│   │
│   ├── keys/                     # Key Method 2 PRF / key expansion
│   │   ├── keymethod2.go
│   │   └── keymethod2_test.go    # byte-exact golden vectors vs ssl.c/crypto.c
│   │
│   └── datachannel/               # AEAD encrypt/decrypt, packet-id, replay window
│       ├── aead.go
│       ├── replay.go
│       └── datachannel_test.go    # fixed key/nonce vectors
│
├── netstack/                      # separate exported package — NOT internal/
│   ├── stack.go                   # Stack, NewStack(serverTunnelIP), Attach(sess, assignedIP)
│   ├── udp.go                     # ListenUDP(port) (net.PacketConn, error)
│   ├── tcp.go                     # ListenTCP(port) (net.Listener, error) — minimal state machine
│   ├── icmp.go                    # echo responder (~20 lines)
│   ├── iphdr.go                   # IPv4 header parse/build (shared by udp/tcp/icmp)
│   └── *_test.go                  # tested against a fake Session (io.Pipe pair), no ovpn dependency
│
├── examples/
│   └── webserver/
│       └── main.go                # package main: ovpn.NewServer + netstack.NewStack + net/http.Serve
│
└── interop/                       # Docker-based interop harness (not shipped as a package)
    ├── docker-compose.yml         # real OpenVPN 2.6 client container
    ├── client.ovpn
    └── run_test.sh
```

### Structure Rationale

- **`internal/` for every protocol-internal piece:** wire format, tls-crypt, reliability, key derivation, and data-channel crypto are all implementation detail that must be free to change without breaking semver. Go's `internal/` visibility rule enforces this at the compiler level, not just by convention — external users literally cannot import `internal/keys` even if they try.
- **Root package (`ovpn`) stays thin:** `Config`, `Server`, `Session`, `NewServer`. This is the entire public surface described in PROJECT.md's usage example — nothing protocol-specific leaks into it. Keeping the public API this small is itself the main defense against having to make breaking changes later (e.g., adding NCP or renegotiation should not need to touch `Config`/`Session`'s existing fields).
- **`netstack` lives outside `internal/`, as a sibling package, and only depends on `io.ReadWriteCloser`.** This is a deliberate architectural test: if `netstack` needs anything from `ovpn/internal/...`, the `Session` abstraction has leaked and the boundary is wrong. It should be buildable and fully unit-tested against a fake `io.Pipe`-backed session before a single line of the real `ovpn` handshake code exists.
- **Every `internal/` package is pure or near-pure (no goroutines, no network) except `controlconn`.** This maximizes independently-testable, parallelizable units — the highest-risk pieces (`keys`, `reliable`) get the most isolated, fastest test loops.
- **`examples/` is `package main`, same module.** No third-party deps are needed for the example (net/http + the two library packages), so there is no reason to split it into its own module — `go run ./examples/webserver` should just work from the repo root. Keep it stdlib-only to match the project's minimal-deps constraint.
- **`interop/` is not a Go package at all** — it's the Docker-based real-client harness PROJECT.md requires as a v1 gate, kept alongside the code it tests but not part of the build graph.

## Architectural Patterns

### Pattern 1: `net.Conn` framing adapter over `io.Pipe`, not a hand-rolled buffer

**What:** `internal/controlconn` implements `net.Conn` by pairing an `io.Pipe` for the read side (a background function pushes reassembled, in-order control-channel plaintext into the pipe writer as the `reliable` layer delivers it) with a `Write` method that hands data straight to `reliable.Send` (fragmenting into ≤~1250-byte control-packet payloads if the TLS record is larger, e.g. big certificate chains). Deadlines are layered on top of `io.Pipe` (which has none natively) via a timer that calls `pipeReader.CloseWithError(os.ErrDeadlineExceeded)`-equivalent on expiry.

**When to use:** Whenever `crypto/tls.Server(conn, cfg)` needs to run over a non-stream transport (here: UDP datagrams reassembled by a custom reliability layer). This is the crux of "reuse stdlib TLS instead of reimplementing it" — the entire justification only holds if this adapter is correct, since `tls.Conn.Handshake()`'s blocking `Read`/`Write` calls become the actual "drive" mechanism: there is no separate poll loop, the handshake advances exactly when the mux delivers a reassembled chunk into the pipe.

**Trade-offs:** `io.Pipe` is fully synchronous and unbuffered, which is *correct* here (backpressure onto the reliability layer is fine — nothing else is racing to fill it) but means the feeder goroutine must never block on anything else while holding data to write into the pipe. Simpler than a hand-rolled ring buffer with condition variables; the main cost is one extra goroutine per session to run the feeder loop.

**Example:**
```go
// internal/controlconn/conn.go (sketch)
type Conn struct {
    pr, pw    *io.PipeReader, *io.PipeWriter
    reliable  *reliable.Layer
    readDL, writeDL atomic.Value // time.Time
}

func (c *Conn) Read(p []byte) (int, error)  { return c.pr.Read(p) }   // driven by reliable's feeder goroutine writing into pw
func (c *Conn) Write(p []byte) (int, error) { return c.reliable.Send(p) } // chunks + queues for (re)transmission, returns once queued
```

### Pattern 2: Mutex-guarded state machine for reliability, not a pure channel pipeline

**What:** The ACK/retransmit window (unacked-send buffer, next-expected packet-id, reorder buffer) is genuinely shared mutable state touched from three different call sites — "new packet arrived" (mux dispatch), "ACK arrived" (mux dispatch), and "retransmit timer fired" (`time.AfterFunc` callback). Model it as a `sync.Mutex`-guarded struct with an injectable clock, not as goroutines exchanging messages over channels for every state transition.

**When to use:** Anywhere state is mutated from multiple independent trigger points that don't form a clean producer→consumer pipeline. This is the textbook case where Go's "share memory by communicating" channel idiom becomes awkward — you'd end up building a request/response channel protocol just to read-modify-write a map, which is strictly worse than a mutex.

**Trade-offs:** Slightly less "idiomatic-looking" than an all-channels design, but far easier to reason about and test (inject a fake clock, call methods directly, assert on state) — no goroutine orchestration needed in tests at all. Reserve channels for the genuine handoff points: mux → per-session inbox, decrypt → `Session.Read()` consumer.

### Pattern 3: One central reader goroutine + light per-session goroutines, not a monolithic event loop or a goroutine-per-packet model

**What:** A single goroutine owns `ReadFrom` on the shared `net.PacketConn` (Go's `net.UDPConn` is documented safe for concurrent `Read`/`Write` from multiple goroutines, but there is no benefit to multiple readers here and it avoids reordering surprises). It demuxes and does a non-blocking send into each session's small buffered inbox channel. Each session then has essentially one goroutine (running the TLS handshake / control-channel driver, which blocks in `tls.Conn.Read` fed by the pipe from Pattern 1) plus zero extra goroutines for retransmission (use `time.AfterFunc`, not a spinning goroutine). Data-channel packets need **no** dedicated goroutine — decrypt happens synchronously in the mux dispatch, encrypt happens synchronously in the caller's `Session.Write()`.

**When to use:** This project's target scale is dozens to low-thousands of concurrent sessions (Voxio phones), not millions — goroutine-per-session is cheap and dramatically simpler to reason about than a single custom event loop multiplexing all session state machines by hand. Revisit only if profiling at real target scale shows scheduler pressure (unlikely).

**Trade-offs:** A true single-threaded event loop (like `libuv`/`nginx`-style) would use less memory per connection and avoid all locking, but is a much larger engineering investment and fights Go's goroutine-based runtime rather than using it. Not justified at this scale, and re-derivable later behind the same `Session` interface without an API break if ever needed.

### Pattern 4: Key-slot / generation design from day one, even though renegotiation is deferred

**What:** `internal/keys.KeySet` and the data-channel decrypt path should be indexed by the 3-bit key-id carried in the data-channel opcode byte from the very first implementation, even though v1 only ever populates slot 0. A tiny fixed-size array (`[8]*KeySet` or similarly small ring, in practice only 2 need to be "live" at once: current + previous during a transition) avoids a structural rewrite when `CONTROL_SOFT_RESET_V1`-driven renegotiation is added later.

**When to use:** Now — it costs almost nothing to model `Session`'s key state as slot-indexed rather than a single flat struct, and it directly de-risks a known future requirement (real OpenVPN 2.6 clients renegotiate by default every `reneg-sec` ~3600s; a server that cannot at least tolerate/ignore a soft-reset gracefully will drop long-lived sessions — see Anti-Patterns).

**Trade-offs:** Marginal extra indirection now for a straightforward extension path later. No downside identified.

## Data Flow

### Inbound (client → server)

```
UDP datagram arrives
    ↓
Server.Serve(): ReadFrom(pc)                         [single reader goroutine]
    ↓ peek [opcode+keyid][session-id] (internal/wire, no decrypt needed to route)
lookup session by session-id/remote-addr
    │
    ├─ unknown + opcode == HARD_RESET_CLIENT_V2/V3 → allocate Session, spawn control goroutine
    └─ known → non-blocking send into session inbox channel
                    ↓
        session dispatch: switch on opcode
            │
            ├─ P_CONTROL_V1 / P_ACK_V1
            │     → internal/tlscrypt.Unwrap (static tls-crypt key)
            │     → internal/wire.ParseControlHeader
            │     → internal/reliable.OnReceive(pktID, payload) [dedupe, reorder, schedule ACK]
            │     → reassembled bytes pushed into controlconn's io.Pipe writer
            │     → tls.Conn.Read() unblocks (handshake) OR Key-Method-2 reader unblocks (post-handshake)
            │
            └─ P_DATA_V2
                  → internal/datachannel.Decrypt (AEAD open, AAD from opcode+peer-id+packet-id)
                  → internal/datachannel.Replay.Check (sliding bitmap window, reject old/dup)
                  → plaintext IP packet → Session's inbound channel → caller's Session.Read()
```

### Outbound (server → client)

```
Control-channel path (TLS handshake bytes, Key Method 2 material, future rekeys):
tls.Conn.Write(record) / Key-Method-2 writer
    → controlconn.Write(p) → internal/reliable.Send(p)   [chunk if > max control payload]
    → assigns packet-id, buffers for retransmit, arms time.AfterFunc
    → internal/wire.EncodeControlHeader + internal/tlscrypt.Wrap
    → pc.WriteTo(remoteAddr)
    [ACKs: reliable layer piggybacks on next outgoing control packet, or sends standalone
     P_ACK_V1 if nothing else queued within a short window]
    [retransmit: time.AfterFunc fires → if still unacked → resend same packet-id, re-arm timer]

Data-channel path:
caller: Session.Write(ipPacket)
    → internal/datachannel.Encrypt (increment send packet-id, build nonce, AEAD seal)
    → internal/wire.EncodeDataHeader
    → pc.WriteTo(remoteAddr)          [synchronous; safe for concurrent callers via a small mutex
                                        serializing packet-id increment]
```

### Key Method 2 sequence (where it sits relative to TLS)

```
1. Client HARD_RESET → Server allocates Session, starts control goroutine
2. tls.Server(controlConn, cfg).Handshake()   — runs entirely over controlConn (framing layer only,
                                                  no OpenVPN-specific bytes visible to TLS itself)
3. Handshake completes → client authenticated via Config.TLSConfig (server cert + client CA)
4. FIRST TLS application-data record (i.e. now written/read via tls.Conn, not controlConn) carries
   OpenVPN's own Key Method 2 struct: pre-master + random1 + random2 (client) / random1 + random2
   (server) — this is OpenVPN's own construct, layered *inside* the already-established TLS tunnel,
   not a TLS-protocol-level exchange.
5. internal/keys.DeriveKeys(preMaster, clientRandom, serverRandom, opts) → KeySet
   (OpenVPN's own two-stage HMAC/PRF construction — verified byte-exact against ssl.c/crypto.c,
   explicitly NOT tls.ConnectionState().ExportKeyingMaterial())
6. KeySet populates data-channel slot 0 (see Pattern 4) → data channel now live
7. "push"-style option exchange (ifconfig / topology subnet) still travels as further TLS
   application-data records over the same tls.Conn
```

**Open question flagged for a dedicated research pass (not resolved here):** some modern OpenVPN documentation states that current implementations use RFC 5705 key-material export for parts of this exchange, while PROJECT.md's own briefing explicitly calls out that Key Method 2 is *not* equivalent to `ExportKeyingMaterial()`. Treat `internal/keys` as the single highest-risk, must-verify-against-C-source component in the whole architecture — its correctness cannot be inferred from this document or from general TLS knowledge, only from `ssl.c`/`crypto.c` and a real-client capture.

### Key Data Flows Summary

1. **Control-channel bring-up:** UDP mux → tls-crypt unwrap → reliable reorder → `net.Conn` → `crypto/tls` handshake → Key Method 2 → `KeySet`. Fully serial, each stage's correctness is a precondition for the next; this is the highest-risk path and dominates build order (see below).
2. **Data-channel steady state:** UDP mux (opcode dispatch only, no tls-crypt) → AEAD decrypt/encrypt → replay window → `Session` `io.ReadWriteCloser`. Independent of the control-channel machinery once a `KeySet` exists; can be built and tested with synthetic keys before the control channel is fully working.
3. **Netstack consumption:** `Session` → IP/UDP/TCP/ICMP parse → routing table (assigned IP → session) → application code (`ListenUDP`/`ListenTCP` consumers). Entirely decoupled from `ovpn` internals; testable against a fake `Session`.

## Scaling Considerations

| Scale | Architecture Adjustments |
|-------|---------------------------|
| Tens of sessions (dev/test, early interop) | Design as described: goroutine-per-session control driver, mutex-guarded reliability state, plain `map` + `RWMutex` session table. No changes needed. |
| Hundreds–low thousands (Voxio phone fleet target) | Same design holds. Watch: bounded inbound-packet channel size per `Session` (drop policy for RTP-tolerant loss vs blocking for reliability-sensitive consumers) should be configurable via `Config`. Central mux's non-blocking send into session inboxes prevents one stuck session from stalling the shared UDP reader. |
| Tens of thousands+ (not a stated goal, but `topology subnet` on a /16 implies headroom) | `sync.RWMutex`+map session table may start showing contention under very high churn (connect/disconnect storms); revisit with `sync.Map` or sharded maps only if profiling shows it. Retransmit timers via `time.AfterFunc` scale fine (Go's runtime timer heap is efficient at this count). No architectural change needed for the components described here — this is a "measure before optimizing" scale, not a redesign trigger. |

### Scaling Priorities

1. **First likely bottleneck:** per-session inbound channel backpressure under bursty RTP — mitigate with a configurable bounded buffer + explicit drop policy (documented, not silent).
2. **Second likely bottleneck (only at much higher scale than the stated use case):** session-table lock contention on connect/disconnect churn — mitigate with `sync.Map` or a sharded map if/when profiling shows it; not a day-one concern.

## Anti-Patterns

### Anti-Pattern 1: Hand-rolling TLS record framing or a custom handshake state machine

**What people do:** Because OpenVPN wraps TLS in its own framing, it's tempting to parse TLS records manually to "help" the framing layer, or to special-case the handshake.
**Why it's wrong:** The entire architectural bet of this project (per PROJECT.md) is that `crypto/tls` handles 100% of TLS semantics if given a correct `net.Conn`. Any TLS-awareness leaking into `internal/controlconn` reintroduces exactly the reimplementation risk the design is meant to avoid, and creates a second place where TLS bugs can hide.
**Do this instead:** Keep `controlconn` fully TLS-agnostic — it only knows about OpenVPN framing (opcodes, session-ids, packet-ids, reliability) and exposes a byte-stream `net.Conn`. Let `crypto/tls` own every byte of the handshake.

### Anti-Pattern 2: Ignoring `CONTROL_SOFT_RESET_V1` / renegotiation entirely at the architecture level

**What people do:** Since NCP and full renegotiation are explicitly out of scope for v1, it's tempting to hardcode a single, non-renewable key set for a session's entire lifetime.
**Why it's wrong:** A real, unmodified OpenVPN 2.6 client (the interop target) renegotiates by default roughly every hour (`reneg-sec`). If the server can't at least gracefully tolerate a soft-reset (even a minimal "accept it, redo Key Method 2 for the same fixed cipher, rotate to a new slot"), long-running sessions from an unmodified client will fail or need `reneg-sec 0` forced client-side — a real interop gap, not just a missing nice-to-have. This is a build-order/roadmap risk worth flagging explicitly rather than silently deferring.
**Do this instead:** Keep the key-slot design from Pattern 4 in place from day one; treat "does the server survive a real client's default renegotiation interval" as an explicit question for the roadmap (either a v1 phase item, or a consciously logged v1 limitation with the interop harness configured with a longer `reneg-sec`/`--reneg-sec 0` on the client side to sidestep it short-term).

### Anti-Pattern 3: Forcing the reliability layer's bookkeeping through channels for "purity"

**What people do:** Apply "share memory by communicating" dogmatically and try to model the ACK/retransmit window as goroutines passing messages for every state change.
**Why it's wrong:** As covered in Pattern 2, this isn't a producer/consumer pipeline — it's shared state touched from independent trigger points (packet arrival, ACK arrival, timer fire). Forcing it through channels produces a bespoke, hard-to-test request/response protocol that is strictly more complex than a mutex, with no concurrency benefit.
**Do this instead:** Mutex-guard the reliability state directly; reserve channels for genuine handoff points (mux → session inbox, decrypt → `Session.Read()`).

### Anti-Pattern 4: Letting `netstack` (or examples) reach into `ovpn/internal/...`

**What people do:** Since `netstack` and `ovpn` live in the same module, it's tempting to have `netstack` import internal helpers (e.g., a shared IP-header parser) "to avoid duplication."
**Why it's wrong:** This silently couples the netstack package to `ovpn`'s protocol internals, defeats the explicit design goal of `netstack` being generically useful to any `io.ReadWriteCloser`-shaped session (not just `ovpn.Session`), and makes it impossible to unit-test `netstack` without a real handshake.
**Do this instead:** If code truly needs sharing (e.g., an IP-header codec), put it in a small standalone package with no OpenVPN-specific knowledge (e.g. a tiny internal `ipheader` helper imported by both, or just duplicate the ~20 lines — it's genuinely small). `netstack`'s only contract with `ovpn` should be the `io.ReadWriteCloser` shape of `Session` plus the assigned-IP value passed into `Attach`.

## Integration Points

### External Services

| Service | Integration Pattern | Notes |
|---------|---------------------|-------|
| Real OpenVPN 2.6 client (Docker) | `interop/` harness: containerized client connects over UDP to a `govpn`-embedding test server process; packet captures verify handshake/data/ping/HTTP | Required as a v1 gate per PROJECT.md, not optional polish — most protocol bugs only surface here, not in unit tests |
| Caller's application (Voxio, or any embedder) | `Config.OnSession` callback receiving `*Session`; either bound to a TUN device or consumed via `netstack` | This is the entire public contract — keep it exactly as small as PROJECT.md's usage example shows |
| `net/http` (via `netstack.ListenTCP`) | Standard `net.Listener` — any stdlib-compatible HTTP server works unmodified once handed the tunnel-only listener | Used by the example web server; proves `netstack`'s TCP is "good enough," not full-conformance |

### Internal Boundaries

| Boundary | Communication | Notes |
|----------|---------------|-------|
| Server mux ↔ per-session control goroutine | buffered channel (inbox) | non-blocking send from mux; slow/stuck session must not stall the shared UDP reader |
| `controlconn` ↔ `crypto/tls` | `net.Conn` interface (`Read`/`Write`/`Close`/deadlines) | this is *the* seam that makes the whole "reuse stdlib TLS" bet work — get its blocking semantics right first, in isolation, before wiring a real client at it |
| `internal/reliable` ↔ everything touching it | mutex-guarded struct, not channels | see Pattern 2 / Anti-Pattern 3 |
| `ovpn.Session` ↔ `netstack` | `io.ReadWriteCloser` only | see Anti-Pattern 4 — the cleanliness of this boundary is itself validated by whether `netstack` needs anything else |
| `internal/keys` ↔ everything | pure function, no shared state | easiest component to test in total isolation; do this first among the crypto pieces given its risk profile |

## Suggested Build Order (dependency- and risk-driven)

Bottom-up by dependency, but front-loaded toward the highest-uncertainty pieces per PROJECT.md's own risk assessment (Key Method 2 and the reliability layer are called out there as the two "no stdlib pattern" unknowns):

1. **`internal/wire`** — opcode/header encode-decode. Pure, zero risk, fixture-testable against real packet captures. No dependencies.
2. **`internal/keys`** — Key Method 2 PRF, in parallel with (1). Pure function; highest-priority unknown per PROJECT.md — verify byte-exact against `ssl.c`/`crypto.c` before any networking code depends on it. Can and should be built with golden-vector tests before a single UDP packet is sent anywhere.
3. **`internal/tlscrypt`** — wrap/unwrap, in parallel with (1)/(2). Pure, testable against a real client-generated capture.
4. **`internal/reliable`** — ACK/retransmit/reorder state machine, in parallel with (1)-(3) once its input/output contract (packet-id, payload, ack-ids) is fixed. Pure state machine, testable via injected fake clock and synthetic loss/reorder/duplicate scenarios — no real network needed. This is the second called-out unknown; get it solid via unit tests before integration.
5. **`internal/controlconn`** — first real integration point, wiring (1)+(3)+(4) to an actual `net.PacketConn`. Validate with a loopback UDP pair (two local processes speaking the wire format) before touching a real client — isolates framing bugs from TLS/crypto bugs.
6. **TLS handshake integration** — `tls.Server(controlConn, cfg).Handshake()`. First against the loopback harness (cheap iteration), then against the real OpenVPN 2.6 client via the Docker interop harness. **First go/no-go milestone:** a successful real-client TLS handshake (no data channel yet) proves framing + reliability + tls-crypt are protocol-correct.
7. **Key Method 2 wiring** — exchange the struct over the now-established `tls.Conn`, feed `internal/keys` (already unit-verified in step 2). Cross-check derived keys against `openvpn --verb 6` debug output from the real client.
8. **`internal/datachannel`** — AEAD encrypt/decrypt + replay window. Unit-test with fixed key/nonce vectors first (in parallel with steps 5-7, since it has no dependency on the control channel being done), then wire to real derived keys from step 7. **Second go/no-go milestone:** real client, real encrypted ping round-trip through the tunnel.
9. **`ovpn.Session` + `Server`/`Config` public API** — glue layer; by this point every hard protocol piece is proven against a real client, so this is mostly plumbing (session table, IP assignment from `Config.Network`, `OnSession` callback wiring).
10. **`netstack` package** — independently buildable and unit-testable against a fake `Session` (`io.Pipe` pair) *starting as early as the `Session` `io.ReadWriteCloser` contract is fixed* — does not need to wait for step 9 to be functionally complete, only for the interface shape to be settled. Integrate with a real `Session` once step 9 lands.
11. **`examples/webserver`** — last; exercises the full stack (`ovpn` + `netstack` TCP + `net/http`) for the interop harness's HTTP-through-tunnel verification.

**Parallelizable tracks:** steps 1-4 are mutually independent pure-code work items (none depends on another) — good candidates for separate parallel plans/phases. `netstack` (step 10) is independently parallelizable against a fake `Session` from very early on. The unavoidably serial chain is 5→6→7→8 (`controlconn` → real-client TLS handshake → Key Method 2 → data channel), because each stage can only be trusted once proven against a real client — this chain should dominate the roadmap's phase ordering and risk flagging, not the pure-code pieces around it.

## Sources

- [OpenVPN Wire Protocol (work in progress) — openvpn.github.io/openvpn-rfc](https://openvpn.github.io/openvpn-rfc/openvpn-wire-protocol.html) — MEDIUM/HIGH confidence; closest thing to an authoritative spec, but self-described as work-in-progress and PROJECT.md is correct that the C source (`ssl.c`/`crypto.c`) remains the final authority for byte-exact details, especially Key Method 2.
- [OpenVPN Reliability Layer module — build.openvpn.net/doxygen/group__reliable.html](https://build.openvpn.net/doxygen/group__reliable.html) — MEDIUM confidence; doxygen-generated from the actual C source, useful for reliability-layer shape (ACK array sizes, retransmit default of 2s) but should be cross-checked against current source during implementation.
- [ooni/minivpn — github.com/ooni/minivpn](https://github.com/ooni/minivpn) — MEDIUM confidence; closest known prior art (pure-Go OpenVPN protocol implementation, client-side, explicitly research-grade/not production-hardened). Useful as an existence proof of the layered architecture (TLS-over-framing, control/data channel split, reliability layer) described here, not as a source of verified byte-level correctness.
- Go stdlib documentation for `net.Conn`, `net.PacketConn`, `net.UDPConn` concurrency guarantees, `crypto/tls.Server`, `io.Pipe` — HIGH confidence, well-established stdlib behavior (`net.Conn` implementations are documented safe for concurrent use by multiple goroutines; `tls.Server(conn, config)` accepts any `net.Conn`).
- PROJECT.md and `openvpn-go-briefing.md` (this repo) — HIGH confidence as the source of project-specific constraints (stdlib-only, tls-crypt in v1, fixed AES-256-GCM, `topology subnet` only, netstack scope) that this architecture is designed against.

---
*Architecture research for: embeddable Go OpenVPN server protocol library*
*Researched: 2026-08-22*
