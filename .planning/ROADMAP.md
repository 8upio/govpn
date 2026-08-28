# Roadmap: govpn

## Overview

Four vertical slices take govpn from an empty module to a real, unmodified OpenVPN 2.6 client exchanging traffic with a Go process. Each phase ends at a gate that only a real client can pass, because every byte-layout mistake in this protocol is silent by design: wrong PRF, wrong tls-crypt ordering, or a missing retransmit all read as working code. Phase 1 gets a real client through the TLS handshake (wire format, tls-crypt, reliability, framing `net.Conn`, and the Docker harness that gates everything after it). Phase 2 turns the handshake into a tunnel — Key Method 2 derivation, AES-256-GCM data channel, PUSH_REPLY — until an encrypted ping round-trips. Phase 3 terminates that traffic in-process through the userspace netstack and loads a web page through the tunnel with no TUN device and no `CAP_NET_ADMIN`. Phase 4 makes a session survive a real deployment: renegotiation, clean shutdown, no leaks.

**Mode:** Vertical MVP — every phase ends in something demonstrable against the reference client, not in a finished layer.

## Phases

**Phase Numbering:**

- Integer phases (1, 2, 3): Planned milestone work
- Decimal phases (2.1, 2.2): Urgent insertions (marked with INSERTED)

Decimal phases appear between their surrounding integers in numeric order.

- [x] **Phase 1: Handshake** - A real OpenVPN 2.6 client in Docker completes the TLS handshake against the library (completed 2026-08-24)
- [x] **Phase 2: Tunnel Up** - Client gets its IP, keys derive byte-exactly, and an encrypted ping round-trips (completed 2026-08-25)
- [x] **Phase 3: In-Process Termination** - Ping, UDP and an HTTP page load through the tunnel via the userspace netstack (completed 2026-08-27)
- [ ] **Phase 4: Durable Sessions** - Sessions survive renegotiation and end cleanly without leaks

## Phase Details

### Phase 1: Handshake

**Goal**: A real, unmodified OpenVPN 2.6 client connects to a Go program embedding the library and reaches "TLS established" — over tls-crypt, with certificate-based mutual auth
**Mode:** mvp
**Depends on**: Nothing (first phase)
**Requirements**: WIRE-01, WIRE-04, CTRL-01, CTRL-02, CTRL-03, SESS-01, VRFY-01
**Success Criteria** (what must be TRUE):

  1. An embedder can start a server with `ovpn.NewServer(Config{...}).Serve(pc)` over UDP, and one command stands up a pinned OpenVPN 2.6 client container (self-built `debian:bookworm-slim`) that connects to it with generated certs and a tls-crypt key
  2. The real client completes the full handshake — HARD_RESET_V2 through TLS established — and both sides report the peer's verified certificate CN
  3. A packet capture shows every control packet tls-crypt wrapped; tls-crypt wrap/unwrap and control-packet parse→serialize round-trip byte-exactly against isolated vectors taken from the C reference (`tls_crypt.c`, `ssl_pkt.c`)
  4. The handshake still completes with a realistic multi-KB certificate chain (fragmented across several control packets) and with 5–10% synthetic packet loss injected on the link

**Plans**: 4/4 plans executed

Plans:
**Wave 1**

- [x] 01-01-PLAN.md — Tracer: real UDP → tls-crypt → wire → HARD_RESET answered, plus isolated WIRE-01/WIRE-04 vectors

**Wave 2** *(blocked on Wave 1 completion)*

- [x] 01-02-PLAN.md — Docker interop harness: pinned OpenVPN 2.6 client reaches the library; capture proves tls-crypt wrapping

**Wave 3** *(blocked on Wave 2 completion)*

- [x] 01-03-PLAN.md — Reliability layer + control-channel `net.Conn` + `crypto/tls`: real client reaches TLS established

**Wave 4** *(blocked on Wave 3 completion)*

- [x] 01-04-PLAN.md — Lossy link + multi-KB cert chain, real-client golden vectors, CI

### Phase 2: Tunnel Up

**Goal**: The client brings its tunnel interface up with a pushed IP and cipher, and encrypted IP packets round-trip between the client and the embedder's `Session`
**Mode:** mvp
**Depends on**: Phase 1
**Requirements**: WIRE-02, WIRE-03, CTRL-04, CTRL-05, DATA-01, DATA-02, DATA-03, SESS-02, SESS-03, VRFY-03
**Success Criteria** (what must be TRUE):

  1. The client logs "Initialization Sequence Completed" after receiving a PUSH_REPLY with a tunnel IP from the configured `Config.Network` (`topology subnet`, server = first host IP, 1 IP per client), an explicit `cipher AES-256-GCM`, and keepalive parameters
  2. The embedder's `OnSession` callback receives a `Session` (`io.ReadWriteCloser`) exposing that assigned tunnel IP; a ping from the client arrives as a raw IP packet on `Read`, and the reply written back reaches the client — an encrypted round-trip in both directions
  3. TLS 1.0 PRF and Key Method 2 expansion (per-direction cipher/HMAC slots and the implicit-IV extraction) pass golden-vector tests derived from `ssl.c`/`crypto.c` before any live data-channel traffic runs
  4. Replayed and out-of-window data packets are dropped, and keepalive/ping magic packets are answered inside the library — the Session consumer never sees one
  5. The harness runs a lossy scenario (5–10% packet loss and reordering) in which handshake and ping round-trip both still succeed

**Plans**: 4/4 plans executed

Plans:
**Wave 1**

- [x] 02-01-PLAN.md — Key Method 2 exchange + byte-exact key derivation (`internal/keyderiv`); closes the PRF/key-expansion gate before any live data-channel traffic

**Wave 2** *(blocked on Wave 1 completion)*

- [x] 02-02-PLAN.md — Tunnel up: PUSH_REQUEST/PUSH_REPLY, tunnel-IP pool, `Session.AssignedIP()`, `OnSession` moves past tunnel-up

**Wave 3** *(blocked on Wave 2 completion)*

- [x] 02-03-PLAN.md — AES-256-GCM data channel (`internal/datachan`), peer-id demux, replay window, ping absorption, real `Session.Read`/`Write`

**Wave 4** *(blocked on Wave 3 completion)*

- [x] 02-04-PLAN.md — Lossy-link tunnel + ping round-trip, real-client data-channel golden vectors, standing prohibition gates

### Phase 3: In-Process Termination

**Goal**: Tunnel traffic terminates entirely in-process — clients ping the server, exchange UDP, and load a web page — in an ordinary container with no TUN device and no `CAP_NET_ADMIN`
**Mode:** mvp
**Depends on**: Phase 2 (the netstack itself can be built in parallel against a fake `Session`, which is what proves the `Session` boundary is clean)
**Requirements**: NET-01, NET-02, NET-03, NET-04, XMPL-01, VRFY-02
**Success Criteria** (what must be TRUE):

  1. The real client can `ping` the server's tunnel IP and gets replies from the built-in ICMP echo responder
  2. `ListenUDP(port)` returns a `net.PacketConn` that unmodified socket-based code uses to round-trip a datagram with a tunnel client; listeners open on arbitrary ports at runtime and sessions attach/detach with correct IP→session routing (RTP-style workloads)
  3. `ListenTCP(port)` returns a `net.Listener` that stdlib `http.Serve` accepts on, and the example web server — one command to run — serves an interactive landing page plus 3–5 subpages that load in a browser inside the client container and are unreachable from outside the tunnel
  4. One automated harness run verifies ICMP, a UDP round-trip, and an HTTP page load through the tunnel from the real client, with no `/dev/net/tun` and no `CAP_NET_ADMIN` in the server container

**Plans**: 6/6 plans executed
**UI hint**: yes

Plans:
**Wave 1**

- [x] 03-01-PLAN.md — Tracer: `netstack` package (Stack, Attach/Detach, IPv4, ICMP echo, injected Clock, `net.Error` deadlines) — a real client's ping answered by the library, harness responder relocated, import-direction gates

**Wave 2** *(blocked on Wave 1 completion)*

- [x] 03-02-PLAN.md — `ListenUDP` as a genuine `net.PacketConn`: port demux, arbitrary runtime ports, multi-session routing, real deadlines (NET-01, NET-04)
- [x] 03-03-PLAN.md — Minimal server-side TCP: segment codec, passive-open state machine, fixed-RTO retransmission, bounded reorder buffer, RST rules, backlog and half-open caps (NET-02)

**Wave 3** *(blocked on Wave 2 completion)*

- [x] 03-04-PLAN.md — `net/http` conformance: real deadlines, `CloseWrite` half-close, stdlib `http.Serve` round-trip over the netstack listener (NET-02)

**Wave 4** *(blocked on Wave 3 completion)*

- [x] 03-05-PLAN.md — `examples/tunnelweb`: one command, landing page plus 4 subpages per the UI-SPEC contract, reachable only through the tunnel (XMPL-01)

**Wave 5** *(blocked on Wave 4 completion)*

- [x] 03-06-PLAN.md — Interop harness: one run verifying ICMP, UDP round-trip, and HTTP page loads from the real client, with no TUN device and no CAP_NET_ADMIN (VRFY-02)

### Phase 4: Durable Sessions

**Goal**: A connected client stays usable for hours and leaves cleanly — key renegotiation does not break traffic, and dead sessions do not accumulate
**Mode:** mvp
**Depends on**: Phase 2 (uses the Phase 3 example as the traffic source for soak runs)
**Requirements**: SESS-04, SESS-05
**Success Criteria** (what must be TRUE):

  1. A client renegotiates its keys (default `reneg-sec 3600`, exercised in the harness with a shortened interval) and its HTTP and UDP traffic keeps flowing across the key rollover — the embedder's `Session` stays open, no reconnect
  2. A client sending explicit-exit-notify ends its session immediately, and the embedder observes the `Session` closing rather than waiting for a timeout
  3. Silent sessions time out and are reaped, and `Session.Close()` tears down all state — a soak run over many connect/disconnect cycles shows goroutine and memory counts flat

**Plans**: 4/4 plans executed

Plans:
**Wave 1**

- [x] 04-01-PLAN.md — Tracer: soft-reset renegotiation — two-slot key state (primary/lame-duck), key-id increment rule, new TLS+KM2 under the new key-id with no PUSH re-exchange, server-side `Config.RenegSec` timer, key-id hard-error validation (SESS-04)

**Wave 2** *(blocked on Wave 1 completion)*

- [x] 04-02-PLAN.md — Exit-notify (data-channel OCC_EXIT, post-decrypt only), idle-session reaping on an injectable clock, `io.EOF` from Read/Write after every teardown cause, no per-session goroutine leaks (SESS-05)

**Wave 3** *(blocked on Wave 2 completion)*

- [x] 04-03-PLAN.md — Interop: a real OpenVPN 2.6 client renegotiates twice with HTTP+UDP flowing across the rollovers and zero reconnects, then leaves via explicit-exit-notify with the close observed immediately (SESS-04, SESS-05)

**Wave 4** *(blocked on Wave 3 completion)*

- [x] 04-04-PLAN.md — Soak: 20 real connect/disconnect cycles against one server process, goroutine count and post-GC HeapAlloc flat against a post-first-cycle baseline, on its own `make soak` target (SESS-05)

## Progress

**Execution Order:**
Phases execute in numeric order: 1 → 2 → 3 → 4

| Phase | Plans Complete | Status | Completed |
|-------|----------------|--------|-----------|
| 1. Handshake | 4/4 | Complete    | 2026-08-24 |
| 2. Tunnel Up | 4/4 | Complete    | 2026-08-25 |
| 3. In-Process Termination | 6/6 | Complete    | 2026-08-27 |
| 4. Durable Sessions | 4/4 | In Progress|  |

## Requirement Coverage

| Phase | Requirements | Count |
|-------|--------------|-------|
| 1. Handshake | WIRE-01, WIRE-04, CTRL-01, CTRL-02, CTRL-03, SESS-01, VRFY-01 | 7 |
| 2. Tunnel Up | WIRE-02, WIRE-03, CTRL-04, CTRL-05, DATA-01, DATA-02, DATA-03, SESS-02, SESS-03, VRFY-03 | 10 |
| 3. In-Process Termination | NET-01, NET-02, NET-03, NET-04, XMPL-01, VRFY-02 | 6 |
| 4. Durable Sessions | SESS-04, SESS-05 | 2 |

**Total: 25/25 v1 requirements mapped. No orphans, no duplicates.**

## Research Flags

Carried from `research/SUMMARY.md` — phases that need source-level verification during planning:

- **Phase 1**: tls-crypt Ka/Ke key-file slot convention (`tls_crypt_init()`/`tls_crypt_wrap()`); control-packet fragmentation threshold against realistic multi-KB cert chains
- **Phase 2**: Key-expansion slot offsets cross-checked line-by-line against `ssl.c`/`crypto.c`; classic 4-byte vs epoch packet-ID format — confirm from the real client's first P_DATA_V2 capture; PUSH_REPLY tolerances (does the 2.6 client hard-fail or warn on missing optional directives?)
- **Phases 3–4**: Standard patterns (userspace IP/UDP/TCP/ICMP parsing, Go timer/mutex idioms) — research phase can be skipped

Reference checkout for all byte-level verification: `/Users/svenloth/dev/openvpn-reference` (branch `release/2.6`, sources under `src/openvpn/`).

---
*Roadmap created: 2026-08-22*
*Granularity: coarse | Mode: vertical MVP*
