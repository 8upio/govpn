# Roadmap: govpn

## Overview

Four vertical slices take govpn from an empty module to a real, unmodified OpenVPN 2.6 client exchanging traffic with a Go process. Each phase ends at a gate that only a real client can pass, because every byte-layout mistake in this protocol is silent by design: wrong PRF, wrong tls-crypt ordering, or a missing retransmit all read as working code. Phase 1 gets a real client through the TLS handshake (wire format, tls-crypt, reliability, framing `net.Conn`, and the Docker harness that gates everything after it). Phase 2 turns the handshake into a tunnel — Key Method 2 derivation, AES-256-GCM data channel, PUSH_REPLY — until an encrypted ping round-trips. Phase 3 terminates that traffic in-process through the userspace netstack and loads a web page through the tunnel with no TUN device and no `CAP_NET_ADMIN`. Phase 4 makes a session survive a real deployment: renegotiation, clean shutdown, no leaks.

**Mode:** Vertical MVP — every phase ends in something demonstrable against the reference client, not in a finished layer.

## Phases

**Phase Numbering:**
- Integer phases (1, 2, 3): Planned milestone work
- Decimal phases (2.1, 2.2): Urgent insertions (marked with INSERTED)

Decimal phases appear between their surrounding integers in numeric order.

- [ ] **Phase 1: Handshake** - A real OpenVPN 2.6 client in Docker completes the TLS handshake against the library
- [ ] **Phase 2: Tunnel Up** - Client gets its IP, keys derive byte-exactly, and an encrypted ping round-trips
- [ ] **Phase 3: In-Process Termination** - Ping, UDP and an HTTP page load through the tunnel via the userspace netstack
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
**Plans**: TBD

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
**Plans**: TBD

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
**Plans**: TBD
**UI hint**: yes

### Phase 4: Durable Sessions
**Goal**: A connected client stays usable for hours and leaves cleanly — key renegotiation does not break traffic, and dead sessions do not accumulate
**Mode:** mvp
**Depends on**: Phase 2 (uses the Phase 3 example as the traffic source for soak runs)
**Requirements**: SESS-04, SESS-05
**Success Criteria** (what must be TRUE):
  1. A client renegotiates its keys (default `reneg-sec 3600`, exercised in the harness with a shortened interval) and its HTTP and UDP traffic keeps flowing across the key rollover — the embedder's `Session` stays open, no reconnect
  2. A client sending explicit-exit-notify ends its session immediately, and the embedder observes the `Session` closing rather than waiting for a timeout
  3. Silent sessions time out and are reaped, and `Session.Close()` tears down all state — a soak run over many connect/disconnect cycles shows goroutine and memory counts flat
**Plans**: TBD

## Progress

**Execution Order:**
Phases execute in numeric order: 1 → 2 → 3 → 4

| Phase | Plans Complete | Status | Completed |
|-------|----------------|--------|-----------|
| 1. Handshake | 0/TBD | Not started | - |
| 2. Tunnel Up | 0/TBD | Not started | - |
| 3. In-Process Termination | 0/TBD | Not started | - |
| 4. Durable Sessions | 0/TBD | Not started | - |

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
