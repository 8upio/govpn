# Phase 2: Tunnel Up - Context

**Gathered:** 2026-08-24
**Status:** Ready for planning

<domain>
## Phase Boundary

The client brings its tunnel interface up with a pushed IP and cipher, and encrypted IP packets round-trip between the client and the embedder's `Session`. This phase delivers: Key Method 2 key derivation (TLS 1.0 PRF, byte-exact against the C reference), the control-message exchange (key material, options/OCC, PUSH_REQUEST/PUSH_REPLY), tunnel IP assignment from `Config.Network`, the AES-256-GCM data channel (classic non-epoch packet-id format), keepalive/ping handling inside the library, and the `Session` as an `io.ReadWriteCloser` for raw IP packets. Out of scope: the userspace netstack (Phase 3), renegotiation/soft reset (Phase 4), NCP/epoch data format, routes/redirect-gateway pushes.

</domain>

<decisions>
## Implementation Decisions

### Tunnel IP assignment & PUSH_REPLY
- IP allocation: sequential first-free from `Config.Network` pool, server = first host IP, 1 IP per client, assigned at PUSH_REPLY time
- IP reuse: freed on session close, immediately reusable — no lease persistence, no hold-down timer
- PUSH_REPLY contents: minimal reference defaults only — `ifconfig` (subnet topology), `topology subnet`, `cipher AES-256-GCM`, `keepalive 10 60` (fixed, not configurable in v1)
- Duplicate CN: allowed, each connection gets its own IP (reference `--duplicate-cn` semantics)

### Session API semantics
- Framing: one full IP packet per `Read`/`Write` call (datagram semantics); short-buffer `Read` returns an error, never silently truncates
- Backpressure: bounded inbound queue, overflow drops packets like a congested link (mirrors Phase 1's `sess.inbound` policy; upper layers retransmit)
- Surface: `AssignedIP() net.IP`, existing `PeerCN`, `ConnectionState()`; keepalive and data-channel bookkeeping stay internal
- `OnSession` timing: fires only after Key Method 2 + PUSH_REPLY complete and data-channel keys are live — the Session is immediately usable when the callback runs (moves the Phase-1 callsite deeper)

### Data-channel crypto & control messages
- Packet-ID format: classic non-epoch (32-bit packet-id, 4-byte explicit ID on the wire; AEAD nonce = packetID ‖ implicit-IV from key expansion). Epoch format out of scope. Byte offsets verified against `crypto.c`/`ssl.c` per the STATE.md research flag before any data-channel code
- Replay protection: 64-wide sliding window per data-channel key direction, same design as Phase 1's tls-crypt window, mirroring `packet_id.c`
- Keepalive: recognize the 16-byte ping magic (`ping.c` `ping_string`) inside the library — absorbed, never surfaced to `Session.Read`; server sends its own pings per the pushed `keepalive 10 60`
- Golden vectors: derived from the C reference checkout (instrumented harness or live-client extraction), committed with provenance like Phase 1's corpus — never hand-derived from RFC text alone

### Claude's Discretion
- Internal package layout for the data channel and key derivation (e.g. `internal/keyderiv`, `internal/datachan`)
- Exact bounded-queue depths, matched to Phase 1 precedents
- How the PUSH_REQUEST/PUSH_REPLY exchange is driven over the TLS stream (control-message loop design)

</decisions>

<code_context>
## Existing Code Insights

### Reusable Assets
- `internal/wire` — control-packet parse/serialize incl. golden-vector pattern
- `internal/tlscrypt` — Wrapper with sliding replay window (design template for the data-channel window), frozen-timestamp long-form packet IDs
- `internal/reliable` + `internal/ctrlconn` — reliability layer and the `net.Conn` the TLS stream runs over; Key Method 2 payload already arrives buffered in `ctrlconn.Conn` (01-03 left it unread by design, T-01-17)
- `ovpn.go`/`session.go` — `Server`, `Session` (stopCh/stopOnce teardown, `OnSession`/`OnSessionPanic`, injectable `handshakeWindow`), per-session tls-crypt wrapper
- `test/interop` harness — scenario table (clean-small/clean-large/lossy-large), pcap assertions, golden export tooling, `cmd/gentestpki`

### Established Patterns
- Stdlib-only; every wire structure verified against the C reference at /Users/svenloth/dev/openvpn-reference (release/2.6)
- Two-tier testing: fast tier (`go test -race ./...`, no Docker) + `interop` build tag for Docker-gated live-client tests
- Golden vectors committed under `testdata/golden/` with provenance README; regeneration only via deliberate `make golden`
- Per-session state (wrapper, windows) — never server-global; deterministic clock-injected tests for timer logic

### Integration Points
- `runHandshake` (ovpn.go): after `Handshake()` returns nil is where Key Method 2 processing begins — the client's payload is already buffered in `sess.conn`
- `handleDatagram` (ovpn.go): data-channel opcodes (P_DATA_V1/V2) must be routed to the session's data path instead of the control pump
- `Session.Read`/`Write` become the IP-packet path; `OnSession` callsite moves after tunnel-up

</code_context>

<specifics>
## Specific Ideas

- STATE.md blocker (carried from init): Key Method 2 byte offsets and classic-vs-epoch packet-ID format MUST be verified against the C source before data-channel code is written — this is a planning/research gate, not an implementation afterthought
- CLAUDE.md: the TLS 1.0 PRF (MD5/SHA1) needs `//nolint:gosec` annotations with rationale; do not use `ExportKeyingMaterial`

</specifics>

<deferred>
## Deferred Ideas

- Routes / redirect-gateway pushes — Phase 3 decides reachability through the netstack
- Configurable keepalive values in `Config` — revisit if an embedder needs it
- Session stats surface (byte/packet counters) — post-v1
- Epoch data-channel format / NCP — out of v1 scope entirely

</deferred>
