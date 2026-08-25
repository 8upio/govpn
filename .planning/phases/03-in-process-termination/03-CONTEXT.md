# Phase 3: In-Process Termination - Context

**Gathered:** 2026-08-25
**Status:** Ready for planning

<domain>
## Phase Boundary

Tunnel traffic terminates entirely in-process — clients ping the server, exchange UDP, and load a web page — in an ordinary container with no TUN device and no `CAP_NET_ADMIN`. This phase delivers: the userspace netstack subpackage (IP/UDP header parse+build, destination demux, minimal server-side TCP, ICMP echo responder), `Attach`/`Detach` session routing, and the example web server reachable only through the tunnel, all verified through the existing Docker interop harness. Out of scope: TUN/TAP devices, general-purpose routing/forwarding, client-initiated TCP from the server side, congestion control, IPv6.

</domain>

<decisions>
## Implementation Decisions

### Netstack API shape
- Single public subpackage `netstack` (import `github.com/8upio/govpn/netstack`) exposing a `Stack` with `ListenUDP(port) (net.PacketConn, error)`, `ListenTCP(port) (net.Listener, error)`, `Attach(sess, ip)` — embedders use it directly; the core `ovpn` package stays independent of it (proves the `Session` boundary is clean)
- Explicit attachment: the embedder calls `stack.Attach(sess, sess.AssignedIP())` from `OnSession`; detach happens when the stack's per-session read loop sees `Session.Read` return an error (session closed). No netstack coupling in `ovpn.Config`
- UDP demux: packets addressed to (server tunnel IP, port) route to that port's `ListenUDP` conn; listeners open on arbitrary ports at runtime. A catch-all port-range API is deferred until a real RTP consumer needs it
- Outbound fail-closed: writes through the stack carry the server tunnel IP as source; anything else is dropped

### Minimal TCP scope
- Server-side accept only: LISTEN → SYN_RCVD → ESTABLISHED → close states; no client-initiator, no simultaneous-open (per the project briefing)
- Reliability: fixed RTO with doubling on retransmit, cumulative ACKs only (no SACK), in-order delivery with a bounded out-of-order buffer
- Flow control: fixed advertised receive window (~64KB), respect the peer's advertised window, no congestion control beyond a fixed in-flight cap — tunnel-quality links only
- Close: proper bidirectional FIN handshake plus a short-timer TIME_WAIT; RST on unexpected segments — browsers must not hang on page loads

### Example server + harness
- `examples/tunnelweb/main.go` — one command to run; embeds ovpn + netstack; serves an interactive landing page plus 4 subpages (status, about, echo-test, headers) via stdlib `http.Serve` on the netstack listener; plain embedded HTML/CSS, no JS build step, no external assets
- Harness: extend the existing interop scenario table — client container runs `ping` (ICMP), a UDP round-trip probe, and `curl` against the landing page + one subpage asserting content markers; `docker inspect` re-asserts the server container has no TUN device and no CAP_NET_ADMIN
- ICMP: echo responder for the server tunnel IP only (~20 lines); all other ICMP dropped silently
- Fast-tier testing: a fake `Session` (in-memory pipe) drives the stack with hand-built packets — no Docker needed to test the netstack itself; the Docker tier reuses the real client

### Claude's Discretion
- Internal structure of the netstack package (files, state-machine layout, timer wiring)
- Exact window/buffer sizes and timer constants, consistent with the "tunnel-quality link" scope
- Landing/subpage content details (must be interactive enough to demo, content at discretion)

</decisions>

<code_context>
## Existing Code Insights

### Reusable Assets
- `Session` (`io.ReadWriteCloser`, one IP packet per Read/Write, `AssignedIP()`, `OnSession` at tunnel-up) — the exact boundary the stack consumes; a fake Session is trivial to build against it
- `internal/datachan/ping.go` — ICMP-adjacent precedent (OpenVPN ping magic absorption); note OpenVPN pings are NOT ICMP — the netstack's ICMP responder is new code
- Existing checksum/binary parsing conventions in `internal/wire` (bounds-checked, typed errors, citation headers)
- `test/interop` harness + scenario table, `docker inspect` assertions, entrypoint.sh probe pattern

### Established Patterns
- Stdlib-only; deterministic clock-injected tests for timer logic (reliable package precedent)
- Per-connection state guarded by mutex or channel-select; teardown via stopCh/stopOnce (Session precedent); lock nesting documented (sess.mu → srv.mu precedent)
- Two-tier testing: fast (`go test -race`, no Docker) + `interop` build tag
- AST-based prohibition gates in gates_test.go (extend for netstack prohibitions if planned)

### Integration Points
- `OnSession` callback in the example: `stack.Attach(sess, sess.AssignedIP())`
- `Session.Read` loop inside the stack: parse IP header → ICMP/UDP/TCP demux
- `Session.Write`: stack-built reply packets (source = server tunnel IP)
- `test/interop/entrypoint.sh` + `interop_test.go`: new probes (ping to server IP already exists from Phase 2's harness ICMP responder — NOTE: Phase 2's harness implemented ICMP echo IN THE HARNESS server via Session.Read/Write; Phase 3 moves that capability into the netstack package and the example replaces the hand-rolled responder)

</code_context>

<specifics>
## Specific Ideas

- PROJECT.md/CLAUDE.md explicitly rule out gVisor and any TUN library — the netstack is hand-built against `encoding/binary` and stdlib only
- The phase's dependency note: the netstack can be built against a fake `Session` first — planning should exploit this for wave parallelism (netstack fast-tier work does not need the live tunnel)
- IPv4 only for v1 (matches `Config.Network` and the 10.8.0.0/24 harness)

</specifics>

<deferred>
## Deferred Ideas

- Catch-all UDP port-range demux for RTP-style dynamic workloads (until a real consumer needs it)
- ICMP error generation (port unreachable, TTL exceeded)
- IPv6, TUN/TAP integration, client-initiated TCP, SACK/congestion control

</deferred>
