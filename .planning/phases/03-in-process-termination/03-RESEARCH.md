# Phase 3: In-Process Termination - Research

**Researched:** 2026-08-25
**Domain:** Userspace IPv4/ICMP/UDP/minimal-TCP netstack (RFC-land), Go `net` interface contracts consumed by `net/http`
**Confidence:** HIGH

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions

**Netstack API shape**
- Single public subpackage `netstack` (import `github.com/8upio/govpn/netstack`) exposing a `Stack` with `ListenUDP(port) (net.PacketConn, error)`, `ListenTCP(port) (net.Listener, error)`, `Attach(sess, ip)` — embedders use it directly; the core `ovpn` package stays independent of it (proves the `Session` boundary is clean)
- Explicit attachment: the embedder calls `stack.Attach(sess, sess.AssignedIP())` from `OnSession`; detach happens when the stack's per-session read loop sees `Session.Read` return an error (session closed). No netstack coupling in `ovpn.Config`
- UDP demux: packets addressed to (server tunnel IP, port) route to that port's `ListenUDP` conn; listeners open on arbitrary ports at runtime. A catch-all port-range API is deferred until a real RTP consumer needs it
- Outbound fail-closed: writes through the stack carry the server tunnel IP as source; anything else is dropped

**Minimal TCP scope**
- Server-side accept only: LISTEN → SYN_RCVD → ESTABLISHED → close states; no client-initiator, no simultaneous-open (per the project briefing)
- Reliability: fixed RTO with doubling on retransmit, cumulative ACKs only (no SACK), in-order delivery with a bounded out-of-order buffer
- Flow control: fixed advertised receive window (~64KB), respect the peer's advertised window, no congestion control beyond a fixed in-flight cap — tunnel-quality links only
- Close: proper bidirectional FIN handshake plus a short-timer TIME_WAIT; RST on unexpected segments — browsers must not hang on page loads

**Example server + harness**
- `examples/tunnelweb/main.go` — one command to run; embeds ovpn + netstack; serves an interactive landing page plus 4 subpages (status, about, echo-test, headers) via stdlib `http.Serve` on the netstack listener; plain embedded HTML/CSS, no JS build step, no external assets
- Harness: extend the existing interop scenario table — client container runs `ping` (ICMP), a UDP round-trip probe, and `curl` against the landing page + one subpage asserting content markers; `docker inspect` re-asserts the server container has no TUN device and no CAP_NET_ADMIN
- ICMP: echo responder for the server tunnel IP only (~20 lines); all other ICMP dropped silently
- Fast-tier testing: a fake `Session` (in-memory pipe) drives the stack with hand-built packets — no Docker needed to test the netstack itself; the Docker tier reuses the real client

### Claude's Discretion
- Internal structure of the netstack package (files, state-machine layout, timer wiring)
- Exact window/buffer sizes and timer constants, consistent with the "tunnel-quality link" scope
- Landing/subpage content details (must be interactive enough to demo, content at discretion)

### Deferred Ideas (OUT OF SCOPE)
- Catch-all UDP port-range demux for RTP-style dynamic workloads (until a real consumer needs it)
- ICMP error generation (port unreachable, TTL exceeded)
- IPv6, TUN/TAP integration, client-initiated TCP, SACK/congestion control
</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|--------------------|
| NET-01 | `ListenUDP(port)` returns a `net.PacketConn` that transparently demuxes tunnel UDP traffic (parse/build IP+UDP headers), usable by unmodified socket-based code | RFC 768 header/pseudo-header/checksum research (Pattern 2); `net.PacketConn` contract read from stdlib (Code Examples); Validation Architecture test map |
| NET-02 | Minimal server-side TCP: `ListenTCP(port)` returns a `net.Listener` sufficient to serve HTTP to tunnel clients (stdlib-only, no gVisor) | RFC 9293 header/state-machine/MSS/ISN/RST/TIME-WAIT research (Pattern 3, Pitfalls 1-4); `net/http` deadline/half-close requirements read from stdlib source (Pitfalls 1-3); Don't Hand-Roll table |
| NET-03 | Built-in ICMP echo responder: tunnel clients can ping the server tunnel IP | RFC 792 research (Pattern 1); existing harness `icmpEchoReply`/`internetChecksum` code read directly (Code Examples), which this requirement moves into the netstack package |
| NET-04 | Sessions attach/detach dynamically with IP→session routing; UDP listeners can be opened on arbitrary ports at runtime | Pattern 4 (single-reader-per-Session dispatch, Read/Write concurrency contracts verified against `session.go`/`internal/datachan`); Pattern 5 (local session interface); Security Domain (source-IP enforcement at Attach) |
| XMPL-01 | Example web server reachable only through the tunnel: interactive landing page plus 3-5 subpages, served via the netstack TCP listener, runnable with a single command | Recommended Project Structure; Environment Availability (Docker/curl); Validation Architecture Wave 0 Gaps (`examples/tunnelweb` does not exist yet) |
| VRFY-02 | End-to-end through the real client: ping (ICMP), UDP round-trip, and HTTP page load through the tunnel all succeed | Validation Architecture (Phase Requirements → Test Map, Wave 0 Gaps); Environment Availability (Docker/curl); Security Domain (container posture re-assertion via `docker inspect`) |
</phase_requirements>

## Summary

This phase is not about a library choice — CLAUDE.md and PROJECT.md already settled that (no gVisor, no TUN library, stdlib only). It is about implementing four RFCs correctly, by hand, against `encoding/binary`: IPv4 (RFC 791) parse/build with the RFC 1071 Internet checksum, ICMP echo (RFC 792), UDP (RFC 768) including the IPv4 pseudo-header checksum, and a deliberately narrow slice of TCP (RFC 9293) — server-side-accept only, fixed RTO, cumulative ACKs, no congestion control. Every wire layout and algorithm below was fetched directly from the RFC text this session (`rfc-editor.org`), the same "read the primary spec directly" discipline this project's own CLAUDE.md already applies to the OpenVPN C reference — not summarized from training memory.

The second half of this research is Go-specific: `net/http`'s `Server.Serve`/`http.Serve` never wraps a caller-supplied `net.Listener` with keep-alive logic (that only happens inside `net.Listen` + `ListenAndServe`), so the netstack's TCP listener does **not** need to implement `SetKeepAlive` for `http.Serve` to work — but it **does** need `SetReadDeadline`/`SetWriteDeadline` to behave correctly, because `(*http.conn).readRequest` calls them unconditionally, and a Read blocked past its deadline must return an error that `errors.Is(err, os.ErrDeadlineExceeded)` recognizes and that satisfies `net.Error` with `Timeout() == true` — verified by reading `net/http/server.go` and `net/net.go` directly from the local Go 1.26.1 toolchain (the same primary-source tier as the RFC reads).

The third finding, which should shape wave planning: `Session.Write` is already safe for concurrent multi-goroutine use — `internal/datachan.Wrapper.Seal` holds its own `mu sync.Mutex`, and `net.PacketConn.WriteTo` is documented concurrency-safe — so the netstack's TCP retransmit-timer goroutine, its ACK-timer goroutine, and an `http.Handler` goroutine can all call `sess.Write` on the same session without any additional locking in the netstack itself. `Session.Read`, by contrast, explicitly documents a single-reader-goroutine contract — the netstack must own exactly one goroutine per attached session that calls `sess.Read`, and fan out to per-port/per-connection state from there.

**Primary recommendation:** Build `netstack` as a subpackage that imports nothing from `ovpn` — define a local, minimal `session` interface (`io.ReadWriteCloser`) so `*ovpn.Session` satisfies it structurally and a fake/in-memory session can too, matching the phase's own stated goal ("the netstack can be built against a fake Session, proving the Session boundary is clean"). One goroutine per attached session reads and demuxes; IPv4/ICMP/UDP handling is synchronous and stateless; TCP is the one place with real per-connection state and timers, modeled after `internal/reliable`'s already-proven injected-`Clock` testability pattern.

## Architectural Responsibility Map

This project has no browser/CDN/DB tiers — the relevant tiers are the ones CLAUDE.md and the phase boundary already draw: the existing crypto/session tier (Phases 1-2), the new netstack tier (this phase), and the application/embedder tier (the example, or any future embedder).

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| IPv4/ICMP/UDP/TCP header parse+build, checksums | Netstack | — | New code this phase; pure RFC implementation, no crypto/session knowledge |
| ICMP echo responder | Netstack | — | NET-03; stateless, answered inline inside the per-session read loop |
| UDP port demux, `net.PacketConn` | Netstack | Application (consumes the `net.PacketConn`) | NET-01; the stack owns the port table, the embedder owns the payload semantics |
| TCP state machine, `net.Listener`/`net.Conn` | Netstack | Application (consumes via `http.Serve`) | NET-02; the stack owns segment reliability, the embedder's `http.Server` owns HTTP semantics |
| Session IP→session routing (`Attach`/`Detach`) | Netstack | Session/Crypto tier (supplies `Read`/`Write`/`AssignedIP`) | NET-04; netstack reads the session boundary but does not modify it |
| Source-IP-spoofing enforcement (packet's IP src must equal the owning session's assigned IP) | Netstack | — | New threat surface this phase introduces (see Security Domain) |
| HTTP request/response semantics, page content | Application (example) | Netstack (transport only) | XMPL-01; `http.Server` and the example's handlers own this, netstack only proves `net.Listener`/`net.Conn` conformance |
| AES-256-GCM encrypt/decrypt, control-channel TLS | Session/Crypto tier (Phases 1-2, unchanged) | — | Out of scope this phase; netstack consumes already-decrypted IP packets |

## Standard Stack

### Core

| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| `encoding/binary` (stdlib) | tracks Go version (repo pins `go 1.24`, toolchain observed: `go1.26.1 darwin/arm64` [VERIFIED: `go version` this session]) | Big-endian field read/write for every header (IP/ICMP/UDP/TCP) | Matches `internal/wire`'s existing convention (bounds-checked, explicit offsets) — no new pattern introduced |
| `net` (stdlib) | same | `net.PacketConn`, `net.Listener`, `net.Conn`, `net.Addr` interfaces the netstack must implement | These are the exact contracts NET-01/NET-02 require ("usable by unmodified socket-based code", "stdlib `http.Serve` accepts on") |
| `sync` / `sync/atomic` / `time` (stdlib) | same | Per-connection state guarding, retransmit timers | Matches `internal/reliable`'s injected-`Clock` precedent (already shipped, security-reviewed) |
| `context` (stdlib) | same | Not required for the netstack's own API surface (CONTEXT.md's `ListenUDP(port)`/`ListenTCP(port)` signatures take no context), but available if a future deadline-aware `Attach` variant is added | No gap; only used if needed |

No third-party dependency is justified or needed for this phase — every byte-manipulation primitive is `encoding/binary` plus manual bit-masking, and every concurrency primitive is stdlib. This matches CLAUDE.md's constraint verbatim and `gates_test.go`'s `TestPhase2NoThirdPartyDependencies` will continue to pass unmodified (it reads `go.mod` directly and fails on any `require`/`replace` line) [VERIFIED: `/Users/svenloth/dev/govpn/gates_test.go` — read this session; the check "reads go.mod directly ... only a `module` line and a `go` directive are permitted"].

### Supporting

| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| none | — | — | This phase adds zero new dependencies |

### Alternatives Considered

| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| Hand-rolled IPv4/ICMP/UDP/TCP parse+build | `github.com/google/gopacket` decoders | Rejected: `gopacket` is explicitly scoped to interop **test tooling only** per CLAUDE.md ("Only inside the interop-testing tooling — not a dependency of the `ovpn` module itself"); pulling it into the core module for production packet building would violate the stdlib-only constraint for a problem this small (4 fixed-shape headers) |
| Hand-rolled minimal server-side TCP | `gvisor.dev/gvisor/pkg/tcpip` | Rejected per CLAUDE.md's own "What NOT to Use" table: a full conformant TCP/IP stack is orders of magnitude more surface area than "serve HTTP through the tunnel" needs |
| Fixed RTO + doubling backoff (CONTEXT.md decision) | RFC 6298's full RTT-measured RTO (SRTT/RTTVAR, Karn's algorithm) [CITED: rfc-editor.org/rfc/9293 — "The RTO MUST be computed according to the algorithm in RFC 6298"] | RFC 9293 mandates RFC 6298 for a **general-purpose, Internet-facing** TCP stack. This project's CONTEXT.md already scoped down to "tunnel-quality links only" with a fixed RTO and doubling backoff — a deliberate, documented deviation from the full RFC, matching the same "minimal server-side TCP suffices" scoping CLAUDE.md's Out-of-Scope table already applies project-wide. Flag this deviation explicitly in code comments (mirroring `internal/reliable`'s own citation-header convention) so a future reader does not mistake it for an oversight. |

**Installation:**
```bash
# No installation step: stdlib only. `go build ./...` picks up the new
# netstack subpackage automatically once its files exist under
# /Users/svenloth/dev/govpn/netstack/.
```

**Version verification:** N/A — no external packages to verify against a registry this phase.

## Package Legitimacy Audit

**Not applicable this phase.** No external packages are installed — the entire netstack implementation is stdlib-only (`encoding/binary`, `net`, `sync`, `sync/atomic`, `time`, `context`, `errors`, `fmt`). `go.mod` remains unmodified (module line + `go 1.24` directive only), enforced by the existing `TestPhase2NoThirdPartyDependencies` gate [VERIFIED: `/Users/svenloth/dev/govpn/gates_test.go:95-115` — read this session; quoted check text above].

**Packages removed due to [SLOP] verdict:** none (none proposed)
**Packages flagged as suspicious [SUS]:** none (none proposed)

## Architecture Patterns

### System Architecture Diagram

```
                         Real OpenVPN 2.6 client
                                   |
                     (encrypted UDP, existing Phase 1-2 code)
                                   |
                                   v
                    +---------------------------+
                    |  ovpn.Session (unchanged)  |   <- Phase 1-2, already built
                    |  Read()/Write() = raw,     |
                    |  decrypted IPv4 packets    |
                    +-------------+-------------+
                                  |
                     one dedicated goroutine per
                     attached session (single
                     reader, per Session.Read's
                     documented contract)
                                  |
                                  v
                    +---------------------------+
                    |   netstack.Stack           |
                    |   .Attach(sess, ip)         |
                    |                             |
                    |   read loop -> parseIPv4 -> |
                    |   source-IP == ip? (else    |
                    |   drop, T-03-xx spoofing)   |
                    |                             |
                    |   protocol switch:          |
                    |     ICMP -> echo responder  |---> sess.Write() (reply, inline)
                    |     UDP  -> port table       |---> queued to a ListenUDP conn's
                    |             lookup            |     ReadFrom() channel
                    |     TCP  -> 4-tuple lookup     |---> queued to a TCP conn's
                    |             (listener or        |     segment-in channel,
                    |             established conn)    |    state machine advances
                    +---------------------------+
                                  |                        |
                    +-------------+--------+   +-----------+-----------+
                    |  net.PacketConn        |   |  net.Listener /        |
                    |  (ListenUDP result)     |   |  net.Conn (ListenTCP)  |
                    +-------------+--------+   +-----------+-----------+
                                  |                        |
                          embedder's UDP code      stdlib http.Serve(ln, handler)
                                                            |
                                                  examples/tunnelweb (landing
                                                  page + 4 subpages)
```

A reader can trace the primary use case (a browser inside the client container loads the landing page) start to finish: real client -> `Session.Read` -> netstack's per-session goroutine -> IPv4 parse -> TCP 4-tuple lookup -> TCP state machine delivers bytes to the accepted `net.Conn` -> `http.Server` reads the HTTP request off that `net.Conn` -> handler writes the response -> TCP state machine segments it -> `sess.Write` -> encrypted back to the client.

### Recommended Project Structure

Internal file layout is explicitly "Claude's Discretion" per CONTEXT.md — this is a recommendation, not a locked decision:

```
netstack/
├── stack.go       # Stack, NewStack, Attach/Detach, per-session read loop, session interface
├── ipv4.go        # parseIPv4/buildIPv4, RFC 1071 checksum (shared by ICMP/UDP/IP header)
├── icmp.go        # ICMP echo request/reply (NET-03)
├── udp.go         # UDP demux, net.PacketConn impl (NET-01), UDP checksum w/ pseudo-header
├── tcp/            # minimal server-side TCP, isolated for the state-machine's own tests
│   ├── conn.go     # net.Conn impl (Read/Write/Close/deadlines), per-conn state
│   ├── listener.go # net.Listener impl, backlog/accept queue
│   ├── segment.go  # segment parse/build incl. MSS option
│   ├── state.go    # LISTEN/SYN_RCVD/ESTABLISHED/... transition table
│   └── timer.go    # injected-Clock retransmit/TIME_WAIT timers (internal/reliable precedent)
└── netstack_test.go / *_test.go  # fake-Session fast tier (no Docker)
```

### Pattern 1: IPv4 checksum — RFC 1071 verbatim

**What:** 16-bit one's-complement sum over big-endian 16-bit words, checksum field zeroed before summing, end-around carry folded back in, final result complemented.
**When to use:** IPv4 header checksum, ICMP checksum, UDP checksum (with pseudo-header), TCP checksum (with pseudo-header) — one function, four call sites.
**Example:**
```go
// Source: RFC 1071 (fetched rfc-editor.org/rfc/rfc1071 this session)
// "Adjacent octets to be checksummed are paired to form 16-bit
// integers, and the 1's complement sum of these 16-bit integers is
// formed." Odd trailing byte is paired with a zero byte.
func internetChecksum(b []byte) uint16 {
    var sum uint32
    n := len(b)
    for i := 0; i+1 < n; i += 2 {
        sum += uint32(b[i])<<8 | uint32(b[i+1])
    }
    if n%2 == 1 {
        sum += uint32(b[n-1]) << 8
    }
    for sum>>16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16)
    }
    return ^uint16(sum)
}
```
This is byte-for-byte the function already written and live-verified in `test/interop/server/main.go`'s harness ICMP responder [VERIFIED: `/Users/svenloth/dev/govpn/test/interop/server/main.go:565-578` — read this session; quoted below]. Phase 3's job is to move the equivalent of this function (and the ICMP responder built on it) from harness code into the `netstack` package itself, per 02-03-SUMMARY.md's own stated "Next Phase Readiness" note.

> ```go
> // internetChecksum computes the RFC 1071 Internet checksum over b: the
> // one's complement of the one's-complement sum of b's 16-bit big-endian
> // words, with a trailing odd byte treated as the high byte of a final
> // zero-padded word.
> func internetChecksum(b []byte) uint16 {
> 	var sum uint32
> 	n := len(b)
> 	for i := 0; i+1 < n; i += 2 {
> 		sum += uint32(b[i])<<8 | uint32(b[i+1])
> 	}
> 	if n%2 == 1 {
> 		sum += uint32(b[n-1]) << 8
> 	}
> 	for sum>>16 != 0 {
> 		sum = (sum & 0xFFFF) + (sum >> 16)
> 	}
> 	return ^uint16(sum)
> }
> ```

### Pattern 2: UDP/TCP pseudo-header checksum (IPv4)

**What:** UDP and TCP checksums are computed over a 12-byte pseudo-header (src IP 4B, dst IP 4B, zero 1B, protocol 1B, segment/datagram length 2B) concatenated with the real header+payload — the pseudo-header itself is never transmitted.
**When to use:** Every outbound UDP or TCP packet the netstack builds; every inbound one it validates (recommend: validate on receive, drop silently on mismatch — do not special-case a client that "usually" sends good checksums).
**Example:**
```go
// Source: RFC 768 (fetched rfc-editor.org/rfc/rfc768 this session) +
// RFC 9293 §3.1 (TCP uses the identical IPv4 pseudo-header shape,
// protocol=6 instead of UDP's 17)
func pseudoHeaderSum(srcIP, dstIP [4]byte, protocol byte, length uint16) uint32 {
    var sum uint32
    sum += uint32(srcIP[0])<<8 | uint32(srcIP[1])
    sum += uint32(srcIP[2])<<8 | uint32(srcIP[3])
    sum += uint32(dstIP[0])<<8 | uint32(dstIP[1])
    sum += uint32(dstIP[2])<<8 | uint32(dstIP[3])
    sum += uint32(protocol)
    sum += uint32(length)
    return sum
}
```
**UDP-specific rule (RFC 768):** if the *computed* checksum is `0x0000`, transmit `0xFFFF` instead — an on-wire `0x0000` means "sender computed no checksum" and must still be accepted by a receiver (do not treat it as corrupt). IPv4 UDP checksums are optional per RFC 768 but this project should always compute and set one — dropping a datagram whose checksum is `0x0000` on receive would incorrectly reject a legitimately-checksum-disabled sender; the safer receive-side rule is "if checksum field is `0x0000`, skip verification; otherwise verify."

### Pattern 3: TCP MSS clamping to the tunnel MTU

**What:** Advertise an MSS in the SYN-ACK's MSS option (kind=2, len=4, 2-byte value) equal to the effective tunnel payload budget, and clamp to `min(own MSS, peer's advertised MSS)` for every segment actually sent.
**When to use:** SYN-RECEIVED → the SYN-ACK the netstack sends.
**Rationale for this project specifically:** the pushed `serverKM2Options` string already fixes `tun-mtu 1500` [VERIFIED: `/Users/svenloth/dev/govpn/ovpn.go:138` — read this session; `const serverKM2Options = "...,dev-type tun,link-mtu 1541,tun-mtu 1500,..."`], meaning every packet handed to `Session.Read`/`Session.Write` is capped at 1500 bytes end-to-end (the real client's own kernel enforces this on its `tun0`, and the client-side OpenVPN process does its own fragmentation/MTU handling below that — nothing this project's server needs to replicate). Standard MSS arithmetic (MTU − 20B IPv4 − 20B TCP, no options) gives **MSS = 1460**. Advertise 1460 in the SYN-ACK; there is no additional VPN-specific overhead to subtract, since the 1500-byte figure is already the tunnel's own effective link MTU as OpenVPN itself defines it — do not double-subtract OpenVPN's own framing overhead (that's already accounted for below the `Session` boundary in Phases 1-2, invisible to this layer). [CITED: MSS-clamping convention, cross-checked against RFC 9293's MSS option format]

### Pattern 4: Single-reader-per-Session dispatch goroutine

**What:** `netstack.Stack.Attach(sess, ip)` starts exactly one goroutine per attached session that loops on `sess.Read`, matching `Session.Read`'s own documented contract.
**When to use:** Always — this is not optional. `Session.Read`'s doc comment states: "Assumes the single-reader-goroutine convention io.Reader implementations ordinarily rely on; concurrent Read calls on one Session are not supported (mirrors bufio.Reader's own contract)." [VERIFIED: `/Users/svenloth/dev/govpn/session.go:198-203` — read this session; quoted]
**Detach trigger:** the same goroutine's `sess.Read` returning a non-nil error (io.EOF on `Session.Close`) is the sole detach signal — CONTEXT.md's own decision text: "detach happens when the stack's per-session read loop sees `Session.Read` return an error (session closed)."
**Write-side concurrency is unconstrained:** `Session.Write` is safe to call from any number of goroutines simultaneously. `internal/datachan.Wrapper` (the field `Session.dataWrapper`) guards its own `Seal` call with an internal `mu sync.Mutex` [VERIFIED: `/Users/svenloth/dev/govpn/internal/datachan/datachan.go:107,164` — read this session; `mu sync.Mutex` field declared, `func (w *Wrapper) Seal(dst, plaintext []byte) ([]byte, error)` uses it], and the underlying `net.PacketConn.WriteTo` is documented safe for concurrent use by the Go standard library [VERIFIED: `/usr/local/go/src/net/net.go` `PacketConn` interface doc — read this session]. This means the netstack's TCP retransmit-timer goroutine, TIME_WAIT timer goroutine, and any `http.Handler` goroutine writing a response body can all call `sess.Write` on the same `Session` concurrently with zero additional locking required in the netstack itself — this is a load-bearing design fact for wave planning (TCP's timer machinery does not need to funnel writes through the single read-loop goroutine).

### Pattern 5: Local `session` interface, no `ovpn` import

**What:** `netstack` package declares its own unexported (or exported, discretion) interface — `io.ReadWriteCloser` is sufficient, since `AssignedIP()` is supplied as a separate `Attach(sess, ip net.IP)` argument per CONTEXT.md's own signature, not read off the session by the netstack itself.
**Why:** CONTEXT.md states this explicitly: "the core `ovpn` package stays independent of it (proves the `Session` boundary is clean)" and "the netstack can be built against a fake `Session`... no Docker needed to test the netstack itself." A structural (implicit) Go interface is the only way to satisfy both constraints simultaneously: `*ovpn.Session` already implements `io.ReadWriteCloser` [VERIFIED: `/Users/svenloth/dev/govpn/session.go:521` — read this session; `var _ io.ReadWriteCloser = (*Session)(nil)`], so it satisfies a `netstack`-local interface with zero coupling, and a fast-tier test can trivially build an in-memory fake (e.g. wrapping `io.Pipe` or a channel pair) that satisfies the same interface without touching `ovpn` at all.
**Recommendation:** do not have `netstack` import `github.com/8upio/govpn` (the root `ovpn` package) — this keeps the dependency direction the phase boundary implies (embedder imports both `ovpn` and `netstack`; `netstack` imports neither `ovpn` nor anything crypto-related).

### Anti-Patterns to Avoid

- **Trusting the IHL/length fields at face value:** always bound-check `ihl*4 <= len(packet)` and `totalLength <= len(packet)` before slicing — a malicious or malformed packet from an authenticated-but-untrusted tunnel peer (see Security Domain) must never cause a slice-bounds panic. Mirrors `internal/wire`'s own "every field read explicitly checks the remaining buffer length first" discipline [VERIFIED: `/Users/svenloth/dev/govpn/internal/wire/wire.go:149` — read this session; comment text].
- **Silently accepting IPv4 packets with options (IHL > 5):** per CONTEXT.md's out-of-scope note and this phase's own narrow goal, do not attempt to parse or forward IP options — either skip past them (start payload parsing at `ihl*4`, correctly computed) or drop the packet outright. Recommend: skip past (a real client's kernel will not add IP options for ordinary ping/HTTP/UDP traffic through a tunnel, but a hand-crafted adversarial packet inside the tunnel could set IHL > 5 — bound-checked skip is strictly safer than a hard drop-everything-with-options policy that could reject benign traffic from an edge-case client).
- **Treating a fragmented IPv4 packet as a protocol error:** CONTEXT.md's research focus text recommends dropping fragments and documenting why. With `tun-mtu 1500` fixed for every session, and no PMTUD-triggering path this server itself introduces, fragments should not occur in ordinary operation — but a malicious peer inside their own tunnel could still construct one. Recommendation: detect via `MF` flag set or `FragOffset != 0`, drop silently (do not attempt reassembly — RFC 791 reassembly is real complexity this phase's scope explicitly excludes), and do not send an ICMP fragmentation-needed error (ICMP error generation is explicitly deferred per CONTEXT.md's Deferred Ideas).
- **Reimplementing Go's own net.Error semantics loosely:** a custom `net.Conn`/`net.PacketConn` whose deadline-exceeded error does not satisfy `errors.Is(err, os.ErrDeadlineExceeded)` **and** implement `net.Error.Timeout() == true` will cause `net/http` to treat an ordinary idle-timeout read as a fatal connection error rather than the graceful "close this idle keep-alive connection" path it expects — see Common Pitfalls below.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead |
|---------|-------------|--------------|
| Full TCP/IP stack with congestion control, SACK, PMTUD, IPv6 | A general-purpose netstack | The narrow, explicitly-scoped subset CONTEXT.md already locked: server-accept-only TCP, fixed RTO, cumulative ACKs, IPv4 only |
| RFC 6298 RTT-measured RTO | SRTT/RTTVAR estimation, Karn's algorithm | CONTEXT.md's locked decision: fixed RTO with doubling on retransmit — this is a deliberate, documented scope reduction from what RFC 9293 mandates for a general Internet host, justified by "tunnel-quality links only" |
| IP packet reassembly | A fragment-reassembly buffer/timer | Drop fragments silently (CONTEXT.md, this phase's research focus) |
| A generic byte-checksum library | Any external checksum package | The ~15-line RFC 1071 function already proven correct and live-verified in `test/interop/server/main.go` — reuse the algorithm, move it into the netstack package |

**Key insight:** every "don't hand-roll" temptation in this domain (a fuller TCP stack, real RTO estimation, fragment reassembly) is explicitly and deliberately out of scope per CONTEXT.md and CLAUDE.md — the risk here is not "reinventing a wheel that exists," it's scope creep into RFC machinery this project has already decided it does not need. The one thing genuinely worth hand-rolling small and correct (the checksum, the header parse/build) has no viable off-the-shelf stdlib alternative and is already precedented in this exact codebase.

## Common Pitfalls

### Pitfall 1: A blocked Read that outlives its deadline must return a `net.Error`-shaped timeout, not merely "an error"

**What goes wrong:** `(*http.conn).readRequest` calls `c.rwc.SetReadDeadline(hdrDeadline)` before reading request headers [VERIFIED: `/usr/local/go/src/net/http/server.go:992` — read this session, `c.rwc.SetReadDeadline(hdrDeadline)`]. If the netstack's TCP `net.Conn.Read` blocks past that deadline and returns a plain `errors.New("timeout")`, `net/http` cannot distinguish "the client is just slow / idle keep-alive" from "the connection is broken," and its behavior (whether it degrades gracefully to closing the connection vs. logging/erroring loudly) depends on the returned error satisfying `net.Error` with `Timeout() == true`, and ideally wrapping `os.ErrDeadlineExceeded` so `errors.Is` checks succeed [VERIFIED: `/usr/local/go/src/net/net.go:158-159` — read this session; doc comment: "I/O methods will return an error that wraps os.ErrDeadlineExceeded. This can be tested using errors.Is(err, os.ErrDeadlineExceeded)."].
**Why it happens:** it's easy to implement `SetReadDeadline` as a no-op-returning-nil during early development (the CONTEXT.md text itself flags this exact temptation: "netstack conns can no-op `SetKeepAlive` but must not error in ways `http.Server` treats as fatal" — the same discipline applies to deadlines, which unlike `SetKeepAlive` actually are load-bearing).
**How to avoid:** implement a real per-conn deadline: a `time.Timer` (or `time.AfterFunc`) that, on firing, unblocks any in-flight `Read`/`Write` (e.g. via a channel-select alongside the inbound-segment channel) and returns a sentinel error type implementing both `Timeout() bool { return true }` and wrapping `os.ErrDeadlineExceeded` via `Unwrap()`. `SetReadDeadline`/`SetWriteDeadline` themselves must be safe to call from a different goroutine than the one blocked in `Read`/`Write` (standard `net.Conn` usage pattern — a caller often sets a deadline from a supervisor goroutine).
**Warning signs:** `curl` against the example server hangs forever instead of erroring on a slow/dead connection; the interop harness's HTTP-page-load probe times out at the *test framework's* outer bound rather than failing fast with a clear connection error.

### Pitfall 2: `http.Serve`/`Server.Serve` never wraps the caller's `net.Listener` — do not build `SetKeepAlive` support expecting it to matter

**What goes wrong:** wasting implementation effort making the netstack's TCP `net.Conn` implement an optional `SetKeepAlive(bool) error` interface, believing `net/http` requires it.
**Why it happens:** older Go documentation and blog posts describe `net/http.ListenAndServe`'s internal `tcpKeepAliveListener` wrapper, which sets TCP keep-alives on accepted connections — but that wrapper is only reachable via `ListenAndServe`'s own internal `net.Listen("tcp", addr)` call [VERIFIED: `/usr/local/go/src/net/http/server.go:3348-3361` — read this session; `ListenAndServe` calls `net.Listen("tcp", addr)` then `s.Serve(ln)`]. `http.Serve(l, handler)` and `(*Server).Serve(l)` take the listener as-is and never type-assert or wrap it for keep-alive purposes [VERIFIED: `/usr/local/go/src/net/http/server.go:2940-2943,3404-3420` — read this session; `Serve` body has no keep-alive-related listener wrapping].
**How to avoid:** the example server calls `http.Serve(stack.ListenTCP(port), handler)` directly (per CONTEXT.md's own architecture) — `SetKeepAlive` is simply never invoked by `net/http` on this path. Do not implement it; it is dead code for this phase's actual call path. (It remains fine, and cheap, to implement `net.TCPConn`-shaped optional interfaces like `CloseWrite() error` — see Pitfall 3 — but `SetKeepAlive` specifically has no caller here.)

### Pitfall 3: Half-close (`CloseWrite`) matters for clean HTTP/1.x connection teardown

**What goes wrong:** browsers loading a page over an HTTP connection that the server intends to close (`Connection: close`, or after the final keep-alive request) can perceive a hung/broken connection if the server only ever does a full bidirectional close and never signals "no more data coming from me" via a TCP half-close.
**Why it happens:** `net/http`'s `(*conn).closeWriteAndWait` explicitly checks whether the underlying `net.Conn` implements an unexported-shape `closeWriter` interface (`CloseWrite() error`) and calls it before waiting briefly and fully closing [VERIFIED: `/usr/local/go/src/net/http/server.go:1772-1787` — read this session; `type closeWriter interface { CloseWrite() error }`, `var _ closeWriter = (*net.TCPConn)(nil)`, and `closeWriteAndWait`'s body: `if tcp, ok := c.rwc.(closeWriter); ok { tcp.CloseWrite() }`]. If the netstack's `net.Conn` does not implement `CloseWrite`, `net/http` silently skips this step and falls back to a full close — CONTEXT.md's own decision text ("proper bidirectional FIN handshake plus a short-timer TIME_WAIT") already anticipates the need for a real half-close, not just a full close.
**How to avoid:** implement `CloseWrite() error` on the TCP `net.Conn` type — send a FIN for the local-to-peer direction while continuing to accept the peer's own data/FIN, matching TCP's own defined half-close semantics (RFC 9293's CLOSE-WAIT/FIN-WAIT states already model this; `CloseWrite` should transition the connection's write side into that half of the state machine without touching the read side).
**Warning signs:** the interop harness's `curl` probe against the landing page occasionally hangs or reports a broken pipe rather than a clean 200 response, especially on the last request of a keep-alive sequence.

### Pitfall 4: Don't reuse the reliability layer's packet-ID space or the data-channel's replay window for TCP sequence numbers

**What goes wrong:** conceptually conflating TCP's own 32-bit sequence-number space (RFC 9293) with either `internal/wire.PacketID` (control-channel reliability) or `internal/datachan`'s AEAD packet-ID/replay window (data-channel anti-replay) — these are three structurally similar-looking but semantically and cryptographically unrelated counters at three different layers.
**Why it happens:** this codebase already has two precedented "packet ID + sliding window" concepts (`internal/wire.PacketID` for control-channel reliability, and `internal/datachan`'s replay window for data-channel anti-replay), and the natural instinct when writing a third one (TCP sequence numbers) is to copy one of them wholesale.
**How to avoid:** TCP sequence numbers are per-4-tuple, generated fresh per `Attach`ed session's own TCP connections (ISN per RFC 9293's clock+PRF construction — CONTEXT.md doesn't lock a specific ISN scheme; a `crypto/rand`-seeded pseudo-random per-connection ISN is a reasonable, RFC-compliant choice that avoids the ISN-prediction attack RFC 9293 itself warns about), tracked entirely within the `tcp` sub-package's own connection state — it must never read or write `internal/wire` or `internal/datachan` state.
**Warning signs:** a code review finding an import of `internal/wire` or `internal/datachan` inside the netstack's TCP files, or TCP ISN generation seeded from the data-channel's packet-ID counter.

## Code Examples

### ICMP echo reply (adapt from the already-live harness version)

```go
// Source: /Users/svenloth/dev/govpn/test/interop/server/main.go:430-472
// (read this session) — this exact logic, byte-for-byte, is what NET-03
// moves from harness code into the netstack package. RFC 792 (fetched
// rfc-editor.org/rfc/rfc792 this session): echo request type=8, echo
// reply type=0; identifier and sequence number and payload data are
// echoed back unchanged; checksum recomputed over the whole ICMP message.
func icmpEchoReply(pkt []byte) (reply []byte, ok bool) {
    const (
        minIPv4HeaderLen = 20
        minICMPHeaderLen = 8
        protocolICMP     = 1
        icmpTypeEchoReq  = 8
        icmpTypeEchoRepl = 0
    )
    if len(pkt) < minIPv4HeaderLen {
        return nil, false
    }
    version := pkt[0] >> 4
    ihl := int(pkt[0]&0x0F) * 4
    if version != 4 || ihl < minIPv4HeaderLen || len(pkt) < ihl+minICMPHeaderLen {
        return nil, false
    }
    if pkt[9] != protocolICMP {
        return nil, false
    }
    icmp := pkt[ihl:]
    if icmp[0] != icmpTypeEchoReq {
        return nil, false
    }

    out := append([]byte(nil), pkt...)
    var src, dst [4]byte
    copy(src[:], out[12:16])
    copy(dst[:], out[16:20])
    copy(out[12:16], dst[:])
    copy(out[16:20], src[:])

    out[10], out[11] = 0, 0
    binary.BigEndian.PutUint16(out[10:12], internetChecksum(out[:ihl]))

    outICMP := out[ihl:]
    outICMP[0] = icmpTypeEchoRepl
    outICMP[2], outICMP[3] = 0, 0
    binary.BigEndian.PutUint16(outICMP[2:4], internetChecksum(outICMP))

    return out, true
}
```

Note: this harness version reuses the *inbound* packet's IHL for the reply's IHL (no options handling needed for an echo reply that mirrors the request's own header shape) and does not currently reject options-bearing requests — if the netstack version chooses to reject IHL>5 outright (Anti-Patterns above recommends "skip past" instead), this is the one call site to adjust.

### Go net.Conn / net.Listener / net.PacketConn contracts (verbatim from stdlib)

```go
// Source: /usr/local/go/src/net/net.go:124-146,325-352,412-422 (read this
// session, Go 1.26.1 toolchain)
type Conn interface {
    Read(b []byte) (n int, err error)
    Write(b []byte) (n int, err error)
    Close() error
    LocalAddr() Addr
    RemoteAddr() Addr
    SetDeadline(t time.Time) error
    SetReadDeadline(t time.Time) error
    SetWriteDeadline(t time.Time) error
}

type PacketConn interface {
    ReadFrom(p []byte) (n int, addr Addr, err error)
    WriteTo(p []byte, addr Addr) (n int, err error)
    Close() error
    LocalAddr() Addr
    SetDeadline(t time.Time) error
    SetReadDeadline(t time.Time) error
    SetWriteDeadline(t time.Time) error
}

type Listener interface {
    Accept() (Conn, error)
    Close() error
    Addr() Addr
}
```

`Addr` itself is trivial: `Network() string` (e.g. `"tcp"`/`"udp"`) and `String() string` (e.g. `"10.8.0.1:8080"`) — both `net.PacketConn`'s and `net.Conn`'s deadline-related doc comments explicitly say "Multiple goroutines may invoke methods... simultaneously," which is the contract the netstack's implementations must honor (matches Pattern 4's finding for the write side; the netstack's `Read`/`ReadFrom`/`Accept` implementations should similarly not assume a single caller, even though this project's own usage — `http.Serve`'s accept loop, a single embedder goroutine per `ListenUDP` conn — will not stress that in practice).

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|---------------|--------|
| `net/http.ListenAndServe`'s internal `tcpKeepAliveListener` | still present for `ListenAndServe`, irrelevant to `http.Serve`/`Server.Serve` with a caller-supplied listener | Long-standing (predates this research; confirmed still true in Go 1.26.1 stdlib read this session) | Netstack's `net.Conn` does not need `SetKeepAlive` for this phase's actual call path (`http.Serve`) |
| RFC 793 (1981) TCP | RFC 9293 (2022) obsoletes RFC 793, folding in years of clarifications (initial sequence number generation guidance, explicit state-machine pseudocode) | 2022 | This research fetched RFC 9293, not RFC 793 — use RFC 9293 as the citation source for any future TCP-related plan/code comments in this codebase, matching the "current, not historical" spec version |

**Deprecated/outdated:** none specific to this phase's narrow scope beyond the RFC 793→9293 supersession noted above.

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|----------------|
| A1 | MSS = 1460 (tunnel MTU 1500 − 20B IPv4 − 20B TCP, no extra VPN-specific subtraction) is the correct value to advertise, because `tun-mtu 1500` is already the effective end-to-end IP-packet budget through `Session.Read`/`Write` | Architecture Patterns, Pattern 3 | If wrong (e.g. some additional per-packet framing overhead exists between `Session.Write` and the wire that this research didn't account for), oversized TCP segments could be silently dropped or need in-tunnel fragmentation this stack doesn't support, causing large HTTP responses (page loads with the example's CSS/content) to hang or corrupt. Low risk: `Session.Write`'s own doc and Phase 2's live-verified 1500-byte real-client behavior back this, but it was not independently re-verified against a live packet capture this session. |
| A2 | A `crypto/rand`-seeded per-connection pseudo-random ISN is an acceptable, RFC-9293-compliant choice for this project (vs. implementing RFC 9293's specific clock+PRF construction) | Common Pitfalls, Pitfall 4 | Low risk for this project's threat model (TCP connections only ever originate from an already TLS-authenticated tunnel peer, not the open Internet) — RFC 9293's ISN-unpredictability concern is primarily about off-path attackers on the open Internet, which does not apply inside an already-encrypted, already-authenticated OpenVPN data channel. Flagged as an assumption because CONTEXT.md does not lock a specific ISN scheme. |
| A3 | "Skip past IP options rather than hard-reject" is the safer default policy | Anti-Patterns to Avoid | If a real client (or the harness) never sends IP options in practice (likely true — ordinary ping/curl/browser traffic through a Linux tun device does not set IP options), this choice has zero practical effect either way; flagged only because CONTEXT.md's phase boundary text doesn't explicitly pick one, leaving it to implementation discretion within the phase's stated "drop fragments, document why" scope for the *fragmentation* case specifically (which CONTEXT.md does lock) — options handling itself is this research's own recommendation, not a locked decision. |

## Open Questions

1. **Exact TCP backlog/half-open-connection cap for SYN-flood mitigation within a single session**
   - What we know: CONTEXT.md locks "fixed advertised receive window (~64KB)... no congestion control beyond a fixed in-flight cap" and the Security Domain below recommends bounding half-open (SYN_RCVD) state per session.
   - What's unclear: no specific numeric cap is locked by CONTEXT.md for concurrent half-open TCP connections per session, nor for the accept backlog depth `ListenTCP` should apply.
   - Recommendation: the planner should pick small, fixed, documented constants (e.g. backlog=16, half-open cap=8 per session) in the same spirit as `internal/reliable`'s own fixed `Capacity = 12` / `NRecBuffers = 12` constants — a specific number is less important than it existing and being named, matching this project's existing "explicit typed constant, no magic number" convention.

2. **Whether the example's `net.Listener`/`net.PacketConn` should be exposed per-session or stack-wide**
   - What we know: CONTEXT.md's API shape is stack-wide (`Stack.ListenUDP(port)`/`Stack.ListenTCP(port)` — one call regardless of how many sessions are attached, demuxed by destination IP inside the stack).
   - What's unclear: nothing — this is already answered by CONTEXT.md's locked decision, listed here only so the planner does not second-guess it against the (less correct) "one listener per client" mental model an RTP-style design might otherwise suggest.
   - Recommendation: no action needed; CONTEXT.md's decision stands.

## Environment Availability

| Dependency | Required By | Available | Version | Fallback |
|------------|------------|-----------|----------|----------|
| Go toolchain | Building `netstack`, the example, and fast-tier tests | ✓ | go1.26.1 darwin/arm64 [VERIFIED: `go version` this session] | — |
| Docker | Interop-tier harness extension (VRFY-02) | Assumed ✓ (used successfully in Phases 1-2's own `make interop`; not re-probed this session since no code changes to the harness's Docker dependency itself) | — | — |
| `curl` inside the client interop container | New HTTP-page-load probe (VRFY-02) | Not yet verified this session — the client image (`test/interop/Dockerfile`) currently installs `iputils-ping` for the existing ping probe [VERIFIED: `/Users/svenloth/dev/govpn/test/interop/server/main.go` change log via `02-03-SUMMARY.md`: "`test/interop/Dockerfile` - adds `iputils-ping`"] but was not read this session to confirm `curl` is present | Add `curl` to the client image's package list if absent — a one-line `Dockerfile` change, not a blocker |

**Missing dependencies with no fallback:** none identified.
**Missing dependencies with fallback:** `curl` in the client container — trivial `apt-get install curl` addition if the planner's Docker-tier plan finds it missing; low risk, flagged for the planner to verify at plan time rather than blocking this research.

## Validation Architecture

### Test Framework

| Property | Value |
|----------|-------|
| Framework | Go stdlib `testing` + `go test -race` (existing project convention, `internal/reliable`/`internal/datachan`/`internal/wire` precedent) |
| Config file | none — no test framework config exists or is needed; `Makefile`'s `test`/`gates`/`interop` targets are the existing harness entry points [VERIFIED: `/Users/svenloth/dev/govpn/Makefile` — read this session] |
| Quick run command | `go test -race ./netstack/... ./netstack/tcp/...` |
| Full suite command | `make test` (fast tier: vet, build, race tests, prohibition gates) then `make interop` (Docker tier) |

### Phase Requirements → Test Map

| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|---------------------|---------------|
| NET-01 | `ListenUDP(port)` returns a working `net.PacketConn`; arbitrary ports at runtime; correct IP→session routing | unit | `go test -race -run TestUDPRoundTrip ./netstack/` | ❌ Wave 0 |
| NET-02 | `ListenTCP(port)` returns a `net.Listener` that `http.Serve` accepts on; full HTTP request/response over it | unit + integration | `go test -race -run TestTCPHTTPRoundTrip ./netstack/tcp/` | ❌ Wave 0 |
| NET-03 | ICMP echo responder answers echo requests to the server's own tunnel IP; drops all other ICMP | unit | `go test -race -run TestICMPEcho ./netstack/` | ❌ Wave 0 |
| NET-04 | Attach/Detach dynamically update IP→session routing; UDP listeners open on arbitrary runtime ports | unit | `go test -race -run TestAttachDetach ./netstack/` | ❌ Wave 0 |
| XMPL-01 | Example web server (landing + 4 subpages) runs with one command, reachable only through the tunnel | manual (Docker tier) + smoke | `go run ./examples/tunnelweb` (manual); `curl` assertion inside `make interop`'s client container | ❌ Wave 0 |
| VRFY-02 | Real client: ping (ICMP) + UDP round-trip + HTTP page load all succeed, no `/dev/net/tun`/`CAP_NET_ADMIN` on server | integration (Docker) | `make interop` (extended scenario table) + `docker inspect` assertion on the server container | ✅ scaffolding exists (`test/interop/interop_test.go`, `docker-compose.yml`); new probes needed |

### Sampling Rate

- **Per task commit:** `go test -race ./netstack/...` (fast, no Docker — matches this phase's own stated design: "the netstack can be built against a fake Session... no Docker needed")
- **Per wave merge:** `make test` (fast tier + prohibition gates)
- **Phase gate:** `make interop` (full Docker tier, all scenarios) green before `/gsd-verify-work`

### Wave 0 Gaps

- [ ] `netstack/netstack_test.go` — fake-`Session` harness (an `io.Pipe`-backed or channel-backed struct satisfying the local `session` interface from Pattern 5) driving `Stack` with hand-built IPv4/ICMP/UDP/TCP packets, covering NET-01/NET-03/NET-04
- [ ] `netstack/tcp/tcp_test.go` — state-machine transition tests using an injected `Clock` (mirroring `internal/reliable`'s `Clock`/`SystemClock` pattern [VERIFIED: `/Users/svenloth/dev/govpn/internal/reliable/reliable.go:79-89` — read this session]), covering NET-02's handshake/close/retransmit behavior without real timers
- [ ] `examples/tunnelweb/main.go` — does not exist yet; no `examples/` directory exists in the repository currently [VERIFIED: `ls /Users/svenloth/dev/govpn` this session — no `examples/` directory listed]
- [ ] `test/interop/entrypoint.sh` extension — a `curl` probe against the landing page + one subpage, asserting content markers (extends the existing ping probe added in Phase 2)
- [ ] `test/interop/interop_test.go` extension — parse the new HTTP/UDP probe output and assert success, alongside the existing `assertDataChannelRoundTrip`/ping assertions
- [ ] `test/interop/docker-compose.yml` — no changes expected (the server container's `user: "65534:65534"`, no `cap_add`, no `devices:` already model the "no TUN, no CAP_NET_ADMIN" requirement this phase must prove holds *with the netstack active* — VRFY-02's `docker inspect` re-assertion is a re-check, not a new mechanism)

## Security Domain

### Applicable ASVS Categories

| ASVS Category | Applies | Standard Control |
|----------------|---------|--------------------|
| V2 Authentication | No | Already enforced upstream (Phases 1-2's TLS mutual-cert handshake); the netstack never sees a packet from an unauthenticated peer — every packet it processes already passed AEAD verification in `internal/datachan.Wrapper.Open` |
| V3 Session Management | No | `ovpn.Session` lifecycle (Phase 1-2/4) is unchanged by this phase; netstack only observes `Read`/`Write`/`Close` |
| V4 Access Control | Yes (new this phase) | Per-session source-IP enforcement at `Attach`-time dispatch: a packet arriving on a given session's `Read` loop whose IPv4 source address does not equal that session's `Attach`-registered IP must be dropped before any further processing — this is the netstack's own access-control boundary, since nothing upstream of it enforces "this session may only claim to be its own assigned IP" |
| V5 Input Validation | Yes | Bounds-checked parsing for every header field (IHL, total length, options), matching `internal/wire`'s existing discipline; never trust a length field without checking it against the actual buffer length before slicing |
| V6 Cryptography | No | No new cryptographic primitive is introduced this phase; all confidentiality/integrity already comes from the AES-256-GCM data channel below the `Session` boundary |

### Known Threat Patterns for this stack

| Pattern | STRIDE | Standard Mitigation |
|---------|--------|-----------------------|
| A tunnel peer sends an IPv4 packet whose source address is not its own `AssignedIP()` (in-tunnel source-IP spoofing — e.g. client A claims to be client B's tunnel IP, or claims to be the server's own tunnel IP) | Spoofing | Enforce at `Attach`-time dispatch: compare parsed IPv4 source against the `net.IP` passed to `Attach` for that session; drop silently on mismatch (CONTEXT.md's own research-focus text explicitly calls this out: "recommend per-session source-IP enforcement at Attach routing") |
| A tunnel peer sends a malformed/adversarial header (bogus IHL, oversized length field claiming more bytes than the actual decrypted packet contains, garbage protocol number) | Tampering | Bounds-check every field before use; never index past `len(packet)`; reject (drop) rather than best-effort-parse anything inconsistent — matches `internal/wire`'s existing "explicit length check before every field read" convention |
| A single authenticated tunnel peer opens many half-open TCP connections against `ListenTCP` (SYN flood, but from *inside* an already-authenticated session, not an open-Internet unauthenticated flood) | Denial of Service | Bound per-session half-open (SYN_RCVD) connection count and the accept backlog depth with fixed, named constants (see Open Questions #1); evict oldest half-open state or simply stop accepting new SYNs past the cap rather than growing unboundedly — mirrors `internal/reliable`'s own fixed `Capacity`/window-size discipline already proven in this codebase |
| A tunnel peer sends a burst of ICMP echo requests to non-server addresses, or of any other ICMP type, attempting to use the responder as an amplification/probe vector | Denial of Service / Information Disclosure | CONTEXT.md already locks the mitigation: "echo responder for the server tunnel IP only... all other ICMP dropped silently" — no ICMP error generation (deferred), so there is no amplification surface (one request in, at most one reply out, same size) |
| A tunnel peer opens a UDP or TCP listener port the embedder did not intend to expose, by guessing port numbers | Information Disclosure (minor) | Not really a distinct threat here — `ListenUDP`/`ListenTCP` are called by the *embedder*, not the tunnel peer; a peer can only reach ports the embedder explicitly opened. No additional mitigation needed beyond what CONTEXT.md's API shape already provides (the tunnel peer has no port-scanning-relevant capability beyond "does this destination port respond," which is true of any network service) |

## Sources

### Primary (HIGH confidence)

- RFC 791 (`rfc-editor.org/rfc/rfc791`) — IPv4 header field layout, IHL definition, header checksum rule, fragmentation flags/offset — fetched and read directly this session. Per this project's own established convention (CLAUDE.md's Sources section treats a direct primary-spec read as HIGH confidence "despite the generic tool-classification tier reported by the research-plan seam... that default doesn't know this *is* the domain's canonical spec"), the same reasoning applies here: these are the canonical Internet Standard specs for this exact problem domain, read directly, not summarized from training memory.
- RFC 792 (`rfc-editor.org/rfc/rfc792`) — ICMP echo request/reply format, type values, checksum scope, identifier/sequence echo rule — fetched and read directly this session.
- RFC 1071 (`rfc-editor.org/rfc/rfc1071`) — Internet checksum algorithm, odd-byte handling, end-around carry, incremental update formula — fetched and read directly this session.
- RFC 768 (`rfc-editor.org/rfc/rfc768`) — UDP header layout, pseudo-header fields/order, zero-checksum special rule — fetched and read directly this session.
- RFC 9293 (`rfc-editor.org/rfc/rfc9293`) — TCP header exact bit/byte offsets, MSS option format, passive-open state transitions, ISN generation guidance, RST rules, MSL/TIME-WAIT duration, RTO/RFC 6298 reference — fetched and read directly this session (two targeted fetches: general state-machine/ISN/RST/MSL content, then a follow-up fetch specifically for the exact header bit-offset table).
- `/usr/local/go/src/net/net.go` (Go 1.26.1 toolchain, local `GOROOT`) — `Conn`/`PacketConn`/`Listener`/`Addr` interface definitions, `OpError`/`net.Error` `Timeout()` semantics, `os.ErrDeadlineExceeded` wrapping contract — read directly this session via the `Read` tool.
- `/usr/local/go/src/net/http/server.go` (same toolchain) — `readRequest`'s `SetReadDeadline`/`SetWriteDeadline` calls, `closeWriter`/`CloseWrite` half-close mechanism, `Serve`/`ListenAndServe`'s listener-wrapping (or lack thereof) — read directly this session.
- `/Users/svenloth/dev/govpn/session.go`, `/Users/svenloth/dev/govpn/ovpn.go`, `/Users/svenloth/dev/govpn/internal/wire/wire.go`, `/Users/svenloth/dev/govpn/internal/datachan/datachan.go`, `/Users/svenloth/dev/govpn/internal/reliable/reliable.go`, `/Users/svenloth/dev/govpn/gates_test.go`, `/Users/svenloth/dev/govpn/test/interop/server/main.go`, `/Users/svenloth/dev/govpn/test/interop/docker-compose.yml`, `/Users/svenloth/dev/govpn/test/interop/entrypoint.sh`, `/Users/svenloth/dev/govpn/Makefile` — all read directly this session; quoted verbatim where cited above.
- `/Users/svenloth/dev/govpn/.planning/phases/02-tunnel-up/02-03-SUMMARY.md` — Phase 2's live-verified ICMP-through-Session precedent and its own stated "Next Phase Readiness" note that Phase 3 moves the harness's ICMP responder into the netstack package — read directly this session.

### Secondary (MEDIUM confidence)

- MSS clamping convention (MSS = MTU − 40 for IPv4+TCP with no options) — WebSearch, cross-checked against RFC 9293's own MSS option format (kind/length/value) fetched directly; the specific "MTU − 40" arithmetic itself is an operational convention documented across multiple vendor/blog sources (Cloudflare, Fortinet, independent blogs), not itself an RFC-mandated number, hence MEDIUM rather than HIGH.

### Tertiary (LOW confidence)

- gVisor netstack's TCP retransmit-timeout defaults and SYN-ACK backoff behavior (WebSearch only, not independently verified against gVisor source this session) — included only as background color for the Alternatives Considered discussion of why gVisor itself is out of scope; not used as a design input for this project's own fixed-RTO TCP.

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH — stdlib-only, zero new dependencies, matches existing gate tests
- Architecture: HIGH — every wire-format claim is a direct RFC read this session; every Go-interface claim is a direct stdlib source read this session; every existing-codebase integration claim (`Session.Read`/`Write` contracts, `Wrapper.Seal` locking, `serverKM2Options` MTU value) is a direct project-source read this session with verbatim quotes
- Pitfalls: HIGH for the `net/http` deadline/keep-alive/half-close findings (direct stdlib source read); MEDIUM for the SYN-flood/backlog-sizing recommendation (no locked numeric constant exists yet — flagged in Open Questions rather than asserted as fact)

**Research date:** 2026-08-25
**Valid until:** RFC content: effectively unbounded (Internet Standards, stable). Go stdlib `net`/`net/http` behavior: 90 days (tracks Go toolchain releases; re-verify if the project's pinned Go version changes materially, though `net.Conn`/`net.Listener` core contracts have been stable for over a decade and are unlikely to change).
