# govpn

## What This Is

A pure-Go library (`github.com/8upio/govpn`, package `ovpn`) implementing the **server side of the OpenVPN protocol** — embeddable in any Go program, no wrapper around the `openvpn` binary, no separate process. Per connected client, the library hands the caller a `Session` that behaves as an `io.ReadWriteCloser` for raw, decrypted IP packets. It ships with a privilege-free userspace netstack (UDP + minimal server-side TCP + ICMP echo) so tunnel traffic can terminate entirely in-process, plus an example web server reachable only through the tunnel. Open source from day one — no comparable full Go implementation of the OpenVPN protocol exists (existing Go "openvpn" libs are process/management-interface wrappers).

## Core Value

A real, unmodified OpenVPN 2.6 client can connect to a Go process embedding this library and exchange traffic through the tunnel — verified against the reference implementation, not approximated from memory.

## Requirements

### Validated

- ✓ Control-channel framing (opcode / session-ID / packet-ID parsing) implemented as a `net.Conn`, with the OpenVPN reliability layer (ACK / retransmission) — Phase 1
- ✓ TLS handshake via stdlib `crypto/tls` layered on the framing conn (`tls.Server(customConn, tlsConfig)`) — no hand-rolled TLS — Phase 1
- ✓ tls-crypt support (control-channel encryption + HMAC wrapping) — Phase 1 (verified on the wire against a real OpenVPN 2.6.14 client)
- ✓ Certificate-based client auth (server cert + client CA via `Config.TLSConfig`) — Phase 1 (mutual TLS with CA-verified peer CN)
- ✓ `srv.Serve(net.PacketConn)` server loop over UDP — Phase 1
- ✓ Interop harness: pinned Docker OpenVPN 2.6 client, pcap assertions, golden vectors, loss injection, CI wiring — Phase 1
- ✓ Data-channel key derivation (Key Method 2 PRF expansion), byte-exact against the C reference (`ssl.c`/`crypto.c` vectors) — Phase 2
- ✓ Data-channel encryption/decryption with AES-256-GCM (classic non-epoch packet-id, replay window, fail-closed nonce counter) — Phase 2
- ✓ Session management: per-client `Session` as `io.ReadWriteCloser` for raw IP packets, `OnSession` at tunnel-up, `AssignedIP()` exposed — Phase 2
- ✓ Virtual tunnel-IP assignment from `Config.Network` (`topology subnet`, server = first host IP, sequential pool, release-on-close) — Phase 2 (real client logs "Initialization Sequence Completed"; encrypted pings round-trip through Session.Read/Write)
- ✓ Userspace netstack (`netstack` package): ListenUDP net.PacketConn, minimal server-side TCP with stdlib http.Serve support, built-in ICMP echo, Attach/Detach IP→session routing — Phase 3
- ✓ Example web server (`examples/tunnelweb`): landing + 4 subpages, reachable only through the tunnel — Phase 3 (real client pings, UDP round-trips, and loads pages live; server container unprivileged, no TUN)

### Active

**Core library (`ovpn`)**

**Userspace netstack (subpackage)**
- [ ] Dynamic-port support for RTP-style workloads (runtime `ListenUDP` on arbitrary ports or catch-all range demux)

**Example**

**Interop verification**
- [ ] Docker-based interop harness: unmodified OpenVPN 2.6 client container connects to the library; handshake, ping, and HTTP through the tunnel verified (packet captures / Wireshark where needed)

### Out of Scope

- **TUN/TAP device handling** — caller's responsibility; primary use case (Voxio) is in-process termination and needs no TUN. May come later as `ovpn/tun` with per-platform build tags.
- **Routing / NAT / IP forwarding** — deliberately outside the library.
- **NCP (Negotiable Crypto Parameters)** — fixed AES-256-GCM is enough for v1; needed for broader interop later.
- **Username/password auth, PSK (static key mode)** — cert-based auth only in v1.
- **LZO / compression** — deprecated in the ecosystem, adds complexity.
- **`net30` topology compatibility** — wastes 4 IPs per client; `topology subnet` only. Explicit non-goal.
- **Client-side OpenVPN implementation** — server only.
- **Management interface** (as in the official binary) — not a process, it's a library.
- **General-purpose TCP stack** — netstack TCP is a minimal server-side implementation sufficient for HTTP-style serving, not a full conformant stack (no gVisor; oversized and a heavy dependency).
- **Windows/macOS client interop hardening** — later phase; v1 targets the reference 2.6 client in the Docker harness.
- **tls-auth** — tls-crypt chosen instead for v1 (superset in practice for new deployments).

## Context

- **Primary driver:** Voxio (Sven's VoIP/CPaaS platform) will auto-provision Snom phones with OpenVPN configs — phone plugs into any internet connection, tunnels SIP/RTP (UDP) directly into the Voxio process. No TUN device, no `CAP_NET_ADMIN`, runs in plain containers (Hetzner/Coolify). Provisioning and ovpn config must be generated from the same source so tunnel range and SIP registrar IP stay consistent.
- **Detailed briefing** exists at `openvpn-go-briefing.md` (repo root, German) — covers design principles, risks, and both usage scenarios (TUN-based and in-process).
- **There is no clean RFC for the OpenVPN protocol.** The C reference implementation (`ssl.c`, `crypto.c` in the openvpn repo) *is* the spec. A local checkout of the `release/2.6` branch lives at `/Users/svenloth/dev/openvpn-reference` (sources under `src/openvpn/`) for byte-exact verification. Every byte-level protocol detail (opcodes, packet formats, key derivation) must be verified against that source, never guessed from training data.
- **Known hard parts:** Key Method 2 data-channel key derivation (its own PRF expansion — *not* `ExportKeyingMaterial()`); the control-channel reliability layer (no stdlib pattern); and interop testing itself — byte-level mistakes only surface against a real client, which is why the Docker harness is a v1 requirement, not an afterthought.
- Ecosystem gap: existing Go "openvpn" packages wrap the binary or its management interface; none implement the protocol.

## Constraints

- **Dependencies**: Go standard library only for the core library and netstack (`crypto/tls`, `crypto/cipher`, `crypto/hmac`, `net`, `encoding/binary`, …) — any third-party dependency needs explicit justification and discussion before adoption.
- **Tech stack**: Go; module path `github.com/8upio/govpn`, package name `ovpn`.
- **Correctness source**: OpenVPN C reference code — protocol details verified against `ssl.c`/`crypto.c`, interop verified against a real OpenVPN 2.6 client via packet capture.
- **Deployment target**: Must run unprivileged (no `CAP_NET_ADMIN`, no `/dev/net/tun`) in ordinary containers — hence the userspace netstack.
- **Compatibility**: OpenVPN 2.6 client with tls-crypt, cert auth, AES-256-GCM, `topology subnet`.
- **License/visibility**: Open source from the start — public API design and documentation matter early.

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Reuse `crypto/tls` over a custom framing `net.Conn` instead of reimplementing TLS | OpenVPN wraps standard TLS in its own framing; building the framing as `net.Conn` eliminates the entire TLS handshake surface | — Pending |
| `Session` = plain `io.ReadWriteCloser` for raw IP packets; consumption (TUN, in-process, tests) is the caller's job | Decouples protocol from IO; enables the privilege-free Voxio scenario | — Pending |
| tls-crypt in v1 (not plain TLS, not tls-auth) | Matches real OpenVPN 2.6 production configs; avoids shipping something that only works with weakened client configs | — Pending |
| Userspace netstack gets minimal server-side TCP (`ListenTCP`) in addition to UDP | Enables the tunnel-only example web server; Voxio benefits later (SIP over TCP); stays stdlib-only and privilege-free | — Pending |
| No gVisor netstack | Massively oversized for the need; heavy dependency against the minimal-deps principle | — Pending |
| `topology subnet` only, 1 IP per client | `net30` burns 4 IPs per client (~63 clients per /24); subnet topology scales to ~65k phones on a /16 | — Pending |
| Docker-based interop harness as a v1 requirement | Interop testing is the real bottleneck; reproducible + CI-automatable beats manual local testing | — Pending |
| Open source under `github.com/8upio/govpn` | No comparable Go implementation exists; ecosystem value | — Pending |
| Example = web server only reachable through the tunnel (interactive page + 3–5 subpages) | Demonstrates the full in-process pattern (ovpn + netstack + TCP) with an immediately tangible result | — Pending |

## Evolution

This document evolves at phase transitions and milestone boundaries.

**After each phase transition** (via `/gsd-transition`):
1. Requirements invalidated? → Move to Out of Scope with reason
2. Requirements validated? → Move to Validated with phase reference
3. New requirements emerged? → Add to Active
4. Decisions to log? → Add to Key Decisions
5. "What This Is" still accurate? → Update if drifted

**After each milestone** (via `/gsd-complete-milestone`):
1. Full review of all sections
2. Core Value check — still the right priority?
3. Audit Out of Scope — reasons still valid?
4. Update Context with current state

---
*Last updated: 2026-08-27 after Phase 3 (In-Process Termination) — tunnel traffic terminates fully in-process; real client pings, UDP round-trips, and browses the example site with an unprivileged server container*
