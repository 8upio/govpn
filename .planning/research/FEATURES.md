# Feature Research

**Domain:** OpenVPN server-side protocol implementation (pure Go library)
**Researched:** 2026-08-22
**Confidence:** HIGH (protocol mechanics — cross-checked against OpenVPN.net protocol docs, OpenVPN source repo docs (`doc/man-sections/`, `doc/doxygen/`), and the openvpn-rfc wire-protocol draft) / MEDIUM (exact 2.6 client tolerances for edge cases not exhaustively tested)

## Feature Landscape

Scope note: this is a protocol-compatibility surface, not a competitive product feature set. "Table stakes" here means literally *the OpenVPN 2.6 client will not complete a handshake or will drop the tunnel without it*. "Differentiators" are things that make govpn more robust/production-ready than a bare MVP but aren't required for a reference client to connect once. "Anti-features" are explicitly out of scope per PROJECT.md and confirmed here as safe to exclude for interop with a *standard* 2.6 client config.

### Table Stakes (Client Won't Connect / Tunnel Breaks Without These)

| Feature | Why Required | Complexity | Notes |
|---------|--------------|------------|-------|
| **Control-channel opcode/session framing** (`P_CONTROL_V1`=4, `P_ACK_V1`=5, `P_CONTROL_HARD_RESET_CLIENT_V2`=7, `P_CONTROL_HARD_RESET_SERVER_V2`=8, `P_CONTROL_SOFT_RESET_V1`=3, `P_DATA_V2`=9) with 64-bit random session IDs (local + remote) | This is the wire format for everything; nothing else works without it | HIGH | No stdlib pattern — this is what becomes the custom `net.Conn` the briefing describes. Byte layout must match `ssl.c`/`reliable.c` exactly. |
| **Reliability layer: ACK + retransmit over UDP** | TLS records inside `P_CONTROL` packets must arrive reliably and in order even though UDP doesn't guarantee either; without this the TLS handshake stalls/fails on any loss or reorder | HIGH | Sliding window of outstanding packet IDs per direction, ACKs can piggyback on the next outgoing `P_CONTROL` or ride alone in a `P_ACK_V1`; retransmit timer with backoff. This is explicitly called out in the briefing as the hardest non-crypto piece. |
| **HARD_RESET handshake sequence (Key Method 2, V2)**: client sends `P_CONTROL_HARD_RESET_CLIENT_V2` (fresh session ID, packet ID 0) → server replies `P_CONTROL_HARD_RESET_SERVER_V2` (its own session ID, ACKs client's packet 0, echoes client's session ID as remote ID) → both switch to `P_CONTROL_V1` for the actual TLS record stream | This is the only handshake initiation sequence a real 2.6 client sends; anything else is silently ignored | MEDIUM | State machine has few states (pre-reset, reset-sent/received, active) but must be exact — clients that see an unexpected opcode or wrong session-ID echo just retry the HARD_RESET forever with no useful error. |
| **tls-crypt unwrap/wrap** (AES-256-CTR + HMAC-SHA256, SIV-style: `auth_tag = HMAC(Ka, header‖msg)`, `IV = top 128 bits of auth_tag`, `ciph = AES-256-CTR(Ke, IV, msg)`) applied to every control-channel packet including the HARD_RESET itself | PROJECT.md commits to tls-crypt for v1 (matches real production configs); a tls-crypt client will send every control packet — including the very first HARD_RESET — pre-wrapped, so this must exist before any control-channel framing can even be parsed | MEDIUM-HIGH | Static pre-shared key (from the client's `.ovpn`/ta.key) derives 2×(Ke,Ka) via OpenVPN's own key-derivation, one pair per direction. Get this wrong and the server can't even see the HARD_RESET — looks like total silence, hard to debug without a packet capture. |
| **TLS handshake via `crypto/tls` over the custom `net.Conn`**, server cert + client CA verification (mutual TLS) | Client auth in scope is cert-based only; a 2.6 client configured with `cert`/`key`/`ca` requires and performs full mutual TLS | MEDIUM | This is the "cheap" part per the architecture bet — stdlib `tls.Server()` does the actual TLS 1.2/1.3 state machine. Real cost is making the framing `net.Conn` behave correctly (blocking reads, correct MTU-sized writes, no reordering) under `crypto/tls`'s assumptions. |
| **Key Method 2 exchange** (first application-data message over the now-established TLS session): client sends `key_method(1)‖random1[32]‖random2[32]‖options_string‖peer_info_block`; server replies `key_method(1)‖random1[32]‖random2[32]‖options_string` | This *is* the mechanism that produces the data-channel key material; without parsing/producing it, no data-channel keys exist | HIGH | Distinct from the TLS handshake — this is OpenVPN's own mini-protocol riding inside the TLS tunnel. The random blocks feed OpenVPN's custom PRF (not `ExportKeyingMaterial`) to derive 4 keys (client/server × encrypt/decrypt); for AEAD ciphers only cipher key + implicit IV per direction are actually used. Flagged in PROJECT.md as the top verification risk — must be checked byte-exact against `crypto.c`. |
| **Data-channel key derivation (custom PRF expansion)**, byte-exact against `ssl.c`/`crypto.c` | If this is off by even one byte, the client and server derive different keys and every data packet fails GCM auth (silent packet drops, no protocol-level error) | HIGH | The single most likely source of "handshake completes but no traffic passes." Needs a from-source verification pass before any data-channel code is written (already identified in the briefing as step 1). |
| **`PUSH_REQUEST` / `PUSH_REPLY` handling** — client sends the literal ASCII string `PUSH_REQUEST` as a control-channel app message after Key Method 2 completes; server must reply with `PUSH_REPLY` containing at minimum `ifconfig <client-ip> <netmask>`, `topology subnet`, `route-gateway <server-tunnel-ip>` | A 2.6 client with no static `ifconfig`/route config (the normal case) sits waiting for `PUSH_REQUEST`→`PUSH_REPLY` before it will bring the tunnel interface up at all — no push reply, no working tunnel even after a "successful" TLS handshake | MEDIUM | This is a second mini text-protocol layered inside the same TLS-wrapped control channel as Key Method 2 — not exposed to the library consumer, must be handled entirely inside `ovpn`. Must include `topology subnet` explicitly since client defaults differ by platform/version otherwise. |
| **Minimal single-cipher announcement via push** (`cipher AES-256-GCM` in the `PUSH_REPLY`) | A 2.6 client sends `IV_CIPHERS=...`/`IV_NCP=2` in its Key-Method-2 peer-info block, meaning it expects the server to *tell it* which cipher was chosen via the push reply, not just assume its own local default. Some real-world client configs set an explicit legacy cipher and would refuse to switch without this signal | LOW-MEDIUM | This is *not* full NCP — it's a one-line, always-the-same-value push. Server does not need to parse the client's offered cipher list or make a choice; it always pushes the one fixed cipher. Cheap to implement, high interop value — treat as a required subset of NCP, not deferred. |
| **Tolerating/ignoring OCC and unrecognized peer-info lines** | Real clients still send OCC-style consistency strings and a peer-info block with many `IV_*` keys (platform, version, proto flags, MTU, comp) the server doesn't need. A server that errors on unknown lines instead of ignoring them will reject real clients | LOW | Parse what's needed (peer-info for logging/diagnostics is optional); everything else must be a no-op. Not implementing OCC response logic is fine — modern clients treat OCC mismatches as warnings, not hard failures, in the default (non-`--opt-verify`) configuration. |
| **`P_DATA_V2` packet format with 24-bit peer-id**: 1-byte opcode/key-id + 3-byte peer-id header, followed by 4-byte packet ID, then AEAD tag + ciphertext | Server must push `peer-id <n>` in the `PUSH_REPLY` for the modern data-channel path (which a default 2.6 client expects); once assigned, the client sends/expects this format, not the legacy `P_DATA_V1` single-opcode-byte format | MEDIUM | Also the mechanism needed for "floating" clients (source IP:port changes without dropping the tunnel) — directly relevant to Voxio phones behind NAT. |
| **AES-256-GCM nonce/AAD construction**: 12-byte nonce = 4-byte packet ID (wire, incrementing) ‖ 8-byte implicit IV (static per session/direction, derived from Key Method 2 material); AAD = the full cleartext header (opcode+peer-id byte(s) + packet ID) | Get this wrong and every data packet fails GCM authentication — connects fine, zero traffic passes | HIGH | Same failure-mode risk profile as data-channel key derivation: silent, hard to diagnose without a reference packet capture to diff against. |
| **Packet-ID replay protection on the data channel** (4-byte incrementing ID, sliding replay window, reset per rekey) | Baseline requirement for any AEAD/GCM use — nonce reuse under a fixed key is catastrophic, and OpenVPN's own security model assumes the replay window is enforced | MEDIUM | Straightforward sliding-window bitmap; must be scoped per active key (old/new key overlap briefly during any future rekey). |
| **Ping/keepalive packet recognition and filtering** — OpenVPN keepalive pings are data-channel packets carrying a fixed 16-byte magic payload, *not* real IP packets | If these are handed to the `Session.Read()` consumer as if they were IP packets, every downstream IP/UDP parser breaks on a non-IP payload; client sends these periodically by default (`ping`/`ping-restart`, commonly pushed as e.g. `ping 10`/`ping-restart 120`) | LOW | Must detect the magic payload post-decryption and swallow it rather than surfacing it through the `io.ReadWriteCloser`. Cheap but easy to miss, and it *will* be hit in any real session lasting more than a few seconds. |
| **Server → client `topology subnet` + `route-gateway`** push, one IP per client from `Config.Network`, server = first host IP by convention | Explicit project requirement; without a topology directive a stock client may assume its compiled-in default, which historically was `net30` (pre-2.6-era) or is otherwise ambiguous — must be explicit to guarantee subnet behavior | LOW | Already scoped in PROJECT.md; listed here because it's also a protocol-level table stake, not just a design preference — a missing/incorrect topology push is a client-visible interop failure, not just a style choice. |
| **UDP demux by session** (`srv.Serve(net.PacketConn)`) — associate inbound UDP datagrams with the right in-flight handshake or established session, initially by source `addr:port`, then by peer-id once assigned | Base transport requirement — there is no OpenVPN over UDP without a working per-client dispatch loop | MEDIUM | Straightforward `map[addr]*session` for MVP; peer-id-based lookup (see `P_DATA_V2` above) is what allows source-address changes without breaking dispatch. |

### Differentiators (Beyond "It Connects Once" — Production Robustness)

| Feature | Value Proposition | Complexity | Notes |
|---------|-------------------|------------|-------|
| **Soft reset / data-channel key renegotiation** (`P_CONTROL_SOFT_RESET_V1`, triggered client-side by default `reneg-sec` ≈ 3600s) | A stock 2.6 client will initiate this ~every hour on any session that stays up that long; if the server can't handle it, the tunnel is forcibly torn down at the 1-hour mark. Not needed to pass a short interop test (handshake+ping+HTTP finishes in seconds), but **required before any real always-on deployment** — directly relevant to Voxio's persistent phone tunnels | HIGH | Explicitly flagged by the milestone question as "deferrable for v1?" — answer: yes for the Docker interop harness (short-lived test sessions complete well under an hour), no for production. Recommend it as the first post-MVP differentiator, not a "someday" item, given the target use case. New key material derived via a fresh Key-Method-2 exchange inside the same session/session-IDs, old+new key overlap briefly for graceful cutover. |
| **Server-side peer inactivity timeout / session reaping** (mirrors client `ping-restart`) | UDP is connectionless — without server-side liveness detection, a client that vanishes (phone unplugged, NAT mapping expired) leaves a session object alive forever, leaking memory/goroutines | LOW-MEDIUM | Simple last-seen timestamp + reaper goroutine; complements pushing `ping`/`ping-restart` to the client. |
| **`explicit-exit-notify` handling** — recognize the client's graceful-disconnect signal and free the session immediately instead of waiting for the inactivity timeout | Faster resource cleanup on clean disconnects (phone reboot, service restart); not required for protocol correctness — the client disconnects either way | LOW | Pure optimization; safe to skip entirely for v1 without any interop risk. |
| **Session floating / NAT-rebind tolerance** (peer-id-keyed dispatch surviving a source-address change mid-session) | Directly matches the Snom-phone-on-arbitrary-network scenario — phones roaming between Wi-Fi/mobile or behind carrier-grade NAT will see their public `addr:port` change without a full reconnect if this works | MEDIUM | Naturally falls out of implementing `P_DATA_V2`/peer-id correctly (already table stakes) — the differentiator is *using* the peer-id for re-keying the dispatch map on address change, not just for AAD construction. |
| **Interop verified via Docker harness against the real 2.6 client with packet-capture diffing** | This is the actual credibility differentiator vs. every other Go "openvpn" package, which wraps the binary instead of implementing the protocol; the value proposition of this whole project rests on this actually being true and re-verifiable in CI | MEDIUM-HIGH | Already a v1 requirement per PROJECT.md — listed here to make explicit that it *is* the competitive edge, not just a QA nicety. |
| **Userspace TCP for HTTP-through-tunnel** (`ListenTCP`, minimal server-side handshake/state machine, no gVisor) | No comparable lightweight, privilege-free, embeddable Go TCP-over-tunnel exists; enables the example web server and future SIP-over-TCP for Voxio without pulling in a full netstack dependency | MEDIUM-HIGH | Scoped in PROJECT.md as "enough for HTTP," explicitly not a conformant general TCP stack — the differentiator is being *minimal and dependency-free*, not being complete. |
| **Dynamic/catch-all UDP port ranges for RTP-style workloads** | Matches Voxio's actual SIP/RTP traffic pattern (RTP ports negotiated per-call via SDP) — a fixed-port-only `ListenUDP` wouldn't cover the real use case | MEDIUM | Already scoped; listed as differentiator because generic "OpenVPN library" competitors have no equivalent (this is downstream of the netstack design, not the protocol itself). |
| **Configurable large subnets** (`/16`-scale `topology subnet`, ~65k addressable clients) | Snom fleet at Voxio's scale needs more than a `/24`; most example OpenVPN setups assume small `/24` deployments | LOW | Just a config surface concern once `topology subnet` + IP assignment are correct — no extra protocol work. |

### Anti-Features (Deliberately Not Building)

| Feature | Why It Seems Needed | Why Excluded for v1 | Alternative |
|---------|----------------------|----------------------|-------------|
| **Full NCP (Negotiable Crypto Parameters)** — parsing the client's offered cipher list, choosing among multiple ciphers, `fallback-cipher`, downgrade/AUTH_FAILED handling | "Real" OpenVPN servers do full multi-cipher negotiation; skipping it looks incomplete | A fixed fixed-cipher server that always pushes `cipher AES-256-GCM` (see table stakes above) satisfies a standard 2.6 client without any of the list-parsing/selection machinery. Full NCP only matters when supporting *multiple* possible ciphers or legacy clients that don't support GCM — out of scope per PROJECT.md | Push a single fixed cipher; document that mixed-cipher fleets aren't supported in v1 |
| **Compression (LZO / `compress`)** | Older configs and some tutorials still enable it | Deprecated in the OpenVPN ecosystem generally (compression-based VPN attacks like VORACLE are why upstream deprecated it); adds a codec + adjustable-length framing complexity for negative practical value in 2026 | Document that compression must be disabled client-side (`comp-lzo no` / no `compress` directive) — standard modern client configs already default this way |
| **`tls-auth`** | Still common in older/legacy `.ovpn` configs found online | `tls-crypt` is a strict superset in practice for new deployments (adds control-channel *encryption*, not just authentication) and is what PROJECT.md commits to; supporting both roughly doubles the control-channel wrapping code path for a shrinking population of `tls-auth`-only configs | Ship `tls-crypt` only; if `tls-auth`-only clients appear later, add as a second wrapping mode behind a config flag |
| **Username/password auth, PSK (static-key mode)** | Some deployments use these instead of/alongside certs | Cert-based mutual TLS is sufficient for the Voxio provisioning model (each phone gets its own cert) and is explicitly the v1 scope; static-key mode bypasses the entire TLS/control-channel design this library is built around | Cert + CA only; static-key mode would be a fundamentally different code path (no TLS handshake at all) better suited to a separate future package if ever needed |
| **`net30` topology** | Historically OpenVPN's default; still what some tutorials show | Burns 4 IPs per client (~63 clients per `/24`); explicit non-goal since `topology subnet` scales to Voxio's phone-fleet numbers on a `/16` | Push `topology subnet` unconditionally; document that `net30`-only legacy clients (pre-2.1, effectively extinct) aren't supported |
| **TUN/TAP device handling** | "A VPN server needs a tunnel device" is the default mental model | Primary use case (Voxio) terminates traffic in-process with no OS-level tunnel; TUN handling is the caller's responsibility per the `Session` = `io.ReadWriteCloser` design | `ovpn/tun` as an optional, separate, platform-tagged package later; core library stays IO-agnostic |
| **Routing / NAT / IP forwarding** | Natural companion to "VPN server" | Deliberately outside the library boundary — belongs to whatever consumes the `Session`, not to the protocol implementation | Caller wires `Session` to TUN + OS routing, or to the in-process netstack, as needed |
| **Full/conformant userspace TCP stack (e.g. gVisor-equivalent)** | "Do TCP properly" is tempting once any TCP support exists | Massively oversized for "serve HTTP through the tunnel"; heavy dependency, violates the stdlib-only minimal-deps principle | Minimal server-side-only TCP state machine sufficient for HTTP request/response patterns; explicitly not a general client-capable TCP stack |
| **Client-side OpenVPN implementation** | "Symmetric" library design instinct | Server-only per PROJECT.md; a client implementation is a materially different problem (initiates HARD_RESET, handles server-chosen options, etc.) and not needed by any current use case | None planned — out of scope, full stop |
| **Windows/macOS client interop hardening** | Real-world client fleets are cross-platform | v1 interop target is specifically the reference Linux 2.6 client in the Docker harness; platform-specific client quirks (if any) are a later-phase concern | Defer to a post-v1 interop-hardening phase once the Linux reference path is solid |
| **Management interface** (as in the official `openvpn` binary — TCP/socket control API for stats, kill, etc.) | The official binary exposes this; feels like "parity" | This is a library, not a standalone process — the embedding Go program *is* the management surface (via `Config`, callbacks, and direct API calls) | Expose equivalent introspection (session list, stats) as Go API calls on the `Server`/`Session` types instead of a wire protocol |

## Feature Dependencies

```
tls-crypt unwrap/wrap
    └──requires──> control-channel opcode/session framing (needs the header to wrap/unwrap around)

control-channel opcode/session framing
    └──requires──> reliability layer (ACK/retransmit)
                       └──requires──> HARD_RESET handshake sequence (bootstraps the session IDs the reliability layer tracks)

HARD_RESET handshake sequence
    └──enables──> TLS handshake via crypto/tls (framing net.Conn must be a working net.Conn before tls.Server() can run over it)

TLS handshake (mutual, cert + CA)
    └──enables──> Key Method 2 exchange (random material + peer-info, first app-data message post-handshake)
                       └──requires──> Data-channel key derivation (custom PRF expansion — the actual point of Key Method 2)

Key Method 2 exchange
    └──enables──> PUSH_REQUEST / PUSH_REPLY exchange (second control-channel mini-protocol, same TLS session)
                       └──produces──> topology subnet + ifconfig + route-gateway + single-cipher push + peer-id assignment

Data-channel key derivation
    └──requires──> AES-256-GCM nonce/AAD construction
                       └──requires──> P_DATA_V2 packet format (peer-id) + packet-ID replay protection

PUSH_REPLY (peer-id assignment)
    └──enables──> Session floating / NAT-rebind tolerance (differentiator; peer-id must exist first)

UDP demux by session (addr:port)
    └──enhances──> peer-id-based dispatch (differentiator; addr:port demux alone is enough for MVP, single stable NAT mapping)

Soft reset / key renegotiation
    └──requires──> Key Method 2 exchange (soft reset reruns the same exchange, new random material, same session IDs)
    └──conflicts-with-shipping-without──> long-lived sessions (any session > ~1hr WILL trigger this from the client; deferring it caps safe session length)

Ping/keepalive packet filtering
    └──requires──> data-channel decryption working (must be post-GCM-decrypt to recognize the magic payload)

Server-side peer inactivity timeout
    └──enhances──> UDP demux by session (frees stale map entries; not required for correctness, required for long-run memory safety)

Full NCP (anti-feature)
    └──conflicts-with──> minimal single-cipher push (the table-stakes item deliberately replaces this)

tls-auth (anti-feature)
    └──conflicts-with──> tls-crypt (mutually exclusive control-channel wrapping modes; picking one excludes the other per-connection)

TUN/TAP handling (anti-feature, deferred)
    └──alternative-to──> userspace netstack (ipudp package) as the primary consumption path for v1
```

### Dependency Notes

- **tls-crypt requires control-channel framing to exist conceptually first, but must be applied before framing can be parsed on the wire:** the *design* dependency runs framing→reliability→handshake, but the *wire* dependency is inverted — every byte of every control packet, including the very first HARD_RESET, arrives tls-crypt-wrapped. Implementation order should therefore be: build the plaintext framing/reliability logic first (testable against synthetic packets), then wrap tls-crypt around it as the outermost layer before any interop test against a real client.
- **Data-channel key derivation requires Key Method 2, which requires a completed TLS handshake, which requires working control-channel framing + reliability.** This is the critical path for "handshake completes at all" — nothing about the data channel can be tested until the full control-channel stack (framing → reliability → tls-crypt → TLS → Key Method 2) works end to end. Recommend building and interop-testing the control channel in isolation (verify via packet capture that a real client completes its TLS handshake) *before* writing any data-channel code, exactly as the briefing's proposed step order suggests.
- **PUSH_REPLY's single-cipher-push and peer-id assignment both gate data-channel correctness**: a client that never receives `cipher AES-256-GCM` may fall back to a locally configured different cipher (mismatch → silent GCM auth failures); a client that never receives a `peer-id` sends legacy `P_DATA_V2`-less packets, changing the header format the server must parse. Both must be correct in the same push-reply message, not staged separately.
- **Soft reset conflicts with "ship without it" only past the ~1-hour mark**: this is a soft dependency on session *duration*, not a hard blocker for interop validation. Safe to sequence after the Docker harness (handshake+ping+HTTP, all <<1hr) passes, but should be scheduled before anything resembling a persistent Voxio pilot.
- **Full NCP conflicts with the minimal single-cipher push by design**: implementing both is wasted effort — the project has explicitly chosen the cheap path (always push one fixed cipher) instead of the general one (negotiate among several). Don't accidentally build cipher-list parsing "for completeness"; it has no interop payoff at fixed-cipher v1 scope.
- **tls-auth and tls-crypt are mutually exclusive per connection** by protocol design (different opcodes/wrapping expectations) — not a phasing concern so much as a "don't build both" scope reminder.

## MVP Definition

### Launch With (v1) — Required for "real 2.6 client connects, ping + HTTP pass through the tunnel"

- [ ] Control-channel opcode/session-ID framing as a `net.Conn` — foundation for everything else
- [ ] Reliability layer (ACK/retransmit) — TLS handshake cannot survive UDP loss without it
- [ ] HARD_RESET V2 handshake sequence — the only client-initiated bootstrap sequence that exists
- [ ] tls-crypt wrap/unwrap on every control packet — matches the committed production config target
- [ ] TLS handshake via `crypto/tls` (mutual cert auth) — client auth model in scope
- [ ] Key Method 2 exchange + byte-exact custom PRF key derivation — the actual point of the whole control channel
- [ ] PUSH_REQUEST/PUSH_REPLY with `ifconfig`, `topology subnet`, `route-gateway`, single fixed-cipher push (`cipher AES-256-GCM`), peer-id assignment — client won't bring the tunnel interface up without this
- [ ] `P_DATA_V2` packet parsing/building with peer-id — this is the header format a peer-id-assigned client actually sends
- [ ] AES-256-GCM nonce/AAD construction, byte-exact — silent failure mode if wrong, must be right from the start
- [ ] Packet-ID replay protection on the data channel — non-negotiable for AEAD safety
- [ ] Ping/keepalive payload filtering — will be hit within seconds of any real session, must not leak into `Session.Read()`
- [ ] UDP demux by session (`srv.Serve`) — base transport dispatch
- [ ] Userspace `ipudp` netstack: `ListenUDP`, `Attach`, ICMP echo responder — needed for the in-process Voxio scenario and the "is the tunnel up" ping test
- [ ] Minimal server-side `ListenTCP` — needed for the example HTTP-through-tunnel deliverable
- [ ] Docker interop harness against real OpenVPN 2.6 client — the acceptance test for all of the above

### Add After Validation (v1.x)

- [ ] Soft reset / key renegotiation (`reneg-sec` handling) — trigger: any session needs to survive longer than ~1 hour (blocks a real Voxio pilot, not the initial interop proof)
- [ ] Server-side peer inactivity timeout / session reaping — trigger: any long-running deployment where clients disappear without a clean disconnect (NAT expiry, phone power loss)
- [ ] Session floating on NAT-rebind (peer-id-based dispatch update) — trigger: real-world testing shows phones changing source `addr:port` mid-session
- [ ] `explicit-exit-notify` fast-path cleanup — trigger: resource churn from slow reaping becomes noticeable under load
- [ ] Dynamic/catch-all UDP port ranges for RTP — trigger: Voxio SIP/RTP integration work begins in earnest

### Future Consideration (v2+)

- [ ] `ovpn/tun` platform-tagged TUN device package — defer until a consumer needs Scenario A (kernel-routed traffic) instead of in-process termination
- [ ] Broader NCP / multi-cipher support — defer until a concrete client population requires a cipher other than AES-256-GCM
- [ ] `tls-auth` support alongside `tls-crypt` — defer until a concrete legacy-client population requires it
- [ ] Windows/macOS client interop hardening — defer until cross-platform client fleets are actually in play

## Feature Prioritization Matrix

| Feature | User Value | Implementation Cost | Priority |
|---------|------------|---------------------|----------|
| Control-channel framing + reliability layer | HIGH | HIGH | P1 |
| tls-crypt wrap/unwrap | HIGH | MEDIUM | P1 |
| TLS handshake (crypto/tls, mutual cert auth) | HIGH | MEDIUM | P1 |
| Key Method 2 + data-channel key derivation | HIGH | HIGH | P1 |
| PUSH_REPLY (ifconfig/topology/cipher/peer-id) | HIGH | MEDIUM | P1 |
| P_DATA_V2 + AES-256-GCM data channel | HIGH | HIGH | P1 |
| Ping/keepalive filtering | HIGH | LOW | P1 |
| Userspace netstack (UDP + ICMP + Attach) | HIGH | MEDIUM | P1 |
| Minimal TCP for HTTP example | MEDIUM | MEDIUM-HIGH | P1 |
| Docker interop harness | HIGH | MEDIUM | P1 |
| Soft reset / renegotiation | MEDIUM (HIGH for real deployment) | HIGH | P2 |
| Server-side peer timeout / reaping | MEDIUM | LOW | P2 |
| Session floating (NAT-rebind) | MEDIUM | MEDIUM | P2 |
| explicit-exit-notify | LOW | LOW | P3 |
| Dynamic RTP port ranges | MEDIUM (HIGH for Voxio SIP phase) | MEDIUM | P2/P3 |
| Full NCP | LOW at fixed-cipher scope | HIGH | Not planned |
| ovpn/tun package | LOW for primary use case | MEDIUM | P3 |

**Priority key:**
- P1: Must have for launch (Docker interop harness passing)
- P2: Should have, add when possible (before any real persistent Voxio pilot)
- P3: Nice to have, future consideration

## Sources

- [OpenVPN Protocol — openvpn.net community docs](https://openvpn.net/community-docs/openvpn-protocol.html)
- [OpenVPN's network protocol — build.openvpn.net doxygen](https://build.openvpn.net/doxygen/network_protocol.html)
- [`doc/doxygen/doc_protocol_overview.h` — OpenVPN/openvpn GitHub](https://github.com/OpenVPN/openvpn/blob/master/doc/doxygen/doc_protocol_overview.h)
- [`doc/man-sections/cipher-negotiation.rst` — OpenVPN/openvpn GitHub](https://github.com/OpenVPN/openvpn/blob/master/doc/man-sections/cipher-negotiation.rst)
- [`doc/man-sections/renegotiation.rst` — OpenVPN/openvpn GitHub](https://github.com/OpenVPN/openvpn/blob/master/doc/man-sections/renegotiation.rst)
- [`doc/man-sections/vpn-network-options.rst` — OpenVPN/openvpn GitHub](https://github.com/OpenVPN/openvpn/blob/master/doc/man-sections/vpn-network-options.rst)
- [`src/openvpn/tls_crypt.h` — OpenVPN/openvpn GitHub](https://github.com/OpenVPN/openvpn/blob/master/src/openvpn/tls_crypt.h)
- [Control channel encryption (tls-crypt, tls-crypt-v2) — build.openvpn.net doxygen](https://build.openvpn.net/doxygen/group__tls__crypt.html)
- [Data Channel Crypto module — build.openvpn.net doxygen](https://build.openvpn.net/doxygen/group__data__crypto.html)
- [Data Packet Formats — OpenVPN/openvpn-rfc DeepWiki](https://deepwiki.com/OpenVPN/openvpn-rfc/2.3.1-data-packet-formats)
- [Cipher Negotiation — OpenVPN/openvpn DeepWiki](https://deepwiki.com/OpenVPN/openvpn/3.4-cipher-negotiation)
- [Use P_DATA_V2 for server->client packets too — OpenVPN devel patchwork](https://patchwork.openvpn.net/project/openvpn2/patch/20171112172237.8285-1-steffan@karger.me/)
- [Rework NCP compatibility logic and drop BF-CBC support by default — OpenVPN devel patchwork](https://patchwork.openvpn.net/patch/1346/)
- [OpenVPN 2.6 Manual — openvpn.net community articles](https://openvpn.net/community-docs/community-articles/openvpn-2-6-manual.html)
- Project context: `/Users/svenloth/dev/govpn/.planning/PROJECT.md` and `/Users/svenloth/dev/govpn/openvpn-go-briefing.md` (internal scope decisions, not external sources)

---
*Feature research for: OpenVPN server-side protocol implementation (pure Go library)*
*Researched: 2026-08-22*
