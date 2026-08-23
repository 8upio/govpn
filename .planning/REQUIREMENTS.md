# Requirements: govpn

**Defined:** 2026-08-22
**Core Value:** A real, unmodified OpenVPN 2.6 client can connect to a Go process embedding this library and exchange traffic through the tunnel — verified against the reference implementation, not approximated from memory.

## v1 Requirements

Requirements for initial release. Each maps to roadmap phases.

### Wire Format & Crypto Primitives

- [ ] **WIRE-01**: Control/data packet parsing and serialization (opcodes, session IDs, packet IDs, ACK arrays) matches the C reference byte-exactly, covered by golden-vector tests
- [ ] **WIRE-02**: TLS 1.0 PRF (MD5+SHA1 P_hash) implemented with stdlib crypto and verified against reference test vectors
- [ ] **WIRE-03**: Key Method 2 data-channel key derivation (master secret → key expansion → per-direction cipher/HMAC key slots incl. implicit IV extraction) verified byte-exactly against `ssl.c`/`crypto.c`
- [ ] **WIRE-04**: tls-crypt wrap/unwrap (HMAC-SHA256 MAC-then-encrypt with AES-256-CTR, tag-as-IV) with key-file parsing and replay protection, verified against `tls_crypt.c` with isolated test vectors

### Control Channel

- [ ] **CTRL-01**: Reliability layer delivers control payloads in order with ACK piggybacking and retransmission, surviving 5–10% synthetic packet loss
- [ ] **CTRL-02**: Control-channel framing exposed as a `net.Conn` byte stream with fragmentation/reassembly, handling multi-KB TLS records (realistic cert chains)
- [ ] **CTRL-03**: A real OpenVPN 2.6 client completes the full TLS handshake (HARD_RESET_V2 through TLS established) with certificate-based mutual auth via stdlib `crypto/tls`
- [ ] **CTRL-04**: Key Method 2 exchange over TLS application data completes (random material, options string, peer-info parsing)
- [ ] **CTRL-05**: PUSH_REQUEST/PUSH_REPLY works: client receives tunnel IP (`topology subnet`), explicit `cipher AES-256-GCM` push, keepalive parameters, and brings its tunnel up

### Data Channel

- [ ] **DATA-01**: P_DATA_V2 packets (24-bit peer-id) encrypt/decrypt with AES-256-GCM using correct nonce construction (packet-ID ‖ implicit IV) and header-as-AAD
- [ ] **DATA-02**: Data-channel replay protection (packet-ID window) drops replayed/out-of-window packets
- [ ] **DATA-03**: Keepalive/ping magic packets are answered and filtered inside the library — never surfaced to the Session consumer

### Session & Server API

- [ ] **SESS-01**: Embedder can start a server with `ovpn.NewServer(Config{...}).Serve(net.PacketConn)` — TLS config, cipher, tunnel network, tls-crypt key, OnSession callback
- [ ] **SESS-02**: Each connected client yields a `Session` (`io.ReadWriteCloser` for raw IP packets) with its assigned tunnel IP exposed
- [ ] **SESS-03**: Tunnel IPs are assigned from a configurable `*net.IPNet` of any size (server = first host IP, `topology subnet`, 1 IP per client)
- [ ] **SESS-04**: Soft reset / key renegotiation works: session survives client-initiated renegotiation (default `reneg-sec 3600`) with key rollover and no traffic interruption beyond the protocol's own switchover
- [ ] **SESS-05**: Sessions end cleanly: explicit-exit-notify is handled, idle sessions time out and are reaped, `Session.Close()` tears down state without goroutine leaks

### Userspace Netstack

- [ ] **NET-01**: `ListenUDP(port)` returns a `net.PacketConn` that transparently demuxes tunnel UDP traffic (parse/build IP+UDP headers), usable by unmodified socket-based code
- [ ] **NET-02**: Minimal server-side TCP: `ListenTCP(port)` returns a `net.Listener` sufficient to serve HTTP to tunnel clients (stdlib-only, no gVisor)
- [ ] **NET-03**: Built-in ICMP echo responder: tunnel clients can ping the server tunnel IP
- [ ] **NET-04**: Sessions attach/detach dynamically with IP→session routing; UDP listeners can be opened on arbitrary ports at runtime (RTP-style dynamic ports)

### Example

- [ ] **XMPL-01**: Example web server reachable only through the tunnel: interactive landing page plus 3–5 subpages, served via the netstack TCP listener, runnable with a single command

### Interop Verification

- [ ] **VRFY-01**: Docker harness: pinned OpenVPN 2.6 client container (self-built Debian image) connects to the library with a generated config (certs, tls-crypt key) — automatable in CI
- [ ] **VRFY-02**: End-to-end through the real client: ping (ICMP), UDP round-trip, and HTTP page load through the tunnel all succeed
- [ ] **VRFY-03**: Harness includes a lossy-network scenario (5–10% packet loss/reordering) under which handshake and traffic still succeed

## v2 Requirements

Deferred to future release. Tracked but not in current roadmap.

### Protocol Breadth

- **PROTO-01**: NCP (cipher negotiation) for broader client compatibility
- **PROTO-02**: Session floating (client IP/port changes mid-session, NAT rebind)
- **PROTO-03**: tls-crypt-v2 (per-client keys)
- **PROTO-04**: TCP transport mode (server accepts clients over TCP)

### Platform

- **PLAT-01**: `ovpn/tun` package for TUN-device binding (Linux first, build tags per platform)
- **PLAT-02**: Windows/macOS client interop hardening

## Out of Scope

| Feature | Reason |
|---------|--------|
| TUN/TAP handling in v1 | Caller's responsibility; primary use case (Voxio) is in-process and privilege-free |
| Routing / NAT / IP forwarding | Deliberately outside the library |
| Username/password auth, PSK static-key mode | Cert-based auth only in v1 |
| LZO / compression | Deprecated in ecosystem, adds complexity and attack surface |
| `net30` topology | Wastes 4 IPs per client; `topology subnet` only — explicit non-goal |
| Client-side implementation | Server only |
| Management interface | It's a library, not a process |
| Full/conformant TCP stack (gVisor) | Minimal server-side TCP suffices; gVisor is oversized and a heavy dependency |
| tls-auth | tls-crypt chosen for v1 instead |
| NCP negotiation in v1 | Fixed AES-256-GCM + explicit cipher push satisfies 2.6 clients |

## Traceability

Which phases cover which requirements. Updated during roadmap creation.

| Requirement | Phase | Status |
|-------------|-------|--------|
| WIRE-01 | Phase 1 | Pending |
| WIRE-04 | Phase 1 | Pending |
| CTRL-01 | Phase 1 | Pending |
| CTRL-02 | Phase 1 | Pending |
| CTRL-03 | Phase 1 | Pending |
| SESS-01 | Phase 1 | Pending |
| VRFY-01 | Phase 1 | Pending |
| WIRE-02 | Phase 2 | Pending |
| WIRE-03 | Phase 2 | Pending |
| CTRL-04 | Phase 2 | Pending |
| CTRL-05 | Phase 2 | Pending |
| DATA-01 | Phase 2 | Pending |
| DATA-02 | Phase 2 | Pending |
| DATA-03 | Phase 2 | Pending |
| SESS-02 | Phase 2 | Pending |
| SESS-03 | Phase 2 | Pending |
| VRFY-03 | Phase 2 | Pending |
| NET-01 | Phase 3 | Pending |
| NET-02 | Phase 3 | Pending |
| NET-03 | Phase 3 | Pending |
| NET-04 | Phase 3 | Pending |
| XMPL-01 | Phase 3 | Pending |
| VRFY-02 | Phase 3 | Pending |
| SESS-04 | Phase 4 | Pending |
| SESS-05 | Phase 4 | Pending |

**Coverage:**
- v1 requirements: 25 total
- Mapped to phases: 25
- Unmapped: 0 ✓

---
*Requirements defined: 2026-08-22*
*Last updated: 2026-08-22 after roadmap creation (traceability mapped)*
