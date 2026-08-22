# Project Research Summary

**Project:** govpn — pure-Go OpenVPN server protocol library
**Domain:** Network protocol implementation (VPN, byte-level interop against C reference)
**Researched:** 2026-08-22
**Confidence:** HIGH

## Executive Summary

**govpn** is a pure-Go reimplementation of the OpenVPN 2.6 server protocol as an embeddable library. It trades architectural simplicity (reusing `crypto/tls` for handshakes) for byte-exact protocol correctness. There is no RFC for OpenVPN — the C reference implementation **is** the specification. Every protocol detail must be verified against `ssl.c`/`crypto.c`/`tls_crypt.c` (local checkout: `/Users/svenloth/dev/openvpn-reference`) before shipping.

The recommended approach is strictly ordered and risk-driven: pure cryptographic/wire-format pieces first (testable in isolation with golden vectors), then real-network integration stages, each gated by a Docker interop criterion against a real OpenVPN 2.6 client. The Docker harness is not optional — every major pitfall manifests as a silent retransmit-loop hang or a "GCM/TLS auth failed" error that is indistinguishable from working code by reading it.

Key risks concentrate in 8 critical pitfalls (all byte-layout bugs): wrong PRF, tls-crypt MAC-then-encrypt ordering, key-expansion slot confusion, `net.Conn` record fragmentation, missing retransmission, P_DATA_V2 AAD/nonce construction, session-ID header parsing, and missing cipher push. Verification against source, not guessing, is the core risk mitigation.

## Key Findings

### Recommended Stack

Go stdlib fully covers TLS handshake, AES-256-GCM AEAD, AES-256-CTR, and HMAC-SHA256 — no third-party crypto needed. The one "gap" is exposure, not primitives: OpenVPN's Key Method 2 uses the legacy RFC 2246 TLS 1.0 PRF (MD5+SHA1 HMAC halves, XOR'd), which Go implements internally (`prf10` in `crypto/tls/prf.go`) but does not export — ~30–40 lines must be hand-written against `crypto/md5`+`crypto/sha1`+`crypto/hmac`. `ExportKeyingMaterial()` is explicitly the wrong tool (different construction, silent interop failure).

**Core technologies:**
- Go stdlib (`crypto/tls`, `crypto/cipher`, `crypto/hmac`, `net`, `encoding/binary`): entire core library — zero-dependency principle holds
- Hand-written TLS 1.0 PRF (stdlib hashes): Key Method 2 key derivation — Go's internal `prf10` is unexported
- Docker harness on self-built `debian:bookworm-slim` + `apt-get install openvpn` (2.6.3): reproducible interop client — avoids unpinned third-party images
- `github.com/gopacket/gopacket` (maintained fork; test tooling only, separate module): packet-capture analysis — never in the core dependency graph

See `STACK.md` for the full C-reference source map (which files spec which subsystem).

### Expected Features

**Must have (table stakes — client won't connect without):**
- Control-channel framing (opcode/session-ID), reliability layer (ACK/retransmit), HARD_RESET_V2 handshake
- tls-crypt wrapping from the very first packet (SIV-style MAC-then-encrypt)
- TLS handshake over framing conn; Key Method 2 exchange as TLS **application data** after handshake
- PUSH_REQUEST/PUSH_REPLY text protocol incl. explicit `cipher AES-256-GCM` push (no full NCP needed — client accepts pushed cipher)
- P_DATA_V2 (24-bit peer-id), AES-256-GCM with nonce = 4-byte packet-ID ‖ 8-byte implicit IV, header as AAD, replay window
- Ping/keepalive filtering (fixed 16-byte magic payload — must be swallowed in the library)

**Should have (differentiators):**
- Privilege-free userspace netstack (UDP demux, minimal server-side TCP, ICMP echo) — the reason this library exists for Voxio
- Tunnel-only example web server demonstrating the full in-process pattern

**Defer (v1.x, but NOT "someday"):**
- Soft reset / key renegotiation (client default `reneg-sec` ≈ 3600 s) — deferrable for short interop tests, required before any real Voxio pilot; keep key-slot/generation design from day one to avoid a structural rewrite

### Architecture Approach

Layered decomposition: UDP mux (client addr → session) → tls-crypt unwrap → opcode demux → control channel (framing `net.Conn` over `io.Pipe` + reliability layer + `crypto/tls.Server()`) vs data channel (key derivation, AEAD, replay window) → `Session` (`io.ReadWriteCloser`) → user callback. Goroutine-per-session with mutex-guarded reliability state (three trigger points: packet arrival, ACK arrival, timer fire), one central UDP reader, `time.AfterFunc` retransmit timers. The netstack is a sibling package depending only on `io.ReadWriteCloser` — unit-testable against a fake session from day one. Closest prior art: `ooni/minivpn` (pure-Go client, research-grade) validates the layer shape, not byte-level details.

**Major components:**
1. `internal/wire` — packet parsing/serialization (opcodes, headers)
2. `internal/keys` — TLS 1.0 PRF + Key Method 2 derivation
3. `internal/tlscrypt` — control-channel wrap/unwrap
4. `internal/reliable` + `internal/controlconn` — ACK/retransmit + `net.Conn` byte-stream adapter
5. `internal/datachannel` — AEAD encrypt/decrypt, replay protection
6. Public API: `Config`, `Server`, `Session`; `netstack` sibling package; `examples/`

### Critical Pitfalls

1. **Wrong PRF for Key Method 2** — hand-write TLS 1.0 PRF, verify with golden vectors against C reference before any data-channel code
2. **tls-crypt is MAC-then-encrypt** (HMAC tag becomes the CTR IV) — opposite of modern tutorials; wrong order drops every HARD_RESET silently. Isolated test vectors before integration
3. **Missing retransmission passes all clean-network tests** — Docker loopback has ~zero loss; harness must inject 5–10% artificial packet loss (`tc netem`/lossy proxy) as a required scenario
4. **`net.Conn` must be a genuine reliable, self-fragmenting byte stream** — even a modest cert chain exceeds one control packet; test fragmentation with multi-KB chains explicitly
5. **P_DATA_V2 implicit IV** — 64 bits from the unused HMAC-key slot of key expansion (not zero, not random); opcode+peer-id header is AAD, not encrypted

## Implications for Roadmap

Suggested phase structure (7 phases, Phase 7 deferred to v1.x):

### Phase 1: Foundation — pure crypto & wire format
**Rationale:** Highest correctness risk, zero network dependencies — testable in isolation with golden vectors
**Delivers:** `internal/wire`, `internal/keys` (TLS 1.0 PRF + Key Method 2), `internal/tlscrypt`
**Avoids:** Pitfalls 1, 2 (wrong PRF, MAC ordering)
**Gate:** Byte-exact match against reference source / golden vectors

### Phase 2: Control-channel reliability & framing
**Rationale:** Independent of Phase 1 (parallelizable); prerequisite for TLS
**Delivers:** `internal/reliable` (ACK+retransmit), `internal/controlconn` (`net.Conn` with fragmentation)
**Avoids:** Pitfalls 4, 5 (fragmentation, missing retransmit)
**Gate:** Byte stream survives 5–10% synthetic loss on loopback

### Phase 3: TLS handshake integration
**Rationale:** First real-client contact; validates Phases 1+2 together
**Delivers:** `crypto/tls.Server()` wired over framing; Docker harness stood up
**Gate:** Real OpenVPN 2.6 client completes TLS handshake; capture validates tls-crypt

### Phase 4: Key Method 2 exchange & data channel
**Rationale:** Needs working control channel; silent-failure zone — derivation errors only visible here
**Delivers:** `internal/datachannel` (AEAD, replay window), Key Method 2 exchange over TLS app data
**Gate:** Encrypted ping round-trips both directions through the tunnel

### Phase 5: Sequencing & PUSH_REPLY
**Rationale:** Client needs IP assignment + cipher push to bring the tunnel up properly
**Delivers:** PUSH_REQUEST/PUSH_REPLY, tunnel-IP assignment (`topology subnet`), peer-id assignment, keepalive
**Gate:** Client receives PUSH_REPLY, configures pushed IP, tunnel stays up

### Phase 6: Userspace netstack + example
**Rationale:** Independent of protocol work once `Session` interface is fixed — parallelizable with 1–5
**Delivers:** `netstack` (ListenUDP, minimal ListenTCP, ICMP echo), tunnel-only example web server (interactive page + 3–5 subpages)
**Gate:** HTTP through the tunnel works end-to-end from the real client

### Phase 7 (v1.x): Session management & robustness
**Delivers:** Soft reset/renegotiation, session timeout/reaping, session floating, explicit-exit-notify
**Gate:** Session survives >1 h with default client `reneg-sec`

### Phase Ordering Rationale

- Phases 1–2 are parallel pure-code phases; the serial risk chain is 3 → 4 → 5 with explicit go/no-go interop gates
- Phase 6 runs in parallel against a fake `Session` — its cleanliness validates the `Session` boundary itself
- The Docker harness gates each major layer (not just the end result) because key-derivation/GCM errors are silent

### Research Flags

Phases needing deeper research during planning:
- **Phase 1:** Byte-exact Key Method 2 verification against `ssl.c`/`crypto.c` — blocker before Phase 4
- **Phase 4:** Classic 4-byte vs epoch packet-id format — confirm from the real client's first P_DATA_V2 capture
- **Phase 3:** Control-packet fragmentation threshold; realistic multi-KB cert chains

Phases with standard patterns (skip research-phase):
- **Phase 2:** Go timer/mutex patterns are well-established
- **Phase 5:** Text-protocol parsing is routine
- **Phase 6:** Standard userspace IP/UDP/TCP/ICMP parsing

## Confidence Assessment

| Area | Confidence | Notes |
|------|------------|-------|
| Stack | HIGH | Verified against OpenVPN source and Go's `crypto/tls/prf.go`; Docker 2.6.3 confirmed |
| Features | HIGH | Cross-checked against OpenVPN protocol docs/doxygen and openvpn-rfc project |
| Architecture | HIGH | Standard Go idioms; layer shape validated against `ooni/minivpn` prior art |
| Pitfalls | MEDIUM-HIGH | 8 critical pitfalls documented; exact byte offsets still need line-level verification against `crypto.c` during coding |

**Overall confidence:** HIGH

### Gaps to Address

- **Epoch vs classic packet-ID:** assume classic 4-byte; verify in Phase 4 by capturing the first P_DATA_V2 from the real client
- **Key-expansion slot offsets:** cross-check every byte offset against `ssl.c`/`crypto.c` line-by-line during Phase 1
- **tls-crypt Ka/Ke slot assignment:** read `tls_crypt_init()`/`tls_crypt_wrap()` to confirm the key-file slot convention
- **Cert chain size vs fragmentation:** test Phase 3 with realistic multi-KB chains early
- **PUSH_REPLY tolerances:** whether the 2.6 client hard-fails or warns on missing optional directives (e.g. no `ping` push) — confirm empirically in the harness
- **tls-crypt v1 vs v2:** v1 assumed sufficient; confirm against the pinned 2.6 client defaults when the harness is built

## Sources

### Primary (HIGH confidence)
- `github.com/OpenVPN/openvpn` source (`ssl.c`, `crypto.c`, `ssl_pkt.c`, `reliable.c`, `tls_crypt.c/h`; local checkout `/Users/svenloth/dev/openvpn-reference`, branch `release/2.6`) — protocol spec
- Go source `src/crypto/tls/prf.go` (`prf10`) — TLS 1.0 PRF construction
- OpenVPN doxygen (`network_protocol.html`, `group__reliable.html`, `group__tls__crypt.html`, `group__data__crypto.html`) — wire formats
- OpenVPN docs `cipher-negotiation.rst`, `renegotiation.rst`, `Changes.rst` — 2.6 client behavior

### Secondary (MEDIUM confidence)
- openvpn-rfc / DeepWiki data-packet-formats — P_DATA_V2 and GCM nonce layout
- `ooni/minivpn` — pure-Go client prior art (layer shape)
- OpenVPN devel patchwork threads — NCP/peer-id behavior

### Tertiary (LOW confidence)
- Secondary claims that "modern OpenVPN uses RFC 5705 export" for parts of key derivation — appears to conflict with primary sources; resolve against `ssl.c` before implementing `internal/keys`

---
*Research completed: 2026-08-22*
*Ready for roadmap: yes*
