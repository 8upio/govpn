# Phase 2: Tunnel Up - Research

**Researched:** 2026-08-24
**Domain:** OpenVPN Key Method 2 data-channel key derivation (TLS 1.0 PRF), PUSH_REQUEST/PUSH_REPLY control exchange, AES-256-GCM data channel (P_DATA_V2), tunnel IP assignment, `Session` as `io.ReadWriteCloser`
**Confidence:** HIGH (wire format, PRF, key derivation, AEAD nonce/tag layout, PUSH_REPLY option strings, ping magic — all read directly from the pinned C reference this session, with line citations and verbatim quotes below) / MEDIUM (tunnel-IP pool arithmetic, internal package layout — standard Go idiom, not reference-verified since it is this project's own design, not upstream's)

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions

**Tunnel IP assignment & PUSH_REPLY**
- IP allocation: sequential first-free from `Config.Network` pool, server = first host IP, 1 IP per client, assigned at PUSH_REPLY time
- IP reuse: freed on session close, immediately reusable — no lease persistence, no hold-down timer
- PUSH_REPLY contents: minimal reference defaults only — `ifconfig` (subnet topology), `topology subnet`, `cipher AES-256-GCM`, `keepalive 10 60` (fixed, not configurable in v1)
- Duplicate CN: allowed, each connection gets its own IP (reference `--duplicate-cn` semantics)

**Session API semantics**
- Framing: one full IP packet per `Read`/`Write` call (datagram semantics); short-buffer `Read` returns an error, never silently truncates
- Backpressure: bounded inbound queue, overflow drops packets like a congested link (mirrors Phase 1's `sess.inbound` policy; upper layers retransmit)
- Surface: `AssignedIP() net.IP`, existing `PeerCN`, `ConnectionState()`; keepalive and data-channel bookkeeping stay internal
- `OnSession` timing: fires only after Key Method 2 + PUSH_REPLY complete and data-channel keys are live — the Session is immediately usable when the callback runs (moves the Phase-1 callsite deeper)

**Data-channel crypto & control messages**
- Packet-ID format: classic non-epoch (32-bit packet-id, 4-byte explicit ID on the wire; AEAD nonce = packetID ‖ implicit-IV from key expansion). Epoch format out of scope. Byte offsets verified against `crypto.c`/`ssl.c` per the STATE.md research flag before any data-channel code
- Replay protection: 64-wide sliding window per data-channel key direction, same design as Phase 1's tls-crypt window, mirroring `packet_id.c`
- Keepalive: recognize the 16-byte ping magic (`ping.c` `ping_string`) inside the library — absorbed, never surfaced to `Session.Read`; server sends its own pings per the pushed `keepalive 10 60`
- Golden vectors: derived from the C reference checkout (instrumented harness or live-client extraction), committed with provenance like Phase 1's corpus — never hand-derived from RFC text alone

### Claude's Discretion
- Internal package layout for the data channel and key derivation (e.g. `internal/keyderiv`, `internal/datachan`)
- Exact bounded-queue depths, matched to Phase 1 precedents
- How the PUSH_REQUEST/PUSH_REPLY exchange is driven over the TLS stream (control-message loop design)

### Deferred Ideas (OUT OF SCOPE)
- Routes / redirect-gateway pushes — Phase 3 decides reachability through the netstack
- Configurable keepalive values in `Config` — revisit if an embedder needs it
- Session stats surface (byte/packet counters) — post-v1
- Epoch data-channel format / NCP — out of v1 scope entirely
</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| WIRE-02 | TLS 1.0 PRF (MD5+SHA1 P_hash) implemented with stdlib crypto and verified against reference test vectors | `openvpn_PRF`/`ssl_tls1_PRF`/`tls1_P_hash` read byte-exact from `ssl.c`/`crypto_openssl.c` below; a real committed reference unit-test vector found in `tests/unit_tests/openvpn/test_crypto.c` |
| WIRE-03 | Key Method 2 data-channel key derivation (master secret → key expansion → per-direction cipher/HMAC key slots incl. implicit IV extraction) verified byte-exactly against `ssl.c`/`crypto.c` | Full `struct key_source2` seed layout, PRF call parameters, `key2.keys[2]` slicing, and the (critical, easy-to-invert) `KEY_DIRECTION_NORMAL`/`INVERSE` slot assignment all captured below with line citations |
| CTRL-04 | Key Method 2 exchange over TLS application data completes (random material, options string, peer-info parsing) | `key_method_2_write`/`key_method_2_read` byte layout fully captured (field order, lengths, `write_string`/`read_string` framing); exchange **order** (server reads client's buffered KM2 first, then writes its own) captured from `tls_process`'s state machine |
| CTRL-05 | PUSH_REQUEST/PUSH_REPLY works: client receives tunnel IP (`topology subnet`), explicit `cipher AES-256-GCM` push, keepalive parameters, and brings its tunnel up | `send_push_reply`/`process_incoming_push_request` message framing (plain NUL-terminated strings, not TLV); exact `keepalive 10 60` → pushed `ping 10`/`ping-restart 60` expansion captured from `helper.c` |
| DATA-01 | P_DATA_V2 packets (24-bit peer-id) encrypt/decrypt with AES-256-GCM using correct nonce construction (packet-ID ‖ implicit IV) and header-as-AAD | Full byte layout derived from both the encrypt (`crypto.c` `openvpn_encrypt_aead`) and decrypt (`openvpn_decrypt_aead` + `ssl.c` `handle_data_channel_packet`) paths, cross-checked against each other; the tag-before-ciphertext wire ordering (opposite of Go `cipher.AEAD.Seal`'s tag-after-ciphertext convention) is the headline finding — see Pitfall 1 |
| DATA-02 | Data-channel replay protection (packet-ID window) drops replayed/out-of-window packets | `DEFAULT_SEQ_BACKTRACK = 64` read from `packet_id.h:100`, confirming CONTEXT.md's 64-wide-window decision matches the reference default exactly; `crypto_check_replay` ordering (tag-verify before replay-check) confirmed |
| DATA-03 | Keepalive/ping magic packets are answered and filtered inside the library — never surfaced to the Session consumer | Exact 16-byte `ping_string` read byte-for-byte from `ping.c:42-45` |
| SESS-02 | Each connected client yields a `Session` (`io.ReadWriteCloser` for raw IP packets) with its assigned tunnel IP exposed | Existing `Session` struct read (`session.go`); `AssignedIP()` addition and data-channel routing gap flagged (Pitfall 5) |
| SESS-03 | Tunnel IPs are assigned from a configurable `*net.IPNet` of any size (server = first host IP, `topology subnet`, 1 IP per client) | `ifconfig <ip> <netmask>` / `topology subnet` push format confirmed from `push.c`/`options.c`; pool arithmetic is this project's own design (not upstream-verified, flagged MEDIUM) |
| VRFY-03 | Harness includes a lossy-network scenario (5–10% packet loss/reordering) under which handshake and traffic still succeed | Reuses Phase 1's `test/interop` lossy harness (`docker-compose.lossy.yml`, `lossyPacketConn`) verbatim; extend assertions to data-channel ping round-trip, no new infrastructure needed |

</phase_requirements>

## Summary

Phase 2 turns a completed TLS handshake (Phase 1's endpoint) into a live, bidirectional, encrypted IP tunnel. Two distinct sub-protocols run, in order, as plaintext TLS application data over the *same* `tls.Conn` the handshake just established — there is no second handshake, no new `net.Conn`:

1. **Key Method 2 (KM2)** — a fixed-layout, length-prefixed binary message exchanged once per direction. The client already sent its KM2 message immediately after its own handshake completed (Phase 1 buffered these bytes, unread, per plan 01-03's own documented deferral). The server must: read the client's buffered KM2 (extracting `pre_master`+`random1`+`random2`), generate its own `random1`+`random2`, write its own KM2 back, then run OpenVPN's own hand-rolled TLS 1.0 PRF **twice** (master-secret derivation, then key-expansion) to produce 256 bytes of key material, sliced into two 128-byte per-direction key/HMAC-slot pairs. **The data-channel key-direction convention (which `key2.keys[N]` slot is "encrypt" vs "decrypt" for the server) is the exact mirror-opposite of the tls-crypt convention Phase 1 already implemented in `internal/tlscrypt.NewWrapper`** — this is the single highest-risk place to introduce a silent, hard-to-diagnose bug, and is called out as Pitfall 1 below.
2. **PUSH_REQUEST/PUSH_REPLY** — two plain, NUL-terminated ASCII strings (not length-prefixed, not binary) exchanged over the same TLS stream once KM2 completes. The server waits for the literal bytes `"PUSH_REQUEST\0"`, then replies with `"PUSH_REPLY,ifconfig <ip> <netmask>,topology subnet,peer-id <n>,cipher AES-256-GCM,ping 10,ping-restart 60\0"`. The `keepalive 10 60` CONTEXT.md decision expands to exactly `ping 10`/`ping-restart 60` on the wire — verified directly from `helper.c`'s own doc comment and code, not inferred.

Once both complete, `Config.OnSession` fires and the data channel goes live: AES-256-GCM over P_DATA_V2 packets, with a wire layout `[opcode+keyid(1)][peer-id(3)][packet-id(4)][AEAD tag(16)][ciphertext(N)]` — **the tag is written BEFORE the ciphertext**, which is the opposite of Go's `cipher.AEAD.Seal`/`Open` convention (tag appended after ciphertext). This is the second headline finding: naively appending `aead.Seal(nil, nonce, plaintext, aad)`'s output straight to the wire produces bytes a real OpenVPN client will reject. The AEAD nonce itself is a 12-byte concatenation (NOT an XOR, despite loose phrasing in some project docs and secondary sources) of the 4-byte explicit packet-ID and an 8-byte implicit IV sliced from the key-expansion output.

**Primary recommendation:** Build key derivation as its own package (`internal/keyderiv`) with byte-exact unit tests seeded by the committed reference PRF test vector found in `tests/unit_tests/openvpn/test_crypto.c` *before* touching any live TLS/data-channel code — this closes the STATE.md research gate mechanically, the way Phase 1 closed its own golden-vector gate. Build the data channel as `internal/datachan`, mirroring `internal/tlscrypt`'s existing structure (`keySlot`, sliding replay window, `Wrap`/`Unwrap`-shaped API) as closely as possible, but with the tag-before-ciphertext reordering made explicit and tested against a tamper-has-teeth assertion exactly like `tlscrypt.golden_test.go`'s existing pattern.

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| Key Method 2 exchange (KM2 read/write, PRF, key expansion) | API / Backend (`ovpn` package, new `internal/keyderiv`) | — | Pure protocol/crypto logic layered on the already-established `tls.Conn`; no I/O beyond what Phase 1's `ctrlconn.Conn` already provides |
| PUSH_REQUEST/PUSH_REPLY exchange | API / Backend (`ovpn.go`) | — | Plain string protocol over the same TLS stream; belongs next to `runHandshake` in the same per-session goroutine |
| Tunnel IP pool / assignment | API / Backend (new `Server`-scoped allocator) | — | Server-wide shared state (must avoid double-assignment across concurrent sessions) — needs its own mutex-guarded type, not per-session state |
| AES-256-GCM data-channel encrypt/decrypt | API / Backend (new `internal/datachan`) | — | Per-session crypto state (own key slots, own replay window), mirrors `internal/tlscrypt`'s existing per-session `Wrapper` pattern exactly |
| P_DATA_V2 datagram routing (UDP demux to `Session`) | API / Backend (`ovpn.go` `handleDatagram`) | — | Existing `handleDatagram` assumes every accepted opcode carries an 8-byte session ID at a fixed offset — **true only for control opcodes**, not `P_DATA_V1`/`P_DATA_V2` (see Pitfall 5); this phase must extend the demux, not just add a crypto call |
| Keepalive/ping absorption | API / Backend (new `internal/datachan` or `Session`) | — | Must intercept the 16-byte ping magic before bytes ever reach `Session.Read`'s caller — an internal filter, not visible surface |
| `Session.Read`/`Write` (raw IP packets) | API / Backend (`session.go`) | — | Public embeddable-library surface; no netstack yet (Phase 3) — caller gets raw decrypted IP bytes exactly as OpenVPN's own TUN device would deliver them |
| Userspace netstack / IP routing | (not this phase) | — | Explicitly deferred to Phase 3 per ROADMAP/CONTEXT — `Session` is `io.ReadWriteCloser` for raw IP, nothing terminates traffic in-process yet |

## Standard Stack

### Core

No new third-party dependencies. Per `CLAUDE.md`'s explicit constraint, every primitive this phase needs is in the Go standard library, already used identically by Phase 1:

| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| `crypto/md5` + `crypto/sha1` + `crypto/hmac` (stdlib) | stdlib, Go `1.24`+ | Hand-rolled `openvpn_PRF`/`tls1_P_hash` (RFC 2246 §5.6.4.1) — Key Method 2's master-secret and key-expansion derivation | `crypto/tls`'s own internal TLS-1.0/1.1 PRF (`prf10`) implements the identical algorithm but is unexported; must hand-write against `md5`/`sha1`/`hmac` directly (see CLAUDE.md's own Core Technologies table, already the locked decision) |
| `crypto/aes` + `crypto/cipher` (stdlib) | stdlib | AES-256-GCM data-channel AEAD | `cipher.NewGCM(block)` — [VERIFIED: `go doc crypto/cipher NewGCM`, run this session against the installed Go 1.26.1 toolchain] returns "the standard nonce length" (12 bytes) AEAD; matches the reference's `OPENVPN_AEAD_MIN_IV_LEN` exactly (see Code Examples) |
| `crypto/rand` (stdlib) | stdlib | KM2 `random1`/`random2` generation, session-ID generation (already used identically in `ovpn.go`'s existing `rand.Read(serverSID[:])`) | Already an established codebase pattern from Phase 1 |
| `net` (stdlib) | stdlib | Tunnel IP pool arithmetic over `*net.IPNet` | Standard `net.IP`/`net.IPNet` byte manipulation; no third-party CIDR library needed for sequential-first-free allocation over IPv4 |
| `bufio` (stdlib) | stdlib | Framing the KM2/PUSH_REQUEST/PUSH_REPLY exchange as sequential exact-length reads over `tls.Conn` | `tls.Conn.Read` returns TLS-record-sized chunks, not protocol-message-sized chunks; `io.ReadFull` over a small buffered reader gives deterministic exact-length reads for KM2's fixed+length-prefixed fields (see Architecture Patterns) |

### Supporting

None beyond stdlib — no supporting third-party libraries needed this phase.

### Alternatives Considered

| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| Hand-rolled `openvpn_PRF` against `md5`/`sha1`/`hmac` | `tls.ConnectionState().ExportKeyingMaterial()` | **Do not use** — this is RFC 5705 keying-material export, a different construction (HKDF in TLS 1.3, a different PRF invocation in TLS 1.2) than OpenVPN's own Key Method 2 PRF. Already explicitly ruled out in CLAUDE.md's own "What NOT to Use" table; producing keys a real client can never derive is a silent, only-detectable-as-garbled-traffic failure mode |
| `net.IP`-based sequential pool allocator (hand-written) | A CIDR/IPAM third-party library | Sequential first-free over a single `*net.IPNet`, freed-on-close, no lease persistence (CONTEXT.md's own locked decision) is ~30 lines of `net.IP` arithmetic; a full IPAM library is unjustified scope for this shape of problem |

**Installation:** none — no new `go.mod` entries this phase.

**Version verification:** `go version` run this session: `go1.26.1 darwin/arm64` [VERIFIED: local toolchain, this session] — inside the `go 1.24` floor CLAUDE.md specifies, consistent with the existing `go.mod`'s `go 1.24` directive [VERIFIED: `/Users/svenloth/dev/govpn/go.mod`, read this session — contents: `module github.com/8upio/govpn` / `go 1.24`].

## Package Legitimacy Audit

**No external packages are installed or proposed this phase.** Per `CLAUDE.md`'s constraint ("Core library: zero dependencies beyond stdlib") and the Standard Stack table above, every primitive needed (TLS-1.0 PRF components, AES-256-GCM, IP arithmetic) is already in `go.mod`'s zero-dependency stdlib-only surface. The Package Legitimacy Gate does not apply — there is nothing to run `gsd-tools query package-legitimacy check` against.

**Packages removed due to [SLOP] verdict:** none (n/a — no packages proposed)
**Packages flagged as suspicious [SUS]:** none (n/a — no packages proposed)

## Architecture Patterns

### System Architecture Diagram

```
                        real OpenVPN 2.6 client (UDP)
                                    │
                                    ▼
                    Server.Serve() UDP read loop (ovpn.go)
                                    │
                     opcode dispatch (Pitfall 5: MUST branch
                     control-opcode vs P_DATA_V1/V2 BEFORE
                     reading bytes[1:9] as an 8-byte SessionID —
                     data packets have no session-ID field there)
                        │                           │
                        ▼                           ▼
              control opcodes                 P_DATA_V1 / P_DATA_V2
          (existing sessionKey{addr,sid}         (NEW: route by
           demux — Phase 1, unchanged)         peer-id or addr —
                        │                        Server-scoped map,
                        ▼                         NOT sessionKey)
              ctrlconn.Conn (Phase 1)                   │
                        │                               ▼
                        ▼                     internal/datachan.Wrapper
              tls.Server(conn,cfg)             (per-Session, mirrors
              .Handshake() [Phase 1: DONE]      internal/tlscrypt's
                        │                        keySlot/window shape)
                        ▼                               │
        ── this phase's new control flow ──             │
                        │                                │
                        ▼                                │
         read client's buffered KM2                      │
         (already sitting in sess.conn                   │
          per Phase 1 T-01-17)                            │
                        │                                │
                        ▼                                │
         openvpn_PRF ×2 (internal/keyderiv)               │
         master secret → key expansion                    │
         → key2.keys[0], key2.keys[1]  ────────────────────┘
         (feeds BOTH the KM2 write-back                (256 bytes: cipher+
          AND internal/datachan's key install)          implicit-IV slots)
                        │
                        ▼
         write server's own KM2 over tls.Conn
                        │
                        ▼
         wait for "PUSH_REQUEST\0" (plain string,
         NOT length-prefixed — different framing
         than KM2's own fields)
                        │
                        ▼
         Server-scoped IP pool: assign next free IP
                        │
                        ▼
         write "PUSH_REPLY,ifconfig …,topology subnet,
         peer-id N,cipher AES-256-GCM,ping 10,
         ping-restart 60\0"
                        │
                        ▼
         Config.OnSession(sess) fires — sess.AssignedIP()
         populated, data-channel keys live
                        │
                        ▼
         Session.Read/Write (session.go) ◄──────► internal/datachan
         raw decrypted IP packets                  encrypt/decrypt +
         (ping magic absorbed internally,           64-wide replay window
          never surfaced to the caller)             (mirrors tlscrypt's
                        │                             sliding window design)
                        ▼
              embedder's application code
           (Phase 3's netstack, or direct use)
```

### Recommended Project Structure

```
internal/
├── keyderiv/          # NEW: openvpn_PRF, tls1_P_hash, key_source2 seed
│                       #      assembly, key2→per-direction slot slicing
│                       #      (mirrors internal/tlscrypt's package-doc
│                       #      citation-header convention)
├── datachan/           # NEW: AES-256-GCM Wrapper (per-session), packet-ID
│                       #      window, ping-magic detection — the data-
│                       #      channel analogue of internal/tlscrypt
├── ctrlconn/            # Phase 1, unchanged
├── reliable/             # Phase 1, unchanged
├── tlscrypt/              # Phase 1, unchanged — but see Pitfall 1: do
│                          #  NOT copy its server/client key-slot
│                          #  assignment convention into internal/datachan;
│                          #  the data-channel convention is the mirror
│                          #  opposite
└── wire/                   # Phase 1, unchanged — P_DATA_V1/V2 opcode
                             #  constants already defined (OpDataV1=6,
                             #  OpDataV2=9); this phase adds a *separate*
                             #  parser for the data-channel header shape
                             #  (opcode+keyid+3-byte peer-id), distinct
                             #  from ControlPacket's 8-byte-SessionID shape
```

`ovpn.go`/`session.go` gain the KM2/PUSH exchange (folded into `runHandshake`'s continuation, per CONTEXT's "Claude's Discretion" on exchange-loop design) and a `Server`-scoped IP pool + peer-id→Session routing table.

### Pattern 1: Key Method 2 wire layout (server perspective)

**What:** A fixed-order, mostly-length-prefixed binary message, exchanged once per direction over the already-established `tls.Conn`.
**When to use:** Immediately after `Handshake()` returns nil (Phase 1's existing seam), before any PUSH_REQUEST handling.

Message layout the SERVER **reads** (the client's already-buffered message — client always sends `pre_master`, server never does):

| Field | Size | Source |
|---|---|---|
| reserved | 4 bytes, discarded | [VERIFIED: `ssl.c:2387-2393` `buf_advance(buf, 4)`] |
| key_method_flags | 1 byte, low nibble must == `KEY_METHOD_2` (2) | [VERIFIED: `ssl.c:2396-2403`, `ssl.h:113,116` — `#define KEY_METHOD_2 2` / `#define KEY_METHOD_MASK 0x0F`] |
| `pre_master` | 48 bytes | [VERIFIED: `ssl.c:1890-1896` `key_source2_read`, called with `server=true` so `if (server) { buf_read(k->pre_master, 48) }`] |
| `random1` | 32 bytes | [VERIFIED: `ssl.c:1898-1901`] |
| `random2` | 32 bytes | [VERIFIED: `ssl.c:1902-1905`] |
| options string | 2-byte BE length (incl. NUL) + bytes, max `TLS_OPTIONS_LEN`=512 | [VERIFIED: `ssl.c:2413`, `ssl.h:69` `#define TLS_OPTIONS_LEN 512`] |
| username string | 2-byte BE length + bytes (may be empty: length field = 0) | [VERIFIED: `ssl.c:2426`] |
| password string | 2-byte BE length + bytes | [VERIFIED: `ssl.c:2427`] |
| peer_info string | 2-byte BE length + bytes (may be absent: length < 1 ⇒ NULL) | [VERIFIED: `ssl.c:2431`, `read_string_alloc` at `ssl.c:2009-2028`] |

**Non-fatal by default:** `options_cmp_equal(options, session->opt->remote_options)` [VERIFIED: `ssl.c:2498`] only *warns* on mismatch unless `--opt-verify` is set (`session->opt->ssl_flags & SSLF_OPT_VERIFY`) — this project does not need to construct a byte-exact-matching options string to interoperate; a reasonable-looking options string (or even an empty one) will not fail a real client's handshake, only produce a benign log warning. **This meaningfully de-scopes CTRL-04**: do not over-invest in reproducing the reference's exact OCC options-string format.

Message the SERVER **writes** (mirror, but server never sends `pre_master`, and `push_peer_info_detail=0` on a P2MP server ⇒ empty peer_info):

| Field | Size |
|---|---|
| reserved | 4 zero bytes |
| key_method | 1 byte = 2 |
| `random1` (server's own, fresh) | 32 bytes |
| `random2` (server's own, fresh) | 32 bytes |
| options string | 2-byte length + bytes (may be a short/empty string, see above) |
| username | `write_empty_string` → 2-byte `0x0000`, **no trailing byte** [VERIFIED: `ssl.c:1952-1959`] |
| password | same, 2-byte `0x0000` |
| peer_info | same, 2-byte `0x0000` (server `push_peer_info_detail` default is 0 — "nothing", [VERIFIED: `ssl.c:2030-2039` doc comment, `ssl.c:2081` `if (session->opt->push_peer_info_detail > 0)` gate]) |

**Exchange order** (not merely "both messages exist" — the reference's own state machine, read this session):

```
// Source: ssl.c:3002-3031 (tls_process), read this session
// Server: "Receive Key" runs when ks->state == S_START (server reads
// FIRST), transitioning to S_GOT_KEY; "Send Key" runs when
// ks->state == S_GOT_KEY (server writes SECOND), transitioning to
// S_SENT_KEY. This is the opposite branch from the client, which writes
// first (already done — Phase 1 buffered it) then reads.
```

Practical Go sequencing: read the client's already-buffered bytes first (`io.ReadFull` chain against `sess.conn`/`tlsConn`), THEN generate+write the server's own KM2. Nothing about the crypto depends on this order (`openvpn_PRF` just needs both halves once both exist), but matching it avoids any edge-case interop surprise and is free to do since the client's bytes are already sitting in the buffer.

### Pattern 2: `openvpn_PRF` / TLS-1.0 PRF (WIRE-02)

**What:** RFC 2246 §5.6.4.1's PRF: split secret into two (possibly 1-byte-overlapping) halves, run `P_hash` with MD5 over one half and SHA1 over the other, XOR the two output streams.
**When to use:** Twice per session — master-secret derivation, then key-expansion.

```c
// Source: crypto_openssl.c:1586-1626 (ssl_tls1_PRF), read this session —
// the manual/portable implementation path (the OpenSSL>=1.1.0 EVP_PKEY_TLS1_PRF
// path at crypto_openssl.c:1403-1447 is functionally identical, just backend-
// delegated).
int len = slen / 2;
const uint8_t *S1 = sec;
const uint8_t *S2 = &sec[len];
len += (slen & 1);           // odd-length secrets overlap S1/S2 by 1 byte;
                              // NOT triggered here — both PRF calls this
                              // project makes use even-length secrets
                              // (48-byte pre_master, 48-byte master secret)
tls1_P_hash(MD5,  S1, len, label_and_seed, ..., out1, olen);
tls1_P_hash(SHA1, S2, len, label_and_seed, ..., out2, olen);
for (i = 0; i < olen; i++) out1[i] ^= out2[i];
```

`P_hash` itself (`tls1_P_hash`, `crypto_openssl.c:1467-1565`, read this session): `A(0) = seed`; `A(i) = HMAC_hash(secret, A(i-1))`; output = `HMAC_hash(secret, A(1)‖seed) ‖ HMAC_hash(secret, A(2)‖seed) ‖ ...` truncated to `olen` — the standard RFC 2246 construction, confirmed byte-for-byte against the actual source rather than assumed from training knowledge.

**Verified reference test vector** (WIRE-02's own acceptance criterion — use directly, no live client needed):

```c
// Source: tests/unit_tests/openvpn/test_crypto.c:140-166, read this session.
// This tests ssl_tls1_PRF/tls1_P_hash IN ISOLATION (not the full KM2 seed
// construction below) — use it as the first unit test for internal/keyderiv's
// PRF primitive before layering on the KM2-specific seed assembly.
secret = "Lorem ipsum dolor sit amet, consectetur adipisici elit, sed eiusmod tempor incidunt ut labore et dolore magna aliqua."
seed   = "Quis aute iure reprehenderit in voluptate velit esse cillum dolore"
output (32 bytes) = d9 8c 85 18 c8 5e 94 69 27 91 6a cf c2 d5 92 fb
                     b1 56 7e 4b 4b 14 59 e6 a9 04 ac 2d da b7 2d 67
```

`openvpn_PRF`'s own seed-assembly wrapper (`ssl.c:1476-1517`, read this session): `seed = label ‖ client_seed ‖ server_seed ‖ [client_sid] ‖ [server_sid]` (session IDs appended only if non-NULL) — this is what feeds `ssl_tls1_PRF` as its `seed` parameter; do not confuse this with `tls1_P_hash`'s own internal `A(i)‖seed` construction above.

### Pattern 3: Key expansion — exact seed material and slot layout (WIRE-03)

**What:** Two PRF calls, in order, producing 256 bytes sliced into two 128-byte per-direction slots.
**Source:** `ssl.c:1579-1630` (`generate_key_expansion_openvpn_prf`), read this session, `struct key_source`/`key_source2` at `ssl_common.h:116-136`, read this session (quoted below).

```c
// Source: ssl_common.h:116-136, read this session.
struct key_source {
    uint8_t pre_master[48];  /* client only */
    uint8_t random1[32];     /* both client and server */
    uint8_t random2[32];     /* both client and server */
};
struct key_source2 {
    struct key_source client;
    struct key_source server;
};
```

Step 1 — master secret (48 bytes out):
```c
// Source: ssl.c:1595-1608, read this session.
openvpn_PRF(key_src->client.pre_master, 48,
            "OpenVPN master secret",              // KEY_EXPANSION_ID=="OpenVPN", ssl.h:49
            key_src->client.random1, 32,
            key_src->server.random1, 32,
            NULL, NULL,                            // no session IDs this step
            master /* out */, 48);
```
**Note the HMAC secret here is ALWAYS `client.pre_master`** — the server never contributes its own pre-master entropy to this step, even server-side (the server has no `pre_master` field populated at all — see Pattern 1).

Step 2 — key expansion (256 bytes out):
```c
// Source: ssl.c:1611-1624, read this session.
openvpn_PRF(master, 48,
            "OpenVPN key expansion",
            key_src->client.random2, 32,
            key_src->server.random2, 32,
            client_sid, server_sid,     // NON-null this step — see below
            (uint8_t*)key2->keys, 256); // key2->keys is struct key[2], 128B each
```
`client_sid`/`server_sid` (`ssl.c:1586-1589`, read this session — **server's own perspective**, `session->opt->server == true`):
```c
client_sid = &ks->session_id_remote;   // the CLIENT's session ID we received
                                        // (== existing sess.clientSessionID)
server_sid = &session->session_id;     // OUR OWN session ID
                                        // (== existing sess.SessionID)
```
These are the *same* 8-byte control-channel session IDs `wire.SessionID` already models (`SessionIDSize = 8`, [VERIFIED: `internal/wire/wire.go:57-58`, quoted: `"SessionIDSize: session_id.h:45 (SID_SIZE = sizeof(session_id.id), 8 bytes)."`]) — no new session-ID concept, just reuse `sess.SessionID`/`sess.clientSessionID` from the existing `Session` struct [VERIFIED: `/Users/svenloth/dev/govpn/session.go:29-43`, quoted: `"SessionID [wire.SessionIDSize]byte"` and `"clientSessionID wire.SessionID"`].

`struct key` (`crypto.h:149-155`, read this session):
```c
struct key {
    uint8_t cipher[MAX_CIPHER_KEY_LENGTH];  // 64 bytes (crypto_backend.h:188)
    uint8_t hmac[MAX_HMAC_KEY_LENGTH];      // 64 bytes (crypto_backend.h:506)
};
```
So `key2.keys` (256 bytes total, the PRF output) slices as:
```
keys[0].cipher = key2[  0: 64]   keys[0].hmac = key2[ 64:128]
keys[1].cipher = key2[128:192]   keys[1].hmac = key2[192:256]
```
Only the first 32 bytes of each 64-byte `cipher` slot are used (AES-256 key size) and only the first 8 bytes of each 64-byte `hmac` slot are used as the AEAD implicit IV (see Pattern 4) — **exactly the same "only take the prefix of a 64-byte slot" pattern `internal/tlscrypt`'s existing `keySlot` struct already established** [VERIFIED: `/Users/svenloth/dev/govpn/internal/tlscrypt/tlscrypt.go:75-82`, quoted: `"type keySlot struct {\n\tcipher [cipherKeySize]byte\n\thmac   [hmacKeySize]byte\n}"` where `cipherKeySize = 32` / `hmacKeySize = 32`].

### Pattern 4: Key-direction slot assignment — **Pitfall 1, the critical inversion**

```c
// Source: ssl.c:1519-1530, crypto.c:1506-1531, read this session.
key_direction = server ? KEY_DIRECTION_INVERSE : KEY_DIRECTION_NORMAL;
// KEY_DIRECTION_NORMAL:   out_key(encrypt)=keys[0], in_key(decrypt)=keys[1]
// KEY_DIRECTION_INVERSE:  out_key(encrypt)=keys[1], in_key(decrypt)=keys[0]

// implicit IV (ssl.c:1556-1560):
key_ctx_update_implicit_iv(&key->encrypt, key2->keys[(int)server].hmac, ...);
key_ctx_update_implicit_iv(&key->decrypt, key2->keys[1-(int)server].hmac, ...);
```

For this project (always the server, `server=true`):

| Direction | Cipher key | Implicit IV (first 8 bytes of) |
|---|---|---|
| **encrypt** (server→client) | `key2[128:160]` (`keys[1].cipher[:32]`) | `key2[192:200]` (`keys[1].hmac[:8]`) |
| **decrypt** (client→server) | `key2[0:32]` (`keys[0].cipher[:32]`) | `key2[64:72]` (`keys[0].hmac[:8]`) |

**This is the exact mirror-opposite of `internal/tlscrypt.NewWrapper`'s existing convention**, which assigns `server: encrypt=keys[0], decrypt=keys[1]` [VERIFIED: `/Users/svenloth/dev/govpn/internal/tlscrypt/tlscrypt.go:180-184`, quoted:
```go
if server {
    w.encrypt, w.decrypt = keys[0], keys[1]
} else {
    w.encrypt, w.decrypt = keys[1], keys[0]
}
```
]. Copy-pasting `tlscrypt`'s server/client slot-assignment pattern into the new `internal/datachan` package — a very natural thing to do given how closely the two packages otherwise mirror each other — silently produces a data channel that can decrypt its own echoed traffic in tests (client-role and server-role unit tests both use the same wrong convention and agree with each other) but fails against a **real** OpenVPN client on the very first data packet, with symptoms indistinguishable from generic AEAD failure (`cipher: message authentication failed`). Flag this explicitly in the plan's own task description and verification steps, and never assert data-channel round-trip correctness with two instances of the *same* Go type unless one is deliberately constructed with the reference's `KEY_DIRECTION_INVERSE` mapping and the other with `KEY_DIRECTION_NORMAL`.

### Pattern 5: P_DATA_V2 wire format and AEAD nonce/AAD/tag layout (DATA-01)

**What:** The full byte layout for encrypted data-channel packets, cross-derived from BOTH the encrypt path (`crypto.c` `openvpn_encrypt_aead`) and the decrypt path (`crypto.c` `openvpn_decrypt_aead` + `ssl.c` `handle_data_channel_packet`), confirmed mutually consistent.

Header construction (`ssl.c:4142-4155`, read this session):
```c
// tls_prepend_opcode_v2:
peer = htonl( ((P_DATA_V2 << P_OPCODE_SHIFT) | key_id) << 24
              | (multi->peer_id & 0xFFFFFF) );
buf_write_prepend(buf, &peer, 4);
```
i.e. 4 bytes, big-endian: `[opcode<<3|key_id (1 byte)][peer_id, 24-bit big-endian (3 bytes)]`. `MAX_PEER_ID = 0xFFFFFF` [VERIFIED: `openvpn.h:552`].

Full wire layout (both directions), assembled from `crypto.c:62-151` (encrypt) and `crypto.c:340-470` (decrypt), read this session:

```
[opcode+keyid (1B)] [peer-id (3B)] [packet-id, BE uint32 (4B)] [AEAD tag (16B)] [ciphertext (N bytes)]
└──────────────── AAD (8 bytes, header only) ─────────────────┘└───────── AEAD-protected ─────────────┘
```

**Critical: the tag comes BEFORE the ciphertext on the wire.** Confirmed from the encrypt side:
```c
// Source: crypto.c:99-137 (openvpn_encrypt_aead), read this session.
mac_out = buf_write_alloc(&work, mac_len);   // reserve 16B for the tag,
                                              // RIGHT AFTER the 8-byte header
cipher_ctx_update_ad(ctx->cipher, BPTR(&work), BLEN(&work) - mac_len); // AAD = header only
cipher_ctx_update(ctx->cipher, BEND(&work), &outlen, BPTR(buf), BLEN(buf)); // ciphertext written
                                                                              // AFTER the reserved tag slot
cipher_ctx_get_tag(ctx->cipher, mac_out, mac_len);  // tag filled into the PRE-reserved slot
```
and independently from the decrypt side (`crypto.c:401-436`): `packet_id_read` (4B) then `tag_ptr = BPTR(buf); buf_advance(buf, tag_size)` (16B) THEN the remaining bytes are ciphertext, with `ad_size = BPTR(buf) - ad_start - tag_size` == exactly the 8 header bytes.

**Go's `cipher.AEAD.Seal`/`Open` do the opposite** — [VERIFIED: `go doc crypto/cipher.AEAD`, run this session] `Seal(dst, nonce, plaintext, additionalData)` "appends the result to dst" as `ciphertext‖tag` (tag last), and `Open` expects its `ciphertext` argument in that same `ciphertext‖tag` order. **You must reorder bytes across this boundary**, both directions:

```go
// Source: this project's own derivation from crypto.c (see above) + Go's
// documented cipher.AEAD contract (VERIFIED: go doc crypto/cipher.AEAD).
// Encrypt:
sealed := aead.Seal(nil, nonce, plaintext, aad) // = ciphertext(N) ‖ tag(16)
tag, ciphertext := sealed[len(sealed)-16:], sealed[:len(sealed)-16]
wire = append(append(append([]byte{}, header...), tag...), ciphertext...)

// Decrypt:
tag, ciphertext := wire[8:24], wire[24:]
sealed := append(append([]byte{}, ciphertext...), tag...) // reorder back to Go's convention
plaintext, err := aead.Open(nil, nonce, sealed, aad) // aad = wire[:8]
```

Nonce construction (`crypto.c:78-101`, read this session — **concatenation, not XOR**, despite `CLAUDE.md`'s own shorthand phrasing "`iv = packet_id XOR implicit_iv`" — that phrasing describes the *effect* of two disjoint byte ranges sharing one 12-byte buffer loosely, not a literal bitwise XOR operation; do not implement a literal `^=`):
```c
iv[0:4]  = packet_id_write(..., long_form=false)   // 4-byte BE explicit packet-id
iv[4:12] = ctx->implicit_iv                         // 8 bytes, from key expansion (Pattern 4)
// iv_len = cipher_ctx_iv_length(cipher) == 12 for AES-256-GCM under OpenSSL's
// default GCM IV length — matches Go's cipher.NewGCM's own "standard nonce
// length" of 12 bytes exactly (VERIFIED: go doc crypto/cipher NewGCM, this
// session), so no NewGCMWithNonceSize override is needed.
```
`OPENVPN_AEAD_TAG_LENGTH = 16` [VERIFIED: `crypto_backend.h:42`] — matches Go's default GCM tag size (`aead.Overhead() == 16`), no `NewGCMWithTagSize` override needed either.

The explicit packet-id is a **third, independently-sequenced counter** — distinct from both the reliability layer's `internal/wire.PacketID` (control-channel ACK bookkeeping) and `internal/tlscrypt`'s own long-form 8-byte packet-ID (tls-crypt authentication). It starts at 1 (not 0 — `packet_id_send_update`, `packet_id.c:323-344`, read this session: `p->id++` happens before first use) and — because the data channel always uses the **short form** (`long_form=false`, confirmed at both `crypto.c:89` encrypt and the decrypt-side `packet_id_read(&pin, buf, false)` at `crypto.c:402`) — **can never roll over**: `packet_id_send_update` only permits `PACKET_ID_MAX → 0` wraparound when `long_form` is true. After ~4.29 billion data packets on one key, the reference fails closed (`"ENCRYPT ERROR: packet ID roll over"`); this is a non-issue at Phase 2's test volumes and is exactly what Phase 4's renegotiation (`SESS-04`, out of this phase's scope) exists to prevent in production.

### Pattern 6: PUSH_REQUEST/PUSH_REPLY — plain strings, different framing than KM2

**What:** Unlike KM2's TLV fields, these are raw NUL-terminated ASCII strings with no length prefix.
```c
// Source: forward.c:374-394 (send_control_channel_string_dowork), read this
// session.
tls_send_payload(ks, (uint8_t*)str, strlen(str) + 1);  // writes str + 1 NUL byte,
                                                          // nothing else
```
Client sends the literal bytes `PUSH_REQUEST\0` (13 bytes) [VERIFIED: `push.c:567`, `push.c:1089` `buf_string_compare_advance(&buf, "PUSH_REQUEST")`]. Server responds with `PUSH_REPLY,<comma-separated options>\0` [VERIFIED: `push.c:775-837` `send_push_reply`, `push.c:41` `static char push_reply_cmd[] = "PUSH_REPLY"`].

`keepalive 10 60` → exact pushed-option expansion (`helper.c:496-558`, read this session, quoted doc comment):
```c
/*
 * HELPER DIRECTIVE:      keepalive 10 60
 * EXPANDS TO (mode server):
 *   ping 10                     (local: server pings every 10s)
 *   ping-restart 120            (local: server gives up after 120s = 2×60)
 *   push "ping 10"              (pushed to client verbatim)
 *   push "ping-restart 60"      (pushed to client verbatim — NOT 120)
 */
```
**The server pushes `ping 10` and `ping-restart 60` as two separate comma-joined options — never a literal `keepalive 10 60` token** (that literal form is also independently valid per `options.c:6952-6957`, but is not what a real OpenVPN server actually transmits; matching the reference's actual on-wire behavior, not merely a technically-parseable alternative, is what CONTEXT.md's "minimal reference defaults only" decision calls for).

Full PUSH_REPLY string this phase should send (topology subnet, `Config.Network` = e.g. `10.8.0.0/24`, assigned client IP `10.8.0.2`, allocated peer-id `0`):
```
PUSH_REPLY,ifconfig 10.8.0.2 255.255.255.0,topology subnet,peer-id 0,cipher AES-256-GCM,ping 10,ping-restart 60\0
```
`ifconfig <local> <netmask>` under `topology subnet` [VERIFIED: `push.c:629-643` `prepare_push_reply`, `options.c:6097-6110` `ifconfig` option parsing — under `TOP_SUBNET` the second parameter is the netmask, not a point-to-point peer address]. `cipher <name>` is only pushed when the peer's own peer-info signals NCP support (`tls_peer_supports_ncp`, `push.c:663-666`) — a real 2.6 client always does, so this is safe to push unconditionally per CONTEXT's own decision.

### Pattern 7: Ping/keepalive magic bytes (DATA-03)

```c
// Source: ping.c:42-45, read this session — exact bytes, not paraphrased.
const uint8_t ping_string[] = {
    0x2a, 0x18, 0x7b, 0xf3, 0x64, 0x1e, 0xb4, 0xcb,
    0x07, 0xed, 0x2d, 0x0a, 0x98, 0x1f, 0xc7, 0x48
};
// PING_STRING_SIZE = 16 (ping.h:38)
```
A ping packet is encrypted/decrypted through the *same* AES-256-GCM path as any other data packet [VERIFIED: `ping.c:74-90` `check_ping_send_dowork`, comment "We will treat the ping like any other outgoing packet, encrypt, sign, etc."] — the 16-byte magic is checked **after** decryption, on the plaintext, not as a special wire opcode. Filter it inside `internal/datachan`'s decrypt path (or `Session.Read`'s internal loop) before any bytes reach the caller; a matched ping never counts as "activity" for `Session.Read`'s framing (matches the reference's own `c->c2.buf.len = 0` after sending, so it never triggers the sender's own activity timers either — not directly relevant server-side, but confirms symmetry).

### Anti-Patterns to Avoid

- **Reusing `internal/tlscrypt.NewWrapper`'s server/client key-slot convention for the data channel:** see Pattern 4/Pitfall 1 above — the conventions are inverted, not identical, despite the packages otherwise mirroring each other closely.
- **Writing `aead.Seal()`'s output straight to the wire:** see Pattern 5 — tag/ciphertext order must be swapped both directions.
- **Treating `keepalive N M` as a literal pushed string:** the reference expands it into two separate `ping`/`ping-restart` pushes with a DIFFERENT second value (`M`, not `2×M`) than what the server uses locally — see Pattern 6.
- **Assuming `handleDatagram`'s existing `bytes[1:1+SessionIDSize]` parse applies to data packets:** it doesn't — see Pitfall 5 below; this is an existing-code gap this phase must close, not a new pattern to avoid introducing.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| AES-256-GCM AEAD primitive | A manual GCM/CTR+GHASH implementation | `crypto/cipher.NewGCM` + `crypto/aes.NewCipher` | Stdlib's GCM is constant-time-hardened where hardware AES is available [VERIFIED: `go doc crypto/cipher NewGCM`, this session] and exactly matches the reference's OpenSSL GCM byte-for-byte at the ciphertext/tag level once the wire reordering (Pattern 5) is applied |
| RFC 2246 §5 TLS-1.0 PRF | Vendoring/copying Go's internal unexported `prf10` (`crypto/tls/prf.go`) | Hand-write against `md5`/`sha1`/`hmac` per Pattern 2 | Already CLAUDE.md's own locked decision — copying stdlib internals couples to unstable internal APIs; the algorithm itself is small (~30-40 lines) and now has a verified test vector to build against |
| IPv4 subnet host-address arithmetic | A CIDR/IPAM library | Stdlib `net.IP`/`net.IPNet` (increment last octet(s), skip network/broadcast, compare against `IPNet.Contains`) | Sequential-first-free over one `*net.IPNet`, no persistence (CONTEXT.md's own locked decision) is small enough that a dependency is unjustified; matches CLAUDE.md's zero-third-party-deps constraint |

**Key insight:** every "hard part" in this phase (PRF, key expansion, AEAD nonce/tag layout) is fully and byte-exactly specified by the pinned C reference — there is no ambiguity to resolve by hand-rolling a plausible-looking alternative. The risk in this phase is not "we don't know what to build" but "the two conventions that look almost identical (tls-crypt's vs the data-channel's key-direction assignment; Go's vs OpenVPN's tag/ciphertext order) are actually inverted" — verification against the reference, not invention, is the whole job.

## Common Pitfalls

### Pitfall 1: Data-channel key-direction convention is the mirror-opposite of `internal/tlscrypt`'s
**What goes wrong:** Server encrypts with `keys[0]` instead of `keys[1]` (or vice versa for decrypt), by analogy with the already-implemented `tlscrypt.NewWrapper`.
**Why it happens:** The two packages are structurally near-identical (`server bool` parameter, two key slots, encrypt/decrypt assignment) and a developer/executor pattern-matching against recently-read code will naturally copy the convention that "worked before."
**How to avoid:** Build the encrypt/decrypt slot assignment as an explicit, separately-unit-tested function (`keyDirection(server bool) (encryptIdx, decryptIdx int)`) with a doc comment quoting Pattern 4's table directly, and a unit test asserting `server: encrypt=1, decrypt=0` and `client: encrypt=0, decrypt=1` (the reverse of `tlscrypt`'s own test expectations) before wiring it into any live crypto.
**Warning signs:** A test that constructs two `internal/datachan` instances (one `server=true`, one `server=false`) from the SAME `key2` bytes and asserts they can decrypt each other's traffic will falsely PASS even with the wrong convention, as long as it's wrong *consistently* on both sides — this is not a sufficient test. The only test that catches the inversion is one seeded from a real captured client exchange (a golden vector) or one that independently re-derives the expected key bytes from the reference's own documented indices and asserts against those, not merely against round-trip self-consistency.

### Pitfall 2: Tag-before-ciphertext wire order vs. Go's tag-after-ciphertext `Seal`/`Open` convention
**What goes wrong:** `wire = append(header, aead.Seal(nil, nonce, plaintext, aad)...)` produces `header‖ciphertext‖tag` — a real OpenVPN client expects `header‖tag‖ciphertext` and will reject every packet with an authentication failure (or, worse, decrypt-then-garbage if a naive re-implementation on the client mis-parses framing rather than failing the tag check).
**Why it happens:** Go's `cipher.AEAD` interface is the single, idiomatic way anyone would reach for AES-GCM in Go, and its documented behavior (tag appended at the end) is the overwhelmingly common convention across TLS/most AEAD wire formats — OpenVPN's choice to put the tag first is the outlier, not Go's.
**How to avoid:** See Pattern 5's exact reorder snippet; wrap it in a named helper (`sealDataV2`/`openDataV2`) so the reordering is a single, testable, well-commented seam rather than inlined at every call site.
**Warning signs:** A round-trip test using only this project's own encrypt+decrypt (never validated against a real client capture or a hand-computed vector) will pass even with the reorder omitted entirely, as long as encrypt and decrypt agree with each other — same failure shape as Pitfall 1. A tamper test that flips a byte in the FIRST 16 bytes after the header (expecting it to be the tag) is a cheap way to prove the ordering assumption is load-bearing, mirroring `internal/tlscrypt/golden_test.go`'s existing `TestGoldenVectorTamperHasTeeth` pattern [VERIFIED: `/Users/svenloth/dev/govpn/.planning/phases/01-handshake/01-04-SUMMARY.md`, coverage item D3].

### Pitfall 3: `handleDatagram`'s existing session-routing demux does not apply to data packets
**What goes wrong:** The existing `handleDatagram` unconditionally reads `packet[1:1+wire.SessionIDSize]` (8 bytes) as a `SessionID` for every accepted opcode [VERIFIED: `/Users/svenloth/dev/govpn/ovpn.go:223-226`, quoted:
```go
var sid wire.SessionID
copy(sid[:], packet[1:1+wire.SessionIDSize])
key := sessionKey{addr: addr.String(), sid: sid}
```
]. `P_DATA_V1`/`P_DATA_V2` have no 8-byte session-ID field at that offset — `P_DATA_V2`'s header is `[opcode+keyid(1)][peer-id(3)]` (4 bytes total) followed directly by the packet-id/tag/ciphertext (Pattern 5). Reading `packet[1:9]` for a data packet reads 3 bytes of peer-id plus 5 bytes of what is actually packet-id/tag data, producing a garbage `sessionKey` that will never match any control-channel session.
**Why it happens:** `handleDatagram` was written and correctly tested in Phase 1, when only control opcodes existed on the wire; the assumption "every accepted opcode has an 8-byte session ID at a fixed offset" was true for 100% of Phase 1's traffic and remains silently embedded in the code.
**How to avoid:** Branch on opcode class (control vs. `OpDataV1`/`OpDataV2`, both already defined [VERIFIED: `/Users/svenloth/dev/govpn/internal/wire/wire.go:36-46`, quoted: `"OpDataV1                   Opcode = 6  // P_DATA_V1"` / `"OpDataV2                   Opcode = 9  // P_DATA_V2"`]) BEFORE any fixed-offset parsing, and add a separate, Server-scoped routing table for data packets (recommended: `map[uint32]*Session` keyed by the 24-bit peer-id this project itself assigns and pushes — mirrors the reference's own `multi->instances[peer_id]` array design intent [VERIFIED: `multi.c:655` `m->instances[mi->context.c2.tls_multi->peer_id] = NULL`], and sidesteps needing the client's source UDP address to stay stable, which this project doesn't guarantee since floating (`PROTO-02`) is v2-scoped-out).
**Warning signs:** Any data-channel round-trip test that only exercises a single concurrent session will not exercise this bug (a garbage `sessionKey` lookup that happens to also miss is indistinguishable from "not yet wired up" during early development). Exercise with ≥2 concurrent sessions from the start.

### Pitfall 4: `options_cmp_equal` OCC-mismatch handling — do not treat as a hard requirement
**What goes wrong:** Over-investing implementation time in reproducing the reference's exact options-string format (`V4,dev-type tun,link-mtu ...`) believing it's required for interop.
**Why it happens:** The wire format is real and documented, and it's easy to assume any mismatch is fatal by default.
**How to avoid:** Per Pattern 1, `options_cmp_equal` mismatches are warning-only unless `--opt-verify` is set client-side — not this project's concern to control. A short, honest options string (or even an empty one) does not break a real 2.6 client's handshake. Spend the saved time on the AEAD/key-direction correctness instead (Pitfalls 1-2), which ARE fatal if wrong.
**Warning signs:** n/a (this is a scope/effort pitfall, not a runtime bug) — but a real client's log showing `WARNING: 'link-mtu' is used inconsistently` etc. during interop testing is expected, benign, and does not indicate the connection is at risk.

### Pitfall 5: Ambiguity between three independently-sequenced "packet ID" concepts
**What goes wrong:** Reusing `internal/wire.PacketID` (the reliability-layer ACK sequence) or `internal/tlscrypt`'s own long-form packet-ID counter/window for the data channel's packet-ID/replay logic — or, conversely, assuming the data channel's short-form packet ID needs the tls-crypt-style frozen-timestamp handling.
**Why it happens:** All three are named "packet ID" in both the reference and this codebase's existing doc comments, and two of the three (tls-crypt, data-channel) are both directly AEAD/HMAC-adjacent security-relevant sequence numbers with sliding replay windows of the same default width (64).
**How to avoid:** The data-channel packet ID is SHORT FORM ONLY (4 bytes, no timestamp — `long_form=false` at both encrypt `crypto.c:89` and decrypt `crypto.c:402`) — there is no frozen-timestamp concern to port from `tlscrypt.Wrapper.sendTime`/`sendRolloverAt`; a plain monotonic `uint32` counter guarded by a mutex, paired with its own independent 64-wide sliding-window `struct` (same shape as `tlscrypt`'s existing `replayWindow`, but a fresh instance — never share the window itself), is sufficient and correctly mirrors the reference (`crypto_check_replay`/`packet_id_test`, `DEFAULT_SEQ_BACKTRACK = 64` [VERIFIED: `packet_id.h:100`]).
**Warning signs:** A single shared replay-window instance across tls-crypt AND the data channel would reject legitimate data packets whose packet-id sequence happens to collide numerically with a recently-seen tls-crypt sequence — an easy, subtle bug if the two windows are accidentally unified "for simplicity." Keep them as three (control-channel reliability, tls-crypt, data-channel) genuinely separate sequence spaces, exactly as CONTEXT.md's own Pitfall-1 cross-reference (inherited from Phase 1's package docs) already establishes for the first two, and this phase must extend to the third.

## Code Examples

### Full P_DATA_V2 encrypt, tying Patterns 4/5 together

```go
// Illustrative Go skeleton — not copied from any source, but every byte
// offset/order/size referenced is VERIFIED per the citations above.
func (w *datachan.Wrapper) sealDataV2(dst []byte, keyID uint8, peerID uint32, plaintext []byte) []byte {
    seq := w.nextPacketID() // uint32, starts at 1, never wraps (short form)

    header := make([]byte, 0, 4)
    header = append(header, byte(wire.OpDataV2)<<3|keyID&0x07)
    header = append(header, byte(peerID>>16), byte(peerID>>8), byte(peerID))

    nonce := make([]byte, 12)
    binary.BigEndian.PutUint32(nonce[0:4], seq)     // explicit packet-id
    copy(nonce[4:12], w.encrypt.implicitIV[:])       // Pattern 4's 8-byte slot

    aad := append(append([]byte{}, header...), nonce[0:4]...) // header(4)+packet-id(4) = 8 bytes

    sealed := w.aead.Seal(nil, nonce, plaintext, aad) // ciphertext ‖ tag (Go convention)
    tag := sealed[len(sealed)-16:]
    ciphertext := sealed[:len(sealed)-16]

    dst = append(dst, aad...)   // header + explicit packet-id
    dst = append(dst, tag...)   // Pattern 5: tag BEFORE ciphertext on the wire
    dst = append(dst, ciphertext...)
    return dst
}
```

### KM2 field-by-field read (framing discipline)

```go
// Illustrative — demonstrates exact-length-read framing (Pattern 1/6), not
// a source citation.
func readString(r io.Reader) ([]byte, error) {
    var lenBuf [2]byte
    if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
        return nil, err
    }
    n := binary.BigEndian.Uint16(lenBuf[:])
    if n == 0 {
        return nil, nil // write_empty_string's counterpart — VERIFIED ssl.c:1952-1959
    }
    buf := make([]byte, n)
    _, err := io.ReadFull(r, buf)
    return buf, err
}
```

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|---------------|--------|
| `P_DATA_V1` (no peer-id, 1-byte header) | `P_DATA_V2` (24-bit peer-id, 4-byte header) | OpenVPN 2.4 (2017), default since | Out of scope per CONTEXT.md — real 2.6 clients always support/prefer V2 (signaled via `IV_PROTO_DATA_V2` peer-info bit, `ssl.h:80` `#define IV_PROTO_DATA_V2 (1<<1)`); this research does not further verify V1 |
| Classic (non-epoch) AEAD packet-ID/nonce format | "Epoch" data format (16-bit epoch + 48-bit counter, 8-byte nonce component) | OpenVPN 2.7 development branch | Explicitly out of scope (CONTEXT.md, ROADMAP) — not researched further this session |
| Manual OCC options-string negotiation | NCP (Negotiable Crypto Parameters) | OpenVPN 2.4+ | Out of scope per project's own `Out of Scope` table (`REQUIREMENTS.md`: "NCP negotiation in v1... Fixed AES-256-GCM + explicit cipher push satisfies 2.6 clients") — this phase pushes a fixed cipher, does not negotiate |

**Deprecated/outdated:** none directly relevant to this phase's scope — the wire format researched here (Key Method 2, classic AEAD data channel) has been protocol-stable since OpenVPN 2.4 and remains the default a 2.6 client speaks unless NCP/epoch features are explicitly configured, neither of which this project's interop harness enables.

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | Sequential-first-free IPv4 pool arithmetic (skip network/broadcast, wrap detection) is straightforward stdlib `net.IP` manipulation with no reference-source gotcha, since this is this project's own design (CONTEXT.md's locked decision), not upstream OpenVPN pool-allocation logic (which this research did not read — `--ifconfig-pool` internals in `pool.c` were not investigated, since CONTEXT.md already locked the allocation *policy* independent of upstream's own implementation) | Pattern/Don't Hand-Roll, IP pool | Low — if wrong, surfaces immediately as a broken/overlapping IP assignment in the very first multi-client interop test, cheap to catch and fix locally, no protocol-interop risk since the client only cares about the pushed `ifconfig`/`topology` strings being self-consistent, not about matching upstream's internal allocator bit-for-bit |
| A2 | The exact contents of a real 2.6 client's own peer-info string (`IV_VER=`, `IV_PLAT=`, `IV_PROTO=`, etc.) do not need to be parsed/acted upon by the server in this phase beyond being read-and-discarded (framing only) — no server-side logic branches on `IV_PROTO_DATA_V2` or any other peer-info bit | Pattern 1, Pitfall 4 | Low — CONTEXT.md's own decisions never call for peer-info-conditional behavior in v1; if a real client ever failed to advertise `IV_PROTO_DATA_V2` (extremely unlikely for a 2.6.14 client, per `IV_PROTO` bit history), the server would still unconditionally send P_DATA_V2, which the interop harness's live-client test would catch immediately as a handshake/data-channel failure |
| A3 | The recommended peer-id-keyed `map[uint32]*Session` for data-packet routing (Pitfall 3's fix) is presented as *this project's* design recommendation, not something read from the reference — the reference's own `multi->instances[peer_id]` array is DCO/multi-process-specific machinery this project doesn't replicate wholesale | Pitfall 3 | Medium — if the planner instead chooses UDP-address-based routing for data packets (also viable, and arguably simpler given no floating support in v1), that is an equally valid alternative; either choice must still fix the underlying bug (data packets don't carry an 8-byte SessionID), so this assumption's risk is about which of two adequate designs is chosen, not about correctness of either |

## Open Questions

1. **Exact `bufio`/exact-length-read strategy for interleaving KM2's TLV fields with the later plain-string PUSH_REQUEST/PUSH_REPLY exchange over the same `tls.Conn`**
   - What we know: KM2 is fully self-delimiting (every field length-prefixed or fixed-size, Pattern 1); PUSH_REQUEST/PUSH_REPLY are NUL-terminated plain strings with no length prefix (Pattern 6); both must be read via exact-byte-count `io.ReadFull` calls against the same underlying `tls.Conn` (which itself only guarantees TLS-record-granularity `Read`s, not message-granularity).
   - What's unclear: whether to buffer at the `ctrlconn.Conn` level (Phase 1's existing type) or introduce a new small wrapper reader scoped to this phase's KM2/PUSH exchange only. CONTEXT.md explicitly leaves "how the PUSH_REQUEST/PUSH_REPLY exchange is driven over the TLS stream" to Claude's discretion.
   - Recommendation: a small internal `bufio.Reader`-backed helper (not exposed on `Session`) scoped to `runHandshake`'s post-handshake continuation is sufficient; no change to `ctrlconn.Conn`'s existing Phase-1-tested behavior is needed, since `tls.Conn` already reads from it transparently.

2. **Whether `--duplicate-cn` semantics (CONTEXT.md's locked "each connection gets its own IP") require any server-side bookkeeping beyond what the existing `sessionKey{addr, sid}` map already provides**
   - What we know: multiple sessions with the same verified `PeerCN` are already structurally supported by Phase 1's `sessionKey{addr, sid}` demux (keyed by address+session-ID pair, not by CN) — nothing in the existing code deduplicates by CN.
   - What's unclear: whether the new peer-id/data-packet routing table (Pitfall 3) needs any CN-awareness at all, or whether it's purely orthogonal (assign IPs and peer-ids per-session regardless of CN, exactly as today's control-channel session table already does per-connection, not per-identity).
   - Recommendation: treat as orthogonal — CONTEXT.md's decision reads as "don't special-case duplicate CNs," not "add new dedup logic," so no additional research or design is needed here; flagging only so the planner doesn't accidentally invent unneeded CN-tracking state.

## Environment Availability

| Dependency | Required By | Available | Version | Fallback |
|------------|------------|-----------|---------|----------|
| Go toolchain | All of this phase | ✓ | `go1.26.1 darwin/arm64` [VERIFIED: `go version`, this session] | — |
| Docker (interop harness) | VRFY-03 (lossy scenario, reused from Phase 1) | Not re-probed this session — already an established Phase 1 dependency (`01-RESEARCH.md`/`01-04-SUMMARY.md`'s own "User Setup Required": "Docker Desktop must be running locally") | — | If unavailable locally, the fast tier (`go test -race ./...`, including WIRE-02/WIRE-03's new golden-vector-style unit tests) still runs and covers the highest-risk crypto correctness; only the live-client PUSH_REPLY/data-channel round-trip needs Docker |
| Real OpenVPN 2.6.14 client (Debian bookworm, pinned) | VRFY-03, live confirmation of Patterns 1/5/6 | Already built and pinned by Phase 1's `test/interop/Dockerfile` [VERIFIED: `/Users/svenloth/dev/govpn/testdata/golden/README.md`, quoted: `"openvpn 2.6.14-0+deb12u2"` (Debian bookworm, resolved 2026-08-23)] | `2.6.14-0+deb12u2` | — |

**Missing dependencies with no fallback:** none identified.
**Missing dependencies with fallback:** Docker (see above) — fast tier remains available.

## Validation Architecture

### Test Framework

| Property | Value |
|----------|-------|
| Framework | Go stdlib `testing` (no third-party test framework — matches Phase 1) |
| Config file | none — `go test` is invoked directly via `Makefile` |
| Quick run command | `go test -race ./...` (fast tier — no Docker) |
| Full suite command | `make interop` (`go test -tags interop -count=1 -timeout 900s ./test/interop/ -run TestInteropScenarios -v`) — Docker-gated live-client scenarios |

[VERIFIED: `/Users/svenloth/dev/govpn/Makefile`, read this session, quoted `test:`/`interop:`/`golden:` targets — see Environment Availability and Sources]

### Phase Requirements → Test Map

| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| WIRE-02 | `openvpn_PRF`/`tls1_P_hash` matches the committed reference test vector byte-for-byte | unit | `go test -race -run TestPRF ./internal/keyderiv/` | ❌ Wave 0 — new package |
| WIRE-03 | Key-expansion slot slicing + `KEY_DIRECTION_INVERSE`/`NORMAL` assignment produce the documented cipher/implicit-IV byte ranges from Pattern 4's table | unit | `go test -race -run TestKeyDirection ./internal/keyderiv/` | ❌ Wave 0 — new package |
| CTRL-04 | Server correctly parses a KM2 message and can construct/write its own; round-trips against a self-constructed byte buffer | unit | `go test -race -run TestKeyMethod2 ./internal/keyderiv/` (or wherever KM2 read/write lands) | ❌ Wave 0 |
| CTRL-04 | A real client's KM2 message (extracted from a Docker capture) parses without error | integration | `go test -tags interop -run TestKeyMethod2FromCapture ./test/interop/` | ❌ Wave 0 — needs a new capture point in the harness |
| CTRL-05 | PUSH_REQUEST/PUSH_REPLY exchange produces the exact expected string (Pattern 6) | unit | `go test -race -run TestPushReply ./...` (package TBD by planner) | ❌ Wave 0 |
| CTRL-05 | Real client logs "Initialization Sequence Completed" and configures its tunnel IP from the pushed `ifconfig`/`topology subnet` | integration | `go test -tags interop -run TestTunnelUp ./test/interop/` | ❌ Wave 0 |
| DATA-01 | AES-256-GCM encrypt/decrypt round-trips with the exact tag-before-ciphertext wire order (Pattern 5); a bit-flip in the tag position causes `Open` to fail | unit + tamper | `go test -race -run TestDataChannel ./internal/datachan/` | ❌ Wave 0 — new package |
| DATA-01 | Real client ping round-trips as an encrypted P_DATA_V2 exchange, decodable by the interop harness's pcap tooling | integration | `go test -tags interop -run TestPingRoundTrip ./test/interop/` | ❌ Wave 0 |
| DATA-02 | Replayed/out-of-window packet-IDs are dropped; 64-wide window matches `DEFAULT_SEQ_BACKTRACK` | unit | `go test -race -run TestReplayWindow ./internal/datachan/` | ❌ Wave 0 |
| DATA-03 | The 16-byte ping magic is absorbed and never surfaces via `Session.Read` | unit | `go test -race -run TestPingAbsorbed ./...` (package TBD) | ❌ Wave 0 |
| SESS-02 | `Session.Read`/`Write` deliver raw IP packets datagram-style (one packet per call; short buffer errors, no truncation) | unit | `go test -race -run TestSessionReadWrite ./...` | ❌ Wave 0 |
| SESS-03 | `AssignedIP()` reflects the pool-assigned IP, matches what was pushed | unit | `go test -race -run TestIPPool ./...` (new pool package/type) | ❌ Wave 0 |
| VRFY-03 | Lossy scenario (5-10% loss+reorder) still completes handshake AND data-channel ping round-trip | integration | `go test -tags interop -run TestInteropScenarios ./test/interop/` (extend existing `lossy-large` scenario's assertions) | ✓ scenario exists (Phase 1) — assertions need extending, not new infrastructure |

### Sampling Rate
- **Per task commit:** `go test -race ./...` (fast tier)
- **Per wave merge:** `make interop` (Docker-gated full suite, matching Phase 1's own cadence)
- **Phase gate:** Full suite green before `/gsd-verify-work`

### Wave 0 Gaps
- [ ] `internal/keyderiv/` — new package, PRF + key-expansion unit tests (WIRE-02, WIRE-03), seeded by the verified reference test vector (Pattern 2)
- [ ] `internal/datachan/` — new package, AES-256-GCM Wrapper + replay window + tamper-has-teeth test (DATA-01, DATA-02), mirroring `internal/tlscrypt`'s existing test structure
- [ ] `test/interop/`: extend the harness to capture/assert on KM2 and PUSH_REPLY exchange bytes, and to verify a real client's ping round-trips (CTRL-04, CTRL-05, DATA-01 live confirmation) — likely a `decode.go` extension analogous to Phase 1's `decodeCapture`, since data-channel packets need AES-256-GCM unwrap (using the harness's own captured/derived session keys) the way `capture_test.go` already unwraps tls-crypt
- [ ] Framework install: none — `go test` already present, no new tooling

## Security Domain

### Applicable ASVS Categories

| ASVS Category | Applies | Standard Control |
|---------------|---------|-----------------|
| V2 Authentication | Indirect — client identity is Phase 1's verified CN, unchanged this phase | n/a, no new auth surface |
| V3 Session Management | Yes | Tunnel-IP pool must not double-assign a live IP to two concurrent sessions (mutex-guarded allocator); IP release-on-close (CONTEXT.md decision) must be race-free against a session that's mid-teardown |
| V4 Access Control | n/a | No new access-control surface this phase |
| V5 Input Validation | Yes | Every KM2/data-channel field read must bounds-check before indexing (mirrors `internal/wire.ParseControlPacket`'s existing discipline — [VERIFIED: `/Users/svenloth/dev/govpn/internal/wire/wire.go:158-207`, this file's own doc comment: `"Every field read explicitly checks the remaining buffer length first and returns a typed sentinel error rather than ever indexing out of range"`]); apply identically to the new KM2 parser and P_DATA_V2 header parser — never trust a client-supplied length field without a remaining-buffer check first |
| V6 Cryptography | Yes | AES-256-GCM via stdlib only (no hand-rolled AEAD); AEAD tag verified BEFORE any plaintext is used/replay-checked (matches both the reference's own ordering, `crypto.c:438-455`, and `internal/tlscrypt.Unwrap`'s existing pattern — [VERIFIED: `/Users/svenloth/dev/govpn/internal/tlscrypt/tlscrypt.go:321-328`, quoted: `"if !hmac.Equal(wireTag, computed) {\n\t\treturn nil, nil, ErrAuth\n\t}\n\n\tseq := binary.BigEndian.Uint32(...)\n\tif !w.replay.accept(seq) {"`] — tag/auth check strictly precedes replay-window mutation, preventing an unauthenticated packet from perturbing replay state) |

### Known Threat Patterns for this stack

| Pattern | STRIDE | Standard Mitigation |
|---------|--------|---------------------|
| Nonce reuse (same 12-byte IV used twice under the same key) | Tampering/Information Disclosure | The packet-ID counter is monotonic, mutex-guarded, and never resets within a key's lifetime (Pitfall 5) — this is the entire nonce-uniqueness guarantee for AES-256-GCM; a bug that resets or duplicates the counter (e.g. two goroutines racing on `nextPacketID()`) catastrophically breaks GCM's authentication guarantee. Guard with the same `sync.Mutex` discipline `tlscrypt.Wrapper.sendSeq` already establishes |
| Data-packet flood before key derivation completes (DoS) | Denial of Service | Mirror Phase 1's existing `handleDatagram` discipline (RESEARCH T-01-01 precedent): never allocate persistent per-attacker state for a data packet that fails AEAD auth or arrives for a peer-id with no live session — drop before any expensive work, exactly as the existing tls-crypt-unwrap-then-parse gate already does for control packets |
| Peer-id spoofing / routing-table confusion (Pitfall 3's new routing table) | Spoofing | A forged data packet claiming an in-use peer-id but arriving from the wrong UDP address is only caught by successful AEAD authentication (wrong key ⇒ decrypt fails) — do not use the peer-id alone as a trust signal; always require AEAD success before treating a packet as legitimate traffic for that session, matching the reference's own two-factor check (`floated \|\| link_socket_actual_match`, `ssl.c:3605`) even though this project doesn't implement floating itself |
| Replay of a captured data packet | Tampering | 64-wide sliding window (Pitfall 5), applied strictly after tag verification, per-session, per-direction — never shared across sessions or with tls-crypt's own window |

## Sources

### Primary (HIGH confidence)
- `/Users/svenloth/dev/openvpn-reference` (release/2.6, commit `c9b790f` "OpenVPN Release 2.6.22") — read directly this session: `src/openvpn/ssl.c` (`openvpn_PRF`, `key_method_2_write`/`read`, `generate_key_expansion_openvpn_prf`, `key_source2_read`/`randomize_write`, `key_ctx_update_implicit_iv`, `key_direction_state_init`, `tls_process`'s KM2 state machine, `tls_prepend_opcode_v2`, `tls_pre_decrypt`/`handle_data_channel_packet`, `write_string`/`read_string`/`push_peer_info`), `src/openvpn/crypto.c` (`openvpn_encrypt_aead`/`openvpn_decrypt_aead`, `crypto_check_replay`, `init_key_ctx_bi`), `src/openvpn/crypto.h`/`crypto_backend.h` (`struct key`/`key2`, `MAX_CIPHER_KEY_LENGTH`, `MAX_HMAC_KEY_LENGTH`, `OPENVPN_AEAD_MIN_IV_LEN`, `OPENVPN_AEAD_TAG_LENGTH`), `src/openvpn/crypto_openssl.c` (`ssl_tls1_PRF`, `tls1_P_hash`), `src/openvpn/ssl_common.h` (`struct key_source`/`key_source2`), `src/openvpn/packet_id.c`/`.h` (`packet_id_write`/`read`, `packet_id_send_update`, `DEFAULT_SEQ_BACKTRACK`), `src/openvpn/ping.c`/`.h` (`ping_string`, `PING_STRING_SIZE`), `src/openvpn/push.c` (`prepare_push_reply`, `send_push_reply`, `process_incoming_push_msg`/`_request`), `src/openvpn/helper.c` (`helper_keepalive`), `src/openvpn/options.c` (`ifconfig`/`keepalive`/`replay-window` option parsing), `src/openvpn/forward.c` (`send_control_channel_string_dowork`, `encrypt_sign` call site), `src/openvpn/openvpn.h` (`MAX_PEER_ID`), `src/openvpn/ssl.h` (`TLS_OPTIONS_LEN`, `KEY_METHOD_2`, `KEY_METHOD_MASK`, `KEY_EXPANSION_ID`, `IV_PROTO_*`), `tests/unit_tests/openvpn/test_crypto.c` (the committed `ssl_tls1_PRF` test vector). Treated as HIGH confidence per this project's own established Sources convention (CLAUDE.md): direct reads of the canonical reference implementation, not a secondhand summary.
- `/Users/svenloth/dev/govpn` (this repo, current state) — read directly this session: `ovpn.go`, `session.go`, `internal/wire/wire.go`, `internal/tlscrypt/tlscrypt.go`, `go.mod`, `Makefile`, `testdata/golden/manifest.json`, `testdata/golden/README.md`, `.planning/phases/01-handshake/01-03-SUMMARY.md`, `.planning/phases/01-handshake/01-04-SUMMARY.md`, `.planning/phases/02-tunnel-up/02-CONTEXT.md`, `.planning/REQUIREMENTS.md`, `.planning/STATE.md`. All in-repo verbatim quotes in this document are sourced from these reads.
- `go doc crypto/cipher NewGCM` / `go doc crypto/cipher.AEAD` — run this session against the installed `go1.26.1 darwin/arm64` toolchain; confirms `cipher.AEAD`'s tag-after-ciphertext `Seal`/`Open` convention and GCM's standard 12-byte nonce length.

### Secondary (MEDIUM confidence)
- WebSearch, "OpenVPN P_DATA_V2 packet format peer-id AEAD nonce packet ID implicit IV wire protocol" — cross-checked the general shape of P_DATA_V2/AEAD-AAD framing against secondary community/doc sources (DeepWiki, `openvpn3`'s own protocol-extensions doc, `patchwork.openvpn.net`); used only as a sanity cross-check, not as the source of any byte offset or ordering claim in this document — every specific byte-level claim above is sourced from the primary C reference read directly, not from this search (one secondary source's "XOR" phrasing was found to be imprecise relative to the primary source and is explicitly called out as such in Pattern 5).

### Tertiary (LOW confidence)
- None used as a basis for any claim in this document.

## Metadata

**Confidence breakdown:**
- Key Method 2 wire format / PRF / key expansion / AEAD nonce-tag layout: HIGH — every byte offset, field order, and edge case (odd-length PRF secret split, tag-before-ciphertext, key-direction inversion) read directly from the pinned reference source this session, with line citations and verbatim quotes
- PUSH_REQUEST/PUSH_REPLY string content and `keepalive` expansion: HIGH — read directly from `push.c`/`helper.c`, including the exact doc-comment table showing `keepalive 10 60`'s pushed expansion
- Tunnel-IP pool arithmetic: MEDIUM — this project's own design (CONTEXT.md's locked policy), not verified against upstream's own `pool.c` implementation (deliberately not investigated, since the policy is already locked and differs from upstream's own pool semantics by design)
- Data-packet routing-table recommendation (Pitfall 3's fix): MEDIUM — a reasoned recommendation grounded in the reference's own design intent (`multi->instances[peer_id]`), not a requirement copied verbatim; the planner has a genuine, flagged choice here (see Open Question 2 / Assumption A3)
- Security domain: HIGH — threat patterns and mitigations directly extend Phase 1's own already-audited/established patterns (`tlscrypt.Unwrap`'s tag-before-replay-check ordering, `handleDatagram`'s cheap-rejection discipline), applied to the new data-channel surface

**Research date:** 2026-08-24
**Valid until:** ~90 days (the underlying protocol — Key Method 2, classic AEAD data channel — has been stable since OpenVPN 2.4/2016; the only near-term churn vector, epoch data format / NCP-by-default, is explicitly out of this project's v1 scope) — re-verify only if the pinned reference checkout is updated to a materially different release, or if `go.mod`'s Go version floor moves and stdlib `crypto/cipher`/`crypto/tls` behavior is re-audited
