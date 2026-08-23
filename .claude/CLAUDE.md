<!-- GSD:project-start source:PROJECT.md -->

## Project

**govpn**

A pure-Go library (`github.com/8upio/govpn`, package `ovpn`) implementing the **server side of the OpenVPN protocol** — embeddable in any Go program, no wrapper around the `openvpn` binary, no separate process. Per connected client, the library hands the caller a `Session` that behaves as an `io.ReadWriteCloser` for raw, decrypted IP packets. It ships with a privilege-free userspace netstack (UDP + minimal server-side TCP + ICMP echo) so tunnel traffic can terminate entirely in-process, plus an example web server reachable only through the tunnel. Open source from day one — no comparable full Go implementation of the OpenVPN protocol exists (existing Go "openvpn" libs are process/management-interface wrappers).

**Core Value:** A real, unmodified OpenVPN 2.6 client can connect to a Go process embedding this library and exchange traffic through the tunnel — verified against the reference implementation, not approximated from memory.

### Constraints

- **Dependencies**: Go standard library only for the core library and netstack (`crypto/tls`, `crypto/cipher`, `crypto/hmac`, `net`, `encoding/binary`, …) — any third-party dependency needs explicit justification and discussion before adoption.
- **Tech stack**: Go; module path `github.com/8upio/govpn`, package name `ovpn`.
- **Correctness source**: OpenVPN C reference code — protocol details verified against `ssl.c`/`crypto.c`, interop verified against a real OpenVPN 2.6 client via packet capture.
- **Deployment target**: Must run unprivileged (no `CAP_NET_ADMIN`, no `/dev/net/tun`) in ordinary containers — hence the userspace netstack.
- **Compatibility**: OpenVPN 2.6 client with tls-crypt, cert auth, AES-256-GCM, `topology subnet`.
- **License/visibility**: Open source from the start — public API design and documentation matter early.

<!-- GSD:project-end -->

<!-- GSD:stack-start source:research/STACK.md -->

## Technology Stack

## Recommended Stack

### Core Technologies

| Technology | Version | Purpose | Why Recommended |
|------------|---------|---------|-----------------|
| Go | `go 1.24` directive in `go.mod`; develop/CI on the latest two stable releases (1.25.x / 1.26.x as of Aug 2026) | Language/runtime | Nothing in this project needs bleeding-edge language features (no generics-heavy design, no new stdlib APIs). The constraint that matters is Go's security-patch policy: only the latest two major releases get backported fixes, and `crypto/tls` is exactly the kind of package that receives them. Pinning too low (e.g. 1.21) risks builders using an unpatched toolchain; pinning to the bleeding-edge release forces adopters to upgrade immediately. `go 1.24` as the floor is safely inside the supported window and lets you re-bump it forward roughly once a year as Go's support window rolls. |
| `crypto/tls` (stdlib) | stdlib, tracks Go version | TLS 1.2/1.3 handshake for the control channel, layered via `tls.Server(customConn, cfg)` | Full client+server TLS implementation including certificate-based mutual auth (`Config.ClientCAs`, `Config.ClientAuth = tls.RequireAndVerifyClientCert`), exactly what's needed for OpenVPN's cert-auth control channel. Works over *any* `net.Conn`, so the custom framing/reliability layer just needs to satisfy that interface — the entire TLS handshake state machine is reused as-is, per the project's own key decision. No gap here for the handshake itself. |
| `crypto/cipher` + `crypto/aes` (stdlib) | stdlib | AES-256-GCM (data channel), AES-256-CTR (tls-crypt) | `cipher.NewGCM` gives you the AEAD primitive, but OpenVPN does **not** use Go's default 96-bit random-nonce GCM convention — the nonce is `packetID XOR implicit_iv` (a per-key 4-byte value derived from key material, XORed against a 4-byte-or-8-byte explicit packet-id sent on the wire; see epoch-format note below). You must call `AEAD.Seal`/`Open` with a manually assembled nonce, not rely on any helper that generates nonces for you. `cipher.NewCTR` covers tls-crypt's AES-256-CTR directly, no gaps. |
| `crypto/hmac` + `crypto/sha256` (stdlib) | stdlib | tls-crypt packet authentication (HMAC-SHA256) | Direct match for `tls_crypt.c`'s wrap/unwrap HMAC. No gaps. |
| `crypto/md5` + `crypto/sha1` + `crypto/hmac` (stdlib) | stdlib | OpenVPN's Key Method 2 data-channel key derivation (the legacy TLS 1.0/1.1 PRF, RFC 2246 §5) | **This is the one real "gap" in stdlib coverage — but it's a gap in *exposure*, not in *primitives*.** OpenVPN's `openvpn_PRF()` (crypto.c/ssl.c) delegates to `ssl_tls1_PRF`, which on every crypto backend (OpenSSL's `EVP_KDF` "TLS1-PRF", AWS-LC's `CRYPTO_tls1_prf`) implements the same RFC 2246 §5.6.4.1 construction: split the secret into two overlapping halves, run an HMAC-based `P_hash` expansion — MD5 over half 1, SHA1 over half 2 — then XOR the two output streams together. Go's own `crypto/tls` internally implements the *identical* algorithm (`prf10` in `src/crypto/tls/prf.go`) to support legacy TLS 1.0/1.1 handshakes, but it is unexported — not reachable from outside the `tls` package. **You cannot use `ConnectionState().ExportKeyingMaterial()`** (that's a different, TLS-1.2/1.3-native construction) — you must hand-write `openvpn_PRF` (~30-40 lines: secret split, two `P_hash` loops, XOR) directly against `crypto/md5`, `crypto/sha1`, `crypto/hmac`. This is small, well-specified, and testable byte-exact against reference test vectors — no need for `golang.org/x/crypto`. |
| `crypto/x509` + `crypto/rand` + `encoding/pem` (stdlib) | stdlib | Test/interop certificate generation (server cert, client cert, CA) for the Docker interop harness | Stdlib's `x509.CreateCertificate` supports everything OpenVPN checks: `ExtKeyUsage` (`x509.ExtKeyUsageServerAuth` / `ExtKeyUsageClientAuth`), `BasicConstraints`, `KeyUsage`. Generate the interop harness's CA/server/client cert chain in Go code (checked into the repo as a small `internal/testpki` or `cmd/gentestcerts` helper) rather than shelling out to `easy-rsa` — this makes cert generation reproducible, versioned, and debuggable without an external tool dependency, and keeps the whole interop harness self-contained in Go + Docker. |

### Supporting Libraries

| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| `github.com/gopacket/gopacket` | latest tagged release (community fork, see "What NOT to Use") | Programmatic pcap parsing/assertions in the interop test harness (e.g. "assert no bytes of the control channel are readable plaintext on the wire") | Only inside the interop-testing tooling — **not** a dependency of the `ovpn` module itself. Keep it in a separate `go.mod` (e.g. `test/interop/go.mod` or a `tools/` submodule) so the core library's dependency graph and `go.sum` stay stdlib-only, consistent with the project's minimal-deps constraint. |
| `golang.org/x/crypto` | — | **Not needed anywhere in this project.** | Every primitive OpenVPN's server protocol requires (AES-GCM, AES-CTR, HMAC-SHA256, the legacy MD5/SHA1 PRF, X.509) is in the standard library. Do not add this dependency speculatively — if a future NCP/cipher-negotiation phase needs something exotic (e.g. ChaCha20-Poly1305, which as of Go 1.22+ actually *is* in stdlib `crypto/chacha20poly1305`... verify at that time), re-evaluate then, not now. |

### Development Tools

| Tool | Purpose | Notes |
|------|---------|-------|
| Docker + a **self-built** interop image (`FROM debian:bookworm-slim` + `apt-get install openvpn`) | Runs an unmodified, version-pinned real OpenVPN client against the library for handshake/ping/HTTP verification | Debian bookworm ships `openvpn` 2.6.3 (patched to `2.6.3-1+deb12u4` and later as security updates land) — this is exactly the target version (OpenVPN 2.6 client) named in the project's constraints. Building your own minimal image from the Debian package repo (rather than pulling a third-party Docker Hub "openvpn-client" image of unknown/unpinned version) gives you full control over the exact client version under test and keeps the harness reproducible in CI. Pin the Debian base image digest, not just the tag. |
| `tcpdump` / `tshark` (external CLI, inside the Docker Compose network) | Ad hoc and CI-captured packet inspection during interop debugging | This is the OpenVPN ecosystem's own standard tooling — zero Go dependency, works identically to how you'd debug the C implementation. Use for interactive debugging and for capturing `.pcap` artifacts on CI failure. Reach for `gopacket` only when you need the test suite itself to *assert* on wire-format properties programmatically (not just capture for a human to inspect). |
| `go vet` / `staticcheck` / `gosec` (or golangci-lint bundling them) | Static analysis in CI | **Expect `gosec` to flag every `crypto/md5` and `crypto/sha1` import as weak crypto (G401/G505).** These flags are correct in general but a false positive here — MD5/SHA1 are used only as label-mixing PRF components mandated by wire compatibility with the OpenVPN protocol, not as the actual security boundary (that's TLS + AES-256-GCM). Add explicit `//nolint:gosec` annotations with a comment pointing at this rationale (and ideally at `openvpn_PRF` in the reference source) rather than disabling the rule globally — this keeps the linter useful everywhere else in the codebase. |
| `go test -race` | Concurrency correctness for the reliability layer (retransmission timers, ACK bookkeeping) and per-session state | The control-channel reliability layer (see below) is exactly the kind of stateful, timer-driven code that hides data races; run the race detector on every CI run, not just occasionally. |

## OpenVPN Reference Source Map

| Source file | Subsystem it defines | Relevant to |
|-------------|----------------------|-------------|
| `src/openvpn/ssl_pkt.c` | Control-channel packet format: opcode byte (`opcode << P_OPCODE_SHIFT \| key_id`), 8-byte session ID, HMAC/wrap-mode-dependent auth, packet-id, ACK array. `write_control_auth()` / `read_control_auth()` / `tls_pre_decrypt_lite()`. | The `net.Conn` framing layer's wire parsing/writing. |
| `src/openvpn/reliable.c` | Control-channel reliability: `reliable_entry` slot array, exponential-backoff retransmit (`timeout *= 2`), ACK-count fast-retransmit (`n_acks >= N_ACK_RETRANSMIT`), packet-id window/wraparound (`reliable_pid_in_range1/2`). | The engine sitting *inside* the `net.Conn` implementation, driving what `Read`/`Write` actually do under the hood. No stdlib pattern matches this — must be built from scratch against this file. |
| `src/openvpn/ssl.c` | `openvpn_PRF()` (calls `ssl_tls1_PRF`), `generate_key_expansion_openvpn_prf()`: two-stage derivation — pre-master secret → master secret (label `"OpenVPN master secret"`) → key expansion (label `"OpenVPN key expansion"`) — feeding client/server random1/random2, session IDs. Also the Key Method 2 control-message format itself (options string, random material exchange). | Data-channel key derivation — the project's own flagged "known hard part." Verify byte-exact against this file's test vectors before writing any data-channel crypto code. |
| `src/openvpn/crypto.c` | AEAD nonce construction for the data channel: `iv = packet_id XOR implicit_iv`; non-epoch format uses a 4-byte explicit packet-id, newer "epoch" format uses 16-bit epoch + 48-bit counter (8 bytes total). Static key file read/write (`Static key v1` format). | Data-channel AES-256-GCM encrypt/decrypt — the exact nonce assembly, not just "use AES-GCM." |
| `src/openvpn/crypto_openssl.c` (and `crypto_mbedtls.c`) | Backend-specific `ssl_tls1_PRF` implementation — confirms it's the standard RFC 2246 §5.6.4.1 construction (OpenSSL calls it via `EVP_KDF_fetch(NULL, "TLS1-PRF", ...)`). | Confirms the algorithm to reimplement in Go against `crypto/md5`/`crypto/sha1`/`crypto/hmac` (see Core Technologies row above). |
| `src/openvpn/tls_crypt.c` | tls-crypt wrap/unwrap: HMAC-SHA256 over packet-id+plaintext → top 128 bits of tag used as the AES-256-CTR IV → `[packet-id][HMAC-tag(32B)][ciphertext]` wire layout. Static key split into 4×64-byte keys (encrypt-cipher/hmac, decrypt-cipher/hmac) assigned by TLS role (client vs. server) via key-direction convention. | tls-crypt implementation — required for realistic OpenVPN 2.6 production config interop per the project's scope. |

## Installation

# go.mod

# Core library: zero dependencies beyond stdlib. Do not run `go get` for

# anything crypto- or framing-related — if you find yourself reaching for

# a third-party package here, stop and re-read PROJECT.md's minimal-deps

# constraint first.

# Interop test tooling (separate module, e.g. test/interop/go.mod):

## Alternatives Considered

| Recommended | Alternative | When to Use Alternative |
|-------------|-------------|--------------------------|
| Hand-rolled `net.Conn` framing + `crypto/tls` on top | `google/gvisor` netstack (full TCP/IP stack) | Never for this project — see "What NOT to Use." Only reconsider if the project's scope expands to a full conformant TCP/IP stack (general-purpose routing, not just "serve HTTP through the tunnel"), which PROJECT.md explicitly rules out. |
| Hand-written `openvpn_PRF` (RFC 2246 PRF) against `crypto/md5`/`sha1`/`hmac` | Vendoring Go's internal `prf10` from `crypto/tls/prf.go` via a fork/copy | Not recommended: copying internal stdlib code couples you to Go's internal (unstable, `internal/`-adjacent) implementation details and its license/version drift. Writing your own ~30-line version against the RFC is small enough that there's no real cost, and it can carry test vectors from the OpenVPN reference source directly. |
| Self-built `debian:bookworm-slim`-based Docker interop image, version-pinned | Third-party Docker Hub `openvpn-client` images (kylemanna/openvpn, rlesouef/alpine-openvpn, etc.) | Those images are convenient for quickly standing up a *server* wrapping the real binary, but for an *interop test harness* you specifically need to control and pin the exact OpenVPN version under test — third-party images' OpenVPN version drifts with upstream Alpine/Debian releases on their own schedule, not yours. Building your own gives reproducibility across CI runs. |
| `github.com/gopacket/gopacket` (community fork) | `google/gopacket` (original) | Never — see "What NOT to Use." |

## What NOT to Use

| Avoid | Why | Use Instead |
|-------|-----|-------------|
| `gVisor` netstack (`gvisor.dev/gvisor/pkg/tcpip`) | A full, conformant, kernel-grade TCP/IP stack — orders of magnitude more code and surface area than this project needs. The project only needs UDP demux, minimal server-side TCP for HTTP, and ICMP echo, all served entirely in-process without kernel privileges. Pulling in gVisor for that is a heavy, security-surface-expanding dependency that also works against the "privilege-free, minimal deps" design goal explicitly stated in PROJECT.md. | Hand-built `ovpn/ipudp` package: manual IP/UDP header parse+build (`encoding/binary` + a struct), destination-IP demux to `Session`s, a minimal server-side-only TCP state machine (no need for a full client-initiator stack), and a ~20-line ICMP echo responder — all already scoped and designed in the project's own briefing document. |
| Third-party Go "openvpn" libraries (`adamwalach/go-openvpn`, `mysteriumnetwork/go-openvpn`, `NordSecurity/gopenvpn`, `apparentlymart/go-openvpn-mgmt`, `smantel-ch/openvpn-go`, etc.) | Every one of these either (a) shells out to the real `openvpn` binary and manages it as a subprocess, or (b) implements a client for OpenVPN's *management interface* (a control/monitoring protocol for a running `openvpn` process) — none of them implement the wire protocol itself. They solve a different problem (process orchestration) than this project (protocol implementation as an embeddable library with no subprocess). Confirms the project's stated ecosystem gap is real, not a research miss. | This project itself. Nothing to reuse from this category. |
| `water` / `songgao/water` (TUN/TAP device libraries) | TUN/TAP device handling is explicitly out of scope for v1 (per PROJECT.md) — the primary use case (Voxio) terminates traffic entirely in-process via the userspace netstack, never touching a kernel TUN device. Pulling in a TUN library now would be scope creep against a decision already made. | Nothing, for v1. If/when a later `ovpn/tun` package is built (flagged as a possible future addition in PROJECT.md), reassess then — Linux TUN is stdlib-reachable via raw `ioctl(TUNSETIFF)` + `os.File` without needing `water` either, so even that future package likely doesn't need this dependency. |
| `golang.org/x/crypto` | Not a single primitive this project needs (AES-GCM, AES-CTR, HMAC-SHA256, the legacy MD5/SHA1 PRF, X.509) is missing from stdlib. Adding it "just in case" is exactly the kind of unjustified dependency PROJECT.md's constraints call out for explicit discussion first. | `crypto/aes`, `crypto/cipher`, `crypto/hmac`, `crypto/sha256`, `crypto/md5`, `crypto/sha1`, `crypto/x509` — all stdlib. |
| `google/gopacket` (the original, not the fork) | Effectively unmaintained; the ecosystem has moved to a community-maintained fork. Depending on the stale original risks missing bugfixes/new protocol decoders and signals an unmaintained-dependency smell in `go.mod`/interop tooling even though it's test-only. | `github.com/gopacket/gopacket` (community fork), and only inside interop-tooling, not the core module. |
| `tls.ConnectionState().ExportKeyingMaterial()` for data-channel key derivation | This is TLS's own RFC 5705 keying-material export, a different construction (HKDF-based key schedule in TLS 1.3, a different PRF invocation in TLS 1.2) than OpenVPN's own Key Method 2 PRF. Using it would produce keys a real OpenVPN client can never derive — instant, silent interop failure that would only surface as garbled/undecryptable data-channel traffic against the real client, exactly the kind of byte-level mistake the project's own briefing flags as the hardest thing to get right. | Hand-implemented `openvpn_PRF` per the Core Technologies table above, verified against `ssl.c`/`crypto.c` test vectors before writing any data-channel code — the project's own suggested first step. |

## Stack Patterns by Variant

- Re-check whether `crypto/chacha20poly1305` (stdlib since Go 1.22, moved from `x/crypto`) covers any newly-required AEAD ciphers before reaching for `golang.org/x/crypto` again.
- Because NCP also changes the control-channel `IV_*`/`OCC` capability negotiation strings, re-verify against `ssl_ncp.c` and `options.c` at that time — not covered by this research pass (out of scope per PROJECT.md).
- Linux TUN is reachable stdlib-only via `os.OpenFile("/dev/net/tun", ...)` + `syscall.Syscall(unix.SYS_IOCTL, ..., TUNSETIFF, ...)` (or `golang.org/x/sys/unix` for the ioctl constants, which is the one `x/` package that's arguably justified since it's Go's own team's syscall-constant package, not a third-party crypto/framing dependency).
- macOS `utun` needs `PF_SYSTEM` sockets — no clean stdlib path, evaluate `x/sys/unix` there too.
- Windows requires the Wintun driver — the project's own briefing already flags this as a conscious, deliberate exception to the minimal-deps rule, deferred past v1.

## Version Compatibility

| Package A | Compatible With | Notes |
|-----------|-----------------|-------|
| `go 1.24`+ `crypto/tls` | OpenVPN 2.6 client's default TLS min-version (TLS 1.2, with TLS 1.3 negotiated when both sides support it) | Set `tls.Config.MinVersion = tls.VersionTLS12` explicitly rather than relying on Go's default floor, since Go's default minimum TLS version has shifted upward across releases (currently 1.2) — pin it explicitly so a future Go stdlib default change can't silently break interop with older/more conservative real-world OpenVPN 2.6 client configs. |
| Debian `bookworm` `openvpn` 2.6.3(+security backports) | Project's stated compatibility target ("OpenVPN 2.6 client with tls-crypt, cert auth, AES-256-GCM, `topology subnet`") | Exact version match for the interop harness; re-verify the specific `2.6.x` patch level in the image at harness-build time, since Debian security updates bump it (`2.6.3-1+deb12u4` and later) without changing the `2.6` major/minor. |
| `github.com/gopacket/gopacket` | Go 1.24+ | No known constraint issues; it's test-tooling-only so version drift here has zero blast radius on the core library. |

## Sources

- `github.com/OpenVPN/openvpn` (master branch, fetched 2026-08-22) — `src/openvpn/ssl.c`, `src/openvpn/crypto.c`, `src/openvpn/crypto_openssl.c`, `src/openvpn/tls_crypt.c`, `src/openvpn/ssl_pkt.c`, `src/openvpn/reliable.c`. **Primary source** — the reference implementation itself, read directly, not a secondhand summary. Treat as HIGH confidence despite the generic tool-classification tier reported by the research-plan seam (which scores raw `webfetch` fetches as LOW by default — that default doesn't know this *is* the domain's canonical spec, per the project's own stated correctness source).
- `github.com/golang/go` (master branch) — `src/crypto/tls/prf.go`, confirming Go's own internal (unexported) TLS 1.0/1.1 PRF implementation matches the RFC 2246 construction OpenVPN's `ssl_tls1_PRF` uses, and confirming it is not reachable from the public `crypto/tls` API.
- Web search (`gopacket` maintenance status) — MEDIUM/LOW confidence, cross-checked against `github.com/gopacket/gopacket`'s existence and `pkg.go.dev` listing as the actively-maintained fork.
- Web search (Debian `bookworm` `openvpn` package version) — `packages.debian.org/bookworm/openvpn`, confirms `openvpn` 2.6.3-based package in Debian 12/bookworm.
- Web search (Go release cadence, Aug 2026 latest stable) — confirms Go 1.26.x as latest stable with 1.27 released around Aug 2026; used to justify the `go 1.24` floor recommendation (inside the two-release security-patch support window with margin).
- Web search (third-party Go "openvpn" packages) — surveyed `adamwalach/go-openvpn`, `mysteriumnetwork/go-openvpn`, `NordSecurity/gopenvpn`, `apparentlymart/go-openvpn-mgmt`, `smantel-ch/openvpn-go` and others; all are process wrappers or management-interface clients, confirming PROJECT.md's stated ecosystem gap.

<!-- GSD:stack-end -->

<!-- GSD:conventions-start source:CONVENTIONS.md -->

## Conventions

Conventions not yet established. Will populate as patterns emerge during development.
<!-- GSD:conventions-end -->

<!-- GSD:architecture-start source:ARCHITECTURE.md -->

## Architecture

Architecture not yet mapped. Follow existing patterns found in the codebase.
<!-- GSD:architecture-end -->

<!-- GSD:skills-start source:skills/ -->

## Project Skills

No project skills found. Add skills to any of: `.claude/skills/`, `.agents/skills/`, `.cursor/skills/`, `.github/skills/`, or `.codex/skills/` with a `SKILL.md` index file.
<!-- GSD:skills-end -->

<!-- GSD:workflow-start source:GSD defaults -->

## GSD Workflow Enforcement

Before using Edit, Write, or other file-changing tools, start work through a GSD command so planning artifacts and execution context stay in sync.

Use these entry points:

- `/gsd-quick` for small fixes, doc updates, and ad-hoc tasks
- `/gsd-debug` for investigation and bug fixing
- `/gsd-execute-phase` for planned phase work

Do not make direct repo edits outside a GSD workflow unless the user explicitly asks to bypass it.
<!-- GSD:workflow-end -->

<!-- GSD:profile-start -->

## Developer Profile

> Profile not yet configured. Run `/gsd-profile-user` to generate your developer profile.
> This section is managed by `generate-claude-profile` -- do not edit manually.
<!-- GSD:profile-end -->
