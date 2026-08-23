---
phase: 01-handshake
plan: 01
subsystem: wire-protocol
tags: [go, openvpn, tls-crypt, aes-256-ctr, hmac-sha256, udp, wire-format]

# Dependency graph
requires: []
provides:
  - "github.com/8upio/govpn module skeleton (go 1.24, zero external dependencies)"
  - "internal/wire: Opcode/SessionID/PacketID/Header/ControlPacket, ParseControlPacket, AppendPlaintext"
  - "internal/tlscrypt: Wrapper (Wrap/Unwrap), NewWrapper, ParseStaticKeyV1, per-instance replay window"
  - "ovpn.go public surface: Config, Server, NewServer, Serve, Close, ParseStaticKeyV1, Session (stub)"
  - "Proven HARD_RESET_CLIENT_V2 -> HARD_RESET_SERVER_V2 exchange over real loopback UDP"
affects: [01-02, 01-03, 01-04]

# Actuals (#2632)
actuals:
  tokens: 14562
  tasks: 2
  commits: 3

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "tls-crypt: MAC-then-CTR with tag-as-IV (SIV-style), never AEAD helpers"
    - "Per-session tlscrypt.Wrapper (independent replay window + send-sequence counter per client), not one server-wide Wrapper"
    - "Cheap pre-decrypt triage (length, opcode range) before any per-session allocation"
    - "Typed sentinel parse errors instead of slice-index panics on untrusted UDP input"

key-files:
  created:
    - go.mod
    - .gitignore
    - internal/wire/wire.go
    - internal/wire/wire_test.go
    - internal/tlscrypt/tlscrypt.go
    - internal/tlscrypt/keyfile.go
    - internal/tlscrypt/tlscrypt_test.go
    - internal/tlscrypt/keyfile_test.go
    - ovpn.go
    - ovpn_test.go
  modified: []

key-decisions:
  - "Per-session tlscrypt.Wrapper allocation (fresh replay window + send-sequence counter per client), not a single server-wide Wrapper — mirrors the C reference's per-tls_session tls_wrap_ctx. A shared decrypt-side replay window across all clients would reject a second client's legitimate first packet as a 'replay' of the first client's packet ID 1, since every client starts its own tls-crypt sequence counter at 1 independently."
  - "Session type declared as a minimal stub (serverSessionID/clientSessionID/remoteAddr/wrapper fields) in this plan so Config.OnSession's signature compiles; full io.ReadWriteCloser behavior is plan 01-03's job per the plan's own Artifacts table."
  - "Datagram read buffer sized maxDatagramSize+1 so an oversized UDP datagram (which the OS would otherwise silently truncate to fit a same-size buffer) is detectable and rejected rather than processed as truncated-but-valid."

patterns-established:
  - "wire.ParseControlPacket / (ControlPacket).AppendPlaintext are exact inverses — every wire-format change in later plans should preserve parse-then-serialize round-trip byte-exactness"
  - "tlscrypt.Wrapper.Unwrap decrypts into a scratch buffer and only returns plaintext after hmac.Equal verifies — plaintext never reaches wire.ParseControlPacket unauthenticated"

requirements-completed: [WIRE-01, WIRE-04, SESS-01]

coverage:
  - id: D1
    description: "Embedder can construct ovpn.NewServer(ovpn.Config{...}) and start it with Serve(net.PacketConn) over UDP in an unprivileged process"
    requirement: "SESS-01"
    verification:
      - kind: integration
        ref: "ovpn_test.go#TestHardResetRoundTrip"
        status: pass
    human_judgment: false
  - id: D2
    description: "tls-crypt wrap/unwrap round-trips under opposing key directions and fails closed on tamper and replay (WIRE-04)"
    requirement: "WIRE-04"
    verification:
      - kind: unit
        ref: "internal/tlscrypt/tlscrypt_test.go#TestWrapUnwrap"
        status: pass
      - kind: unit
        ref: "internal/tlscrypt/tlscrypt_test.go#TestUnwrapRejectsTamperedPacket"
        status: pass
      - kind: unit
        ref: "internal/tlscrypt/tlscrypt_test.go#TestUnwrapRejectsReplay"
        status: pass
      - kind: unit
        ref: "internal/tlscrypt/tlscrypt_test.go#TestWrapConcurrentSequenceIDs"
        status: pass
      - kind: unit
        ref: "internal/tlscrypt/keyfile_test.go#TestParseStaticKeyV1"
        status: pass
    human_judgment: false
  - id: D3
    description: "Control-packet opcode/session-ID/ACK-array parse<->serialize round-trips byte-exactly, and truncated/out-of-range input returns typed errors without panicking (WIRE-01)"
    requirement: "WIRE-01"
    verification:
      - kind: unit
        ref: "internal/wire/wire_test.go#TestControlPacketRoundTrip"
        status: pass
      - kind: unit
        ref: "internal/wire/wire_test.go#TestControlPacketAdjacency"
        status: pass
      - kind: unit
        ref: "internal/wire/wire_test.go#TestControlPacketTruncation"
        status: pass
      - kind: unit
        ref: "internal/wire/wire_test.go#TestOpcodeRange"
        status: pass
      - kind: other
        ref: "go test -race -fuzz FuzzParseControlPacket -fuzztime 20s ./internal/wire/"
        status: pass
    human_judgment: false
  - id: D4
    description: "Serve handles datagrams from multiple distinct client session IDs concurrently without cross-session state corruption, and Serve returns once the PacketConn is closed"
    verification:
      - kind: integration
        ref: "ovpn_test.go#TestConcurrentSessions"
        status: pass
      - kind: unit
        ref: "ovpn_test.go#TestServeClose"
        status: pass
    human_judgment: false

duration: 55min
completed: 2026-08-23
status: complete
---

# Phase 1 Plan 1: Wire Format, tls-crypt, and HARD_RESET Round Trip Summary

**End-to-end HARD_RESET_CLIENT_V2 -> HARD_RESET_SERVER_V2 exchange over real loopback UDP, built on hand-ported OpenVPN wire framing (`internal/wire`) and a from-scratch tls-crypt MAC-then-CTR construction (`internal/tlscrypt`), with zero external Go dependencies.**

## Performance

- **Duration:** ~55 min
- **Completed:** 2026-08-23
- **Tasks:** 2
- **Files modified:** 10 (all created; no pre-existing files touched)

## Accomplishments

- `github.com/8upio/govpn` module initialized (`go 1.24`, `go list -m all` reports exactly 1 module)
- `internal/wire`: opcode/key-id header packing, control-packet plaintext parse/serialize (ack array, remote session ID, own reliability packet ID) — byte-exact round trip, bounds-checked against truncated/adversarial input, verified with a 20-second native fuzz run (no crashers)
- `internal/tlscrypt`: MAC-then-CTR wrap/unwrap (HMAC-SHA256 tag doubling as the AES-256-CTR IV), Static key V1 file parsing, server/client key-direction slot assignment, per-instance replay window and monotonic send-sequence counter (race-tested for uniqueness under concurrent `Wrap`)
- `ovpn.go`: public `Config`/`Server` surface, UDP read loop with cheap pre-decrypt triage (length, opcode range) before any per-session allocation, per-session `tlscrypt.Wrapper` dispatch keyed by (remote address, session ID), full `HARD_RESET_CLIENT_V2` → `HARD_RESET_SERVER_V2` exchange
- Proven live over a real loopback `net.PacketConn`: a synthetic client using the client tls-crypt key direction sends one hard reset and receives a reply it can authenticate, decrypt, and parse — correct server session ID, packet ID 0, and ACK of the client's packet ID

## Task Commits

1. **Task 1: End-to-end HARD_RESET round trip — one packet, every layer** - `e8c2304` (feat)
2. **Task 2: Isolated golden vectors and untrusted-input hardening for WIRE-01 and WIRE-04** - `f9bf17d` (test)

**Follow-up fix (same plan, before hand-off):** `640bbc1` (fix) — corrected an inaccurate code comment discovered while reviewing Task 1's own DoS-triage claim (see Deviations below).

_Note: Task 2 is `tdd="true"`, but no `feat(...)` GREEN-phase commit exists — see TDD Gate Compliance below for why._

## Files Created/Modified

- `go.mod` - module `github.com/8upio/govpn`, `go 1.24`, zero dependencies
- `.gitignore` - build output, workspace files, `test/interop/pki|captures` (for plans 01-02+), OS cruft
- `internal/wire/wire.go` - `Opcode`, `SessionID`, `PacketID`, `Header`, `ControlPacket`, `ParseControlPacket`, `AppendPlaintext`
- `internal/wire/wire_test.go` - golden-vector round trip, adjacency, truncation, opcode-range, and fuzz tests for WIRE-01
- `internal/tlscrypt/tlscrypt.go` - `Wrapper`, `NewWrapper`, `Wrap`, `Unwrap`, per-instance replay window
- `internal/tlscrypt/keyfile.go` - `ParseStaticKeyV1`, Static key V1 envelope parsing
- `internal/tlscrypt/tlscrypt_test.go` - wrap/unwrap, tamper, replay, concurrency, and fuzz tests for WIRE-04
- `internal/tlscrypt/keyfile_test.go` - key-file parse and slot-assignment tests
- `ovpn.go` - `Config`, `Server`, `Session` (stub), `NewServer`, `Serve`, `Close`, `ParseStaticKeyV1`
- `ovpn_test.go` - `TestHardResetRoundTrip`, `TestConcurrentSessions`, `TestServeClose`

## Decisions Made

- **Per-session `tlscrypt.Wrapper`, not one server-wide instance.** Discovered while implementing Task 1: a single shared `Wrapper` (one decrypt-side replay window for the whole server) made `TestConcurrentSessions` fail, because two independently-connecting clients each start their own tls-crypt sequence counter at 1 — the server's shared replay window accepted the first client's packet ID 1 and then rejected the second client's packet ID 1 as a replay. Fixed by allocating a fresh `tlscrypt.Wrapper` per new session (mirroring the C reference's per-`tls_session` `tls_wrap_ctx`), stored on the minimal `Session` stub and reused for that client's subsequent traffic. This does not change the `tlscrypt.Wrapper`/`NewWrapper` public signatures the plan's `<interfaces>` block locks in — only how `ovpn.go` allocates instances.
- **Session state is only persisted after authentication succeeds.** `handleDatagram` must construct a candidate `Wrapper`+`Session` before it can even attempt `Unwrap` (tls-crypt needs keyed state to authenticate), but these candidates are discarded (never written to `s.sessions`) unless both `Unwrap` and `ParseControlPacket` succeed — a spoofed-source flood of forged `HARD_RESET_CLIENT_V2` datagrams can force transient per-packet allocation but can never grow the server's persistent session table.
- **`Session` declared here as a minimal stub.** The plan's own Artifacts table assigns `Session`'s real `io.ReadWriteCloser` implementation to plan 01-03; this plan only needs the type to exist so `Config.OnSession func(*Session)` compiles, plus enough private state (server/client session IDs, remote addr, this session's `Wrapper`) to answer the hard reset and support dispatch.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 2 - Missing Critical] Per-session tls-crypt replay-window/send-sequence state**
- **Found during:** Task 1 (writing `TestConcurrentSessions`, before the first commit)
- **Issue:** The plan's `<interfaces>` block specifies `Wrapper`/`NewWrapper` but doesn't dictate whether `ovpn.go` should hold one `Wrapper` for the whole server or one per session. A single server-wide `Wrapper` is a correctness bug: two clients' independent tls-crypt sequence counters both start at 1, and a shared decrypt-side replay window would treat the second client's first packet as a replay of the first client's.
- **Fix:** Allocate a fresh `tlscrypt.Wrapper` per newly-authenticated session, stored on `Session` and reused for that client going forward. `ovpn.go`'s `Server` no longer holds a server-wide `wrapper` field.
- **Files modified:** `ovpn.go` (part of the initial Task 1 implementation, before any commit was made — the bug never reached a committed state)
- **Verification:** `TestConcurrentSessions` passes under `-race`
- **Committed in:** `e8c2304` (Task 1 commit, already containing the fix)

**2. [Rule 1 - Bug] Inaccurate DoS-triage comment**
- **Found during:** post-Task-2 review, before hand-off
- **Issue:** A comment in `handleDatagram` claimed "no per-session state (Wrapper, Session) is allocated" before `Unwrap` succeeds — false; a candidate `Wrapper`+`Session` pair must be constructed to attempt authentication at all.
- **Fix:** Rewrote the comment to accurately describe the real security property: candidate objects are transient and only persisted into `s.sessions` after both `Unwrap` and `ParseControlPacket` succeed, so the server's persistent session table cannot be grown by a spoofed-source flood, even though per-packet transient allocation is unavoidable.
- **Files modified:** `ovpn.go`
- **Verification:** `go build ./... && go vet ./... && go test -race ./...` all pass; comment-only change, no behavior difference
- **Committed in:** `640bbc1`

---

**Total deviations:** 2 auto-fixed (1 missing-critical caught and fixed pre-commit, 1 bug fix post-hoc)
**Impact on plan:** Both fixes are necessary for correctness (concurrent multi-client dispatch) and honesty (accurate security-property documentation). No scope creep — the `tlscrypt.Wrapper`/`NewWrapper` interface the plan locks in for later plans is unchanged.

## TDD Gate Compliance

Task 2 carries `tdd="true"`, but this plan's RED/GREEN/REFACTOR gate does not apply in the usual sense: Task 2's job was writing golden-vector and hardening tests **against Task 1's already-implemented code**, not driving new implementation from a failing test. Running the full Task 2 test suite (`internal/wire/wire_test.go`, `internal/tlscrypt/tlscrypt_test.go`, `internal/tlscrypt/keyfile_test.go`) immediately passed with zero production-code changes required — Task 1's bounds-checked parsing, fail-closed tls-crypt authentication, and per-session replay windows already satisfied every case Task 2's `<behavior>` block specifies, including the 20-second `FuzzParseControlPacket` run (no crashers). There is a `test(...)` commit (`f9bf17d`) but no corresponding `feat(...)` GREEN-phase commit, because no GREEN-phase code change was needed — everything was already green. This is a legitimate outcome, not a skipped gate: the plan's own `<action>` text for Task 2 anticipated this possibility ("Harden the parse path **wherever the tests expose a gap**"), and no gap was found.

## Issues Encountered

None beyond the concurrent-session design bug documented above, which was caught and fixed before the first commit.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- `internal/wire` and `internal/tlscrypt` are stable, tested building blocks that plan 01-03's `internal/reliable` and `internal/ctrlconn` packages can build on directly.
- `Session` is currently a minimal stub (session IDs, remote addr, its own `Wrapper`) with no `io.ReadWriteCloser` behavior — plan 01-03 is expected to expand this type substantially; that expansion will very likely rewrite large parts of `ovpn.go`'s dispatch logic to route non-hard-reset opcodes into the reliability layer instead of the current "silently ignore" default case.
- `Config.TLSConfig`, `Config.Network`, `Config.Cipher`, and `Config.OnSession` are declared but unused by this plan — all are Phase 1 later-plan (01-03+) consumers, as scoped.
- No blockers for plan 01-02 (interop harness) or 01-03 (TLS handshake + reliability layer + real `Session`).

---
*Phase: 01-handshake*
*Completed: 2026-08-23*
