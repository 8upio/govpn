---
phase: 01-handshake
plan: 03
subsystem: control-protocol
tags: [go, openvpn, tls, crypto-tls, reliability-layer, net-conn, docker-interop]

# Dependency graph
requires:
  - phase: 01-01
    provides: "internal/wire (opcode/session-ID/control-packet parsing), internal/tlscrypt (Wrapper/NewWrapper/ParseStaticKeyV1), ovpn.NewServer/Serve with the HARD_RESET exchange"
  - phase: 01-02
    provides: "cmd/gentestpki, test/interop Docker Compose harness, test/interop/server observing-conn pattern, test/interop/capture_test.go's stdlib-only pcap tls-crypt verification"
provides:
  - "internal/reliable: role-agnostic Go port of the OpenVPN reliability layer (Reliable, AckSet, PacketID, all constants) — ACK bookkeeping, packet-ID windows, exponential-backoff retransmission, fast retransmit, strictly in-order delivery"
  - "internal/ctrlconn: Conn, a net.Conn over the control channel — outbound fragmentation at MaxPayload=1150, inbound in-order reassembly, ACK piggyback capped at 8, dedicated ack-only packets, idempotent Close, deadline support"
  - "session.go: real ovpn.Session (SessionID, RemoteAddr, PeerCN, ConnectionState()) with placeholder Read/Write for Phase 2's data channel and a real Close"
  - "ovpn.go: each session gets a real internal/ctrlconn.Conn and a goroutine running tls.Server(conn, cfg).Handshake(); Config.OnSession fires exactly once, only after Handshake() returns nil; a 60s handshake-window goroutine tears down sessions that never complete"
  - "test/interop/server: harness success condition raised from first contact to a completed, 2s-stable TLS handshake, printing peer CN/TLS version/cipher suite via Session.ConnectionState()"
  - "test/interop: TestRealClientCompletesTLSHandshake — a real OpenVPN 2.6.14 client completes TLS 1.3 mutual-cert-auth handshake against the library"
affects: [01-04, phase-02]

# Actuals (#2632)
actuals:
  tokens: 22885
  tasks: 3
  commits: 3

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "internal/reliable.Reliable is a single role-agnostic type: one instance sized NSendBuffers (6) drives Next/MarkActive/SetPayload/Ack/Due for outgoing entries, a second sized NRecBuffers (12) drives Put/Get for incoming entries — mirroring the reference's separate send_reliable/rec_reliable per tls_session"
    - "Clock interface (Now() time.Time) injected through Reliable's constructor so retransmit/backoff tests run in milliseconds with zero time.Sleep, never wall-clock sleeps"
    - "ctrlconn.Conn.absorb (ACK processing + recv-window Put/Get, no transmission) is split from Deliver (absorb + flush a dedicated ack-only packet) and DeliverAndRespond (absorb + one explicit reply packet that itself carries the ack) — the split exists specifically so a session's bootstrap HARD_RESET_SERVER_V2 reply IS the ack for the client's reset, never a separate ack-only packet racing an unacked reply"
    - "ovpn.go's handleDatagram constructs a new session's ctrlconn.Conn (and, transitively, starts its goroutines) strictly while still holding Server.mu, before the session becomes visible via s.sessions — required to avoid a data race with Server.Close() reading sess.conn outside the lock (caught by go test -race, see Deviations)"
    - "Session.ConnectionState() returns the full captured tls.ConnectionState verbatim (not ad-hoc TLSVersion/CipherSuite fields) — idiomatic, matches crypto/tls's own naming, and is what the interop harness calls directly"

key-files:
  created:
    - internal/reliable/reliable.go
    - internal/reliable/reliable_test.go
    - internal/ctrlconn/conn.go
    - internal/ctrlconn/conn_test.go
    - session.go
  modified:
    - ovpn.go
    - ovpn_test.go
    - test/interop/server/main.go
    - test/interop/interop_test.go
    - test/interop/capture_test.go

key-decisions:
  - "AckSet (pending-ACK accumulator) has no storage cap on Add, unlike the reference's fixed RELIABLE_ACK_SIZE=8 struct reliable_ack (which relies on a separate ack_mru structure for redundant re-acking once full — out of Phase 1 scope). Only Drain caps how many IDs go out per packet at 8, with the remainder queued for the next packet. This preserves the protocol-visible behavior the plan's <behavior> block specifies without porting the reference's MRU redundancy optimization."
  - "The client's own HARD_RESET_CLIENT_V2 is fed into the new session's Conn synchronously via DeliverAndRespond, on the same goroutine that creates the session — not through the per-session inbound channel/pump goroutine used for every later packet. This guarantees the server's HARD_RESET_SERVER_V2 reply carries the ack for packet ID 0 deterministically; racing it through the channel non-deterministically produced either an ack-only packet or an unacked reset depending on goroutine scheduling (caught while running Task 1's own tests, see Deviations)."
  - "Session gained ConnectionState() tls.ConnectionState (returning the full state captured once after Handshake() returns nil) rather than picking out individual TLSVersion/CipherSuite fields — matches crypto/tls's own idiom and is what test/interop/server/main.go calls directly to satisfy Task 3's printed diagnostic line."
  - "test/interop/server's harness explicitly sleeps 2 seconds past OnSession before printing PASS and exiting 0 — the client's Key Method 2 application data arrives during that window; if it disturbed the session, Serve would error/exit before PASS could ever print. This makes 'the server doesn't error on post-handshake TLS application data' a self-verifying property of a passing run, not something the Go test has to inspect timestamps for."

patterns-established:
  - "reliable.Reliable's send-side (Next/MarkActive/SetPayload/Ack/Due) and receive-side (Put/Get) method pairs are the vocabulary later plans (and Phase 2's data-channel key negotiation, if it ever needs reliable delivery semantics) should reuse rather than re-deriving window/backoff logic."
  - "ctrlconn.Conn's Transport interface (WriteTo(p, addr)) is the minimal seam between the reliability-driven framing layer and the raw UDP socket — any future layer needing to intercept/observe outgoing wire bytes can wrap this interface exactly as test/interop/server's observingConn wraps net.PacketConn."

requirements-completed: [CTRL-01, CTRL-02, CTRL-03, SESS-01]

coverage:
  - id: D1
    description: "internal/reliable ports the reference's ACK bookkeeping, packet-ID windows, exponential-backoff retransmission (2s/4s/8s), fast retransmit after 3 later acks, and strictly in-order delivery, with every constant traced to reliable.h/ssl_pkt.h/options.c"
    requirement: "CTRL-01"
    verification:
      - kind: unit
        ref: "internal/reliable/reliable_test.go#TestRetransmitBackoff"
        status: pass
      - kind: unit
        ref: "internal/reliable/reliable_test.go#TestFastRetransmitAfterThreeLaterAcks"
        status: pass
      - kind: unit
        ref: "internal/reliable/reliable_test.go#TestSendWindowBlocksAtSix"
        status: pass
      - kind: unit
        ref: "internal/reliable/reliable_test.go#TestRejectsReplayAndOutOfWindow"
        status: pass
      - kind: unit
        ref: "internal/reliable/reliable_test.go#TestOrderedDelivery"
        status: pass
      - kind: unit
        ref: "internal/reliable/reliable_test.go#TestPacketIDWraparound"
        status: pass
      - kind: unit
        ref: "internal/reliable/reliable_test.go#TestAckPiggybackCapAndAckOnlyPacket"
        status: pass
      - kind: unit
        ref: "internal/reliable/reliable_test.go#TestReliabilityAndTLSCryptWindowsAreIndependent"
        status: pass
    human_judgment: false
  - id: D2
    description: "internal/ctrlconn.Conn implements net.Conn over the control channel: outbound fragmentation at MaxPayload=1150 bytes, inbound in-order reassembly with no separate fragmentation header, ACK piggyback capped at 8 with a dedicated ack-only packet when nothing else is queued"
    requirement: "CTRL-02"
    verification:
      - kind: integration
        ref: "internal/ctrlconn/conn_test.go#TestTLSHandshakeOverCtrlConn"
        status: pass
    human_judgment: false
  - id: D3
    description: "A real, unmodified OpenVPN 2.6 client completes the full TLS handshake (HARD_RESET_V2 through Handshake()==nil) against the library over the Docker interop harness, with mutual certificate authentication, both sides reporting the peer's verified CommonName"
    requirement: "CTRL-03"
    verification:
      - kind: integration
        ref: "test/interop/interop_test.go#TestRealClientCompletesTLSHandshake"
        status: pass
      - kind: integration
        ref: "test/interop/capture_test.go#TestCaptureIsFullyTLSCryptWrapped"
        status: pass
      - kind: other
        ref: "go test -tags interop -count=1 -timeout 300s -v ./test/interop/ (live run: real OpenVPN 2.6.14 client, TLS 1.3, TLS_AES_128_GCM_SHA256)"
        status: pass
    human_judgment: false
  - id: D4
    description: "Config.OnSession fires exactly once per client, only after Handshake() returns nil, with a Session whose PeerCN is the verified client CommonName; a session that never completes its handshake within 60s is torn down"
    requirement: "SESS-01"
    verification:
      - kind: unit
        ref: "internal/ctrlconn/conn_test.go#TestTLSHandshakeOverCtrlConn (asserts both sides' verified CommonName)"
        status: pass
      - kind: integration
        ref: "test/interop/interop_test.go#TestRealClientCompletesTLSHandshake (asserts server logs peer_cn=govpn-interop-client only after OnSession)"
        status: pass
    human_judgment: false
  - id: D5
    description: "The server tolerates TLS application data (the real client's Key Method 2 payload) arriving after the handshake completes, without erroring, closing, or resetting the connection — verified by staying alive 2 seconds past OnSession before exiting"
    verification:
      - kind: other
        ref: "test/interop/server/main.go's postHandshakeSurvival window; live run log shows 'handshake established' then 'PASS: session established and stable 2s past handshake completion' 2 seconds later"
        status: pass
    human_judgment: false

duration: ~110min
completed: 2026-08-23
status: complete
---

# Phase 1 Plan 3: TLS Handshake Over the Control-Channel net.Conn Summary

**A real OpenVPN 2.6.14 client completes a full TLS 1.3 mutual-certificate handshake against the library, over a hand-ported OpenVPN reliability layer (`internal/reliable`) and a `net.Conn` control channel (`internal/ctrlconn`) carrying stdlib `crypto/tls` completely unmodified.**

## Performance

- **Duration:** ~110 min
- **Completed:** 2026-08-23
- **Tasks:** 3
- **Files modified:** 10 (5 created, 5 modified)

## Accomplishments

- `internal/reliable`: a role-agnostic Go port of `reliable.c` — send-side window (6 entries), receive-side window (12 entries), 2s→4s→8s exponential backoff, fast retransmit after 3 later ACKs, wraparound-safe packet-ID range/replay checks, and an unbounded-accumulation/8-per-packet-drain `AckSet` — every constant and heuristic traced to a named construct in the pinned reference, verified with a clock-injected test suite that runs in milliseconds with zero `time.Sleep`
- `internal/ctrlconn`: `Conn`, a real `net.Conn` implementation — outbound fragmentation at 1150 bytes/packet, inbound in-order reassembly (no wire fragmentation header), idempotent `Close`, deadline support — proven by two real `Conn` instances over loopback UDP carrying a complete TLS 1.2-or-better handshake with mutual certificate verification and post-handshake payload delivery, under the race detector
- `ovpn.go` rewired end to end: each new session gets a real `internal/ctrlconn.Conn`, a goroutine running `tls.Server(conn, cfg).Handshake()`, and a 60-second handshake-window goroutine; `Config.OnSession` fires exactly once, only after `Handshake()` returns nil, with the verified peer CommonName
- `session.go`: a real `ovpn.Session` (`SessionID`, `RemoteAddr`, `PeerCN`, `ConnectionState()`) with Phase-2-deferred `Read`/`Write` placeholders and a real `Close`
- The interop harness's pass condition raised from "client's hard reset was answered" to "client's TLS handshake completed and the session survived 2 seconds of subsequent application data" — **live-verified**: a real, unmodified OpenVPN 2.6.14 client negotiates TLS 1.3 / `TLS_AES_128_GCM_SHA256`, both sides report the peer's verified CommonName (server logs `peer_cn=govpn-interop-client`; the client's own verbose log shows `VERIFY OK: depth=0, CN=govpn-interop-server`), and the server stays alive and error-free through the client's post-handshake Key Method 2 payload

## Task Commits

1. **Task 1: A full TLS handshake completes over the control-channel net.Conn** - `0c6d400` (feat)
2. **Task 2: Complete reliability semantics — retransmission, windows, replay, ACK policy** - `f3c2b1e` (test)
3. **Task 3: Real OpenVPN 2.6 client reaches TLS established through the harness** - `bd65325` (feat)

_Note: Task 1 is `type="tracer"` — committed and its own `<verify>` re-run end-to-end (autonomous worktree execution, no interactive user to checkpoint to) before expanding into Tasks 2 and 3. Task 2 is `tdd="true"` but, like plan 01-01's own Task 2, produced no separate GREEN-phase commit: the tests were written against Task 1's already-complete implementation and passed immediately — see TDD Gate Compliance below._

## Files Created/Modified

- `internal/reliable/reliable.go` - `Reliable`, `AckSet`, `PacketID`, `Clock`/`SystemClock`, every window/timing constant
- `internal/reliable/reliable_test.go` - clock-injected retransmit/backoff/window/replay/ordering/wraparound/ACK-piggyback/independence tests
- `internal/ctrlconn/conn.go` - `Conn` (`net.Conn`), `New`, `MaxPayload`, `Deliver`/`DeliverAndRespond`/`SendReset`
- `internal/ctrlconn/conn_test.go` - `TestTLSHandshakeOverCtrlConn` (real loopback UDP, real generated CA/cert pair, mutual TLS 1.2)
- `session.go` - `ovpn.Session` (`SessionID`, `RemoteAddr`, `PeerCN`, `ConnectionState()`, placeholder `Read`/`Write`, real `Close`)
- `ovpn.go` - per-session `ctrlconn.Conn` + handshake goroutine + handshake-window enforcement; `Server.Close()` now closes in-flight sessions
- `ovpn_test.go` - `testTLSConfig` helper (Serve now requires `Config.TLSConfig`)
- `test/interop/server/main.go` - success condition raised to a completed, 2s-stable handshake; structured PASS line via `Session.ConnectionState()`
- `test/interop/interop_test.go` - `TestRealClientCompletesTLSHandshake` replacing `TestRealClientFirstContact`
- `test/interop/capture_test.go` - doc-comment accuracy fix (no functional change)

## Decisions Made

- **`AckSet` accumulates without a storage cap; only `Drain` caps at 8 per outgoing packet.** The reference's `struct reliable_ack` itself caps storage at `RELIABLE_ACK_SIZE=8` and relies on a separate `ack_mru` structure for redundant re-acking once full. Porting that MRU mechanism was out of scope for this plan; the protocol-visible behavior the plan's `<behavior>` block actually specifies ("with more than 8 pending, the remainder stay queued for the next packet") is preserved without it.
- **The client's own hard reset is delivered synchronously, not through the per-session channel, for session bootstrap.** See Deviations — this was a correctness fix, not a stylistic choice.
- **`Session.ConnectionState()` returns the full `tls.ConnectionState`, not ad-hoc fields.** More idiomatic than picking out `TLSVersion`/`CipherSuite` fields, matches `crypto/tls`'s own naming, and is what Task 3's acceptance criteria (`test/interop/server/main.go contains ConnectionState()`) expected the harness to call directly.
- **The interop harness proves post-handshake stability by construction.** `test/interop/server` sleeps 2 seconds past `OnSession` before printing PASS; a crash or error on the client's post-handshake application data would prevent PASS from ever appearing, making "the server survives post-handshake TLS application data" a property of a passing run rather than something the Go test has to measure via timestamps.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Data race between session creation and `Server.Close()`**
- **Found during:** Task 1, running `go test -race ./...` for the first time after wiring `internal/ctrlconn` into `ovpn.go`
- **Issue:** `handleDatagram` wrote `sess.conn = ctrlconn.New(...)` to a newly-created `*Session` *after* releasing `Server.mu` from the map-insertion step. `Server.Close()` (added in this same task, see Deviation 3) read `s.sessions` under `Server.mu` and then read `sess.conn` for each entry *outside* the lock — an unsynchronized read racing the unsynchronized write, caught immediately by `-race`.
- **Fix:** Restructured `handleDatagram` so `sess.conn = ctrlconn.New(...)` happens strictly *while still holding* `Server.mu`, before `s.sessions[key] = sess` publishes the session. Any later goroutine that acquires the same lock to read the map sees a fully-initialized `sess.conn` (Go memory model happens-before through the shared mutex).
- **Files modified:** `ovpn.go`
- **Verification:** `go test -race ./...` clean across 3 consecutive runs
- **Committed in:** `0c6d400` (Task 1 commit — the race never reached a committed state)

**2. [Rule 1 - Bug] Session-bootstrap ACK non-determinism**
- **Found during:** Task 1, `TestHardResetRoundTrip`/`TestConcurrentSessions` failing intermittently after wiring the reliability layer
- **Issue:** The initial design pushed the client's own `HARD_RESET_CLIENT_V2` onto the new session's inbound channel (processed by an async `pump()` goroutine) and, on the same triggering goroutine, immediately called a separate `SendReset`. Depending on goroutine scheduling, the reply either carried the ack for packet ID 0 (if `pump()` had already run) or didn't (if it hadn't) — visible as the reply sometimes arriving as an ack-only packet (opcode 5) instead of `HARD_RESET_SERVER_V2` (opcode 8), or arriving with an empty ACK array / zero `RemoteSessionID`.
- **Fix:** Split `Conn.Deliver` into an unexported `absorb` (ACK processing + recv-window Put/Get, no transmission) and two ways to turn it into outgoing traffic: `Deliver` (absorb + flush a dedicated ack-only packet, used by every packet after the first) and `DeliverAndRespond` (absorb + one explicit reply that itself carries the ack, used exactly once for session bootstrap). `handleDatagram` now calls `DeliverAndRespond` synchronously, deterministically, before starting the session's async pump for all later traffic.
- **Files modified:** `internal/ctrlconn/conn.go`, `ovpn.go`
- **Verification:** `go test -race ./...` (including `TestHardResetRoundTrip`, `TestConcurrentSessions`) passes consistently across repeated runs
- **Committed in:** `0c6d400` (Task 1 commit — caught and fixed before the first commit)

**3. [Rule 2 - Missing Critical] `Server.Close()` didn't close in-flight sessions**
- **Found during:** Task 1, reasoning through goroutine lifecycle while wiring per-session handshake/retransmit goroutines
- **Issue:** The plan's existing `Server.Close()` only closed the underlying `PacketConn`. With real per-session goroutines now in play (handshake, retransmit loop, handshake-window timer), a server shutdown would leave every in-flight session's goroutines blocked forever (a resource leak in any long-lived embedding process).
- **Fix:** `Server.Close()` now also closes every session's `*ctrlconn.Conn`, which stops the retransmit loop and unblocks any blocked `Read`/`Write`, letting the handshake goroutine's `Handshake()` call return (with an error) and its own cleanup run.
- **Files modified:** `ovpn.go`
- **Verification:** `go test -race ./...` (no reported goroutine issues; `TestServeClose` still passes)
- **Committed in:** `0c6d400` (Task 1 commit)

**4. [Rule 2 - Missing Critical] `Session.ConnectionState()` didn't exist for the harness to call**
- **Found during:** Task 3, implementing the interop server's structured PASS line
- **Issue:** Task 3's acceptance criteria requires `test/interop/server/main.go` to call `ConnectionState()` and print the negotiated TLS version and cipher suite "from the session" — but `ovpn.Session` (as built in Task 1) only exposed `PeerCN`, with no way for an embedder to reach the underlying `tls.Conn`'s negotiated version/cipher suite.
- **Fix:** Added `Session.ConnectionState() tls.ConnectionState`, populated once in `runHandshake` immediately after `Handshake()` returns nil, alongside `PeerCN`. `test/interop/server/main.go` calls `sess.ConnectionState()` directly.
- **Files modified:** `session.go`, `ovpn.go`, `test/interop/server/main.go`
- **Verification:** live interop run's PASS line: `peer_cn=govpn-interop-client tls_version=TLS 1.3 tls_version_raw=0x0304 cipher_suite=TLS_AES_128_GCM_SHA256`
- **Committed in:** `bd65325` (Task 3 commit)

---

**Total deviations:** 4 auto-fixed (2 bugs caught by `-race` and by test flakiness before any commit, 2 missing-critical-functionality additions required by the plan's own stated goals). No scope creep: all four are necessary for the correctness or acceptance criteria this plan itself specifies.

## TDD Gate Compliance

Task 2 carries `tdd="true"`, but — exactly like plan 01-01's own Task 2 — this plan's RED/GREEN/REFACTOR gate does not apply in the usual sense: Task 1 already implemented the full reliability semantics `<behavior>` block describes (retransmission, windows, replay, ACK policy), so Task 2's job was writing deterministic, clock-injected tests *against already-complete code*, not driving new implementation from a failing test. Every test in `internal/reliable/reliable_test.go` passed on first run with zero production-code changes required. There is a `test(...)` commit (`f3c2b1e`) but no corresponding `feat(...)` GREEN-phase commit, because none was needed — everything was already green. This is a legitimate outcome, not a skipped gate.

## Issues Encountered

None beyond the four items documented in Deviations, all caught and fixed via the plan's own stated verification commands (`go test -race ./...`, `go test -race -run TestTLSHandshakeOverCtrlConn -v ./internal/ctrlconn/`) before their respective task's commit.

## User Setup Required

None - no external service configuration required. Docker Desktop must be running locally (already an Environment Availability item from `01-RESEARCH.md` and `01-02-SUMMARY.md`, not new setup for this plan).

## Next Phase Readiness

- `internal/reliable` and `internal/ctrlconn` are stable, tested building blocks: Phase 2's data-channel work builds directly on top of the now-completed control channel (`tls.Conn` over `ctrlconn.Conn`) rather than needing to touch either package's internals.
- `Session.Read`/`Session.Write` remain deliberate placeholders (`io.EOF` / an explicit "not implemented until phase 2" error) — Phase 2 (`CTRL-04`, Key Method 2, AES-256-GCM data channel) is expected to replace them with real data-channel crypto without needing to change `Session`'s already-locked-in `SessionID`/`RemoteAddr`/`PeerCN`/`ConnectionState()`/`Close()` surface.
- The real client's Key Method 2 payload is now reliably delivered, in order, into `Session.conn`'s internal read buffer (via the same `internal/ctrlconn.Conn` the TLS handshake used) — unread by Phase 1 by design, but Phase 2 has a concrete, already-proven path to start reading it: nothing about how that data arrives needs to change, only that something finally calls `Session`'s (soon-to-be-real) `Read`.
- Plan 01-04 (the lossy-network / packet-loss-injection gate mentioned throughout this plan's flagged assumptions and RESEARCH) can now exercise the full reliability layer's retransmission and fast-retransmit behavior against a real client, not just the clean-link path this plan verified.
- No blockers for plan 01-04.

---
*Phase: 01-handshake*
*Completed: 2026-08-23*

## Self-Check: PASSED

All 5 created files (`internal/reliable/reliable.go`, `internal/reliable/reliable_test.go`, `internal/ctrlconn/conn.go`, `internal/ctrlconn/conn_test.go`, `session.go`) confirmed present on disk; all 3 task commits (`0c6d400`, `f3c2b1e`, `bd65325`) confirmed present in `git log --oneline --all`.
