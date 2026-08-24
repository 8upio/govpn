---
phase: 02-tunnel-up
plan: 02
subsystem: api
tags: [go, openvpn, push-reply, ip-pool, tunnel-ip, tls, docker-interop]

# Dependency graph
requires:
  - phase: 02-01
    provides: "internal/keyderiv (Key Method 2 key derivation), Session.dataKeys, Session.tlsReader (the buffered TLS reader plan 02-02's PUSH_REQUEST/PUSH_REPLY continuation reads from), performKeyMethod2Exchange"
provides:
  - "push.go: readControlString/writeControlString (plain NUL-terminated framing) and buildPushReply — the byte-exact PUSH_REPLY option assembly"
  - "ippool.go: mutex-guarded ipPool — sequential first-free IPv4 allocation, server = first host IP, network/broadcast reserved, ErrPoolExhausted sentinel, 24-bit peer-id cap, no persistence"
  - "ovpn.go: performPushExchange — the real PUSH_REQUEST/PUSH_REPLY exchange (supersedes 02-01's diagnostic-only watchForPushRequest), and the relocated OnSession callsite (D-08)"
  - "session.go: Session.AssignedIP()/PeerID() accessors, Close releasing the assigned IP/peer-id back to the pool"
  - "a live-client gate (test/interop) proving a real OpenVPN 2.6.14 client receives its pushed tunnel IP and reports Initialization Sequence Completed, across all three interop scenarios"
affects: [02-03, 02-04]

# Actuals (#2632)
actuals:
  tokens: 19684
  tasks: 3
  commits: 4

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "push.go mirrors internal/keyderiv's own C-reference citation-header convention (line-numbered src/openvpn/<file>.c references) for the PUSH_REQUEST/PUSH_REPLY framing and option assembly"
    - "ipPool represents the pool as a flattened uint32 host-address space (base + offset) rather than per-octet byte arithmetic, so allocation crosses octet boundaries (e.g. 10.9.0.255 -> 10.9.1.0) for free, without any hand-rolled carry logic — the exact pitfall RESEARCH.md's Assumption A1 flags this whole area for"
    - "performPushExchange takes io.Writer, not *tls.Conn, even though runHandshake's only real caller passes a *tls.Conn — narrowing the parameter to the interface it actually needs unlocks a fully deterministic unit test of its buffered-retransmit loop (TestPerformPushExchangeAnswersBufferedRetransmitWithSameIP) that doesn't depend on live network timing to land two TLS records in one read"
    - "test client harness (ovpn_test.go): a synthetic client drives its initial hard reset through ctrlconn.Conn's own SendReset (not a hand-crafted raw packet sent outside the Conn's bookkeeping) so the client's send-side packet-ID counter for its first REAL write (the TLS ClientHello) starts at 1, not 0 again — otherwise it silently duplicates, from the server's recvRel's point of view, the packet ID already consumed by the hard reset itself, corrupting the reassembled TLS byte stream"

key-files:
  created:
    - push.go
    - push_test.go
    - ippool.go
    - ippool_test.go
  modified:
    - ovpn.go
    - session.go
    - ovpn_test.go
    - test/interop/server/main.go
    - test/interop/interop_test.go
    - test/interop/decode.go

key-decisions:
  - "Session.PeerID() uint32 exported accessor added, beyond D-07's literal AssignedIP()/PeerCN()/ConnectionState() surface — test/interop/server/main.go (an external package) needs to read the allocated peer-id to build its PASS line's peer_id= field, exactly the same rationale 02-01-SUMMARY.md already recorded for Session.PushRequestSeen(). (Rule 2 — missing critical: the plan's own acceptance criterion 'the clean-small scenario's server output carries assigned_ip= and peer_id= on the structured PASS line' is otherwise unreachable across the package boundary.)"
  - "runHandshake's watchForPushRequest goroutine (02-01's diagnostic-only PUSH_REQUEST watcher) was removed rather than left alongside the new real exchange. It read from the SAME sess.tlsReader that performPushExchange now needs to read synchronously and reply on, and bufio.Reader is not safe for concurrent readers — running both would race. Replacing it with the real, synchronous exchange is what this plan's own action text asks for ('extend runHandshake's continuation'); the removal itself wasn't spelled out verbatim but is the only way to satisfy the instruction without introducing a data race."
  - "sess.doneCh (which enforceHandshakeWindow watches) now closes after the WHOLE bring-up sequence (Handshake + Key Method 2 + push exchange), not immediately after Handshake() returns as in 02-01. This is what D-08 requires structurally: a session that completes TLS but stalls before requesting its configuration must still be reaped by the handshake window, which needs doneCh to stay open through that stall. Task 3's own acceptance criteria (TestOnSessionDoesNotFireWhenPushNeverArrives) name this explicitly as 'the desired behavior, not a regression.'"
  - "test/interop/server/main.go's Config gained Network (10.8.0.0/24, throwaway) and Cipher ('AES-256-GCM') — previously absent from the harness's Config entirely. Without a configured Network, performPushExchange has no pool and every session fails at the push exchange; the harness could never have reached this plan's own PASS-line acceptance criteria without this addition. (Rule 3 — blocking: the harness cannot exercise the very feature this plan built without it.)"

patterns-established:
  - "push.go's readControlString/writeControlString/buildPushReply and ippool.go's ipPool are the stable interfaces plan 02-03 builds on: internal/datachan's P_DATA_V2 routing table is keyed on the SAME peer-id ipPool.allocate() hands out (D-16), and Session.assignedIP/peerID are already populated by the time plan 02-03's Read/Write become real."

requirements-completed: [CTRL-05, SESS-02, SESS-03]

coverage:
  - id: D1
    description: "buildPushReply produces the byte-exact PUSH_REPLY option list (ifconfig/topology subnet/peer-id/cipher/ping 10/ping-restart 60) the reference server actually transmits, terminated by exactly one NUL byte"
    requirement: "CTRL-05"
    verification:
      - kind: unit
        ref: "push_test.go#TestPushReplyStringExact"
        status: pass
      - kind: unit
        ref: "push_test.go#TestPushReplyNetmaskFromPrefix"
        status: pass
      - kind: unit
        ref: "push_test.go#TestPushReplyEndsWithSingleNUL"
        status: pass
      - kind: integration
        ref: "test/interop/interop_test.go#assertTunnelUp (all three scenarios)"
        status: pass
    human_judgment: false
  - id: D2
    description: "readControlString frames plain NUL-terminated PUSH_REQUEST/PUSH_REPLY strings correctly and rejects an unterminated flood without unbounded growth (T-02-09)"
    requirement: "CTRL-05"
    verification:
      - kind: unit
        ref: "push_test.go#TestReadPushRequestAcceptsExactLiteral"
        status: pass
      - kind: unit
        ref: "push_test.go#TestReadPushRequestRejectsUnterminatedFlood"
        status: pass
    human_judgment: false
  - id: D3
    description: "The tunnel-IP pool reserves the first host IP for the server, allocates clients sequentially first-free, skips network/broadcast, releases on close for immediate reuse, and survives 200 concurrent allocations under -race with zero duplicates (T-02-08, T-02-10)"
    requirement: "SESS-03"
    verification:
      - kind: unit
        ref: "ippool_test.go#TestPoolServerTakesFirstHostIP"
        status: pass
      - kind: unit
        ref: "ippool_test.go#TestPoolSkipsNetworkAndBroadcast"
        status: pass
      - kind: unit
        ref: "ippool_test.go#TestPoolSequentialFirstFree"
        status: pass
      - kind: unit
        ref: "ippool_test.go#TestPoolExhaustionReturnsTypedError"
        status: pass
      - kind: unit
        ref: "ippool_test.go#TestPoolConcurrentAllocationNeverDuplicates"
        status: pass
      - kind: unit
        ref: "ippool_test.go#TestPoolLargeNetwork"
        status: pass
    human_judgment: false
  - id: D4
    description: "Two sessions whose verified CommonName is identical still receive distinct tunnel addresses and peer-ids (D-04, reference --duplicate-cn semantics)"
    requirement: "SESS-03"
    verification:
      - kind: unit
        ref: "ovpn_test.go#TestDuplicateCNGetsDistinctIPs"
        status: pass
    human_judgment: false
  - id: D5
    description: "Config.OnSession fires exactly once per client, only after Key Method 2 and the PUSH_REQUEST/PUSH_REPLY exchange both complete, with Session.AssignedIP() already populated (D-08) — proven over a real, live TLS handshake, not merely asserted structurally"
    requirement: "SESS-02"
    verification:
      - kind: unit
        ref: "ovpn_test.go#TestOnSessionFiresAfterPushReply"
        status: pass
      - kind: unit
        ref: "ovpn_test.go#TestOnSessionFiresExactlyOnce"
        status: pass
      - kind: unit
        ref: "ovpn_test.go#TestPerformPushExchangeAnswersBufferedRetransmitWithSameIP"
        status: pass
      - kind: unit
        ref: "ovpn_test.go#TestOnSessionDoesNotFireWhenPushNeverArrives"
        status: pass
      - kind: unit
        ref: "ovpn_test.go#TestOnSessionPanicStillRecovered"
        status: pass
      - kind: unit
        ref: "ovpn_test.go#TestCloseIsIdempotentAfterTunnelUp"
        status: pass
    human_judgment: false
  - id: D6
    description: "A real, unmodified OpenVPN 2.6.14 client requests its configuration, receives the pushed tunnel address, and reports Initialization Sequence Completed with its tun interface configured with that address — proven live across all three interop scenarios (clean-small, clean-large, lossy-large), including through genuine packet loss/retransmission"
    requirement: "CTRL-05"
    verification:
      - kind: integration
        ref: "test/interop/interop_test.go#TestInteropScenarios (assertTunnelUp, assertKeyExchangeCompleted)"
        status: pass
      - kind: other
        ref: "live docker interop run (go run ./cmd/gentestpki -out test/interop/pki -profile large && go test -tags interop -count=1 -timeout 900s ./test/interop/ -run TestInteropScenarios -v): all 3 scenarios PASS, clean-small server PASS line 'assigned_ip=10.8.0.2 peer_id=0', client log shows 'Initialization Sequence Completed' and 'net_addr_v4_add: 10.8.0.2/24 dev tun0'"
        status: pass
    human_judgment: false

duration: ~2h
completed: 2026-08-24
status: complete
---

# Phase 2 Plan 2: PUSH_REQUEST/PUSH_REPLY and Tunnel IP Assignment Summary

**A byte-exact PUSH_REPLY exchange with a mutex-guarded sequential-first-free IPv4 pool, live-verified end to end against a real OpenVPN 2.6.14 client that receives its pushed tunnel address and reports `Initialization Sequence Completed` across all three interop scenarios.**

## Performance

- **Duration:** ~2h
- **Completed:** 2026-08-24
- **Tasks:** 3
- **Files modified:** 10 (4 created, 6 modified)

## Accomplishments

- `push.go`: `readControlString`/`writeControlString` (plain NUL-terminated framing, bounded at 1024 bytes against an unterminated flood — T-02-09) and `buildPushReply`, producing the reference's exact `PUSH_REPLY,ifconfig <ip> <netmask>,topology subnet,peer-id <n>,cipher AES-256-GCM,ping 10,ping-restart 60` payload
- `ippool.go`: `ipPool` — a mutex-guarded, in-memory-only allocator over a flattened uint32 host-address space (no per-octet arithmetic pitfalls at range boundaries), server = first host IP, sequential first-free client allocation, `ErrPoolExhausted` sentinel, 24-bit peer-id cap and reuse, IPv4-only validated at construction
- `ovpn.go`: `runHandshake`'s continuation now runs `performPushExchange` after Key Method 2 — reading the client's PUSH_REQUEST, allocating from `s.pool`, answering buffered retransmits with the SAME already-assigned IP/peer-id rather than reallocating (T-02-06), and only then calling `s.callOnSession(sess)` (D-08). `sess.doneCh` now closes after the whole bring-up sequence, so `enforceHandshakeWindow` still reaps a session that completes TLS but never requests its configuration.
- `session.go`: `Session.AssignedIP()`/`PeerID()` accessors (defensive-copy for the IP), `Close` releasing the assigned IP/peer-id back to the pool inside the existing `stopOnce.Do`
- Live-verified against a real OpenVPN 2.6.14 client across all three interop scenarios (clean-small, clean-large, lossy-large): the client receives `PUSH_REPLY,ifconfig 10.8.0.2 255.255.255.0,topology subnet,peer-id 0,cipher AES-256-GCM,ping 10,ping-restart 60`, configures `tun0` with `10.8.0.2/24`, and logs `Initialization Sequence Completed`; the server's PASS line reads `km2=ok push_request=seen assigned_ip=10.8.0.2 peer_id=0`

## Task Commits

1. **Task 1: A real OpenVPN 2.6 client brings its tunnel interface up** - `d8c3213` (feat)
   - Follow-up fix (Rule 1, bug this task's own new behavior exposed): `5869732` (fix) — see Deviations
2. **Task 2: The tunnel-IP pool allocates, releases and never double-assigns** - `38afa0e` (test)
3. **Task 3: `Session.AssignedIP()` is populated before the embedder ever sees the Session** - `d839d7f` (test)

_Note: Task 1 is `type="tracer"` — committed, then its own `<verify>` re-run end-to-end (autonomous worktree execution, no interactive user to checkpoint to, matching 02-01's own precedent for this phase) before expanding into Tasks 2 and 3. Tasks 2 and 3 are `tdd="true"`: Task 1 already built the real `ipPool` and `performPushExchange`/`AssignedIP()` implementations as part of the tracer's own end-to-end `<behavior>`, so Tasks 2/3's own job was writing the dedicated test suites against already-complete production code, not driving new implementation from a failing test — the same legitimate "no separate feat commit" outcome 02-01-SUMMARY.md documents for its own Task 2, reinforced here by every acceptance criterion (200-goroutine concurrent allocation, live handshake timing gates, deterministic retransmit proof) genuinely exercising the code, not merely re-confirming it compiles._

## Files Created/Modified

- `push.go` - `readControlString`, `writeControlString`, `buildPushReply`, `maxControlStringLen`
- `push_test.go` - byte-exact PUSH_REPLY assertion, netmask-from-prefix, single-NUL-termination, control-string framing (accept/reject/flood-bound)
- `ippool.go` - `ipPool`, `newIPPool`, `allocate`/`release`/`serverIP`, `ErrPoolExhausted`, `maxPeerID`
- `ippool_test.go` - server-takes-first-host-IP, network/broadcast skipping, first-free reuse, idempotent release, typed exhaustion, 200-goroutine concurrency under `-race`, `/16` octet-boundary crossing, peer-id distinctness/cap, construction-time validation
- `ovpn.go` - `runHandshake` restructured (doneCh timing, `performPushExchange`, relocated `OnSession` callsite); `Server.pool` field and its `Serve`-time construction; `Config.Network`/`Config.Cipher`/`Config.OnSession` doc comments updated; `watchForPushRequest` removed (superseded)
- `session.go` - `Session.assignedIP`/`peerID` fields, `AssignedIP()`/`PeerID()` accessors, `Close` releases both; type doc comment updated
- `ovpn_test.go` - `TestDuplicateCNGetsDistinctIPs`; a synthetic mutual-TLS test client (`testPushClient`, `testHandshakeTLSConfig`) driving a real handshake+KM2+push exchange without Docker, and the full `TestOnSession*`/`TestAssignedIP*`/`TestCloseIsIdempotentAfterTunnelUp` suite
- `test/interop/server/main.go` - `Config.Network`/`Config.Cipher` set; PASS line gains `assigned_ip=`/`peer_id=`
- `test/interop/interop_test.go` - `assertTunnelUp` (Initialization Sequence Completed + pushed address appearing in the client's own tun-configuration log)
- `test/interop/decode.go` - `decodeCapture` skips data-channel opcodes (see Deviations)

## Decisions Made

- **`Session.PeerID()` exported accessor added.** D-07 names `AssignedIP()`/`PeerCN`/`ConnectionState()` as the locked public surface, but `test/interop/server/main.go` — an external package — needs the allocated peer-id to satisfy this plan's own acceptance criterion (`peer_id=` on the PASS line). Same rationale 02-01-SUMMARY.md already recorded for `PushRequestSeen()`.
- **`watchForPushRequest` removed, not left running alongside the real exchange.** It read from the same `sess.tlsReader` `performPushExchange` now reads and replies on synchronously; `bufio.Reader` is not safe for two concurrent readers, so keeping both would be a data race.
- **`sess.doneCh` close moved to the end of the whole bring-up sequence.** D-08 requires the handshake window to keep covering a session that completes TLS but stalls before requesting its configuration; Task 3's own acceptance criteria name this "the desired behavior, not a regression."
- **`test/interop/server/main.go` gained `Config.Network`/`Config.Cipher`.** Without a configured `Network`, `performPushExchange` has no pool and every session fails the push exchange — the harness could not otherwise reach this plan's own PASS-line acceptance criteria.
- **`performPushExchange` takes `io.Writer`, not `*tls.Conn`.** Narrowing to the interface it actually uses (a single `Write` call) is behavior-neutral for the real caller (`*tls.Conn` already satisfies `io.Writer`) and unlocks a fully deterministic unit test of the buffered-retransmit loop, avoiding a live-network-timing-dependent test (see Issues Encountered).
- **Test-only mutual TLS uses a real, throwaway CA rather than `InsecureSkipVerify`.** These push-exchange tests are this package's first to drive an actual `tls.Client(...).Handshake()` against a live `srv.Serve` loop; skipping verification here would be a real, avoidable weakening rather than a harmless shortcut (flagged by the project's own security-guidance tooling during review), so a CA + DNSNames-bearing leaf (mirroring `internal/ctrlconn`'s own `genTestCerts` precedent) is used instead.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] `decodeCapture` skipped data-channel opcodes before tls-crypt-unwrapping them**
- **Found during:** Task 1's own tracer `<verify>` re-run (`make interop`-equivalent)
- **Issue:** `decodeCapture` assumed every captured UDP payload on the tunnel port was a tls-crypt-wrapped control packet — true throughout Phase 1, since the tunnel never came up and no data-channel traffic ever existed on the wire. This task's own change (a real client now completes PUSH_REPLY and immediately starts sending `P_DATA_V2` keepalive traffic, which is never tls-crypt wrapped) broke that assumption: the decoder errored on the first such packet with "tls-crypt authentication failed", failing `clean-large`/`lossy-large`'s `assertCertificateFlightFragmented` and `logRetransmissionEvidence`.
- **Fix:** Skip `OpDataV1`/`OpDataV2` payloads before attempting the tls-crypt unwrap, rather than treating them as control packets. No consumer of `decodeCapture`'s output ever inspected data-channel entries, so filtering them out is transparent.
- **Files modified:** `test/interop/decode.go`
- **Verification:** Live interop run — all three scenarios PASS, including fragmentation and retransmission-evidence assertions
- **Committed in:** `5869732` (fix, immediately after Task 1's `d8c3213`)

---

**Total deviations:** 1 auto-fixed (1 bug this task's own new behavior exposed in existing test tooling). No scope creep — the fix is entirely confined to test infrastructure, not production code.

## Issues Encountered

- **Test-harness-only bug: client-side packet-ID discontinuity across a hand-crafted hard reset.** Building the synthetic mutual-TLS test client for Task 3 (`ovpn_test.go`'s `testPushClient`), an early version sent the client's initial hard reset as a hand-crafted raw packet (outside any `ctrlconn.Conn`'s own bookkeeping — the same pattern this package's existing `TestHardResetRoundTrip` already uses, but that test never continues past the raw reply into real `ctrlconn.Conn` traffic). Constructing a fresh `ctrlconn.Conn` afterward for the TLS handshake meant its own send-side packet-ID counter started at 0 again for its first real write (the TLS ClientHello) — duplicating, from the server's `recvRel`'s point of view, the packet ID already consumed by the hard reset itself. The server's receive window treated the ClientHello as an already-seen retransmit and never delivered its payload, producing `tls: first record does not look like a TLS handshake` and a 5-minute `Handshake()` hang (diagnosed via a temporary debug harness with wire-level tracing, since fixed and removed). Fixed by routing the initial hard reset through the same `ctrlconn.Conn`'s own `SendReset` method instead, keeping packet-ID bookkeeping consistent end to end — this is exactly what the SERVER's own `handleDatagram`/`DeliverAndRespond` already does, and confirmed by `grep` that no receiver in this codebase validates the `RemoteSessionID` field, so leaving it unlearned (zero) on the client side is harmless. This was caught and fixed before any test commit — no production code was affected.
- **Flaky test redesign: `TestOnSessionFiresExactlyOnce`'s original retransmit assertion depended on live network timing** (two `PUSH_REQUEST` writes landing in the same buffered read before the server's first reply) and lost that race once under `go test -race`, hanging for the test binary's default 10-minute timeout before the harness killed it. Redesigned into two tests: `TestOnSessionFiresExactlyOnce` now asserts the simpler, deterministic single-request case (exactly one allocation, exactly one `OnSession` call) over a live handshake, and a new `TestPerformPushExchangeAnswersBufferedRetransmitWithSameIP` calls `performPushExchange` directly with both `PUSH_REQUEST` occurrences pre-buffered, deterministically proving the T-02-06 "answer a buffered retransmit with the same IP" claim without any network-timing dependency. Enabled by the `io.Writer` refactor documented in Decisions Made.

## User Setup Required

None - no external service configuration required. Docker Desktop must be running locally for the interop harness (already an established Environment Availability item from Phase 1); confirmed running and used for two live 3-scenario interop runs during this plan's execution.

## Next Phase Readiness

- `Session.dataKeys` (from 02-01) and `Session.assignedIP`/`peerID` (this plan) are both live by the time `Config.OnSession` fires — plan 02-03's `internal/datachan.Wrapper` and its `P_DATA_V2` routing table (keyed on the same peer-id `ipPool.allocate()` already hands out, D-16) have everything they need without any further Session-surface changes.
- `Session.Read`/`Write` remain plan 02-01's placeholders (`io.EOF` / "not implemented"); their doc comments now point at plan 02-03 specifically rather than "Phase 2" generically. Not a stub blocking this plan's own goal — the plan's stated scope stops at tunnel-up, and the raw IP-packet path is explicitly plan 02-03's job (RESEARCH.md, CONTEXT.md).
- `test/interop/server/main.go`'s harness Config now carries a real `Network`/`Cipher`; plan 02-03's own interop verification (ping/data round-trip) can reuse the same `10.8.0.0/24` range and `assigned_ip=`/`peer_id=` diagnostic fields already wired into the PASS line.
- No blockers for plan 02-03.

---
*Phase: 02-tunnel-up*
*Completed: 2026-08-24*

## Self-Check: PASSED

All 4 created files (`push.go`, `push_test.go`, `ippool.go`, `ippool_test.go`) confirmed present on disk; all 5 commits (`d8c3213`, `5869732`, `38afa0e`, `d839d7f`, `f9dd17e`) confirmed present in `git log --oneline --all`.
