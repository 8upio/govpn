---
phase: 02-tunnel-up
plan: 03
subsystem: crypto
tags: [go, openvpn, aes-256-gcm, data-channel, replay-window, keepalive, docker-interop]

# Dependency graph
requires:
  - phase: 02-01
    provides: "internal/keyderiv (Key Method 2 key derivation), Session.dataKeys (*keyderiv.Key2), Key2.ServerSlots() — the inverted per-direction cipher keys and implicit IVs this plan's Wrapper consumes directly"
  - phase: 02-02
    provides: "ippool.go's peer-id allocation (ipPool.allocate), Session.assignedIP/peerID, the performPushExchange callsite this plan's data-channel wrapper construction and keepalive-start hook into, and the relocated OnSession callsite (D-08)"
provides:
  - "internal/datachan: AES-256-GCM Wrapper (Seal/Open, tag-before-ciphertext wire reorder, concatenated nonce), a 64-wide sliding replay window (independent instance, never shared with internal/tlscrypt's or the reliability layer's own sequence spaces), and ping-magic absorption/emission (IsPing/SealPing/ErrPingAbsorbed)"
  - "ovpn.go: the opcode-class branch in handleDatagram (data packets routed by peer-id via Server.dataSessions, never the control-channel sessionKey table) and the data-channel Wrapper/keepalive-goroutine construction at the same point performPushExchange allocates the tunnel IP/peer-id"
  - "session.go: real Session.Read/Write (datagram-shaped, D-05 — Read retains an oversized packet in pendingRead rather than truncating or dropping it), handleDataPacket (the decrypt path feeding ipInbound), and the per-session keepalive goroutine (startKeepalive/runKeepalive/emitPing, driven by an injected tick channel for tests)"
  - "a live-client gate (test/interop) proving a real OpenVPN 2.6.14 client's ping of the server's pushed tunnel IP round-trips through Session.Read/Write with 0% loss, across all three interop scenarios"
affects: [02-04]

# Actuals (#2632)
actuals:
  tokens: 21557
  tasks: 3
  commits: 3

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "internal/datachan mirrors internal/tlscrypt's package-doc citation-header convention and its independent-replay-window-per-package discipline, but its key-direction input (keyderiv.Key2.ServerSlots()) and its Seal/Open tag-before-ciphertext wire reorder are unique to the data channel — never pattern-matched from tlscrypt's own Wrap/Unwrap shape"
    - "Server.dataSessions map[uint32]*Session is a second, peer-id-keyed routing table alongside Server.sessions{addr,sid} — handleDatagram branches on opcode class (control vs P_DATA_V1/V2) before either table is consulted, since data packets carry no 8-byte session ID at the offset the control-channel table is keyed on"
    - "The per-session keepalive timer (session.go) is driven by an injected tick channel, not a Clock interface — the constructor-supplied-channel half of the same pattern internal/reliable's own injected-Clock established, chosen here because the timer's own logic is 'one tick, one ping' rather than duration-comparison arithmetic"
    - "pingIntervalSeconds (ovpn.go) is the single constant both push.go's buildPushReply (the pushed `ping N` option) and session.go's keepalive goroutine (the emission period) read from, so the pushed and emitted schedules are structurally unable to drift apart"

key-files:
  created:
    - internal/datachan/datachan.go
    - internal/datachan/datachan_test.go
    - internal/datachan/replay.go
    - internal/datachan/replay_test.go
    - internal/datachan/ping.go
    - internal/datachan/ping_test.go
  modified:
    - ovpn.go
    - session.go
    - push.go
    - ovpn_test.go
    - test/interop/server/main.go
    - test/interop/interop_test.go
    - test/interop/entrypoint.sh
    - test/interop/Dockerfile

key-decisions:
  - "Session.Read retains an oversized packet in a new pendingRead field rather than dropping it (D-05 explicitly leaves this choice to the implementation). The plan's own Task 1 <behavior> text (\"not truncated and not consumed-and-lost\") reads as requiring retention, not drop — a subsequent Read with a large-enough buffer still receives the exact packet, undamaged."
  - "TestReplayLargeJumpResetsWindow's literal expected outcome (accepting packet ID 100000 after 100 should make 99999 REJECTED) was corrected to match the actual, already-shipped, Phase-1-precedented sliding-window algorithm the plan's own action text mandates copying verbatim from internal/tlscrypt.replayWindow: after a large jump, the bitmap resets around the NEW highest, so 99999 (one below the new highest, within the 64-wide re-anchored window and never actually seen) is correctly ACCEPTED, not rejected — rejecting it would require breaking the correctly-functioning algorithm to satisfy an internally inconsistent test expectation. The corrected test still proves the bitmap genuinely reset (a value 65 below the new highest is rejected as below the new floor) rather than merely accepting everything after a jump."
  - "postHandshakeSurvival (test/interop/server/main.go) raised from 2s to 5s, and the interop client's ping uses -i 0.2 (not the default 1s interval): the original 2-second window was sized for Phase 1's own \"prove KM2 traffic doesn't disturb the session\" purpose and left no room for tun0 to come up and 4 real ICMP round trips to complete before the server's postHandshakeSurvival elapsed and pulled the whole compose run down via --abort-on-container-exit."
  - "test/interop/entrypoint.sh now runs the real OpenVPN client in the background (was foreground) so the script itself can drive a ping through the tunnel once tun0 is up, then waits on the client process; this is the only way to add live ping-through-the-tunnel behavior without forking the client into a second container."

patterns-established:
  - "internal/datachan's Wrapper/replayWindow/ping constants are the stable interface later phases build on: Session.dataWrapper, Server.dataSessions, and the keepalive goroutine are all now live before Config.OnSession fires, so Phase 3's userspace netstack (NET-03's real ICMP responder) can plug directly into Session.Read/Write with no further Session-surface changes."

requirements-completed: [DATA-01, DATA-02, DATA-03, SESS-02]

coverage:
  - id: D1
    description: "P_DATA_V2 packets encrypt/decrypt with AES-256-GCM using the exact reference wire layout: tag-before-ciphertext, concatenated packetID||implicitIV nonce (never XOR), header-only AAD, and the data channel's own mirror-opposite key-direction convention (keyderiv.Key2.ServerSlots()) — verified against an independently-constructed direct aead.Seal call and a literal expected nonce, not merely self-consistency"
    requirement: "DATA-01"
    verification:
      - kind: unit
        ref: "internal/datachan/datachan_test.go#TestSealLayout"
        status: pass
      - kind: unit
        ref: "internal/datachan/datachan_test.go#TestSealAADIsHeaderOnly"
        status: pass
      - kind: unit
        ref: "internal/datachan/datachan_test.go#TestNonceIsConcatenationNotXor"
        status: pass
      - kind: unit
        ref: "internal/datachan/datachan_test.go#TestOpenRejectsShortPacket"
        status: pass
      - kind: unit
        ref: "internal/datachan/datachan_test.go#TestOpenRejectsWrongPeerID"
        status: pass
      - kind: unit
        ref: "internal/datachan/datachan_test.go#TestOpenRejectsTamperedTag"
        status: pass
      - kind: unit
        ref: "internal/datachan/datachan_test.go#TestPacketIDStartsAtOne"
        status: pass
      - kind: integration
        ref: "test/interop/interop_test.go#assertDataChannelRoundTrip (clean-small scenario)"
        status: pass
      - kind: other
        ref: "live docker interop run (make interop): all 3 scenarios PASS; clean-small client log '4 packets transmitted, 4 received, 0% packet loss'; server PASS line 'ping_rx=4 ping_tx=4'"
        status: pass
    human_judgment: false
  - id: D2
    description: "A 64-wide sliding replay window (independent instance, matching DEFAULT_SEQ_BACKTRACK) drops duplicate and below-floor data-channel packet IDs, consulted strictly after the AEAD tag verifies — proven by a state assertion, not a comment — and is independent of tls-crypt's own window"
    requirement: "DATA-02"
    verification:
      - kind: unit
        ref: "internal/datachan/replay_test.go#TestReplayAcceptsMonotonic"
        status: pass
      - kind: unit
        ref: "internal/datachan/replay_test.go#TestReplayRejectsExactDuplicate"
        status: pass
      - kind: unit
        ref: "internal/datachan/replay_test.go#TestReplayAcceptsInWindowReorder"
        status: pass
      - kind: unit
        ref: "internal/datachan/replay_test.go#TestReplayRejectsBelowWindowFloor"
        status: pass
      - kind: unit
        ref: "internal/datachan/replay_test.go#TestReplayLargeJumpResetsWindow"
        status: pass
      - kind: unit
        ref: "internal/datachan/datachan_test.go#TestAuthFailureDoesNotTouchWindow"
        status: pass
      - kind: unit
        ref: "internal/datachan/datachan_test.go#TestDataChannelWindowIndependentOfTLSCrypt"
        status: pass
      - kind: unit
        ref: "internal/datachan/datachan_test.go#TestTamperHasTeeth"
        status: pass
      - kind: unit
        ref: "internal/datachan/datachan_test.go#TestConcurrentSealNeverDuplicatesPacketID"
        status: pass
      - kind: unit
        ref: "internal/datachan/datachan_test.go#TestPacketIDFailsClosedAtMax"
        status: pass
    human_judgment: false
  - id: D3
    description: "The 16-byte ping magic is absorbed on the decrypted plaintext and never reaches Session.Read's caller; the server emits its own pings on the same pushed 10-second schedule over the encrypted data path, driven by an injected tick channel so the tests run in milliseconds, and the keepalive goroutine exits cleanly on Close"
    requirement: "DATA-03"
    verification:
      - kind: unit
        ref: "internal/datachan/ping_test.go#TestPingMagicBytesExact"
        status: pass
      - kind: unit
        ref: "internal/datachan/ping_test.go#TestPingIsAbsorbedNotDelivered"
        status: pass
      - kind: unit
        ref: "internal/datachan/ping_test.go#TestPingIsEncryptedLikeAnyPacket"
        status: pass
      - kind: unit
        ref: "ovpn_test.go#TestPingNeverReachesSessionRead"
        status: pass
      - kind: unit
        ref: "ovpn_test.go#TestServerEmitsPingOnSchedule"
        status: pass
      - kind: unit
        ref: "ovpn_test.go#TestPingTimerStopsOnClose"
        status: pass
      - kind: unit
        ref: "ovpn_test.go#TestPingEmissionDoesNotConsumeSessionWriteQuota"
        status: pass
    human_judgment: false
  - id: D4
    description: "Each connected client's Session is a real io.ReadWriteCloser for raw IP packets: Write seals and sends exactly one full IP packet per call, Read delivers exactly one full IP packet per call, and a too-small Read buffer returns an error and retains the packet (not truncated, not silently lost) for a subsequent larger Read"
    requirement: "SESS-02"
    verification:
      - kind: unit
        ref: "ovpn_test.go#TestSessionReadWriteDatagramSemantics"
        status: pass
      - kind: other
        ref: "live docker interop run (make interop): the harness's ICMP echo responder (test/interop/server/main.go's startICMPResponder) reads/writes exclusively through Session.Read/Write, proving the public API carries genuine encrypted traffic against a real client"
        status: pass
    human_judgment: false

duration: ~55min
completed: 2026-08-24
status: complete
---

# Phase 2 Plan 3: AES-256-GCM Data Channel, Replay Window, and Keepalive Summary

**A real, live-verified encrypted tunnel: AES-256-GCM P_DATA_V2 Seal/Open with the reference's exact tag-before-ciphertext wire order and mirror-opposite key-direction convention, a 64-wide independent replay window, and library-internal ping keepalive — proven end to end by a real OpenVPN 2.6.14 client pinging the server's tunnel IP with 0% loss through `Session.Read`/`Write`.**

## Performance

- **Duration:** ~55 min
- **Completed:** 2026-08-24
- **Tasks:** 3
- **Files modified:** 14 (6 created, 8 modified)

## Accomplishments

- `internal/datachan`: `Wrapper.Seal`/`Open` implementing the P_DATA_V2 wire format byte-exactly — `[opcode+keyid(1B)][peer-id(3B)][packet-id(4B)][tag(16B)][ciphertext(N)]`, tag written before ciphertext (the reorder from Go's own `cipher.AEAD.Seal`/`Open` convention isolated to one seam each in `Seal`/`Open`), and the 12-byte nonce built as the literal concatenation `packetID(4)‖implicitIV(8)` — never a bitwise XOR, asserted against a literal expected nonce so an XOR implementation would fail the test
- `internal/datachan/replay.go`: a 64-wide sliding anti-replay window (`DEFAULT_SEQ_BACKTRACK`), a deliberate independent copy of `internal/tlscrypt`'s own `replayWindow`/`accept`, wired into `Open` strictly after the AEAD tag verifies — proven with a state assertion (tamper, then re-deliver the untampered packet with the same ID, confirm it's still accepted) rather than a comment
- `internal/datachan/ping.go`: the 16-byte ping keepalive magic (`IsPing`/`PingSize`/`SealPing`), absorbed on the decrypted plaintext inside `Open` (`ErrPingAbsorbed`) — never surfacing to `Session.Read`'s caller even during the very first live client interaction
- `ovpn.go`: `handleDatagram` now branches on opcode class (control vs `P_DATA_V1`/`P_DATA_V2`) **before** the fixed-offset control-channel session-ID parse — data packets route through a new peer-id-keyed `Server.dataSessions` table instead; the data-channel `Wrapper` and the per-session keepalive goroutine are both constructed at the same point `performPushExchange` allocates the tunnel IP/peer-id, live before `OnSession` ever fires (D-08)
- `session.go`: `Read`/`Write` are real — `Write` seals and sends one full IP packet per call over the same `net.PacketConn` the control channel uses; `Read` delivers one full decrypted IP packet per call and, on a too-small buffer, retains the packet in `pendingRead` for a subsequent larger `Read` rather than truncating or losing it (D-05); the keepalive goroutine (`startKeepalive`/`runKeepalive`/`emitPing`) emits pings directly through `dataWrapper`/`srv.pc`, never through the public `Write` path, and exits cleanly on `Close`
- Live-verified against a real OpenVPN 2.6.14 client across all three interop scenarios: the client pings the server's pushed tunnel IP (`10.8.0.1`) once `tun0` is up and reports `4 packets transmitted, 4 received, 0% packet loss`; the server's harness ICMP echo responder (driven exclusively through `Session.Read`/`Write`) answers, and the PASS line reads `ping_rx=4 ping_tx=4`

## Task Commits

1. **Task 1: An encrypted ping from a real client round-trips through Session.Read and Session.Write** - `cb76161` (feat)
2. **Task 2: Replayed and out-of-window data packets are dropped, and the assertion has teeth** - `13edbfb` (test)
3. **Task 3: Keepalive pings are answered inside the library and never reach the Session consumer** - `3789f36` (feat)

_Note: Task 1 is `type="tracer"` — committed, then its own `<verify>` (including the full live `make interop` run) re-run end-to-end before expanding into Tasks 2 and 3, matching 02-01's and 02-02's own precedent for this phase (autonomous worktree execution, no interactive user to checkpoint to). Tasks 2 and 3 are `tdd="true"`: Task 1 already implemented the production code each task's own tests exercise (the replay window's call site and the ping guard's structural shape were sketched in Task 1's own action text as "leave the call site in place" / "minimal guard"), so Tasks 2/3's job was completing that production code alongside writing their dedicated test suites — the same "no separate feat-only GREEN commit needed" legitimate outcome 02-01-SUMMARY.md and 02-02-SUMMARY.md already document for this phase's own tracer-then-test-task shape._

## Files Created/Modified

- `internal/datachan/datachan.go` - `Wrapper`, `NewWrapper`, `Seal`, `Open`, `SealPing`, wire offset constants, sentinel errors (`ErrShort`, `ErrAuth`, `ErrReplay`, `ErrPacketIDExhausted`, `ErrPingAbsorbed`)
- `internal/datachan/datachan_test.go` - wire-layout, AAD, nonce, tamper, packet-ID, replay-independence, and tls-crypt-independence tests
- `internal/datachan/replay.go` - `replayWindow`, `accept`, `replayWindowSize = 64`
- `internal/datachan/replay_test.go` - monotonic/duplicate/reorder/floor/large-jump replay-window tests
- `internal/datachan/ping.go` - `PingSize`, `pingMagic`, `IsPing`
- `internal/datachan/ping_test.go` - magic-bytes, absorption, and encrypted-like-any-packet tests
- `ovpn.go` - opcode-class branch in `handleDatagram`, `handleDataDatagram`, `Server.dataSessions`, data-channel `Wrapper`/keepalive construction in `performPushExchange`, `ipInboundQueueSize`/`dataChannelKeyID`/`pingIntervalSeconds`/`pingInterval` constants
- `session.go` - real `Read`/`Write`, `pendingRead`, `handleDataPacket`, `startKeepalive`/`runKeepalive`/`emitPing`, `dataWrapper`/`ipInbound` fields, `Close` releasing the `dataSessions` entry
- `push.go` - `buildPushReply` reads `pingIntervalSeconds` instead of a hardcoded `"ping 10"` literal
- `ovpn_test.go` - `TestSessionReadWriteDatagramSemantics`, `TestPingNeverReachesSessionRead`, `TestServerEmitsPingOnSchedule`, `TestPingTimerStopsOnClose`, `TestPingEmissionDoesNotConsumeSessionWriteQuota`, `testSymmetricDataKeys` helper; `TestPerformPushExchangeAnswersBufferedRetransmitWithSameIP` updated to supply a valid `dataKeys`/`dataSessions` now that `performPushExchange` constructs a real data-channel wrapper
- `test/interop/server/main.go` - `startICMPResponder`/`icmpEchoReply`/`internetChecksum` (harness-only ICMP echo, real responder is Phase 3's NET-03), `postHandshakeSurvival` raised 2s→5s, PASS line gains `ping_rx=`/`ping_tx=`
- `test/interop/interop_test.go` - `assertDataChannelRoundTrip` (clean-small scenario), `pingStatsRe`/`pingRxTxRe`
- `test/interop/entrypoint.sh` - runs the real client in the background, waits for `tun0`, pings the server's tunnel IP (`10.8.0.1`) with `-i 0.2`, then waits on the client process
- `test/interop/Dockerfile` - adds `iputils-ping`

## Decisions Made

- **`Session.Read` retains an oversized packet (`pendingRead`) rather than dropping it.** D-05 explicitly leaves this choice to the implementation, but the plan's own Task 1 `<behavior>` text ("not truncated and not consumed-and-lost") reads as requiring retention — a subsequent `Read` with a large-enough buffer still receives the exact packet.
- **`TestReplayLargeJumpResetsWindow`'s literal expectation was corrected**, not the (correctly-functioning, Phase-1-precedented) production algorithm — see Deviations below.
- **`postHandshakeSurvival` raised from 2s to 5s**, and the interop client's ping uses `-i 0.2`. The original 2-second window (sized for Phase 1's own "prove KM2 traffic doesn't disturb the session" purpose) left no room for `tun0` to come up and 4 real ICMP round trips to complete before the server exited and pulled the whole compose run down.
- **`test/interop/entrypoint.sh` runs the real client in the background, not the foreground**, so the script itself can drive a ping through the tunnel once `tun0` is up, then waits on the client process — the only way to add live ping-through-the-tunnel behavior without a second container.
- **`pingIntervalSeconds` is a single shared constant** consumed by both `push.go`'s pushed `ping N` option and `session.go`'s keepalive emission period, so the two schedules cannot drift apart (an explicit ask in the plan's own action text).

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Corrected `TestReplayLargeJumpResetsWindow`'s expected outcome**
- **Found during:** Task 2, first test run
- **Issue:** The plan's own `<behavior>` text asserted that after accepting packet ID 100 then 100000, packet ID 99999 should be *rejected* "as below the new floor." Running the test against the algorithm the plan's own action text mandates copying verbatim (`internal/tlscrypt.replayWindow`'s bit-shift sliding window, already shipped and security-reviewed in Phase 1) showed 99999 is correctly *accepted*: it is only 1 below the new highest, well within the re-anchored 64-wide window, and had never actually been seen — rejecting it would defeat the window's own purpose (legitimate reordering near the new highest) and would require introducing a behavioral difference from the already-proven reference algorithm to satisfy an internally inconsistent test expectation.
- **Fix:** Rewrote the test to assert what the algorithm actually and correctly does: 99999 is accepted (proving in-window reorder still works after a jump) and rejected on a second delivery (duplicate), while a value 65 below the new highest (99935) is rejected as below the new floor — proving the bitmap genuinely reset around the NEW highest rather than either "reject everything" or "accept everything" after a jump.
- **Files modified:** `internal/datachan/replay_test.go`
- **Verification:** `go test -race -run TestReplayLargeJumpResetsWindow ./internal/datachan/` passes; the corrected test still fails loudly if a future change breaks either in-window-reorder acceptance or floor rejection after a jump.
- **Committed in:** `13edbfb` (Task 2 commit)

**2. [Rule 3 - Blocking] Extended `postHandshakeSurvival` and the interop harness's ping timing**
- **Found during:** Task 1's own tracer `<verify>` re-run (first `make interop`-equivalent attempt)
- **Issue:** With the default `ping` interval (1s) and the original 2-second `postHandshakeSurvival`, the client's 4-packet ping (~3-4s at default interval) could not complete before the server exited and `--abort-on-container-exit` tore the whole compose run down — the acceptance criterion (`ping_rx=`/`ping_tx=` greater than zero, client log showing a completed ping) was structurally unreachable at the original timing.
- **Fix:** Raised `postHandshakeSurvival` 2s→5s; changed the client's `ping` invocation to `-i 0.2` (root-permitted fast interval, this container already runs as root for `NET_ADMIN`/tun).
- **Files modified:** `test/interop/server/main.go`, `test/interop/entrypoint.sh`
- **Verification:** Live `make interop` run — all 3 scenarios PASS, clean-small shows `4 packets transmitted, 4 received, 0% packet loss` and `ping_rx=4 ping_tx=4`.
- **Committed in:** `cb76161` (Task 1 commit)

**3. [Rule 3 - Blocking] `TestPerformPushExchangeAnswersBufferedRetransmitWithSameIP` needed a real `dataKeys`/`dataSessions`**
- **Found during:** Task 1, first `go test -race ./...` run after wiring the data-channel `Wrapper` construction into `performPushExchange`
- **Issue:** This pre-existing test (from 02-02) calls `performPushExchange` directly against a `Session{}` with no `dataKeys` set — Task 1's new code unconditionally calls `sess.dataKeys.ServerSlots()` at allocation time, which nil-pointer-panicked. The test also constructed a bare `Server{pool: pool, cfg: ...}` with a nil `dataSessions` map, which the same new code path writes into.
- **Fix:** Gave the test session a real `*keyderiv.Key2` (via `keyderiv.NewKey2`) and gave the test server an initialized `dataSessions` map.
- **Files modified:** `ovpn_test.go`
- **Verification:** `go test -race ./...` passes.
- **Committed in:** `cb76161` (Task 1 commit)

---

**Total deviations:** 3 auto-fixed (1 corrected test expectation that contradicted a mandated-to-copy, already-proven algorithm; 2 blocking fixes needed to make this task's own acceptance criteria reachable). No scope creep — all three are required for the plan's own stated acceptance criteria or for a pre-existing test this plan's new code path affected.

## Issues Encountered

None beyond the three items documented in Deviations, all caught and fixed via the plan's own stated verification commands (`go build ./...`, `go vet ./...`, `go test -race ./...`, live `make interop` runs) before each task's commit.

## User Setup Required

None - no external service configuration required. Docker Desktop must be running locally for the interop harness (already an established Environment Availability item from Phase 1); confirmed running and used for four live 3-scenario interop runs during this plan's execution (one per task iteration plus a final `make interop` confirmation).

## Next Phase Readiness

- `internal/datachan` is a stable, tested building block: `Session.dataWrapper`/`ipInbound` and `Server.dataSessions` are all live by the time `Config.OnSession` fires — plan 02-04's golden-vector work (byte-exact data-channel vectors extracted from a real client capture) can build directly on `Wrapper.Seal`/`Open`'s existing offset constants and error sentinels with no further `internal/datachan` surface changes.
- `Session` is now a genuine `io.ReadWriteCloser` for raw IP packets, live-verified against a real client — Phase 3's userspace netstack (`NET-03`'s real, in-process ICMP responder) can plug directly into `Session.Read`/`Write` exactly the way this plan's own harness-only `test/interop/server/main.go` responder does, with zero `Session`-surface changes needed.
- `Server.dataSessions`'s peer-id-keyed routing (Assumption A3, RESEARCH.md) is now the load-bearing design for all inbound data traffic; any future `PROTO-02` (session floating / stable source-address routing) work should be aware this table is keyed on peer-id, not on `sessionKey{addr,sid}`.
- The keepalive goroutine only emits pings; it does not implement `ping-restart`/idle-session reaping (`SESS-05`, Phase 4's scope) — a session whose peer stops responding is not currently torn down by this plan's own code, by design (documented in `session.go`'s own doc comments so a future reader does not read the omission as an oversight).
- No blockers for plan 02-04.

---
*Phase: 02-tunnel-up*
*Completed: 2026-08-24*
