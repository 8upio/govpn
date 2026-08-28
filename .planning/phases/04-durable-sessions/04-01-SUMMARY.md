---
phase: 04-durable-sessions
plan: "01"
subsystem: infra
tags: [openvpn, tls, control-channel, key-renegotiation, ctrlconn, session-lifecycle]

# Dependency graph
requires:
  - phase: 03-in-process-termination
    provides: netstack Session boundary, unprivileged server-side traffic termination
provides:
  - Two-slot (primary/lameDuck) key state on Session replacing the single dataWrapper field
  - Client-initiated and server-initiated P_CONTROL_SOFT_RESET_V1 renegotiation, full new TLS + Key Method 2 exchange under an incremented key-id, over the SAME control-channel session
  - Config.RenegSec (0 -> 3600s default) driving the server's own independent reneg-sec timer
  - Key-id validation as a hard error, a reneg-flood rate limit, and a lame-duck expiry sweep (Conn + decrypt-validity both bounded)
  - internal/ctrlconn.NewWithKeyID — a Conn parameterized by its own TLS key-id
affects: [04-02, 04-03, 04-04]

# Actuals (#2632)
actuals:
  tokens: 23384
  tasks: 3
  commits: 3

tech-stack:
  added: []
  patterns:
    - "Two named key-state fields (primary/lameDuck) instead of a map, mirroring the reference's own KS_PRIMARY/KS_LAME_DUCK two-slot design"
    - "start*/run* ticker-plus-injectable-channel split (startReneg/runReneg) mirroring the existing startKeepalive/runKeepalive precedent"
    - "Shared deriveKeyMethod2 core consumed by both the initial handshake and every renegotiation, so key derivation logic can never diverge between the two paths"

key-files:
  created:
    - reneg_test.go
  modified:
    - session.go
    - ovpn.go
    - internal/ctrlconn/conn.go
    - ovpn_test.go
    - gates_test.go
    - Makefile

key-decisions:
  - "Two-slot key-state (primary/lameDuck) as named struct fields, not a map[uint8]keySlot, per RESEARCH's reference-mirroring recommendation"
  - "runRenegotiation stops after Key Method 2 — no performPushExchange, no pool.allocate, no OnSession — enforced by a standing AST gate, not just a code review"
  - "transitionWindow=3600s (options.c:881) and defaultRenegSec=3600s (options.c:878) resolved directly from the C reference rather than guessed, per the plan's own explicit lookup instruction"
  - "renegMinInterval = defaultRenegSec/60 (60s) as a rate-limit floor, documented as defense in depth on top of tls-crypt's own replay window, not the primary defense"

patterns-established:
  - "Any new renegotiation-Conn construction site must take its key-id from nextKeyID's own local computation — enforced going forward by TestPhase4KeyIDNeverTrustedFromPeer"
  - "A synthetic test client must react to an unprompted server-initiated control packet only AFTER actually receiving it (auto-register-on-receipt in testPushClientDemux), never speculatively pre-open a Conn and send before the server has a route — doing so trips tls-crypt's replay window permanently for that packet-id"

requirements-completed: [SESS-04]

coverage:
  - id: D1
    description: "A client that sends P_CONTROL_SOFT_RESET_V1 at the correct next key-id completes a full new TLS + Key Method 2 handshake over the same control-channel session; the Session is never replaced or re-handed to OnSession, and AssignedIP()/PeerID() are unchanged"
    requirement: "SESS-04"
    verification:
      - kind: unit
        ref: "reneg_test.go#TestSoftResetRollover"
        status: pass
    human_judgment: false
  - id: D2
    description: "After a rollover, a data packet sealed under the new key decrypts via the primary slot, and a data packet sealed under the old key still decrypts via the lame-duck slot until the transition window elapses, after which it is refused and the lame-duck Conn is closed"
    requirement: "SESS-04"
    verification:
      - kind: unit
        ref: "reneg_test.go#TestSoftResetRollover"
        status: pass
      - kind: unit
        ref: "reneg_test.go#TestLameDuckKeyRefusedAfterTransitionWindow"
        status: pass
      - kind: unit
        ref: "reneg_test.go#TestLameDuckConnClosedOnExpiry"
        status: pass
    human_judgment: false
  - id: D3
    description: "The server's own reneg-sec timer fires a soft reset with no inbound client packet required, and re-arms from the new primary slot's own established timestamp after each rollover"
    requirement: "SESS-04"
    verification:
      - kind: unit
        ref: "reneg_test.go#TestServerInitiatedRenegOnRenegSec"
        status: pass
      - kind: unit
        ref: "reneg_test.go#TestRenegTimerRearmsAfterRollover"
        status: pass
      - kind: unit
        ref: "reneg_test.go#TestRenegTimerStopsOnClose"
        status: pass
    human_judgment: false
  - id: D4
    description: "An incoming SOFT_RESET_V1 at the wrong key-id, or arriving before the primary slot is established, or arriving in a flood, is refused without advancing any session state"
    requirement: "SESS-04"
    verification:
      - kind: unit
        ref: "reneg_test.go#TestForgedKeyIDRenegRejected"
        status: pass
      - kind: unit
        ref: "reneg_test.go#TestRenegRejectedBeforePrimaryEstablished"
        status: pass
      - kind: unit
        ref: "reneg_test.go#TestRenegFloodRateLimited"
        status: pass
    human_judgment: false
  - id: D5
    description: "A session that never renegotiates behaves exactly as it did in Phase 3 — no pre-existing test assertion weakened, skipped, or deleted"
    requirement: "SESS-04"
    verification:
      - kind: unit
        ref: "go test -race -count=1 ./..."
        status: pass
    human_judgment: false
  - id: D6
    description: "Standing prohibition gates (TestPhase4*) enforce the four must_haves prohibitions this plan introduced, wired into make gates/make test"
    verification:
      - kind: unit
        ref: "gates_test.go#TestPhase4RenegotiationNeverRepeatsPushExchange"
        status: pass
      - kind: unit
        ref: "gates_test.go#TestPhase4RenegotiationReusesSessionTLSCryptWrapper"
        status: pass
      - kind: unit
        ref: "gates_test.go#TestPhase4KeyIDNeverTrustedFromPeer"
        status: pass
      - kind: unit
        ref: "gates_test.go#TestPhase4NoNewModuleDependencies"
        status: pass
    human_judgment: false

duration: 55min
completed: 2026-08-28
status: complete
---

# Phase 4 Plan 01: Soft-Reset Key Renegotiation Summary

**A live session survives client- and server-initiated `P_CONTROL_SOFT_RESET_V1` renegotiation — full new TLS + Key Method 2 handshake under an incremented key-id, same control channel, zero packet-visible interruption, with forged key-ids and reneg floods rejected and the lame-duck key actually expiring.**

## Performance

- **Duration:** ~55 min
- **Completed:** 2026-08-28
- **Tasks:** 3
- **Files modified:** 6 (1 created: `reneg_test.go`)

## Accomplishments

- Two-slot key state (`Session.primary`/`Session.lameDuck`) replaces the single `dataWrapper` field; every existing data-path call site (`Write`, `emitPing`, `handleDataPacket`, `Close`) migrated, and `pump` now routes control packets by key-id instead of unconditionally to one fixed Conn.
- Client-initiated renegotiation: an inbound `SOFT_RESET_V1` at the locally-computed next key-id starts a full new TLS handshake + Key Method 2 exchange over a fresh `ctrlconn.Conn` that reuses the session's own tls-crypt `Wrapper` and session IDs — proven end-to-end against a live `srv.Serve` loop with a synthetic client (`TestSoftResetRollover`): new-key decrypt, old-key decrypt during the lame-duck window, transmit switched, and `AssignedIP`/`PeerID`/the `*Session` pointer unchanged.
- Server-initiated renegotiation: `Config.RenegSec` (0 → 3600s default) drives a per-session timer (`startReneg`/`runReneg`, mirroring `startKeepalive`/`runKeepalive`) that fires a soft reset with no inbound client packet required, and re-arms from the new primary slot's own `established` timestamp after each rollover.
- Hardening: a key-id other than the locally-computed next value is a hard refusal (never trusted from the peer); a `renegMinInterval` rate limit bounds how often a peer can force a full handshake; a lame-duck expiry sweep (same ticker as the reneg-sec timer) closes the demoted Conn and zeroes the slot once its `mustDie` deadline passes, freeing its retransmit goroutine.
- Four `TestPhase4*` standing gates (AST-based, matching this repo's existing `gates_test.go` style) enforce the plan's own prohibitions going forward — each one manually confirmed to fail when its prohibition was temporarily violated, then reverted clean.

## Task Commits

Each task was committed atomically:

1. **Task 1: A client renegotiates and traffic keeps flowing on both keys** - `e6f1e91` (feat)
2. **Task 2: The server starts its own renegotiation on its own clock** - `cd85632` (feat)
3. **Task 3: A forged key-id is refused, and the lame-duck key really dies** - `d65e14e` (feat)

_No separate TDD RED/GREEN commits: `tdd_mode` is `false` in this project's config, and the plan's own tracer-task feedback gate (re-running `TestSoftResetRollover` end-to-end before expanding) was satisfied inline within Task 1's single commit._

## Files Created/Modified

- `session.go` - `keySlot` type; `Session.primary`/`lameDuck`/`clock`/`pendingReneg`/`pendingRenegKeyID`/`lastRenegAccepted`; `now()`; `routeControlPacket`; dual-key `handleDataPacket`; `startReneg`/`runReneg`/`checkReneg`/`sweepLameDuck`; `Close` closes every Conn a session ever owned
- `ovpn.go` - `Config.RenegSec`; `Server.renegSec`/`clock`; `keyIDMask`/`nextKeyID`; `transitionWindow`/`defaultRenegSec`/`renegMinInterval`/`renegPollInterval` constants; `beginRenegotiation`/`startRenegotiation`/`runRenegotiation`; `deriveKeyMethod2` (shared core); key-id-aware `pump`; soft-reset interception in `handleDatagram`; retired `dataChannelKeyID`
- `internal/ctrlconn/conn.go` - `Conn.keyID`; `NewWithKeyID`; `New` is now a thin delegate at key-id 0
- `reneg_test.go` - all fast-tier renegotiation tests (created)
- `ovpn_test.go` - `testPushClient` per-key-id demux map, `renegotiate()` helper, `dataOut` channel, auto-register-on-receipt for server-initiated soft resets; mechanical `dataWrapper` → `primary.wrapper` renames in pre-existing tests (no assertion changes)
- `gates_test.go` - four `TestPhase4*` standing gates
- `Makefile` - `gates` target regex extended to match `TestPhase4`

## Decisions Made

- Two named key-slot fields (`primary`, `lameDuck`) rather than a `map[uint8]keySlot` — the reference itself never holds more than two live slots per session (RESEARCH's own Alternatives Considered).
- `runRenegotiation` and `performKeyMethod2Exchange` share a `deriveKeyMethod2` core so the initial handshake and every renegotiation run byte-identical key-derivation logic — enforced structurally rather than by convention.
- `transitionWindow` (3600s, options.c:881) and `defaultRenegSec` (3600s, options.c:878) were looked up directly in the C reference checkout rather than guessed, per the plan's explicit instruction (RESEARCH's Open Question 1).
- `renegMinInterval` set to `defaultRenegSec/60` (60s) — a small fraction of the reference default, documented as defense-in-depth on top of tls-crypt's own replay window rather than the primary anti-flood mechanism.
- The receiving server's reply to an inbound `SOFT_RESET_V1` is itself a `SOFT_RESET_V1` with an empty payload (via `DeliverAndRespond`), mirroring the reference's `session_move_pre_start` (`ssl.c:2594`) — confirmed by reading the C reference directly (the plan's own `read_first` instruction) rather than assumed.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Test-harness-only: synthetic client must react to a server-initiated soft reset only after receiving it, never pre-emptively**
- **Found during:** Task 2 (writing `TestRenegTimerRearmsAfterRollover`)
- **Issue:** An early version of the test pre-registered a client-side Conn for the next key-id and immediately called `tls.Client(...).Handshake()` before the server had decided to renegotiate. The premature ClientHello got dropped (no server-side route yet), and every retransmission of that exact packet-id was then permanently rejected by the server's tls-crypt replay window, hanging the test.
- **Fix:** Extended `testPushClientDemux` to auto-register a new Conn only when it actually observes an inbound `SOFT_RESET_V1` for an unrecognized key-id — mirroring how a real client reacts to an unprompted server-initiated soft reset — and report the new Conn on a channel (`serverInitiatedReneg`) the test waits on before starting its own handshake.
- **Files modified:** `ovpn_test.go`, `reneg_test.go`
- **Verification:** `TestRenegTimerRearmsAfterRollover` passes under `-race`.
- **Committed in:** `cd85632` (Task 2 commit)

---

**Total deviations:** 1 auto-fixed (1 bug, test-harness-only — no production code affected)
**Impact on plan:** No scope creep; the fix only touches test infrastructure and, incidentally, documents a real protocol property (premature retransmission of an already-seen tls-crypt packet-id is permanently rejected) that is worth knowing for any future synthetic-client test in this codebase.

## Issues Encountered

None beyond the deviation above — debugged via temporary `println` instrumentation (session.go's `checkReneg`, ovpn.go's `pump`/`runRenegotiation`, internal/ctrlconn's `retransmitLoop`), all removed before the Task 2 commit (confirmed via `git diff --stat` showing net-zero change to `internal/ctrlconn/conn.go`).

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- Two-slot key state, the renegotiation driver, and `Config.RenegSec` are all in place for plan `04-02` (explicit-exit-notify, idle-session reaping) to extend `handleDataPacket` and `Session.Close` further.
- Plans `04-03`/`04-04` (interop scenario, soak test) can drive `Config.RenegSec` down to a short interval against a real client — the mechanism is proven fast-tier; Docker-tier verification is out of this plan's scope.
- No blockers. `go build ./... && go vet ./... && go test -race -count=1 ./...` and `make gates`/`make test` all exit 0.

---
*Phase: 04-durable-sessions*
*Completed: 2026-08-28*

## Self-Check: PASSED

- All key files confirmed present on disk: `session.go`, `ovpn.go`, `internal/ctrlconn/conn.go`, `reneg_test.go`, `ovpn_test.go`, `gates_test.go`, `Makefile`, `.planning/phases/04-durable-sessions/04-01-SUMMARY.md`.
- All three task commits confirmed present in `git log --oneline --all`: `e6f1e91`, `cd85632`, `d65e14e`.
