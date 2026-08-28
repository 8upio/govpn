---
phase: 04-durable-sessions
plan: "02"
subsystem: infra
tags: [openvpn, session-lifecycle, exit-notify, idle-reap, data-channel]

# Dependency graph
requires:
  - phase: 04-durable-sessions
    provides: "04-01's two-slot (primary/lameDuck) key state, dual-key decrypt path in handleDataPacket, and the injected-clock/start*-run* ticker precedent"
provides:
  - "OCC_EXIT (explicit-exit-notify) detection on the authenticated data channel, closing a session immediately on a real client's `explicit-exit-notify`"
  - "A server-authoritative idle-session reaper (60s window, six times the pushed ping interval) driven by an injectable clock"
  - "Write() honoring teardown (io.EOF) alongside Read(), and a Session doc contract naming all three teardown causes"
  - "Three standing TestPhase4* gates enforcing this plan's own prohibitions (post-decrypt-only exit-notify check, Close-only teardown, no OnSessionClosed callback)"
affects: [04-03, 04-04]

# Actuals (#2632)
actuals:
  tokens: 11026
  tasks: 3
  commits: 3

tech-stack:
  added: []
  patterns:
    - "start*/run* ticker-plus-injectable-channel split (startReap/runReap) mirroring the existing startKeepalive/startReneg precedent"
    - "Post-decrypt-only protocol-constant check (isExitNotify) gated strictly on authenticated plaintext, never ciphertext, enforced by a standing AST gate"
    - "Single shared last-authenticated-traffic timestamp reset from exactly two call sites (pump's control-delivery path, handleDataPacket's post-decrypt path), mirroring the reference's own two reset sites"

key-files:
  created:
    - lifecycle_test.go
  modified:
    - session.go
    - ovpn.go
    - reneg_test.go
    - gates_test.go

key-decisions:
  - "defaultReapWindow expressed as 6*pingInterval rather than a bare 60*time.Second, making its relationship to the pushed keepalive schedule structural rather than just documented"
  - "Server.reapWindow is a test-injectable field defaulted in NewServer only (like handshakeWindow) — not resolved from any Config field, since 04-CONTEXT.md deliberately defers a configurable reap timeout beyond the pushed keepalive"
  - "isExitNotify checked with bytes.Equal, not crypto/subtle — occMagic is a public 16-byte protocol constant, not a secret, matching the reference's own non-constant-time buf_string_match_head"
  - "Write's pre-existing 'data channel not yet established' error is kept distinct from the new post-teardown io.EOF — a session mid-negotiation and a session that has already ended are different states an embedder may need to distinguish"

requirements-completed: [SESS-05]

coverage:
  - id: D1
    description: "A client sending explicit-exit-notify (OCC_EXIT) on the authenticated data channel closes the session immediately: Session.Read returns io.EOF, the session leaves Server.sessions/Server.dataSessions, and its tunnel IP/peer-id become reallocatable — while three negative cases (wrong opcode, truncated magic, ordinary IP) leave the session open"
    requirement: "SESS-05"
    verification:
      - kind: unit
        ref: "lifecycle_test.go#TestExitNotifyClosesSessionImmediately"
        status: pass
      - kind: unit
        ref: "lifecycle_test.go#TestExitNotifyOnLameDuckKeyClosesSession"
        status: pass
    human_judgment: false
  - id: D2
    description: "A session with no authenticated traffic for the reap window (60s) is closed by the server on an injected clock; any authenticated arrival — control or data, primary or lame-duck — resets the timer; a forged/failed-auth packet does not"
    requirement: "SESS-05"
    verification:
      - kind: unit
        ref: "lifecycle_test.go#TestSilentSessionReaped"
        status: pass
      - kind: unit
        ref: "lifecycle_test.go#TestAuthenticatedDataResetsReapTimer"
        status: pass
      - kind: unit
        ref: "lifecycle_test.go#TestLameDuckDecryptResetsReapTimer"
        status: pass
      - kind: unit
        ref: "lifecycle_test.go#TestForgedPacketDoesNotResetReapTimer"
        status: pass
      - kind: unit
        ref: "lifecycle_test.go#TestDeliveredControlPacketResetsReapTimer"
        status: pass
      - kind: unit
        ref: "lifecycle_test.go#TestReapTimerStopsOnClose"
        status: pass
    human_judgment: false
  - id: D3
    description: "After teardown from any cause (embedder Close, exit-notify, reap, handshake-window timeout), Session.Read and Session.Write both return io.EOF, and no per-session goroutine (pump, keepalive, reneg/expiry ticker, reaper) outlives the session"
    requirement: "SESS-05"
    verification:
      - kind: unit
        ref: "lifecycle_test.go#TestReadWriteReturnEOFAfterEveryTeardownCause"
        status: pass
      - kind: unit
        ref: "lifecycle_test.go#TestNoGoroutineLeakAcrossSessionLifecycle"
        status: pass
    human_judgment: false
  - id: D4
    description: "Standing prohibition gates enforce this plan's own must_haves prohibitions going forward: the exit-notify check runs only inside handleDataPacket post-decrypt, all teardown flows through Close's stopOnce, and Config declares no OnSessionClosed-style callback"
    verification:
      - kind: unit
        ref: "gates_test.go#TestPhase4ExitNotifyCheckedOnlyPostDecrypt"
        status: pass
      - kind: unit
        ref: "gates_test.go#TestPhase4TeardownAlwaysFlowsThroughClose"
        status: pass
      - kind: unit
        ref: "gates_test.go#TestPhase4NoSessionClosedCallback"
        status: pass
    human_judgment: false

duration: 65min
completed: 2026-08-28
status: complete
---

# Phase 4 Plan 02: Session Teardown — Exit-Notify, Idle Reap, and the EOF Contract Summary

**A client's explicit-exit-notify closes its session immediately, a silent session is reaped after 60s on the server's own clock, and every teardown cause now leaves `Read`/`Write` returning `io.EOF` with zero leaked goroutines.**

## Performance

- **Duration:** ~65 min
- **Completed:** 2026-08-28
- **Tasks:** 3
- **Files modified:** 4 (1 created: `lifecycle_test.go`)

## Accomplishments

- Explicit-exit-notify (OCC_EXIT) detection: a decrypted data-channel payload matching `occ_magic` (`occ.c:55-58`) followed by the `OCC_EXIT` opcode byte (`occ.h:29-30,67`) tears the session down immediately via the existing `Close()`/`stopOnce` path — checked only after a successful `Wrapper.Open`, on either the primary or lame-duck key slot, never on ciphertext. Three negative cases (wrong OCC opcode, a truncated 16-byte magic, an ordinary IP packet) are proven to leave the session open and functional.
- Idle-session reaper: `Session.startReap`/`runReap` (mirroring `startKeepalive`/`startReneg`'s own ticker-plus-injectable-channel shape) close a session that has received no authenticated traffic for `defaultReapWindow` (60s — six times the pushed `pingIntervalSeconds`, expressed as `6*pingInterval` so the relationship is structural). `lastAuthTraffic` is touched from exactly two call sites — a delivered control packet in `pump`, and a successful data-channel decrypt (primary or lame-duck) in `handleDataPacket` — never on a forged or failed-auth packet.
- Teardown contract completed: `Write` now checks `s.closing()` first and returns `io.EOF`, matching `Read`'s existing behavior, while keeping the pre-existing "data channel not yet established" error distinct for the genuinely-pre-tunnel-up case. `Session`'s doc comment now names all three teardown causes (embedder `Close`, client exit-notify, idle reap).
- `TestNoGoroutineLeakAcrossSessionLifecycle` proves a full tunnel-up + one renegotiation + teardown returns `runtime.NumGoroutine()` to its pre-session baseline — manually confirmed to FAIL when `runReap`'s `stopCh` case is temporarily removed, then reverted clean (`git diff --stat session.go` showed only the intended net change afterward).
- Three new `TestPhase4*` standing gates (matching this repo's existing AST-based `gates_test.go` style) enforce the plan's own prohibitions: the exit-notify check's only call site is `handleDataPacket`; every `stopCh` close / `sessions`/`dataSessions` delete / `pool.release` outside `Close`'s `stopOnce` body (and its one narrow, pre-existing `performPushExchange` rollback-on-error exception) is flagged; `Config` declares no `OnSessionClosed`-style field.

## Task Commits

Each task was committed atomically:

1. **Task 1: A client that says goodbye is gone immediately** - `005bad9` (feat)
2. **Task 2: A silent session is reaped** - `7bdf8ce` (feat)
3. **Task 3: Teardown from any cause leaves nothing behind** - `bb0bbd4` (feat)

_No separate TDD RED/GREEN commits: `tdd_mode` is `false` in this project's config, matching 04-01's own precedent._

## Files Created/Modified

- `session.go` — `occMagic`/`occExit` constants (`// Source: occ.c:55-58`, `occ.h:29-30,67`); `isExitNotify`; the exit-notify branch inside `handleDataPacket`; `lastAuthTraffic` field; `touchAuthTraffic`; `startReap`/`runReap`; `Write` returning `io.EOF` after teardown; updated `Session`/`Write`/`mu` doc comments
- `ovpn.go` — `defaultReapWindow`/`reapPollInterval` constants; `Server.reapWindow` (test-injectable, defaulted in `NewServer`); `touchAuthTraffic` call in `pump`'s delivered-control-packet path; `lastAuthTraffic` init + `startReap()` call in `performPushExchange`, alongside `startKeepalive`/`startReneg`
- `reneg_test.go` — `TestRenegTimerRearmsAfterRollover`'s hand-built `Server` now sets `reapWindow` explicitly (see Deviations below)
- `lifecycle_test.go` — all fast-tier exit-notify, reap, teardown-contract, and goroutine-leak tests (created)
- `gates_test.go` — three `TestPhase4*` standing gates

## Decisions Made

- `defaultReapWindow = 6 * pingInterval` rather than a bare `60 * time.Second` — the relationship to the pushed keepalive schedule is structural, not just documented in a comment.
- `Server.reapWindow` follows `handshakeWindow`'s exact precedent: defaulted only in `NewServer`, not resolved from any `Config` field (04-CONTEXT.md deliberately defers a configurable reap timeout beyond the pushed keepalive).
- `isExitNotify` uses `bytes.Equal`, not `crypto/subtle` — `occMagic` is a public 16-byte protocol constant, not a secret, matching the reference's own non-constant-time `buf_string_match_head`.
- `Write`'s existing "data channel not yet established" error is kept distinct from the new post-teardown `io.EOF` — a session mid-negotiation and one that has already ended are different states an embedder may need to tell apart.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] `TestRenegTimerRearmsAfterRollover` broke against the new idle-reap timer**
- **Found during:** Task 2, running the full race suite after adding `startReap`
- **Issue:** This pre-existing (04-01) test hand-builds a `*Server{}` directly (bypassing `NewServer`, so `reapWindow` defaulted to its Go zero value) and jumps the injected fake clock forward 2 hours to make the reneg-sec poller observe an already-elapsed deadline. Once `startReap` began running for every real tunnel-up session, the SAME clock jump made `runReap`'s next real-second tick see `s.now().Sub(lastAuthTraffic)` as 2+ hours — vastly exceeding even the intended 60s default — and reap the session before the test's own server-initiated renegotiation could complete. Failures: `"server never initiated the second (server-triggered) renegotiation"` and `"ctrlconn: i/o timeout"`.
- **Fix:** Set `reapWindow: 24 * time.Hour` explicitly on the test's hand-built `Server` literal, mirroring how it already sets `handshakeWindow: reliable.HandshakeWindow` explicitly (hand-built `Server`s bypass `NewServer`'s defaults for every test-injectable window field, by existing convention). This is a test-harness-only fix — no production code changed, no assertion weakened.
- **Files modified:** `reneg_test.go`
- **Verification:** `TestRenegTimerRearmsAfterRollover` passes under `-race` (confirmed 3x consecutively); full `go test -race -count=1 ./...` passes.
- **Committed in:** `7bdf8ce` (Task 2 commit)

---

**Total deviations:** 1 auto-fixed (1 bug, test-harness-only — no production code affected)
**Impact on plan:** No scope creep. The fix documents a genuine interaction between this plan's new server-authoritative reap timer and 04-01's fake-clock-jump testing pattern: any future fast-tier test that jumps an injected clock by more than the reap window, across a real tunnel-up, must set `reapWindow` explicitly on its hand-built `Server` — the same discipline `handshakeWindow` already established.

## Issues Encountered

None beyond the deviation above.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- OCC_EXIT detection, the idle reaper, and the completed `io.EOF`/goroutine-teardown contract are all in place for plan `04-03`'s interop scenario to assert the same behaviors against a real OpenVPN 2.6 client (with `explicit-exit-notify 1` in its config, per `04-RESEARCH.md` Pitfall 3) and for plan `04-04`'s soak test to measure the same goroutine/heap property over 20 real connect/disconnect cycles.
- No blockers. `go build ./... && go vet ./... && go test -race -count=1 ./...`, `make gates`, and `make test` all exit 0. `git diff --stat go.mod` produces no output.

---
*Phase: 04-durable-sessions*
*Completed: 2026-08-28*

## Self-Check: PASSED

- All key files confirmed present on disk: `session.go`, `ovpn.go`, `reneg_test.go`, `lifecycle_test.go`, `gates_test.go`, `.planning/phases/04-durable-sessions/04-02-SUMMARY.md`.
- All three task commits confirmed present in `git log --oneline`: `005bad9`, `7bdf8ce`, `bb0bbd4`.
