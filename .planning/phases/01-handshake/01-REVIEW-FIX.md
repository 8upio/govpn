---
phase: 01-handshake
fixed_at: 2026-08-24T07:30:00Z
review_path: .planning/phases/01-handshake/01-REVIEW.md
iteration: 2
findings_in_scope: 3
fixed: 3
skipped: 0
status: all_fixed
---

# Phase 01: Code Review Fix Report

**Fixed at:** 2026-08-24T07:30:00Z
**Source review:** .planning/phases/01-handshake/01-REVIEW.md
**Iteration:** 2

**Summary:**
- Findings in scope: 3 (fix_scope: critical_warning — CR-*/BL-* and WR-*; IN-* findings out of scope. This iteration's review found 0 Critical findings and 3 Warning findings: WR-03, WR-04, WR-05.)
- Fixed: 3
- Skipped: 0

**Verification environment:** All fixes were applied and verified (`go build ./...`, `go vet ./...`, `go test -race -count=1 ./...` — run three times to check for flakiness in the new goroutine-count regression test) inside an isolated git worktree at `.claude/worktrees/rf-01-9161-1787556052` on temp branch `gsd-reviewfix/01-9161`, fast-forwarded onto `main` on cleanup. The numbers below are reproducible from `main` after the worktree teardown.

## Fixed Issues

### WR-03: `callOnSession`'s panic recovery is a silent swallow — no observability into a caller callback that panicked

**Files modified:** `ovpn.go`
**Commit:** `c429ed1`
**Applied fix:** Added an optional `Config.OnSessionPanic func(sess *Session, recovered any, stack []byte)` hook. `callOnSession`'s deferred `recover()` now captures the panic value and, if `OnSessionPanic` is set, invokes it with the `Session`, the recovered value, and `runtime/debug.Stack()` instead of discarding the panic silently. `OnSessionPanic` is nil-safe (no-op when unset), preserving prior behavior for embedders who don't opt in. Matches the REVIEW.md fix suggestion's shape.

### WR-04: `Wrapper.Wrap` writes a live `time.Now()` into the tls-crypt long-form packet ID on every packet instead of the reference's frozen per-key timestamp

**Files modified:** `internal/tlscrypt/tlscrypt.go`
**Commit:** `c1c01ab`
**Applied fix:** Added a `sendTime int64` field to `Wrapper`, set once on the first `Wrap` call (mirroring `packet_id_send_update`'s `if (!p->time) { p->time = now; }`, `packet_id.c:323-326`) and thereafter frozen for the life of the key — updated only alongside the existing `sendRolloverAt` gate at a genuine sequence rollover. `Wrap` now writes `pid[4:8]` from `w.sendTime` instead of a fresh `time.Now().Unix()` per call. The existing WR-02 rollover gate (`sendRolloverAt`, `sendSeq == 0xFFFFFFFF` check) was left untouched per the task's guidance to keep it consistent — `sendTime` is updated in lockstep with `sendRolloverAt` at rollover, exactly as the REVIEW.md fix snippet specified.

### WR-05: CR-01/WR-01/WR-02 shipped without any regression test

**Files modified:** `ovpn_test.go`, `internal/tlscrypt/tlscrypt_test.go`
**Commit:** `12582f5`
**Applied fix:** Added four white-box regression tests:
- `TestSessionCloseStopsPumpAndRemovesFromSessions` (ovpn_test.go) — establishes a real session via a UDP hard-reset datagram, grabs the `*Session` from `Server.sessions`, calls `Close()`, and asserts (a) the session is removed from `Server.sessions` and (b) `runtime.NumGoroutine()` returns to its pre-session baseline within a 2s poll window — covering CR-01 (pump/runHandshake/enforceHandshakeWindow goroutine leak + session-table leak).
- `TestOnSessionPanicRecovered` (ovpn_test.go) — drives `Server.callOnSession` directly with an `OnSession` that panics and an `OnSessionPanic` hook, asserting the call returns normally and the hook receives the recovered value — covering WR-01/WR-03.
- `TestWrapPacketIDRolloverGate` (internal/tlscrypt/tlscrypt_test.go) — deterministically forces `sendSeq = 0xFFFFFFFF` and `sendRolloverAt` into the future (white-box, no wall-clock timing dependency), asserting the next `Wrap` call returns an error and leaves `sendSeq` unchanged rather than silently wrapping around — covering WR-02.
- `TestWrapPacketIDTimestampFrozenPerKey` (internal/tlscrypt/tlscrypt_test.go) — asserts the wire packet-ID timestamp bytes are identical across two successive `Wrap` calls and match the Wrapper's own frozen `sendTime` field — covering WR-04 (added in this same iteration, so it ships with test coverage from the start rather than repeating WR-05's gap).

All four tests pass under `go test -race -count=1 ./...`, run three times consecutively with no flakiness observed.

---

_Fixed: 2026-08-24T07:30:00Z_
_Fixer: Claude (gsd-code-fixer)_
_Iteration: 2_
