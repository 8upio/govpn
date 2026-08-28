---
phase: 04-durable-sessions
fixed_at: 2026-08-28T12:05:31Z
review_path: .planning/phases/04-durable-sessions/04-REVIEW.md
iteration: 1
findings_in_scope: 3
fixed: 3
skipped: 0
status: all_fixed
---

# Phase 04: Code Review Fix Report

**Fixed at:** 2026-08-28T12:05:31Z
**Source review:** .planning/phases/04-durable-sessions/04-REVIEW.md
**Iteration:** 1

**Summary:**
- Findings in scope (critical + warning): 3
- Fixed: 3
- Skipped: 0

Fix scope was `critical_warning`, so IN-01 (`cmd/gentestpki/main.go`'s dead
`rootCert` variable) was left untouched — out of scope for this pass.

## Fixed Issues

### CR-01: In-flight renegotiation has no timeout — a stalled reneg leaks a goroutine and permanently disables future rekeying for the session

**Files modified:** `ovpn.go`, `reneg_test.go`
**Commit:** de3a1e2
**Applied fix:** Added `enforceRenegotiationWindow`, mirroring
`enforceHandshakeWindow`'s shape exactly: a companion goroutine, started
from inside `runRenegotiation` itself (so both existing call sites —
`beginRenegotiation` and `checkReneg`'s server-initiated path — get the
watchdog with no change needed at either site), races
`time.After(s.handshakeWindow)` against a `done` channel that
`runRenegotiation` closes via `defer` on every return path. On timeout, it
clears `sess.pendingReneg` (if still pointing at the stalled `newConn`)
and calls `newConn.Close()`, which unblocks the stuck
`tls.Server(...).Handshake()`/`deriveKeyMethod2` call and routes execution
into the existing `abandon()` path — the old primary key is left live and
usable exactly as the reference's own S_GENERATED_KEYS-gated abandonment
semantics require (T-04-04); the session itself is never torn down for a
stalled reneg, only the stuck attempt.

Regression test `TestStalledRenegotiationRecoversAfterWindow` starts a
renegotiation with no peer ever driving the TLS handshake to completion
(reproducing the "client goes silent mid-handshake" scenario CR-01
describes), confirms `sess.pendingReneg` clears and the
`runRenegotiation` goroutine returns once the (test-shortened,
30ms) `handshakeWindow` elapses, and then confirms a **second**
`startRenegotiation` call succeeds — the actual regression CR-01
identified, since without the fix every subsequent attempt is refused
forever once one stalls. Verified to fail (times out waiting for
`pendingReneg` to clear) against the pre-fix `ovpn.go`, and to pass
against the fix.

Note on "clock-injected, no real sleeps": `internal/reliable.Clock` only
abstracts `Now()`, not timers, and `enforceHandshakeWindow` — the
mechanism CR-01's fix mirrors — is itself built on `time.After` with a
short, test-overridden `srv.handshakeWindow` (see
`lifecycle_test.go`'s pre-existing "handshake-window timeout" case, and
`ovpn_test.go`'s own 150ms overrides). The new test follows this same,
already-established codebase convention (a short real duration, not a
long production-sized sleep) rather than inventing a parallel
clock-injection mechanism for this one watchdog.

### WR-01: `Session.dataKeys` is written under `sess.mu` in `runRenegotiation` but read without any lock in `DebugDataKeys`/`DebugKeyMethod2Material`

**Files modified:** `session.go`, `ovpn.go`, `reneg_test.go`
**Commit:** d3e146b
**Applied fix:** Took the review's "cheapest" option: `DebugDataKeys` now
locks `sess.mu` around its read of `s.dataKeys`, `performKeyMethod2Exchange`
(the initial-handshake write site) now locks `sess.mu` around its write of
`sess.dataKeys` for consistency with `runRenegotiation`'s already-locked
write, and `dataKeys` was added to `Session.mu`'s own doc comment's
guarded-field list. `clientKM`/`serverKM` were deliberately left
unguarded — they are written exactly once, unlocked, during the
single-writer initial handshake before `OnSession` ever publishes the
`*Session` to an embedder, and are never rewritten by
`runRenegotiation` — and this is now documented explicitly in the doc
comment rather than left as a silent exception.

Regression test `TestDebugDataKeysConcurrentWithWrite` drives a tight
concurrent loop of `sess.mu`-guarded writes to `sess.dataKeys` against a
tight loop of `DebugDataKeys()` reads, with no other synchronization point
between them (deliberately not polling under `sess.mu` first, which is
what let every pre-existing test in the suite pass under `-race` even
before this fix). Verified to fail under `go test -race` (reports the
exact `WARNING: DATA RACE` at `session.go:467`, the pre-fix unguarded
read) against the pre-fix `session.go`, and to pass against the fix.

### WR-02: Packets already queued before `Close()` can still be routed to an already-closed `Conn`

**Files modified:** `ovpn.go`, `reneg_test.go`
**Commit:** 890ceec
**Applied fix:** Added a `sess.closing()` check at the top of `pump()`'s
`case cp := <-sess.inbound:` branch, exactly as the review's fix snippet
proposed — once `Close()` has closed `stopCh`, no further packet is
dispatched to any `Conn`, whether or not `select` happened to pick the
`inbound` case over the `stopCh` case on that particular iteration.

Regression test `TestPumpDoesNotDeliverAfterClose` pre-loads one
ack-only packet into `sess.inbound` and closes `stopCh` *before* `pump()`
ever starts running, so `pump`'s first `select` call sees both channels
ready simultaneously on every one of 200 trials — reproducing WR-02's
race window on each trial regardless of which case Go's runtime happens
to pick. It asserts `sess.lastAuthTraffic` (delivery's own observable
side effect) is never set across all 200 trials. Verified to fail
immediately (trial 0) against the pre-fix `ovpn.go`, and to pass all 200
trials against the fix.

## Verification

Run after each fix and again at the end of the pass, all in the isolated
review-fix worktree:

- `go build ./...` — clean, no errors.
- `go vet ./...` — clean, no errors.
- `go test -race -count=1 ./...` — all packages pass.
- `make gates` — all Phase 2/3/4 standing-prohibition assertions pass.
- `make test` (gates + vet + build + `go test -race ./...`) — all
  packages pass.
- `make interop` (Docker available) — all four scenarios pass:
  `clean-small`, `clean-large`, `lossy-large`, and `reneg`. The `reneg`
  scenario is the live confirmation for this fix set: a real, unmodified
  OpenVPN 2.6 client completed 3 renegotiations
  (`renegotiations=3`, want at least 2) against the CR-01/WR-01/WR-02-fixed
  server, followed by a clean explicit-exit-notify teardown observed
  0s after the client's graceful stop.

No skipped findings in scope. IN-01 (info-level, out of `critical_warning`
scope) is unaddressed by this pass.

---

_Fixed: 2026-08-28T12:05:31Z_
_Fixer: Claude (gsd-code-fixer)_
_Iteration: 1_
