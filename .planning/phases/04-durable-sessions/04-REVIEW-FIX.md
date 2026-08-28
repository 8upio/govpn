---
phase: 04-durable-sessions
fixed_at: 2026-08-28T12:37:50Z
review_path: .planning/phases/04-durable-sessions/04-REVIEW.md
iteration: 3
findings_in_scope: 1
fixed: 1
skipped: 0
status: all_fixed
---

# Phase 04: Code Review Fix Report

**Fixed at:** 2026-08-28T12:37:50Z
**Source review:** .planning/phases/04-durable-sessions/04-REVIEW.md
**Iteration:** 3

**Summary:**
- Findings in scope (critical + warning): 1
- Fixed: 1
- Skipped: 0

This is iteration 3, scoped to the single open blocker surfaced by
iteration 3's own narrow re-verification pass over CR-02 (`4f25152`) and
WR-03 (`296e63e`): CR-03, a mirror-image race `runRenegotiation`'s success
(swap) path left open even after CR-02 closed the equivalent window on
`enforceRenegotiationWindow`'s timeout branch. Fix scope was
`critical_warning`; IN-01 (`cmd/gentestpki/main.go`'s dead `rootCert`
variable, carried forward unchanged since iteration 1, out of file scope
for every iteration of this fix pass) remains unaddressed by design.

## Fixed Issues

### CR-03: `runRenegotiation`'s success path could promote an already-closed `newConn` to `sess.primary.conn`, because it never re-checked `sess.pendingReneg == newConn` before committing the swap

**Files modified:** `ovpn.go`, `reneg_test.go`
**Commit:** `e647f49`
**Applied fix:** Matched the review's proposed fix exactly: at the same
point `runRenegotiation` already checks `sess.closing()` under `sess.mu`
(immediately after `tlsConn.Handshake()`/`deriveKeyMethod2` succeed, before
committing the primary/lame-duck swap), added a re-check that
`sess.pendingReneg == newConn`. If it no longer matches — meaning
`enforceRenegotiationWindow`'s watchdog won the race, observed
`sess.pendingReneg == newConn`, cleared it, and closed `newConn` in the
window between the handshake completing and this lock acquisition — the
swap is now abandoned exactly like the `sess.closing()` branch already
does: unlock, `newConn.Close()` (idempotent if the watchdog already closed
it), return. This makes the swap's entry gate symmetric with the
watchdog's own compare-and-clear (`ovpn.go`'s
`enforceRenegotiationWindow`): whichever side observes the mismatch first
is the one that tears `newConn` down, and the other becomes a no-op. The
trailing `if sess.pendingReneg == newConn { sess.pendingReneg = nil }` at
the end of the swap was left in its existing guarded form (per the
review's own note that this is harmless and keeps the two clear sites
textually consistent), since with the lock held continuously from the new
check through the clear it is now unconditionally true whenever reached.

Regression test `TestRunRenegotiationAbandonsSwapWhenPendingRenegAlreadyCleared`
reproduces the exact scenario deterministically, without depending on any
real timing race: `sess` is constructed with `pendingReneg` already `nil`
— simulating "the watchdog already got here first and cleared it" — while
a real client goroutine drives an actual `tls.Client(...).Handshake()` and
Key Method 2 exchange to completion over `newConn`, so
`runRenegotiation`'s own `Handshake()`/`deriveKeyMethod2` calls genuinely
succeed (this exercises the swap-lock gate itself, not a failed-handshake
early return). Because a live `srv.Serve()` loop's own packet routing
(`session.go`'s `routeControlPacket`) routes to a renegotiation's `Conn`
strictly via `sess.pendingReneg`/`sess.pendingRenegKeyID` — which would
never deliver anything to `newConn` while `pendingReneg` is deliberately
held `nil` for the whole test — the test instead drives two small,
symmetric manual dispatch goroutines (server-side and client-side) that
unwrap inbound datagrams and call `Conn.Deliver` directly, bypassing
session-level routing entirely, mirroring `ovpn.go`'s own unwrap-and-parse
step. Since `sess.pendingReneg` never equals `newConn` at any point in this
test (not just transiently), the fix's re-check is guaranteed to observe
the mismatch on every run, regardless of scheduler timing. The test
asserts: `sess.primary` is unchanged (still the old key-id/`Conn`),
`sess.renegotiations` stayed at 0 (swap never ran), `sess.pendingReneg`
stayed `nil`, and `newConn` was actually closed (`Read` after a short
deadline returns `io.EOF`, not a timeout). Verified to fail
(`sess.primary` promoted to the closed `newConn`) against the pre-fix
`ovpn.go`, and to pass against the fix.

No regression to the two named prior tests: `TestStalledRenegotiationRecoversAfterWindow`
(CR-01) and `TestEnforceRenegotiationWindowDoesNotCloseSwappedConn` (CR-02)
both still pass, run alongside the new test and the full suite, including
under `-race` with `-count=3`.

## Verification

Run after the fix, in the isolated review-fix worktree
(`.claude/worktrees/rf-04-53275-*`, branch `gsd-reviewfix/04-53275`,
fast-forwarded onto `main` on cleanup as commit `e647f49`):

- `go build ./...` — clean, no errors.
- `go vet ./...` — clean, no errors.
- `go test -race -count=1 ./...` — all packages pass (`ok` across the
  module and every internal package, `examples/tunnelweb`, and
  `test/interop/server`).
- Targeted `-race -count=3` reruns of
  `TestRunRenegotiationAbandonsSwapWhenPendingRenegAlreadyCleared`,
  `TestStalledRenegotiationRecoversAfterWindow`,
  `TestEnforceRenegotiationWindowDoesNotCloseSwappedConn`,
  `TestRunRenegotiationClearsPendingRenegOnWrapperFailure`,
  `TestSoftResetRollover`, and `TestRenegTimerRearmsAfterRollover` — all
  pass, no flakes across 3 iterations.
- `make gates` — all Phase 2/3/4 standing-prohibition assertions pass.
- Sanity check: the new regression test was confirmed to fail against the
  pre-fix `ovpn.go` (via `git stash` of the fix commit's `ovpn.go` change
  only, test rerun, then `git stash pop` to restore the fix) before being
  committed.

No skipped findings in scope. IN-01 (info-level, out of `critical_warning`
scope) remains unaddressed, unchanged from iteration 1. With CR-03 now
fixed and no other open findings, `04-REVIEW.md`'s `status` has been set
to `clean`.

---

_Fixed: 2026-08-28T12:37:50Z_
_Fixer: Claude (gsd-code-fixer)_
_Iteration: 3_
