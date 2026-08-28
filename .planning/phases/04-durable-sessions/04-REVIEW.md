---
phase: 04-durable-sessions
reviewed: 2026-08-28T00:00:00Z
depth: standard
files_reviewed: 2
files_reviewed_list:
  - ovpn.go
  - reneg_test.go
findings:
  critical: 0
  warning: 0
  info: 1
  total: 1
status: clean
---

# Phase 04: Code Review Report (Iteration 3 — Final Verification)

**Reviewed:** 2026-08-28T00:00:00Z
**Depth:** standard
**Files Reviewed:** 2 (`ovpn.go`, `reneg_test.go` — narrowly scoped to re-verify CR-02 (`4f25152`) and WR-03 (`296e63e`))
**Status:** issues_found

## Summary

This is a narrowly-scoped final verification pass over the two fixes from
iteration 2: CR-02 (`4f25152`, watchdog closing an already-promoted `Conn`)
and WR-03 (`296e63e`, `runRenegotiation`'s `datachan.NewWrapper` failure path
not clearing `pendingReneg`).

**Both CR-02 and WR-03 are genuinely and correctly fixed for the exact
scenarios they targeted.**

- CR-02: `enforceRenegotiationWindow`'s timeout branch now only calls
  `newConn.Close()` when `stillPending` (the same variable that gated the
  `pendingReneg` clear) is true — verified by direct code trace and by
  `TestEnforceRenegotiationWindowDoesNotCloseSwappedConn`, which reproduces
  the exact post-swap/pre-`done` window (sess already has `pendingReneg ==
  nil` and `primary.conn == newConn`, `done` deliberately never closed) and
  confirms `newConn` is not torn down.
- WR-03: the `datachan.NewWrapper` failure branch in `runRenegotiation` now
  clears `sess.pendingReneg` (guarded by the same `== newConn` check used
  elsewhere) before unlocking and closing `newConn` — verified by direct
  code trace and by `TestRunRenegotiationClearsPendingRenegOnWrapperFailure`
  (a structural `go/ast` assertion, since the failure itself has no runtime
  injection seam today).
- CR-01's original guarantees are intact: `TestStalledRenegotiationRecoversAfterWindow`
  still passes and still proves a stalled renegotiation's goroutine exits,
  `pendingReneg` clears, and a fresh renegotiation attempt re-arms afterward.
  `go build ./...` is clean and `go test -race -count=1 .` passes in full
  (all packages, all reneg tests included).

**However, tracing every interleaving of `enforceRenegotiationWindow`'s
timeout branch against `runRenegotiation`'s *success* (swap) path — as this
verification pass was specifically asked to do — surfaces a related, still-open
race that CR-02's fix does not cover**, because CR-02 only closed the window
*after* the swap commits; it left open a mirror-image window *before* the
swap commits. See CR-03 below. `pendingReneg` itself is never cleared twice
(every clear site uses the same `if sess.pendingReneg == newConn { ... =
nil }` compare-and-clear idiom under `sess.mu`, so at most one caller's clear
ever "wins" and every other caller correctly observes it already gone) — the
new finding is not a `pendingReneg` double-clear, but the swap path
unconditionally publishing `newConn` as the new primary `Conn` without
re-checking that this specific renegotiation attempt is still the live one.

## Critical Issues

### CR-03 (CLOSED, `e647f49`): `runRenegotiation`'s success path can promote an already-closed `newConn` to `sess.primary.conn`, because it never re-checks `sess.pendingReneg == newConn` before committing the swap

**Status: fixed in `e647f49` (04-REVIEW-FIX.md iteration 3).** Applied the
fix exactly as proposed below: `runRenegotiation`'s swap section now
re-checks `sess.pendingReneg != newConn` alongside `sess.closing()` before
committing the swap, abandoning it (closing `newConn`) if the watchdog
already cleared `pendingReneg` in the interim. Regression test
`TestRunRenegotiationAbandonsSwapWhenPendingRenegAlreadyCleared` added in
`reneg_test.go`, confirmed to fail against the pre-fix code and pass
against the fix; `TestStalledRenegotiationRecoversAfterWindow` and
`TestEnforceRenegotiationWindowDoesNotCloseSwappedConn` re-verified with no
regression. `go build ./...`, `go vet ./...`, `go test -race -count=1
./...`, and `make gates` all pass. See 04-REVIEW-FIX.md for full detail.

**File:** `ovpn.go:1092-1183` (`runRenegotiation`), specifically the gap between the `tlsConn.Handshake()`/`deriveKeyMethod2` calls (`ovpn.go:1117-1127`) and the swap's lock acquisition (`ovpn.go:1129`); compare `ovpn.go:1206-1227` (`enforceRenegotiationWindow`).

**Issue:** CR-02 fixed the race where the watchdog fires *after* the swap has
already published `newConn` as `sess.primary.conn` and cleared
`sess.pendingReneg` — the watchdog now checks `sess.pendingReneg == newConn`
before closing, and by the time the swap has committed that's already false,
so it correctly does nothing.

But `sess.pendingReneg` is only cleared *inside* the swap's own critical
section, at the very end (`ovpn.go:1170-1172`), immediately before its
`sess.mu.Unlock()`. Nothing checks `sess.pendingReneg` (or `newConn`'s own
closed state) at the *start* of that critical section, before deciding to
proceed with the swap. The only gate at that point is `sess.closing()`
(`ovpn.go:1130`), which asks "is the whole *session* tearing down?" — not
"is *this specific renegotiation attempt* still the one the watchdog
believes is live?"

Concretely:

1. `tlsConn.Handshake()` (`ovpn.go:1118`) and `s.deriveKeyMethod2(...)`
   (`ovpn.go:1123`) both complete successfully over `newConn` — the client's
   renegotiation genuinely succeeded, real bytes were exchanged.
2. Before `runRenegotiation`'s next line reaches `sess.mu.Lock()`
   (`ovpn.go:1129`), the independent `enforceRenegotiationWindow` goroutine's
   `time.After(s.handshakeWindow)` fires (this only requires wall-clock time
   elapsed since the renegotiation began to have reached `s.handshakeWindow`
   — entirely plausible for a real client whose network conditions make the
   handshake take close to the full window, and trivially reproducible with
   a short `handshakeWindow` such as the ones several of this file's own
   tests already configure, e.g. `1ms`/`30ms`).
3. The watchdog wins the race for `sess.mu`: `sess.pendingReneg == newConn`
   is still true at this point (nothing has cleared it yet — the swap
   hasn't run), so it sets `stillPending = true`, clears
   `sess.pendingReneg = nil`, unlocks, and — per CR-02's own (correct) logic
   for *this* scenario — closes `newConn`, because as far as the watchdog
   can tell this attempt genuinely timed out.
4. `runRenegotiation` then acquires `sess.mu` (`ovpn.go:1129`). `sess.closing()`
   is false (the *session* isn't closing — only this one renegotiation
   attempt was just invalidated by the watchdog). `datachan.NewWrapper(...)`
   (`ovpn.go:1136`) succeeds — it only depends on already-derived key
   material and IDs, not on `newConn`'s liveness. The function then
   unconditionally proceeds through the swap (`ovpn.go:1151-1173`): it
   demotes the OLD, still-good primary key to lame-duck
   (`sess.lameDuck = sess.primary`, with a `transitionWindow` expiry), and
   publishes `sess.primary = keySlot{conn: newConn, ...}` — where `newConn`
   was closed by the watchdog one step ago. The trailing
   `if sess.pendingReneg == newConn { sess.pendingReneg = nil }`
   (`ovpn.go:1176-1178`) is a no-op (already nil from step 3), so nothing
   here notices anything went wrong.

Result: `sess.primary.conn` now points at a `Conn` whose `closed` field is
already `true` (`internal/ctrlconn/conn.go:383-388`). Any further
control-channel traffic routed to this key-id —
`routeControlPacket`/`pump`'s `Deliver` call (`ovpn.go:667-668`,
`session.go:626-647`), which matches purely on `keyID` with no liveness
check — silently fails: `Deliver` → `absorb` → `flushAckOnly` → `transmit`
goes through `writeChunk`/`waitForSendSlot`, which observes `c.closed` and
errors out (`internal/ctrlconn/conn.go:307-329`), and any read on that `Conn`
returns `io.EOF` immediately. Meanwhile the previously-live primary key was
needlessly demoted to a lame-duck that will itself be torn down after
`transitionWindow`. The already-derived data-channel key (`newWrapper`) still
works for actual tunnel traffic (data-channel packets never go through
`ctrlconn.Conn`), so this is not a total outage, but it silently and
permanently breaks this session's control channel for the just-negotiated
key-id — e.g. a lost final ACK that would otherwise be retransmitted is now
simply dropped forever, and the corruption is invisible to the embedder
(`OnSession` already fired long ago; nothing surfaces this failure).

This is not a `pendingReneg` double-clear (the compare-and-clear idiom
correctly prevents that) and it is not the literal CR-02 scenario (the
watchdog does not close an *already-primary* `Conn` here — it closes
`newConn` *before* the swap runs). It is the mirror-image gap: the runtime
sequence never re-validates, immediately before committing state that treats
`newConn` as live, that the watchdog hasn't already invalidated it in the
interim. None of the existing regression tests exercise this window —
`TestEnforceRenegotiationWindowDoesNotCloseSwappedConn` starts from a state
where the swap has *already* happened; `TestStalledRenegotiationRecoversAfterWindow`
never lets the handshake succeed at all.

**Fix:** Re-check `sess.pendingReneg == newConn` at the same point
`sess.closing()` is already checked, and abandon the swap (closing `newConn`,
exactly as the `closing()` branch already does) if it no longer matches —
this makes the swap section symmetric with the watchdog's own
compare-and-clear, so whichever side observes the mismatch first is the one
that tears `newConn` down, and the other becomes a no-op:

```go
sess.mu.Lock()
if sess.closing() || sess.pendingReneg != newConn {
	sess.mu.Unlock()
	_ = newConn.Close()
	return
}

newWrapper, err := datachan.NewWrapper(dataKeys.ServerSlots(), sess.peerID, keyID)
...
```

With this change, the final `if sess.pendingReneg == newConn { sess.pendingReneg
= nil }` at the end of the swap becomes unconditionally true (never a no-op)
since the lock is held continuously from the new check through the clear, so
it can simply become an unconditional `sess.pendingReneg = nil` if desired —
though leaving the guarded form is harmless and keeps the two clear sites
textually consistent.

A regression test can reproduce this deterministically without a real
timing race, mirroring `TestEnforceRenegotiationWindowDoesNotCloseSwappedConn`'s
own technique: construct `sess` with `pendingReneg` already `nil` (simulating
"the watchdog got here first") and `primary` still pointing at the *old* key,
then call `runRenegotiation`'s post-handshake continuation directly (or
factor the swap into a small helper that can be called with a pre-closed
`newConn` and asserted to leave `sess.primary` unchanged / `newConn` closed
rather than promoted).

## Info

### IN-01 (carried forward, unfixed, out of this iteration's file scope): Dead variable `rootCert` in `cmd/gentestpki/main.go`

**File:** `cmd/gentestpki/main.go:122-193` (declaration `:123`, assignments `:140`/`:160`, discard `:193`)

**Issue:** Unchanged since iteration 1 — `cmd/gentestpki/main.go` is outside
this iteration's fix surface (`ovpn.go`, `reneg_test.go` only), so this item
was not addressed. `rootCert` is still declared, assigned in both the
`profileSmall` and `profileLarge` branches, and then immediately discarded
via `_ = rootCert` with no other use.

**Fix:** Remove the `rootCert` variable and its two assignments along with
the `_ = rootCert` line, since nothing downstream uses it.

---

_Reviewed: 2026-08-28T00:00:00Z_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: standard_
_Verification: `go build ./...` clean; `go test -race -count=1 .` passes (all
existing tests, including the CR-01/CR-02/WR-01/WR-02/WR-03 regression tests,
pass under the race detector). CR-02 and WR-03 were confirmed fixed by direct
code trace against commits `4f25152` and `296e63e` respectively, and by their
dedicated regression tests. CR-03 (new) is not caught by the current suite —
it requires the same class of narrow wall-clock/scheduler timing window
already acknowledged for CR-02, but one step earlier in `runRenegotiation`'s
sequence (between `deriveKeyMethod2` succeeding and the swap's
`sess.mu.Lock()`), which no existing test drives._
