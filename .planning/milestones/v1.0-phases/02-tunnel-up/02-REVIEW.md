---
phase: 02-tunnel-up
reviewed: 2026-08-25T00:00:00Z
depth: standard
files_reviewed: 4
files_reviewed_list:
  - ovpn.go
  - session.go
  - ovpn_test.go
  - ippool.go
findings:
  critical: 0
  warning: 0
  info: 0
  total: 0
status: clean
---

# Phase 02: Code Review Report (Re-review, iteration 3 — final)

**Reviewed:** 2026-08-25T00:00:00Z
**Depth:** standard
**Files Reviewed:** 4 (`ovpn.go`, `session.go`, `ovpn_test.go`, `ippool.go`)
**Status:** clean

## Summary

Narrowly-scoped re-review of the single open finding from iteration 2
(WR-05: zombie-session/pool-leak race between `Close()` and
`performPushExchange`), fixed in commit `812c2c8`. `go build ./...`,
`go vet ./...`, and `go test -race -count=1 .` are all clean; the WR-05
regression test and the pre-existing WR-03/WR-04 regression tests were also
re-run at `-race -count=10` (and the full package at `-count=3`) with no
flakes.

**WR-05 is genuinely closed.** Verified rigorously against the diff
(`git show 812c2c8`) and by tracing every interleaving by hand:

1. **Lock-ordering check.** `sess.mu → srv.mu` is the only nesting order
   used anywhere in these files. It appears in exactly two places —
   `performPushExchange`'s atomic publish (`ovpn.go:648-661`) and
   `Session.Close` (`session.go:486-507`) — and both use the identical
   order. Every other lock-taking site (`handleDatagram`, `removeSession`,
   `Server.Close`, `pump`, `enforceHandshakeWindow`, `AssignedIP`,
   `PeerID`) either takes only one of the two mutexes or never holds one
   while blocking on the other (`Server.Close` builds its session slice
   under `s.mu`, fully releases it, and only then calls `sess.Close()` on
   each session outside the lock). `ipPool.mu` (a third lock) is never
   nested inside `sess.mu`/`srv.mu` in either call site — both
   `s.pool.release(...)` calls happen strictly after the corresponding
   `sess.mu.Unlock()`. No lock-ordering cycle, no deadlock risk.

2. **Leak scenario — exhaustive interleaving trace.** `Close`'s
   `stopOnce.Do` body closes `s.stopCh` as its unconditional first
   statement, before ever touching `sess.mu`, and `performPushExchange`
   checks `sess.closing()` (which reads that same channel) under `sess.mu`
   immediately before publishing `assignedIP`/`peerID`/`dataWrapper` and
   the `dataSessions` entry as one atomic, `sess.mu`-then-`srv.mu`-nested
   step. Tracing both possible orderings of the two critical sections:
   - If `Close`'s snapshot runs first (or `stopCh` closes before
     `performPushExchange`'s check), `performPushExchange` always observes
     `closing() == true` (channel-close is a one-way, permanently-visible
     state transition) and takes the abort branch, releasing the IP/peer-id
     it just allocated via `s.pool.release(ip, peerID)` — `Close`'s own
     snapshot sees all three fields still nil/zero and correctly skips its
     own release/delete, since nothing was ever published for it to clean
     up. Released exactly once.
   - If `performPushExchange`'s publish runs first (mutex exclusion
     guarantees it completes atomically, including the nested
     `dataSessions` write, before `Close`'s critical section can begin),
     `Close`'s later snapshot observes `assignedIP`/`peerID`/`dataWrapper`
     fully populated, correctly deletes the `dataSessions` entry (WR-04's
     order preserved: delete before release) and releases the pool
     allocation. Released exactly once.
   No interleaving leaves the IP/peer-id/`dataSessions` entry either
   double-released or permanently stranded. `TestPerformPushExchangeReleasesAllocationWhenSessionAlreadyClosing`
   (`ovpn_test.go:638`) exercises the first case end-to-end on an
   exactly-one-slot `/30` network and fails against the pre-fix code, as
   documented in its own comment; re-run at `-count=10 -race` here with no
   failures.

3. **D-08 contract.** `runHandshake` now re-checks `sess.closing()`
   immediately after `close(sess.doneCh)` and before ever calling
   `OnSession` (`ovpn.go:547-550`), treating an already-closing session
   exactly like a failed bring-up. This closes the residual window where
   `enforceHandshakeWindow`'s timeout could land after
   `performPushExchange`'s atomic publish committed but before control
   reached `runHandshake`'s tail. A vanishingly narrow TOCTOU remains
   between that check and the `OnSession` call two lines later (inherent to
   any final-gate design that doesn't hold a lock across an arbitrary
   caller-supplied callback, which would be a worse trade-off) — this is
   qualitatively different from, and much narrower than, the WR-05 leak
   window that spanned all of `performPushExchange` including
   `pool.allocate()` and the reply I/O; not treated as an open finding.

4. **No regressions to CR-01/WR-01..04.** `handleDatagram`'s
   data-packet branch still runs before the `minDatagramSize` gate
   (CR-01, `ovpn.go:317-320`); `normalizeIPv4Mask` in `ippool.go` is
   byte-for-byte unchanged from iteration 2 (WR-01; `ippool.go` was not
   touched by commit `812c2c8` per `git show --stat`); `Close` still
   removes the `dataSessions` entry before releasing `peerID` (WR-04,
   `session.go:491-506`), reconfirmed by `TestCloseRemovesRoutingEntryBeforeReleasingPeerID`
   passing at `-race -count=10`; the `sess.mu` guard over
   `assignedIP`/`peerID`/`dataWrapper` (WR-03) is preserved and its own
   regression test (`TestPerformPushExchangeFieldWritesRaceSafeAgainstClose`)
   still passes at `-race -count=10`.

No new issues were found in `ovpn.go`, `session.go`, `ippool.go`, or
`ovpn_test.go` during this pass. `go vet ./...` is clean and no debug
artifacts (TODO/FIXME/console-log-equivalents) are present in the reviewed
files.

All three prior findings across the review's history (CR-01, WR-01 through
WR-04, and now WR-05) are closed. No open Critical, Warning, or Info items
remain.

---

_Reviewed: 2026-08-25T00:00:00Z_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: standard_
_Iteration: 3 (final re-review — WR-05 verification)_
