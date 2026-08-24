---
phase: 02-tunnel-up
fixed_at: 2026-08-25T00:06:22+02:00
review_path: .planning/phases/02-tunnel-up/02-REVIEW.md
iteration: 2
findings_in_scope: 1
fixed: 1
skipped: 0
status: all_fixed
---

# Phase 02: Code Review Fix Report (iteration 2)

**Fixed at:** 2026-08-25T00:06:22+02:00
**Source review:** .planning/phases/02-tunnel-up/02-REVIEW.md
**Iteration:** 2

**Summary:**
- Findings in scope: 1 (WR-05; CR-01/WR-01..04 were already fixed and closed as of the
  iteration-2 REVIEW.md)
- Fixed: 1
- Skipped: 0

## Fixed Issues

### WR-05: `performPushExchange` can allocate and publish session state after `enforceHandshakeWindow` has already closed the session, permanently leaking the pool IP/peer-id and the `dataSessions` routing entry

**Files modified:** `ovpn.go`, `session.go`, `ovpn_test.go`
**Commit:** `812c2c8`
**Applied fix:**

The review's suggested fix (a single `sess.mu`-guarded "closing" check right after
`s.pool.allocate()`, before writing `assignedIP`/`peerID`) was evaluated against the actual
code and found to close only the *first* sub-window of the race, not the whole
allocate-then-publish sequence the finding describes. Tracing the interleaving in detail
showed that if `enforceHandshakeWindow`'s `Close()` landed strictly *between*
`performPushExchange`'s field-publish step (`assignedIP`/`peerID`/`dataWrapper` under
`sess.mu`) and its later, separately-locked `dataSessions` publish (under `srv.mu`), the
single-check fix would still let `Close()` release `peerID` back to the pool while
`performPushExchange` was mid-flight — opening a narrower but more severe window where a
freshly-reallocated `peerID` for a brand-new legitimate session could be clobbered a moment
later by the zombie `performPushExchange`'s stale `dataSessions` write (a routing hijack, not
just a leak).

To close the entire window structurally rather than probabilistically, the fix instead makes
the whole allocate-then-publish sequence one atomic step:

- **`Session.closing()`** (new, `session.go`): a small helper that reports whether `stopCh` is
  already closed — reused by both call sites below. Selecting on a closed channel is one of
  the operations the Go memory model itself guarantees as synchronizing, matching the existing
  `select`-on-`stopCh` discipline already used by `pump`/`Read`/`runKeepalive`.
- **`performPushExchange`** (`ovpn.go`): builds the `dataWrapper` *before* acquiring `sess.mu`
  (rather than after, as before), then does the closing check and the entire publish —
  `assignedIP`, `peerID`, `dataWrapper`, `ipInbound`, and the `dataSessions[peerID] = sess`
  routing entry — as one critical section held under `sess.mu`, with `srv.mu` nested inside it
  for the `dataSessions` write. If `sess.closing()` is true at the check, nothing is published
  and the just-allocated `ip`/`peerID` is released back to the pool immediately
  (`s.pool.release`), and an error is returned so `runHandshake` calls `sess.Close()` (a no-op,
  idempotent via `stopOnce`) instead of ever invoking `Config.OnSession`.
- **`Session.Close`** (`session.go`): mirrors the same nesting order (`sess.mu` outer, `srv.mu`
  inner) across its own snapshot-and-delete sequence, rather than releasing `sess.mu` between
  the snapshot and the `dataSessions` delete as before. This is what makes the two critical
  sections (publish vs. cleanup) mutually exclusive as a whole: whichever one the mutex
  serializes second always observes a fully consistent state from the other (either "nothing
  published yet" or "everything published, including the routing entry"), never a partial one.
- **`runHandshake`** (`ovpn.go`): added a final `sess.closing()` check immediately before
  invoking `Config.OnSession`, closing the residual (much narrower) window where
  `enforceHandshakeWindow`'s `Close()` lands *after* `performPushExchange`'s atomic publish
  committed but *before* control returns to `runHandshake` — the leaks/hijack are already
  prevented by the atomic publish above in this case, but without this check `OnSession` could
  still fire for a `Session` whose `Read` returns `io.EOF` immediately, violating this
  project's D-08 contract ("the Session handed to OnSession is immediately usable"). On
  detecting closure, `sess.Close()` is called (idempotent no-op) and `OnSession` is skipped,
  exactly like a failed bring-up step.

No lock-ordering cycle is introduced: nothing in the codebase acquires `srv.mu` and then tries
to acquire a session's `sess.mu` while holding it (confirmed by inspection of every `.mu.Lock()`
call site in `ovpn.go`/`session.go`), so `sess.mu`-then-`srv.mu` is a new but uncontested
nesting order, consistently applied in both `performPushExchange` and `Close`.

**Regression test:** `TestPerformPushExchangeReleasesAllocationWhenSessionAlreadyClosing`
(`ovpn_test.go`) deterministically forces the exact "Close already ran" state by calling the
real, idempotent `sess.Close()` before invoking `performPushExchange` on a session with a
one-address `/30` pool, then asserts: (1) `performPushExchange` returns a non-nil error, (2)
`sess.assignedIP`/`sess.dataWrapper` remain unset, (3) `srv.dataSessions` gains no entry, and
(4) a subsequent `pool.allocate()` on the same network succeeds — proving the allocation made
inside `performPushExchange` was released, not leaked. Verified this test **fails** against the
pre-fix code (`performPushExchange` succeeds, publishes state, and the pool's sole address
never becomes allocatable again) and **passes** with the fix applied, via a temporary
`git stash` of `ovpn.go`/`session.go` while keeping the new test.

**Verification performed** (from the isolated worktree, `workflow.use_worktrees` was not set to
`false` so the standard worktree flow ran):
- `go build ./...` — clean.
- `go vet ./...` — clean.
- `go test -race -count=1 ./...` — all packages pass, including the new regression test and
  the existing WR-03 (`TestPerformPushExchangeFieldWritesRaceSafeAgainstClose`, 50 iterations)
  and WR-04 (`TestCloseRemovesRoutingEntryBeforeReleasingPeerID`) regression tests, confirming
  no new races and no regression of the earlier fixes' lock-ordering guarantees.
- `go test -tags interop -run TestInteropScenarios -v ./test/interop/...` — Docker was
  available; ran all three scenarios (clean-small, clean-large, lossy-large) against a real,
  unmodified OpenVPN 2.6 client. All passed: handshake completed, `PUSH_REPLY` delivered
  (`ifconfig 10.8.0.2 255.255.255.0 ... peer-id 0`), data-channel ping round-tripped
  successfully (9/10 replies on the lossy link, within tolerance), and the server logged `PASS:
  session established and stable 20s past handshake completion`. Confirms the restructured
  `performPushExchange`/`Close` interaction did not disturb the real tunnel-up path.

**Note on classification:** this fix involves lock-ordering/concurrency reasoning beyond what
Tier 1/2 syntax verification can confirm. The reasoning is documented above and backed by both
a deterministic regression test (proven to fail pre-fix) and a passing `-race` run across 50+
iterations of the adjacent WR-03 race test plus a full real-client interop run, but per this
workflow's own guidance for logic-classified findings, **human verification of the concurrency
argument is still recommended** before this phase proceeds to the verifier stage.

## Skipped Issues

None — the only in-scope finding (WR-05) was fixed.

---

_Fixed: 2026-08-25T00:06:22+02:00_
_Fixer: Claude (gsd-code-fixer)_
_Iteration: 2_
